package ws

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// upgrader는 일반 HTTP 연결을 양방향 통신이 가능한 WebSocket 연결로 전환(업그레이드)합니다.
var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

// HandleWebSocket은 웹소켓 연결을 처리하고 터미널 세션을 중계합니다.
func HandleWebSocket(c *gin.Context) {
	githubUser := c.GetString("username")
	nodeHost := c.Query("node_host")
	loginUser := c.Query("login_user")
	if nodeHost == "" || loginUser == "" {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	var certID string
	// 1. 사용자를 위한 단기 인증서를 저장할 고유한 임시 파일 경로 생성 (파일은 생성하지 않음)
	outBase := fmt.Sprintf("%s/tsh-cert-%d-%d", os.TempDir(), os.Getpid(), time.Now().UnixNano())
	privKeyPath := outBase
	certPubPath := outBase + "-cert.pub"

	// 기존 파일이 남아있다면 삭제 (tctl openssh 포맷은 <out>와 <out>-cert.pub 두 파일을 생성)
	_ = os.Remove(privKeyPath)
	_ = os.Remove(certPubPath)

	// 세션 종료 시 정리
	defer os.Remove(privKeyPath)
	defer os.Remove(certPubPath)
	defer func() {
		// 인증서 폐기
		if certID != "" {
			log.Printf("세션 종료: 인증서 폐기 중... (ID: %s)", certID)
			revokeCmd := exec.Command("sudo", "tctl", "auth", "certs", "rm", certID)
			if output, err := revokeCmd.CombinedOutput(); err != nil {
				log.Printf("인증서 폐기 실패 (ID: %s): %v, 출력: %s", certID, err, string(output))
			} else {
				log.Printf("인증서 폐기 성공 (ID: %s)", certID)
			}
		}
	}()

	log.Printf("사용자 '%s'를 위한 단기 인증서 생성 중... (대상: %s@%s)", githubUser, loginUser, nodeHost)

	// 2. tctl auth sign 명령으로 단기 인증서 발급
	authSignCmd := exec.Command("sudo", "tctl",
		"--auth-server=openswdev.duckdns.org:3080",
		"--identity=/opt/jarvis-service-identity",
		"auth", "sign",
		"--user", githubUser,
		"--out", privKeyPath,
		"--format=openssh",
		"--ttl=1m",
	)
	var stdoutBuf, stderrBuf bytes.Buffer
	authSignCmd.Stdout = &stdoutBuf
	authSignCmd.Stderr = &stderrBuf

	if err := authSignCmd.Run(); err != nil {
		log.Printf("tctl auth sign 실패: %v, Stderr: %s", err, stderrBuf.String())
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// 3. 발급된 인증서의 ID를 파싱
	re := regexp.MustCompile(`Certificate ID:\s*([0-9a-fA-F-]+)`)
	matches := re.FindStringSubmatch(stdoutBuf.String())
	if len(matches) > 1 {
		certID = matches[1]
		log.Printf("사용자 '%s'의 인증서가 발급되었습니다 (ID: %s). SSH 세션을 시작합니다.", githubUser, certID)
	} else {
		log.Printf("인증서 ID를 파싱하지 못했습니다. 출력: %s", stdoutBuf.String())
	}

	// 4. 발급받은 단기 인증서를 사용하여 SSH 연결
	sshCmd := exec.Command("sudo", "tsh", "ssh",
		"-tt", // PTY 강제 할당
		"--proxy", "openswdev.duckdns.org:3080",
		"-i", privKeyPath, // 생성된 단기 인증서 사용
		fmt.Sprintf("%s@%s", loginUser, nodeHost),
		"--",          // 이후 인수를 원격 커맨드로 전달
		"bash", "-lc", // login 셸 모드 + 커맨드 실행
		fmt.Sprintf("echo 'Welcome %s'; exec bash", githubUser),
	)

	stdout, err := sshCmd.StdoutPipe()
	if err != nil {
		log.Printf("StdoutPipe 생성 실패: %v", err)
		return
	}
	stdin, err := sshCmd.StdinPipe()
	if err != nil {
		log.Printf("StdinPipe 생성 실패: %v", err)
		return
	}
	sshCmd.Stderr = os.Stderr

	if err := sshCmd.Start(); err != nil {
		log.Printf("SSH Command 시작 실패: %v", err)
		return
	}
	defer sshCmd.Process.Kill()

	feConn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("웹소켓 업그레이드 실패: %v", err)
		return
	}
	defer feConn.Close()

	log.Println("프론트엔드와 WebSocket 연결 성공. 데이터 중계를 시작합니다.")

	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := stdout.Read(buf)
			if err != nil {
				log.Printf("SSH stdout 읽기 실패: %v", err)
				return
			}
			if err := feConn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
				log.Printf("웹소켓으로 데이터 쓰기 실패: %v", err)
				return
			}
		}
	}()

	for {
		_, msg, err := feConn.ReadMessage()
		if err != nil {
			log.Printf("웹소켓에서 데이터 읽기 실패: %v", err)
			return
		}
		if _, err := stdin.Write(msg); err != nil {
			log.Printf("SSH stdin으로 데이터 쓰기 실패: %v", err)
			return
		}
	}
}
