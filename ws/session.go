package ws

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
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
	// 1. 사용자를 위한 단기 인증서를 저장할 고유한 임시 파일 경로 생성
	outBase := fmt.Sprintf("%s/tsh-cert-%d-%d", os.TempDir(), os.Getpid(), time.Now().UnixNano())
	identityFile := fmt.Sprintf("%s/tsh-identity-%d-%d", os.TempDir(), os.Getpid(), time.Now().UnixNano())
	tshHome := fmt.Sprintf("%s/tsh-home-%d-%d", os.TempDir(), os.Getpid(), time.Now().UnixNano())

	if err := os.MkdirAll(tshHome, 0700); err != nil {
		log.Printf("tsh home 디렉토리 생성 실패: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// 기존 파일이 남아있다면 삭제
	_ = os.Remove(outBase)
	_ = os.Remove(outBase + "-cert.pub")
	_ = os.Remove(identityFile)

	// 세션 종료 시 정리
	defer os.Remove(outBase)
	defer os.Remove(outBase + "-cert.pub")
	defer os.Remove(identityFile)
	defer os.RemoveAll(tshHome)
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
		"--out", outBase,
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
	re := regexp.MustCompile(`(?i)Certificate ID:\s*([0-9a-fA-F-]+)`)
	matches := re.FindStringSubmatch(stdoutBuf.String())
	if len(matches) > 1 {
		certID = matches[1]
		log.Printf("사용자 '%s'의 인증서가 발급되었습니다 (ID: %s). SSH 세션을 시작합니다.", githubUser, certID)
	} else {
		// Certificate ID가 없는 경우 새 포맷 처리: 파일 경로를 fallback ID로 사용
		certID = "" // Teleport 최신 버전에서는 ID 자체가 출력되지 않음
		log.Printf("파일 기반 인증서만 사용합니다. 출력: %s", stdoutBuf.String())
	}

	// 4. 생성된 파일들이 존재하는지 확인
	if _, err := os.Stat(outBase); err != nil {
		log.Printf("개인키 파일이 생성되지 않았습니다: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	if _, err := os.Stat(outBase + "-cert.pub"); err != nil {
		log.Printf("인증서 파일이 생성되지 않았습니다: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// 5. identity 파일 생성 (개인키 + 인증서를 합친 형태)
	keyContent, err := os.ReadFile(outBase)
	if err != nil {
		log.Printf("개인키 파일 읽기 실패: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	certContent, err := os.ReadFile(outBase + "-cert.pub")
	if err != nil {
		log.Printf("인증서 파일 읽기 실패: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// identity 파일 형식: 개인키 + 개행 + 인증서
	var identityBuilder strings.Builder
	identityBuilder.Write(keyContent)
	if !bytes.HasSuffix(keyContent, []byte("\n")) {
		identityBuilder.WriteString("\n")
	}
	identityBuilder.Write(certContent)

	err = os.WriteFile(identityFile, []byte(identityBuilder.String()), 0600)
	if err != nil {
		log.Printf("identity 파일 생성 실패: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	log.Printf("identity 파일 생성 완료: %s", identityFile)

	// 6. tsh login으로 세션 먼저 생성
	log.Printf("tsh login으로 세션 생성")
	loginCmd := exec.Command("sudo", "tsh", "login",
		"--proxy=openswdev.duckdns.org:3080",
		"--identity="+identityFile,
		githubUser,
	)

	// 각 명령마다 독립적인 tsh home 사용
	loginEnv := append(os.Environ(),
		"TSH_HOME="+tshHome,
		"TELEPORT_HOME="+tshHome,
	)
	loginCmd.Env = loginEnv

	var loginOut, loginErr bytes.Buffer
	loginCmd.Stdout = &loginOut
	loginCmd.Stderr = &loginErr

	if err := loginCmd.Run(); err != nil {
		log.Printf("tsh login 실패: %v", err)
		log.Printf("Login Stdout: %s", loginOut.String())
		log.Printf("Login Stderr: %s", loginErr.String())
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	log.Printf("tsh login 성공: %s", loginOut.String())

	// 7. tsh ssh 명령으로 연결
	sshCmd := exec.Command("sudo", "tsh", "ssh",
		"-tt", // PTY 강제 할당
		"--proxy", "openswdev.duckdns.org:3080",
		"--identity", identityFile, // 통합 identity 파일 사용
		"--insecure",
		fmt.Sprintf("%s@%s", githubUser, nodeHost),
		"bash", "-l",
	)

	sshCmd.Env = loginEnv

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
