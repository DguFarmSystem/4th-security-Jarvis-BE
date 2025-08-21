package ws

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"

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

	log.Printf("사용자 '%s'를 위해 SSH 세션 준비 중... (대상: %s@%s)", githubUser, loginUser, nodeHost)

	sshCmd := exec.Command("sudo", "tsh", "ssh",
		"-tt", // PTY 강제 할당
		"--proxy", "openswdev.duckdns.org:3080",
		"-i", "/opt/machine-id/identity",
		fmt.Sprintf("%s@%s", loginUser, nodeHost),
		"--",          // 이후 인수를 원격 커맨드로 전달
		"bash", "-lc", // login 셸 모드 + 커맨드 실행
		fmt.Sprintf("echo %s; exec bash", githubUser),
	)

	stdout, err := sshCmd.StdoutPipe()
	if err != nil {
		return
	}
	stdin, err := sshCmd.StdinPipe()
	if err != nil {
		return
	}
	sshCmd.Stderr = os.Stderr

	if err := sshCmd.Start(); err != nil {
		return
	}
	defer sshCmd.Process.Kill()

	feConn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	defer feConn.Close()

	log.Println("프론트엔드와 WebSocket 연결 성공. 데이터 중계를 시작합니다.")

	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := stdout.Read(buf)
			if err != nil {
				return
			}
			if err := feConn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
				return
			}
		}
	}()

	for {
		_, msg, err := feConn.ReadMessage()
		if err != nil {
			return
		}
		if _, err := stdin.Write(msg); err != nil {
			return
		}
	}
}
