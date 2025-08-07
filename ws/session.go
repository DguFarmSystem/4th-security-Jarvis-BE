package ws

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// PairSession은 공유되는 하나의 터미널 세션을 관리합니다.
type PairSession struct {
	Cmd   *exec.Cmd      // 실행 중인 tsh 프로세스
	Stdin io.WriteCloser // 프로세스의 표준 입력

	// 여러 클라이언트에게 출력을 브로드캐스팅하기 위한 구조
	clients   map[*websocket.Conn]bool
	broadcast chan []byte
	mutex     sync.Mutex
}

// 전역 세션 저장소. key는 우리가 생성한 UUID, value는 PairSession.
var sessions = make(map[string]*PairSession)
var sessionsMutex = sync.Mutex{}

var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

// broadcaster는 세션의 출력을 모든 연결된 클라이언트에게 전송합니다.
func (s *PairSession) broadcaster() {
	for data := range s.broadcast {
		s.mutex.Lock()
		for client := range s.clients {
			if err := client.WriteMessage(websocket.BinaryMessage, data); err != nil {
				// 에러 발생 시 클라이언트 연결 제거
				client.Close()
				delete(s.clients, client)
			}
		}
		s.mutex.Unlock()
	}
}

// addClient는 세션에 새로운 참여자를 추가합니다.
func (s *PairSession) addClient(conn *websocket.Conn) {
	s.mutex.Lock()
	s.clients[conn] = true
	s.mutex.Unlock()
}

// removeClient는 세션에서 참여자를 제거하고, 아무도 없으면 세션을 종료합니다.
func (s *PairSession) removeClient(conn *websocket.Conn, pairSessionID string) {
	s.mutex.Lock()
	delete(s.clients, conn)
	s.mutex.Unlock()

	// 세션에 남은 사람이 아무도 없으면 프로세스를 종료하고 맵에서 삭제
	if len(s.clients) == 0 {
		log.Printf("마지막 참여자가 세션 '%s'를 떠났습니다. 세션을 종료합니다.", pairSessionID)
		sessionsMutex.Lock()
		s.Cmd.Process.Kill()
		delete(sessions, pairSessionID)
		sessionsMutex.Unlock()
	}
}

// ListSessionsHandler는 현재 활성화된 Teleport 세션 목록을 반환합니다.
func ListSessionsHandler(c *gin.Context) {
	// tsh ls는 모든 활성 세션을 보여줍니다. json 포맷으로 파싱하기 쉽게 만듭니다.
	cmd := exec.Command("sudo", "tsh", "ls", "-a", "--format=json")
	cmd.Env = append(cmd.Env, "TELEPORT_IDENTITY_FILE=/opt/machine-id/identity")

	out, err := cmd.Output()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list sessions", "details": err.Error()})
		return
	}

	var activeSessions []interface{}
	// Teleport는 각 세션을 개행으로 구분된 JSON 객체로 출력합니다.
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		var sessionData map[string]interface{}
		if err := json.Unmarshal(scanner.Bytes(), &sessionData); err == nil {
			activeSessions = append(activeSessions, sessionData)
		}
	}

	c.JSON(http.StatusOK, activeSessions)
}

// JoinSessionHandler는 기존 Teleport 세션에 참여하는 웹소켓을 처리합니다.
func JoinSessionHandler(c *gin.Context) {
	sessionID := c.Query("session_id") // 참여하려는 Teleport 세션 ID
	if sessionID == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "session_id is required"})
		return
	}

	pairSessionID := uuid.New().String()
	log.Printf("사용자 '%s'를 위해 공유 세션 준비 중... (대상 세션 ID: %s)", c.GetString("username"), sessionID)

	cmd := exec.Command("sudo", "tsh", "join",
		"--proxy", "openswdev.duckdns.org:3080",
		"-i", "/opt/machine-id/identity",
		"--mode=peer", // 다른 참여자와 상호작용하기 위해 peer 모드로 참여
		sessionID,
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "StdoutPipe failed"})
		return
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "StdinPipe failed"})
		return
	}

	if err := cmd.Start(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start tsh join", "details": err.Error()})
		return
	}

	session := &PairSession{
		Cmd:       cmd,
		Stdin:     stdin,
		clients:   make(map[*websocket.Conn]bool),
		broadcast: make(chan []byte),
	}

	go session.broadcaster()

	// stdout에서 읽어 모든 클라이언트에게 브로드캐스트
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := stdout.Read(buf)
			if err != nil {
				log.Printf("세션 stdout 읽기 오류: %v. 브로드캐스트를 종료합니다.", err)
				close(session.broadcast)
				return
			}
			session.broadcast <- buf[:n]
		}
	}()

	sessionsMutex.Lock()
	sessions[pairSessionID] = session
	sessionsMutex.Unlock()

	log.Printf("새로운 공유 세션이 생성되었습니다. PairSessionID: %s", pairSessionID)
	// 프론트엔드에 이 ID를 전달하여 다른 사용자들이 참여할 수 있게 함
	c.JSON(http.StatusOK, gin.H{"pair_session_id": pairSessionID})
}

// EnterSessionHandler는 생성된 공유 세션에 웹소켓으로 입장합니다.
func EnterSessionHandler(c *gin.Context) {
	pairSessionID := c.Param("pairSessionID")

	sessionsMutex.Lock()
	session, ok := sessions[pairSessionID]
	sessionsMutex.Unlock()

	if !ok {
		log.Printf("참여하려는 세션 '%s'를 찾을 수 없습니다.", pairSessionID)
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("웹소켓 업그레이드 실패: %v", err)
		return
	}
	defer conn.Close()

	session.addClient(conn)
	log.Printf("새로운 참여자가 세션 '%s'에 입장했습니다. 현재 참여자 수: %d", pairSessionID, len(session.clients))

	defer session.removeClient(conn, pairSessionID)

	// 클라이언트로부터 메시지를 받아 세션의 stdin으로 전송
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			log.Printf("클라이언트 메시지 읽기 오류: %v", err)
			break // 루프를 빠져나가면 defer에 의해 removeClient 호출됨
		}
		if _, err := session.Stdin.Write(msg); err != nil {
			log.Printf("세션 stdin 쓰기 오류: %v", err)
			break
		}
	}
}

// HandleWebSocket은 웹소켓 연결을 처리하고 터미널 세션을 중계합니다.
func HandleWebSocket(c *gin.Context) {
	// ... (기존 handleWebSocket 로직과 동일) ...
	// 아래는 완성된 코드
	githubUser := c.GetString("username")
	nodeHost := c.Query("node_host")
	loginUser := c.Query("login_user")
	if nodeHost == "" || loginUser == "" {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	log.Printf("사용자 '%s'를 위해 SSH 세션 준비 중... (대상: %s@%s)", githubUser, loginUser, nodeHost)

	sshCmd := exec.Command("sudo", "tsh", "ssh",
		"--proxy", "openswdev.duckdns.org:3080",
		"-i", "/opt/machine-id/identity",
		fmt.Sprintf("%s@%s", loginUser, nodeHost),
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
