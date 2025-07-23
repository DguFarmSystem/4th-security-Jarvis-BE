// 파일 경로: teleport-backend/main.go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/types"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"google.golang.org/grpc"
)

var (
	githubOAuthConfig    *oauth2.Config
	teleportProxyAddr    string
	teleportIdentityFile string
	teleportAuthAddr     string
	clientWrapper        *TeleportClientWrapper
)

var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

type TeleportClientWrapper struct{ Client *client.Client }

func init() {
	teleportProxyAddr = os.Getenv("TELEPORT_PROXY_ADDR")
	teleportAuthAddr = os.Getenv("TELEPORT_AUTH_ADDR")
	teleportIdentityFile = os.Getenv("TELEPORT_IDENTITY_FILE")

	githubOAuthConfig = &oauth2.Config{
		ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("GITHUB_CALLBACK_URL"),
		Endpoint:     github.Endpoint,
		Scopes:       []string{"read:user", "read:org"},
	}

	if teleportProxyAddr == "" || teleportAuthAddr == "" || teleportIdentityFile == "" || githubOAuthConfig.ClientID == "" {
		log.Println("경고: 일부 기능에 필요한 환경 변수가 설정되지 않았을 수 있습니다.")
	}
	log.Printf("teleportProxyAddr : %s", teleportProxyAddr)
	log.Printf("teleportAuthAddr : %s", teleportAuthAddr)
	log.Printf("teleportIdentityFile : %s", teleportIdentityFile)
	log.Printf("githubOAuthConfig.ClientID : %s", githubOAuthConfig.ClientID)
}

func main() {
	// 1. 기존 API용 Go 클라이언트 초기화
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	creds := client.LoadIdentityFile(teleportIdentityFile)
	mainClient, err := client.New(ctx, client.Config{
		Addrs: []string{teleportAuthAddr}, Credentials: []client.Credentials{creds}, DialOpts: []grpc.DialOption{},
	})
	if err != nil {
		log.Fatalf("Teleport API 클라이언트 생성 실패: %v", err)
	}
	defer mainClient.Close()
	clientWrapper = &TeleportClientWrapper{Client: mainClient}

	// 2. Gin 라우터 생성 및 모든 엔드포인트 등록
	router := gin.Default()

	// 2-1. 기존 API 엔드포인트 (/api/v1/*)
	apiV1 := router.Group("/api/v1")
	apiV1.Use(AuthMiddleware())
	{
		apiV1.GET("/users", clientWrapper.GetUsers)
		apiV1.GET("/roles", clientWrapper.GetRoles)
		apiV1.GET("/resources/nodes", clientWrapper.GetNodes)
		apiV1.GET("/audit/events", clientWrapper.GetAuditEvents)
	}
	log.Println("기존 API 엔드포인트(/api/v1) 등록 완료.")

	// 2-2. 신규 GitHub SSO 및 웹 터미널 엔드포인트
	router.GET("/login", handleGitHubLogin)
	router.GET("/callback", handleGitHubCallback)
	router.GET("/ws", handleWebSocket)
	log.Println("GitHub SSO 및 웹 터미널 엔드포인트(/login, /callback, /ws) 등록 완료.")

	// 3. 서버 시작
	log.Println("통합 백엔드 서버를 8080 포트에서 시작합니다.")
	router.Run(":8080")
}

// AuthMiddleware는 Teleport OSS 버전의 헤더 기반 인증을 처리하는 미들웨어입니다.
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		/*
			// 1. 요청 헤더에서 사용자 이름과 역할 정보 추출
			username := c.GetHeader("Teleport-Username")

			// 2. 필수 헤더가 없는 경우, 요청을 거부합니다.
			// 이는 Teleport 프록시를 통하지 않은 직접적인 접근을 막는 역할을 합니다.
			if username == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "인증 정보(Teleport-Username 헤더)가 없습니다. Teleport를 통해 접속해야 합니다."})
				c.Abort()
				return
			}

			// 3. 다음 핸들러에서 사용할 수 있도록 사용자 정보를 컨텍스트에 저장
			c.Set("username", username)
		*/

		c.Next()
	}
}

func (t *TeleportClientWrapper) GetUsers(c *gin.Context) {
	username, _ := c.Get("username")
	log.Printf("'%s' 사용자의 요청으로 사용자 목록을 조회합니다.", username)

	users, err := t.Client.GetUsers(c.Request.Context(), false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "사용자 목록을 가져오는 데 실패했습니다: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, users)
}

// ... 나머지 핸들러 함수들은 기존과 동일합니다 ...
func (t *TeleportClientWrapper) GetRoles(c *gin.Context) {
	roles, err := t.Client.GetRoles(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "역할 목록을 가져오는 데 실패했습니다: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, roles)
}

func (t *TeleportClientWrapper) GetNodes(c *gin.Context) {
	nodes, err := t.Client.GetNodes(c.Request.Context(), "")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "서버(노드) 목록을 가져오는 데 실패했습니다: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, nodes)
}

func (t *TeleportClientWrapper) GetAuditEvents(c *gin.Context) {
	events, _, err := t.Client.SearchEvents(
		c.Request.Context(),
		time.Now().Add(-24*time.Hour),
		time.Now(),
		"",
		nil,
		100,
		types.EventOrderDescending,
		"",
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "감사 로그를 가져오는 데 실패했습니다: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, events)
}

func handleGitHubLogin(c *gin.Context) {
	url := githubOAuthConfig.AuthCodeURL("random-state-string", oauth2.AccessTypeOffline)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func handleGitHubCallback(c *gin.Context) {
	code := c.Query("code")
	token, err := githubOAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		c.String(http.StatusInternalServerError, "GitHub 토큰 교환 실패: "+err.Error())
		return
	}

	client := githubOAuthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		c.String(http.StatusInternalServerError, "GitHub에서 사용자 정보 조회 실패: "+err.Error())
		return
	}
	defer resp.Body.Close()

	var user struct {
		Login string `json:"login"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		c.String(http.StatusInternalServerError, "사용자 데이터 파싱 실패")
		return
	}

	c.SetCookie("github_user", user.Login, 3600, "/", "localhost", false, true)
	c.Redirect(http.StatusFound, "http://localhost:3000/terminal")
}

func handleWebSocket(c *gin.Context) {
	githubUser, err := c.Cookie("github_user")
	if err != nil {
		log.Println("쿠키에서 GitHub 사용자 정보를 찾을 수 없습니다. 로그인이 필요합니다.")
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	nodeHost := c.Query("node_host")
	loginUser := c.Query("login_user")
	if nodeHost == "" || loginUser == "" {
		log.Println("쿼리 파라미터(node_host, login_user)가 필요합니다.")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	log.Printf("사용자 '%s'를 위해 SSH 세션 준비 중... (대상: %s@%s)", githubUser, loginUser, nodeHost)

	certDir, err := os.MkdirTemp("", "teleport-certs-")
	if err != nil {
		log.Println("임시 인증서 디렉터리 생성 실패:", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	defer os.RemoveAll(certDir)

	loginCmd := exec.Command("tsh", "login", "--proxy", teleportProxyAddr, "--identity", teleportIdentityFile, "--impersonate", githubUser, "--out", certDir)
	if output, err := loginCmd.CombinedOutput(); err != nil {
		log.Printf("사용자 %s 대리 로그인 실패: %v, 출력: %s", githubUser, err, string(output))
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	log.Printf("사용자 '%s' 대리 로그인 성공.", githubUser)

	wsCmd := exec.Command("tsh", "proxy", "ws", fmt.Sprintf("%s@%s", loginUser, nodeHost), "--identity", certDir)
	stdout, _ := wsCmd.StdoutPipe()
	stdin, _ := wsCmd.StdinPipe()
	wsCmd.Stderr = os.Stderr

	if err := wsCmd.Start(); err != nil {
		log.Println("'tsh proxy ws' 시작 실패:", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	defer wsCmd.Process.Kill()

	feConn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Println("웹소켓 업그레이드 실패:", err)
		return
	}
	defer feConn.Close()

	log.Printf("프론트엔드와 WebSocket 연결 성공. 데이터 중계를 시작합니다.")

	go func() { // tsh -> Frontend
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
	for { // Frontend -> tsh
		_, msg, err := feConn.ReadMessage()
		if err != nil {
			return
		}
		if _, err := stdin.Write(msg); err != nil {
			return
		}
	}
}
