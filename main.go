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
	"github.com/golang-jwt/jwt/v5"
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
	jwtSecretKey         []byte
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
	secretString := os.Getenv("JWT_SECRET_KEY")
	if secretString == "" {
		log.Fatal("치명적 오류: JWT_SECRET_KEY 환경 변수가 설정되지 않았습니다.")
	}
	jwtSecretKey = []byte(secretString)

	if teleportProxyAddr == "" || teleportAuthAddr == "" || teleportIdentityFile == "" || githubOAuthConfig.ClientID == "" {
		log.Println("경고: 일부 기능에 필요한 환경 변수가 설정되지 않았을 수 있습니다.")
	}
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

	// 2-2. 신규 GitHub SSO 및 웹 터미널 엔드포인트
	router.GET("/login", handleGitHubLogin)
	router.GET("/callback", handleGitHubCallback)
	router.GET("/ws", handleWebSocket)

	// 3. 서버 시작
	log.Println("통합 백엔드 서버를 8080 포트에서 시작합니다.")
	router.Run(":8080")
}

// AuthMiddleware는 Teleport OSS 버전의 헤더 기반 인증을 처리하는 미들웨어입니다.
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 이후 쿠키의 JWT를 검증하는 로직으로 변경
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
	// 1. GitHub로부터 받은 임시 코드로 Access Token 교환
	code := c.Query("code")
	log.Printf("[DEBUG] /callback: GitHub로부터 받은 임시 코드(code): %s", code)

	oauthToken, err := githubOAuthConfig.Exchange(context.Background(), code)
	log.Printf("[DEBUG] /callback: GitHub Access Token 교환 성공. 토큰 타입: %s", oauthToken.TokenType)

	if err != nil {
		c.String(http.StatusInternalServerError, "GitHub 토큰 교환 실패: "+err.Error())
		return
	}
	log.Printf("[DEBUG] /callback: GitHub로부터 받은 임시 코드(code): %s", code)

	client := githubOAuthConfig.Client(context.Background(), oauthToken)
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

	log.Printf("[DEBUG] /callback: GitHub 사용자 이름 조회 성공: %s", user.Login)

	claims := jwt.MapClaims{
		"username": user.Login,                           // GitHub 사용자 이름
		"exp":      time.Now().Add(time.Hour * 1).Unix(), // 토큰 만료 시간: 1시간
		"iat":      time.Now().Unix(),                    // 토큰 발급 시간
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// [수정] 이제 전역 변수인 jwtSecretKey를 사용하여 토큰을 서명합니다.
	tokenString, err := jwtToken.SignedString(jwtSecretKey)

	log.Printf("[DEBUG] /callback: JWT 생성 성공. 토큰 시작 부분: %s...", tokenString[:10])

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "토큰 생성 실패"})
		return
	}

	c.SetCookie(
		"auth_token", // 쿠키 이름
		tokenString,  // [수정] 실제 JWT 문자열을 쿠키 값으로 사용
		3600,
		"/",
		"",    // 도메인을 비워두면 현재 도메인에만 적용됨 (localhost, duckdns 등 모두 동작)
		false, // Secure 플래그 (HTTPS에서만 전송)
		true,  // HttpOnly 플래그 (JS 접근 방지)
	)

	c.Redirect(http.StatusFound, "http://openswdev.duckdns.org:3000")
}

func handleWebSocket(c *gin.Context) {
	tokenString, err := c.Cookie("auth_token")
	if err != nil {
		log.Println("쿠키에서 GitHub 사용자 정보를 찾을 수 없습니다. 로그인이 필요합니다.")
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// 2. [추가] 읽어온 JWT 토큰을 파싱하고 검증합니다.
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// 서명 방식을 확인하고, init()에서 로드한 비밀 키를 반환합니다.
		return jwtSecretKey, nil
	})
	if err != nil {
		log.Printf("유효하지 않은 JWT 토큰입니다: %v", err)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// 3. [추가] 토큰의 클레임(내용)에서 사용자 이름을 추출합니다.
	githubUser, ok := claims["username"].(string)
	if !ok || githubUser == "" {
		log.Println("JWT 토큰에 사용자 이름이 포함되어 있지 않습니다.")
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

	loginCmd := exec.Command("tsh", "login", "--proxy", "teleport-daemon:3080", "--identity", teleportIdentityFile, "--out", certDir)
	if output, err := loginCmd.CombinedOutput(); err != nil {
		// [수정] 로그 메시지를 더 명확하게 변경합니다.
		log.Printf("Bot User(%s)로 로그인 실패: %v, 출력: %s", teleportIdentityFile, err, string(output))
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	// [수정] 로그 메시지를 더 명확하게 변경합니다.
	log.Printf("Bot User(%s)로 로그인 성공.", teleportIdentityFile)

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
