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
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/trace"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const machineIDIdentityFile = "/opt/machine-id/identity"

var (
	githubOAuthConfig *oauth2.Config
	teleportProxyAddr string
	teleportAuthAddr  string
	clientWrapper     *TeleportClientWrapper
	jwtSecretKey      []byte
)

var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

type TeleportClientWrapper struct{ Client *client.Client }

func init() {
	teleportProxyAddr = os.Getenv("TELEPORT_PROXY_ADDR")
	teleportAuthAddr = os.Getenv("TELEPORT_AUTH_ADDR")
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

	if teleportProxyAddr == "" || teleportAuthAddr == "" || githubOAuthConfig.ClientID == "" {
		log.Println("경고: 일부 기능에 필요한 환경 변수가 설정되지 않았을 수 있습니다.")
	}
}

func main() {
	// 1. 기존 API용 Go 클라이언트 초기화
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	creds := client.LoadIdentityFile(machineIDIdentityFile)
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
	apiV1.Use(AuthenticateJWT())
	{
		apiV1.GET("/users", clientWrapper.GetUsers)
		apiV1.GET("/roles", clientWrapper.GetRoles)
		apiV1.GET("/resources/nodes", clientWrapper.GetNodes)
		apiV1.GET("/audit/events", clientWrapper.GetAuditEvents)
	}

	// 2-2. 신규 GitHub SSO 및 웹 터미널 엔드포인트

	router.GET("/login", handleGitHubLogin)
	router.GET("/callback", handleGitHubCallback)
	router.GET("/ws", AuthenticateJWT(), handleWebSocket)

	// 3. 서버 시작
	log.Println("통합 백엔드 서버를 8080 포트에서 시작합니다.")
	router.Run(":8080")
}

// AuthenticateJWT는 Teleport OSS 버전의 헤더 기반 인증을 처리하는 미들웨어입니다.
func AuthenticateJWT() gin.HandlerFunc {
	return func(c *gin.Context) {

		tokenString, err := c.Cookie("auth_token")
		if err != nil {
			log.Println("쿠키에서 GitHub 사용자 정보를 찾을 수 없습니다. 로그인이 필요합니다.")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// 2. 읽어온 JWT 토큰을 파싱하고 검증합니다.
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

		// 3. 토큰의 클레임(내용)에서 사용자 이름을 추출합니다.
		githubUser, ok := claims["username"].(string)
		if !ok || githubUser == "" {
			log.Println("JWT 토큰에 사용자 이름이 포함되어 있지 않습니다.")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		// 4. 인증 성공! 사용자 정보를 Gin 컨텍스트에 저장하여
		// 이후의 핸들러(예: handleWebSocket)에서 사용할 수 있도록 합니다.
		c.Set("username", githubUser)

		c.Next()
	}
}

func (t *TeleportClientWrapper) GetUsers(c *gin.Context) {
	// 1. 미들웨어로부터 현재 요청을 보낸 사용자의 이름을 가져옵니다.
	impersonatedUser := c.GetString("username")
	if impersonatedUser == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "인증된 사용자 정보를 찾을 수 없어 가장에 실패했습니다."})
		return
	}

	log.Printf("[DEBUG] 역할 가장 시도: 현재 사용자 '%s'의 권한으로 API를 호출합니다.", impersonatedUser)
	// 2. 역할 가장을 위한 메타데이터를 현재 요청의 컨텍스트에 추가합니다.
	// 이 컨텍스트는 이 API 호출 동안에만 유효합니다.
	ctx := metadata.AppendToOutgoingContext(c.Request.Context(), "teleport-impersonate-user", impersonatedUser)

	// 디버그 코드 시작
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		log.Println("[DEBUG] 컨텍스트에서 발신 메타데이터를 찾을 수 없습니다.")
	} else {
		// 보기 쉽게 JSON 형태로 변환하여 출력합니다.
		mdJSON, err := json.MarshalIndent(md, "", "  ")
		if err != nil {
			log.Printf("[DEBUG] 메타데이터 JSON 변환 실패: %v", err)
		} else {
			// 이 로그가 바로 ctx가 어떻게 전송될지를 보여줍니다.
			log.Printf("[DEBUG] API 호출에 사용될 gRPC 메타데이터:\n%s", string(mdJSON))
		}
	}
	// 디버그 코드 끝

	// 3. '가장된 클라이언트'를 사용하여 API를 호출합니다.
	// 이제 이 호출은 Teleport에 의해 'basic-user'의 권한으로 자동 필터링됩니다.
	users, err := t.Client.GetUsers(ctx, false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "사용자 목록을 가져오는 데 실패했습니다: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, users)
}

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
	url := githubOAuthConfig.AuthCodeURL("random-state-string", oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("scope", "read:org"))
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

	// <<<--- 추가된 팀 멤버십 확인 로직 시작 --->>>
	orgName := "4th-security-Jarvis"
	teamSlug := "4th-security-jarvis" // 팀 이름이 URL에 사용될 수 있도록 변환된 형태

	// GitHub API를 호출하여 사용자가 팀 멤버인지 확인합니다.
	teamMembershipURL := fmt.Sprintf("https://api.github.com/orgs/%s/teams/%s/memberships/%s", orgName, teamSlug, user.Login)

	// 이전에 생성한 인증된 클라이언트를 재사용합니다.
	req, _ := http.NewRequest("GET", teamMembershipURL, nil)
	teamResp, err := client.Do(req)
	if err != nil {
		c.String(http.StatusInternalServerError, "GitHub 팀 정보 조회 실패: "+err.Error())
		return
	}
	defer teamResp.Body.Close()

	// API 응답 코드로 멤버 여부를 판단합니다.
	// 멤버가 맞으면 200 OK, 멤버가 아니면 404 Not Found를 반환합니다.
	if teamResp.StatusCode == http.StatusNotFound {
		log.Printf("[INFO] 로그인 거부: 사용자 '%s'는 팀 '%s'의 멤버가 아님", user.Login, teamSlug)
		c.String(http.StatusForbidden, "접근 거부: 허가된 팀의 멤버가 아닙니다.")
		return
	}

	if teamResp.StatusCode != http.StatusOK {
		log.Printf("[ERROR] 팀 정보 조회 실패: 상태 코드 %d", teamResp.StatusCode)
		c.String(http.StatusInternalServerError, "팀 정보를 확인하는 중 오류가 발생했습니다.")
		return
	}

	log.Printf("[INFO] 로그인 승인: 사용자 '%s'는 팀 '%s'의 멤버임", user.Login, teamSlug)
	// <<<--- 추가된 팀 멤버십 확인 로직 끝 --->>>

	err = clientWrapper.ProvisionTeleportUser(c.Request.Context(), user.Login)
	if err != nil {
		log.Printf("[ERROR] Teleport 사용자 프로비저닝 실패: %v", err)
		c.String(http.StatusInternalServerError, "사용자 계정을 준비하는 중 오류가 발생했습니다.")
		return
	}

	claims := jwt.MapClaims{
		"username": user.Login,                           // GitHub 사용자 이름
		"exp":      time.Now().Add(time.Hour * 1).Unix(), // 토큰 만료 시간: 1시간
		"iat":      time.Now().Unix(),                    // 토큰 발급 시간
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	//  이제 전역 변수인 jwtSecretKey를 사용하여 토큰을 서명합니다.
	tokenString, err := jwtToken.SignedString(jwtSecretKey)

	log.Printf("[DEBUG] /callback: JWT 생성 성공. 토큰 시작 부분: %s...", tokenString[:10])

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "토큰 생성 실패"})
		return
	}

	c.SetCookie(
		"auth_token", // 쿠키 이름
		tokenString,  //  실제 JWT 문자열을 쿠키 값으로 사용
		3600,
		"/",
		"",    // 도메인을 비워두면 현재 도메인에만 적용됨 (localhost, duckdns 등 모두 동작)
		false, // Secure 플래그 (HTTPS에서만 전송)
		true,  // HttpOnly 플래그 (JS 접근 방지)
	)

	c.Redirect(http.StatusFound, "http://openswdev.duckdns.org:3000")
}

func (t *TeleportClientWrapper) ProvisionTeleportUser(ctx context.Context, githubUsername string) error {
	// 기본적으로 할당할 역할 목록
	defaultRoles := []string{"basic-user"}

	// 1. 사용자가 이미 존재하는지 확인합니다.
	_, err := t.Client.GetUser(ctx, githubUsername, false)

	// 사용자가 존재하지 않는 경우 (err != nil 이고, NotFound 에러일 때)
	// 2. 에러가 발생했을 경우에만 처리 로직을 실행합니다.
	if err != nil {
		// 디버그 코드 시작>>
		// IsNotFound 확인 전에, 수신된 에러의 전체 내용을 그대로 출력합니다.
		// '%T'는 에러의 타입을, '%v'는 에러 메시지를, '%#v'는 구조체의 상세 내용을 보여줍니다.
		log.Printf("[DEBUG] GetUser API 에러 발생. 타입: %T, 내용: %v", err, err)
		log.Printf("[DEBUG] 에러 상세 구조: %#v", err)
		// 디버그 코드 끝 >
		// 3. 에러의 종류가 'NotFound'가 맞는지 명확하게 확인합니다.
		//    이것이 에러를 안정적으로 감지하는 핵심입니다.
		if trace.IsNotFound(err) || strings.Contains(err.Error(), "not found") {
			log.Printf("[INFO] 신규 사용자 '%s'를 생성합니다.", githubUsername)

			// 새로운 사용자 객체를 정의합니다.
			user, err := types.NewUser(githubUsername)
			if err != nil {
				return trace.Wrap(err)
			}
			user.SetRoles(defaultRoles)

			// Teleport에 사용자 생성을 요청합니다.
			_, err = t.Client.CreateUser(ctx, user)
			if err != nil {
				return trace.Wrap(err)
			}
			log.Printf("[INFO] 사용자 '%s'가 역할 '%v'로 성공적으로 생성되었습니다.", githubUsername, defaultRoles)
			// 사용자 생성이 성공적으로 완료되었으므로, 에러 없이(nil) 함수를 종료합니다.
			return nil
		}

		// 4. 'NotFound'가 아닌 다른 종류의 에러(예: 권한 부족, 네트워크 문제 등)라면,
		//    문제를 보고하기 위해 해당 에러를 그대로 반환합니다.
		return trace.Wrap(err)
	}

	// 5. 에러가 전혀 발생하지 않았다면 (err == nil), 사용자가 이미 존재한다는 의미입니다.
	log.Printf("[INFO] 기존 사용자 '%s'의 로그인을 확인했습니다.", githubUsername)
	return nil
}

func handleWebSocket(c *gin.Context) {

	githubUser := c.GetString("username")
	nodeHost := c.Query("node_host")
	loginUser := c.Query("login_user")
	if nodeHost == "" || loginUser == "" {
		log.Println("쿼리 파라미터(node_host, login_user)가 필요합니다.")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	log.Printf("사용자 '%s'를 위해 SSH 세션 준비 중... (대상: %s@%s)", githubUser, loginUser, nodeHost)

	// 3. [변경됨] tsh ssh 명령어를 머신 ID 방식으로 실행합니다.
	// 'tsh login' 단계는 완전히 제거되었습니다.
	// sudo를 사용하여 root 소유의 신원 파일을 읽을 수 있도록 합니다.
	sshCmd := exec.Command("sudo", "tsh", "ssh",
		"--proxy", "openswdev.duckdns.org:3080",
		"-i", machineIDIdentityFile, // -i 플래그로 머신 ID 신원 파일을 직접 지정
		fmt.Sprintf("%s@%s", loginUser, nodeHost),
	)
	log.Printf("[DEBUG] Executing command: %s", strings.Join(sshCmd.Args, " "))

	// '키보드'에 해당하는 stdin 파이프를 가져옵니다.

	// --- 여기서부터 파이프 연결, 프로세스 시작, 데이터 중계 로직 ---
	stdout, err := sshCmd.StdoutPipe() // 여기서 stdout 변수 생성
	if err != nil {
		log.Printf("tsh ssh stdout 파이프 생성 실패: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	stdin, err := sshCmd.StdinPipe() // 여기서 stdin 변수 생성
	if err != nil {
		log.Printf("tsh ssh stdin 파이프 생성 실패: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	sshCmd.Stderr = os.Stderr

	if err := sshCmd.Start(); err != nil {
		log.Printf("tsh ssh 프로세스 시작 실패: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	defer sshCmd.Process.Kill()

	feConn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Println("웹소켓 업그레이드 실패:", err)
		return
	}
	defer feConn.Close()

	log.Println("프론트엔드와 WebSocket 연결 성공. 데이터 중계를 시작합니다.")

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
