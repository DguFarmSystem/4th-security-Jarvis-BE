// 파일 경로: teleport-backend/main.go
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/gravitational/teleport/api/client" // UserCertsRequest를 위해 필요
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/trace"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"google.golang.org/grpc"
)

const machineIDIdentityFile = "/opt/machine-id/identity"

var (
	githubOAuthConfig *oauth2.Config
	teleportProxyAddr string
	teleportAuthAddr  string
	clientWrapper     *TeleportClientWrapper
	jwtSecretKey      []byte
)

//	(1) ---
//
// 업데이트 요청 시 받을 JSON 데이터 구조체를 정의합니다.
// 여기서는 사용자의 역할을 변경하는 경우를 예로 듭니다.
type UpdateUserRequest struct {
	Roles []string `json:"roles"`
}

type GenerateTokenRequest struct {
	TTL   string   `json:"ttl"`
	Roles []string `json:"roles"`
}

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
	creds := client.LoadIdentityFile(machineIDIdentityFile)
	mainClient, err := client.New(context.Background(), client.Config{
		Addrs: []string{teleportAuthAddr}, Credentials: []client.Credentials{creds}, DialOpts: []grpc.DialOption{},
	})
	if err != nil {
		log.Fatalf("Teleport API 클라이언트 생성 실패: %v", err)
	}
	defer mainClient.Close()

	clientWrapper = &TeleportClientWrapper{Client: mainClient}

	// 2. Gin 라우터 생성 및 모든 엔드포인트 등록
	router := gin.Default()
	//  (2): CORS 미들웨어 설정 및 적용 ---
	// CORS 설정을 생성합니다.
	config := cors.Config{
		// AllowOrigins는 요청을 허용할 출처 목록입니다.
		// 여기서는 프론트엔드 주소인 "https://openswdev.duckdns.org:3000"을 명시합니다.
		AllowOrigins: []string{"https://openswdev.duckdns.org:3000"},

		// AllowMethods는 허용할 HTTP 메서드 목록입니다.
		AllowMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},

		// AllowHeaders는 요청에서 허용할 헤더 목록입니다.
		AllowHeaders: []string{"Origin", "Content-Type", "Accept", "Authorization"},

		// ExposeHeaders는 클라이언트가 접근할 수 있는 응답 헤더 목록입니다.
		ExposeHeaders: []string{"Content-Length"},

		// AllowCredentials가 true이면, 요청에 쿠키를 포함할 수 있습니다.
		// 프론트엔드에서 'credentials: "include"' 옵션을 사용하므로 반드시 true로 설정해야 합니다.
		AllowCredentials: true,

		// MaxAge는 pre-flight 요청 결과를 캐시할 시간(초)입니다.
		MaxAge: 12 * time.Hour,
	}

	// 설정한 CORS 정책을 라우터의 전역 미들웨어로 적용합니다.
	// 이 코드는 모든 라우터 그룹보다 먼저 와야 합니다.
	router.Use(cors.New(config))

	// 2-1. 기존 API 엔드포인트 (/api/v1/*)
	apiV1 := router.Group("/api/v1")
	apiV1.Use(AuthenticateJWT())
	{
		apiV1.GET("/users", clientWrapper.GetUsers)
		apiV1.DELETE("/users/:username", clientWrapper.DeleteUser)
		apiV1.PUT("/users/:username", clientWrapper.UpdateUser)
		apiV1.GET("/roles", clientWrapper.GetRoles)
		apiV1.POST("/roles", clientWrapper.CreateRole) // 새 역할 생성 (POST 메서드 사용)
		apiV1.PUT("/roles", clientWrapper.UpsertRole)  // 역할 생성 또는 업데이트 (PUT 메서드 사용)
		apiV1.DELETE("/roles/:rolename", clientWrapper.DeleteRole)
		apiV1.GET("/resources/nodes", clientWrapper.GetNodes)
		apiV1.POST("/resources/nodes/token", clientWrapper.GenerateNodeJoinToken)
		apiV1.GET("/audit/events", clientWrapper.GetAuditEvents)
	}

	// 2-2. 신규 GitHub SSO 및 웹 터미널 엔드포인트

	router.GET("/login", handleGitHubLogin)
	router.GET("/callback", handleGitHubCallback)
	router.GET("/ws", AuthenticateJWT(), handleWebSocket)

	// HTTPS용 인증서/키 파일 경로
	certFile := "/etc/letsencrypt/live/openswdev.duckdns.org/fullchain.pem"
	keyFile := "/etc/letsencrypt/live/openswdev.duckdns.org/privkey.pem"

	// log 표시는 선택
	log.Println("통합 백엔드 서버를 8080 포트(HTTPS)에서 시작합니다.")

	// *** HTTPS 서버 실행 ***
	if err := router.RunTLS(":8080", certFile, keyFile); err != nil {
		log.Fatalf("HTTPS 서버 실행 실패: %v", err)
	}
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

func (t *TeleportClientWrapper) GetImpersonatedClient(ctx context.Context, username string) (*client.Client, string, error) {
	// 1. 사용자 정보 조회
	user, err := t.Client.GetUser(ctx, username, false)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get user info: %w", err)
	}

	userRoles := user.GetRoles()
	if len(userRoles) == 0 {
		return nil, "", fmt.Errorf("user '%s' has no assigned roles", username)
	}

	targetRole := userRoles[0] // 첫 번째 역할 사용 (필요 시 로직 확장 가능)

	identityFilePath := fmt.Sprintf("/opt/machine-id/%s/identity", targetRole)

	creds := client.LoadIdentityFile(identityFilePath)

	impersonatedClient, err := client.New(ctx, client.Config{
		Addrs:       []string{teleportAuthAddr},
		Credentials: []client.Credentials{creds},
	})
	if err != nil {
		return nil, targetRole, fmt.Errorf("failed to create impersonated client with role %s: %w", targetRole, err)
	}

	return impersonatedClient, targetRole, nil
}

func (t *TeleportClientWrapper) GetUsers(c *gin.Context) {
	// 1. 미들웨어로부터 현재 요청을 보낸 사용자의 이름을 가져옵니다.
	impersonatedUser := c.GetString("username")
	if impersonatedUser == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "인증된 사용자 정보를 찾을 수 없어 가장에 실패했습니다."})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	impersonatedClient, _, err := t.GetImpersonatedClient(ctx, impersonatedUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer impersonatedClient.Close()

	// 5. 생성된 클라이언트로 최종 API를 호출합니다. 이 요청은 'targetRole'의 권한으로 실행됩니다.
	users, err := impersonatedClient.GetUsers(ctx, false)
	if err != nil {
		// 이제 권한이 없으면 여기서 'access denied' 에러가 발생합니다.
		c.JSON(http.StatusInternalServerError, gin.H{"error": "사용자 목록 조회에 실패했습니다: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, users)
}

func (t *TeleportClientWrapper) DeleteUser(c *gin.Context) {

	// 1. 미들웨어로부터 현재 요청을 보낸 사용자의 이름을 가져옵니다.
	impersonatedUser := c.GetString("username")
	if impersonatedUser == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "인증된 사용자 정보를 찾을 수 없어 가장에 실패했습니다."})
		return
	}

	userToDelete := c.Param("username")
	if userToDelete == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "삭제할 사용자의 이름(username)이 반드시 필요합니다."})
		return
	}

	//자기 자신을 삭제하려는 요청을 방지합니다.
	if userToDelete == impersonatedUser {
		c.JSON(http.StatusForbidden, gin.H{"error": "자기 자신을 삭제할 수 없습니다."})
		return
	}
	log.Printf("[DeleteUser] 요청 시작: 요청자='%s', 삭제 대상='%s'", impersonatedUser, userToDelete)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	impersonatedClient, _, err := t.GetImpersonatedClient(ctx, impersonatedUser)
	if err != nil {
		log.Printf("[DeleteUser] 클라이언트 생성 실패: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer impersonatedClient.Close()

	// 5. 생성된 클라이언트로 최종 API를 호출합니다. 이 요청은 'targetRole'의 권한으로 실행됩니다.
	err = impersonatedClient.DeleteUser(ctx, userToDelete)
	if err != nil {
		// 이제 권한이 없으면 여기서 'access denied' 에러가 발생합니다.

		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("'%s' 사용자 삭제에 실패했습니다: %s", userToDelete, err.Error())})
		return
	}
	log.Printf("[DeleteUser] 성공: 사용자 '%s'가 성공적으로 삭제되었습니다.", userToDelete)
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("사용자 '%s'이(가) 성공적으로 삭제되었습니다.", userToDelete)})

}

func (t *TeleportClientWrapper) UpdateUser(c *gin.Context) {
	// 1. URL 파라미터에서 업데이트할 사용자 이름을 가져옵니다.
	userToUpdate := c.Param("username")
	if userToUpdate == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "업데이트할 사용자의 이름(username)이 반드시 필요합니다."})
		return
	}
	// 2. 요청 본문(JSON)에서 업데이트할 데이터를 읽어옵니다.
	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "요청 본문이 잘못되었습니다: " + err.Error()})
		return
	}

	// 1. 미들웨어로부터 현재 요청을 보낸 사용자의 이름을 가져옵니다.
	impersonatedUser := c.GetString("username")
	if impersonatedUser == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "인증된 사용자 정보를 찾을 수 없어 가장에 실패했습니다."})
		return
	}
	log.Printf("[UpdateUser] 요청 시작: 요청자='%s', 대상='%s', 요청 데이터: %+v", impersonatedUser, userToUpdate, req)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	impersonatedClient, _, err := t.GetImpersonatedClient(ctx, impersonatedUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer impersonatedClient.Close()

	// 업데이트를 위해 먼저 기존 사용자 정보를 가져옵니다.
	user, err := impersonatedClient.GetUser(ctx, userToUpdate, false) // `false`는 withSecrets를 비활성화
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("사용자 '%s' 정보 조회에 실패했습니다: %s", userToUpdate, err.Error())})
		return
	}
	// 6. 가져온 사용자 정보에 요청받은 데이터를 적용합니다. (예: 역할 업데이트)
	user.SetRoles(req.Roles)

	// 7. 변경된 사용자 객체로 업데이트 API를 호출합니다.
	_, err = impersonatedClient.UpdateUser(ctx, user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("사용자 '%s' 업데이트에 실패했습니다: %s", userToUpdate, err.Error())})
		return
	}

	// 8. 성공적으로 업데이트되었음을 응답합니다.
	log.Printf("[UpdateUser] 성공: 사용자 '%s'의 정보가 성공적으로 업데이트되었습니다.", userToUpdate)
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("사용자 '%s'의 정보가 성공적으로 업데이트되었습니다.", userToUpdate)})
}

func (t *TeleportClientWrapper) GetRoles(c *gin.Context) {
	impersonatedUser := c.GetString("username")
	if impersonatedUser == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "인증된 사용자 정보를 찾을 수 없어 가장에 실패했습니다."})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	impersonatedClient, _, err := t.GetImpersonatedClient(ctx, impersonatedUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer impersonatedClient.Close()

	roles, err := impersonatedClient.GetRoles(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "역할 목록을 가져오는 데 실패했습니다: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, roles)
}

func (t *TeleportClientWrapper) CreateRole(c *gin.Context) {
	impersonatedUser := c.GetString("username")
	if impersonatedUser == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "인증된 사용자 정보를 찾을 수 없어 가장에 실패했습니다."})
		return
	}

	// 1. 요청 본문(JSON)에서 역할 데이터를 읽어옵니다.
	// types.Role은 인터페이스이므로, 구체적인 타입인 RoleV6로 바인딩합니다.
	var role *types.RoleV6
	if err := c.ShouldBindJSON(&role); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "요청 본문(Role)이 잘못되었습니다: " + err.Error()})
		return
	}
	log.Printf("[CreateRole] 요청 시작: 요청자='%s', 생성할 역할명='%s'", impersonatedUser, role.GetName())

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	impersonatedClient, _, err := t.GetImpersonatedClient(ctx, impersonatedUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer impersonatedClient.Close()

	//  (1): 두 개의 값을 반환받도록 수정 ---
	// API가 (types.Role, error)를 반환하므로, createdRole 변수에 결과를 받습니다.
	createdRole, err := impersonatedClient.CreateRole(ctx, role)
	if err != nil {
		log.Printf("[CreateRole] API 호출 실패: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("역할 '%s' 생성에 실패했습니다: %s", role.GetName(), err.Error())})
		return
	}

	//  (2): 성공 시 생성된 객체 자체를 반환 ---
	log.Printf("[CreateRole] 성공: 역할 '%s'가 생성되었습니다.", createdRole.GetName())
	c.JSON(http.StatusCreated, createdRole) // 단순 메시지 대신, 생성된 Role 객체를 반환
}

func (t *TeleportClientWrapper) UpsertRole(c *gin.Context) {
	impersonatedUser := c.GetString("username")
	if impersonatedUser == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "인증된 사용자 정보를 찾을 수 없어 가장에 실패했습니다."})
		return
	}

	// 1. 요청 본문(JSON)에서 역할 데이터를 읽어옵니다.
	var role *types.RoleV6
	if err := c.ShouldBindJSON(&role); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "요청 본문(Role)이 잘못되었습니다: " + err.Error()})
		return
	}
	log.Printf("[UpsertRole] 요청 시작: 요청자='%s', 생성/수정할 역할명='%s'", impersonatedUser, role.GetName())

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	impersonatedClient, _, err := t.GetImpersonatedClient(ctx, impersonatedUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer impersonatedClient.Close()

	//  (1): 두 개의 값을 반환받도록 수정 ---
	upsertedRole, err := impersonatedClient.UpsertRole(ctx, role)
	if err != nil {
		log.Printf("[UpsertRole] API 호출 실패: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("역할 '%s' 생성/수정에 실패했습니다: %s", role.GetName(), err.Error())})
		return
	}

	//  (2): 성공 시 생성/수정된 객체 자체를 반환 ---
	log.Printf("[UpsertRole] 성공: 역할 '%s'가 생성/수정되었습니다.", upsertedRole.GetName())
	c.JSON(http.StatusOK, upsertedRole) // 단순 메시지 대신, 생성/수정된 Role 객체를 반환
}

func (t *TeleportClientWrapper) DeleteRole(c *gin.Context) {
	impersonatedUser := c.GetString("username")
	if impersonatedUser == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "인증된 사용자 정보를 찾을 수 없어 가장에 실패했습니다."})
		return
	}

	roleToDelete := c.Param("rolename")
	if roleToDelete == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "삭제할 역할의 이름(rolename)이 반드시 필요합니다."})
		return
	}

	log.Printf("[DeleteRole] 요청 시작: 요청자='%s', 삭제 대상 역할='%s'", impersonatedUser, roleToDelete)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	impersonatedClient, _, err := t.GetImpersonatedClient(ctx, impersonatedUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer impersonatedClient.Close()

	err = impersonatedClient.DeleteRole(ctx, roleToDelete)
	if err != nil {
		log.Printf("[DeleteRole] API 호출 실패: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("역할 '%s' 삭제에 실패했습니다: %s", roleToDelete, err.Error())})
		return
	}

	log.Printf("[DeleteRole] 성공: 역할 '%s'가 삭제되었습니다.", roleToDelete)
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("역할 '%s'이(가) 성공적으로 삭제되었습니다.", roleToDelete)})
}

func (t *TeleportClientWrapper) GetNodes(c *gin.Context) {
	impersonatedUser := c.GetString("username")
	if impersonatedUser == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "인증된 사용자 정보를 찾을 수 없어 가장에 실패했습니다."})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	impersonatedClient, _, err := t.GetImpersonatedClient(ctx, impersonatedUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer impersonatedClient.Close()

	nodes, err := impersonatedClient.GetNodes(ctx, "default")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "서버(노드) 목록을 가져오는 데 실패했습니다: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, nodes)
}

func (t *TeleportClientWrapper) GenerateNodeJoinToken(c *gin.Context) {
	impersonatedUser := c.GetString("username")
	if impersonatedUser == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "인증된 사용자 정보를 찾을 수 없습니다."})
		return
	}

	// 1. 요청 본문을 바인딩하고 유효성을 검사합니다.
	var req GenerateTokenRequest
	// 요청 값이 없을 경우 사용할 기본값 설정
	defaults := GenerateTokenRequest{
		TTL:   "15m",
		Roles: []string{"node"},
	}

	// 요청 본문이 비어있어도 오류로 처리하지 않고 기본값을 사용합니다.
	if err := c.ShouldBindJSON(&req); err != nil && err.Error() != "EOF" {
		log.Printf("[GenerateToken] JSON 바인딩 오류: %v. 요청자: %s", err, impersonatedUser)
		c.JSON(http.StatusBadRequest, gin.H{"error": "요청 형식이 잘못되었습니다: " + err.Error()})
		return
	}

	// 사용자가 값을 보내지 않은 경우 기본값으로 채웁니다.
	if req.TTL == "" {
		req.TTL = defaults.TTL
	}
	if len(req.Roles) == 0 {
		req.Roles = defaults.Roles
	}

	ttl, err := time.ParseDuration(req.TTL)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "유효하지 않은 TTL 형식입니다. '5m', '1h'와 같이 입력하세요."})
		return
	}

	log.Printf("[GenerateToken] 요청 시작: 요청자='%s', TTL='%s', Roles='%v'", impersonatedUser, req.TTL, req.Roles)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	impersonatedClient, _, err := t.GetImpersonatedClient(ctx, impersonatedUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "사용자 권한 클라이언트 생성에 실패했습니다: " + err.Error()})
		return
	}
	defer impersonatedClient.Close()

	// 2. [핵심] 클라이언트 측에서 안전한 랜덤 토큰 문자열 생성
	// 16바이트 -> 32자리 헥스(hex) 문자열
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "안전한 토큰 생성에 실패했습니다: " + err.Error()})
		return
	}
	tokenValue := hex.EncodeToString(tokenBytes)
	log.Printf("[GenerateToken] 새로운 토큰 값 생성 완료: %s", tokenValue)
	// 3. [핵심] 생성한 토큰 값으로 ProvisionToken 객체 생성
	token, err := types.NewProvisionToken(tokenValue, []types.SystemRole{types.RoleNode}, time.Now().Add(ttl))
	if err != nil {
		log.Printf("[GenerateToken] 랜덤 토큰 생성 실패: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ProvisionToken 객체 생성에 실패했습니다: " + err.Error()})
		return
	}

	log.Printf("[GenerateToken] 서버에 토큰(%s) 등록을 시도합니다.", tokenValue)
	// 4. [핵심] 올바른 메서드인 CreateToken을 사용하여 서버에 등록
	err = impersonatedClient.CreateToken(ctx, token)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "조인 토큰을 서버에 등록하는 데 실패했습니다: " + err.Error()})
		return
	}
	log.Printf("[GenerateToken] 토큰 등록 성공.")

	// 스크립트 URL에 토큰과 역할을 쿼리 파라미터로 전달합니다.
	scriptURL := fmt.Sprintf("https://%s/scripts/install.sh", teleportProxyAddr)

	// 최종적으로 사용자가 실행할 명령어
	oneLineInstallCommand := fmt.Sprintf(`curl "%s" | sudo bash`, scriptURL)

	manualStartCommand := fmt.Sprintf("sudo teleport start --roles=node --token=%s --auth-server=%s", tokenValue, teleportAuthAddr)
	// 5. 사용자에게 제공할 안내 정보 구성 (환경에 맞게 수정 필요)

	response := gin.H{
		"token":   tokenValue,
		"expires": token.GetMetadata().Expires.Format(time.RFC3339),
		"roles":   req.Roles,
		"commands": gin.H{
			"automatic_install": oneLineInstallCommand,
			"manual_start":      manualStartCommand,
		},
		"instructions": gin.H{
			"step1": "새 에이전트를 설치할 서버에서 'automatic_install' 명령어를 실행하여 Teleport 서비스를 설치 및 시작하세요.",
			"step2": "또는, 수동으로 Teleport를 설치한 후 'manual_start' 명령어를 실행하여 클러스터에 노드를 등록하세요.",
		},
	}
	c.JSON(http.StatusOK, response)
}

func (t *TeleportClientWrapper) GetAuditEvents(c *gin.Context) {

	impersonatedUser := c.GetString("username")
	if impersonatedUser == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "인증된 사용자 정보를 찾을 수 없어 가장에 실패했습니다."})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	impersonatedClient, _, err := t.GetImpersonatedClient(ctx, impersonatedUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer impersonatedClient.Close()

	events, _, err := impersonatedClient.SearchEvents(
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
		false, // HttpOnly 플래그 (JS 접근 방지)
	)

	c.Redirect(http.StatusFound, "https://openswdev.duckdns.org:3000")
}

// 인증서 만료 에러인지 확인
func isCertExpiredError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "certificate has expired") ||
		strings.Contains(msg, "x509: certificate has expired") ||
		strings.Contains(msg, "expired certificate") ||
		strings.Contains(msg, "access denied: expired session")
}

// 클라이언트 재생성 코드
func (t *TeleportClientWrapper) refreshClient() error {
	// 필요시 sync.Mutex 등으로 동시성 보호
	creds := client.LoadIdentityFile(machineIDIdentityFile)
	newClient, err := client.New(context.Background(), client.Config{
		Addrs: []string{teleportAuthAddr}, Credentials: []client.Credentials{creds}, DialOpts: []grpc.DialOption{},
	})
	if err != nil {
		return err
	}
	if t.Client != nil {
		t.Client.Close()
	}
	t.Client = newClient
	return nil
}

func (t *TeleportClientWrapper) ProvisionTeleportUser(ctx context.Context, githubUsername string) error {
	// 기본적으로 할당할 역할 목록
	defaultRoles := []string{"basic-user"}

	// [추가] 별도의 타임아웃 컨텍스트 생성 (전역 클라이언트와 무관)
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// 1. 사용자가 이미 존재하는지 확인합니다.
	_, err := t.Client.GetUser(reqCtx, githubUsername, false)

	// 인증서가 만료되었으면~ 클라이언트 재생성
	if isCertExpiredError(err) {
		log.Printf("[INFO] 인증서 만료 감지, 클라이언트 갱신 시도...")
		if refreshErr := t.refreshClient(); refreshErr != nil {
			log.Printf("[ERROR] 클라이언트 갱신 실패: %v", refreshErr)
			return trace.Wrap(refreshErr)
		}
		// 갱신 후 다시 시도
		_, err = t.Client.GetUser(reqCtx, githubUsername, false)
	}

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
			_, err = t.Client.CreateUser(reqCtx, user)
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
