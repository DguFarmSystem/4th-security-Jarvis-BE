// 파일 이름: main.go
package main

import (
	"context"
	"log"
	"net/http"
//	"strings"
	"time"
//	"fmt"
	"github.com/gin-gonic/gin"
	
	"github.com/gravitational/teleport/api/client"
//	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"google.golang.org/grpc"
)

// TeleportClientWrapper는 관리자 권한의 Teleport 클라이언트를 감싸는 구조체입니다.
type TeleportClientWrapper struct {
	Client *client.Client
}

// AuthMiddleware는 Teleport OSS 버전의 헤더 기반 인증을 처리하는 미들웨어입니다.
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		
		// 1. 요청 헤더에서 사용자 이름과 역할 정보 추출
		username := c.GetHeader("Teleport-Username")
		//roles := c.GetHeader("Teleport-Roles")
		test := c.GetHeader("test")
		log.Printf("%s, hi",test)
		// 2. 필수 헤더가 없는 경우, 요청을 거부합니다.
		// 이는 Teleport 프록시를 통하지 않은 직접적인 접근을 막는 역할을 합니다.
		if username == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "인증 정보(Teleport-Username 헤더)가 없습니다. Teleport를 통해 접속해야 합니다."})
			c.Abort()
			return
		}

		// 3. 다음 핸들러에서 사용할 수 있도록 사용자 정보를 컨텍스트에 저장
//		roleList := strings.Split(roles, ",")
		c.Set("username", username)
//		c.Set("roles", roleList)
		c.Next()
	}
}


func main() {
	const authServerAddr = "openswdev.duckdns.org:3025"
	const identityFilePath = "auth.pem"

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	creds := client.LoadIdentityFile(identityFilePath)
	mainClient, err := client.New(ctx, client.Config{
		Addrs:       []string{authServerAddr},
		Credentials: []client.Credentials{creds},
		DialOpts:    []grpc.DialOption{},
	})
	if err != nil {
		log.Fatalf("Teleport 메인 클라이언트 생성에 실패했습니다: %v", err)
	}
	defer mainClient.Close()

	log.Println("Teleport 클러스터에 성공적으로 연결되었습니다.")

	clientWrapper := &TeleportClientWrapper{
		Client: mainClient,
	}

	router := gin.Default()
	apiV1 := router.Group("/api/v1")
	
	apiV1.Use(AuthMiddleware()) 
	{
		usersGroup := apiV1.Group("/users")
		{
			usersGroup.GET("", clientWrapper.GetUsers)
		}
		rolesGroup := apiV1.Group("/roles")
		{
			rolesGroup.GET("", clientWrapper.GetRoles)
		}
		resourcesGroup := apiV1.Group("/resources")
		{
			resourcesGroup.GET("/nodes", clientWrapper.GetNodes)
		}
		auditGroup := apiV1.Group("/audit")
		{
			auditGroup.GET("/events", clientWrapper.GetAuditEvents)
		}
	}

	log.Println("백엔드 API 서버를 시작합니다. (http://localhost:8080)")
	if err := router.Run(":8080"); err != nil {
		log.Fatalf("서버 실행에 실패했습니다: %v", err)
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


