package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"teleport-backend/api"
	"teleport-backend/auth"
	"teleport-backend/config"
	"teleport-backend/services"
	"teleport-backend/teleport"
	"teleport-backend/ws"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	// 1. 설정 로드
	cfg := config.LoadConfig()
	ctx := context.Background()
	// 2. Teleport 서비스 초기화
	teleportService, err := teleport.NewService(cfg)
	if err != nil {
		log.Fatalf("Teleport 서비스 초기화 실패: %v", err)
	}
	defer teleportService.Close()

	// 1. Gemini 서비스 초기화
	geminiService, err := services.NewGeminiService(ctx, cfg)
	if err != nil {
		log.Fatalf("Gemini 서비스 초기화 실패: %v", err)
	}

	// 3. 핸들러 및 미들웨어 초기화 (의존성 주입)
	apiHandlers := api.NewHandlers(teleportService, geminiService)
	authMiddleware := api.NewAuthMiddleware(cfg)
	authHandler := auth.NewHandler(cfg, teleportService)

	// 4. Gin 라우터 설정
	router := gin.Default()

	// CORS 미들웨어 설정
	corsConfig := cors.Config{
		AllowOrigins: []string{
        "https://jarvis-indol-omega.vercel.app",
        "http://localhost:5173",
        "https://openswdev.duckdns.org:3000",
    },
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}
	router.Use(cors.New(corsConfig))

	// 5. 라우트 등록
	// GitHub SSO 라우트
	router.GET("/login", authHandler.HandleGitHubLogin)
	router.GET("/callback", authHandler.HandleGitHubCallback)

	// API v1 라우트 (JWT 인증 필요)
	apiV1 := router.Group("/api/v1")
	apiV1.Use(authMiddleware)
	{
		apiV1.GET("/users", apiHandlers.GetUsers)
		apiV1.DELETE("/users/:username", apiHandlers.DeleteUser)
		apiV1.PUT("/users/:username", apiHandlers.UpdateUser)

		apiV1.GET("/roles", apiHandlers.GetRoles)
		apiV1.POST("/roles", apiHandlers.CreateRole)
		apiV1.PUT("/roles", apiHandlers.UpsertRole)
		apiV1.DELETE("/roles/:rolename", apiHandlers.DeleteRole)

		apiV1.GET("/resources/nodes", apiHandlers.GetNodes)
		apiV1.POST("/resources/nodes/token", apiHandlers.GenerateNodeJoinToken)
		apiV1.DELETE("/resources/nodes/:nodename", apiHandlers.DeleteNode)

		apiV1.GET("/audit/events", apiHandlers.GetAuditEvents)
		apiV1.GET("/audit/session", apiHandlers.ListRecordedSessions)
		apiV1.GET("/audit/session/:sessionID", apiHandlers.StreamRecordedSession)
	}
	internalAPI := router.Group("/internal")
	{
		internalAPI.POST("/analyze-session", apiHandlers.AnalyzeSession)
	}

	// 웹소켓 라우트
	router.GET("/ws", authMiddleware, ws.HandleWebSocket)

	// 6. 서버 시작
	log.Printf("통합 백엔드 서버를 %s 포트(HTTPS)에서 시작합니다.", cfg.ListenAddr)

	server := &http.Server{
		Addr:    cfg.ListenAddr, // 서버가 수신 대기할 주소
		Handler: router,         // Gin 라우터 엔진을 핸들러로 사용

		// 요청의 전체 내용을 읽는 데까지 허용하는 시간
		ReadTimeout: 0,
		// 응답을 쓰는 데 허용하는 최대 시간.
		WriteTimeout: 5 * time.Minute,
		// Keep-Alive 연결에서 다음 요청을 기다리는 최대 시간
		IdleTimeout: 0,
	}

	// 직접 생성한 서버 객체로 TLS 서버를 시작합니다.
	if err := server.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile); err != nil {
		log.Fatalf("HTTPS 서버 실행 실패: %v", err)
	}
}
