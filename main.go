package main

import (
	"log"
	"net/http"
	"time"

	"teleport-backend/api"
	"teleport-backend/auth"
	"teleport-backend/config"
	"teleport-backend/teleport"
	"teleport-backend/ws"

	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	// 설정 로드
	cfg := config.LoadConfig()

	// SQLite 초기화 (루트에 teleport.db)
	db, err := config.InitDB("./teleport.db")
	if err != nil {
		log.Fatalf("DB 초기화 실패: %v", err)
	}
	defer db.Close()

	// Teleport 서비스 초기화
	teleportService, err := teleport.NewService(cfg)
	if err != nil {
		log.Fatalf("Teleport 서비스 초기화 실패: %v", err)
	}
	defer teleportService.Close()

	// 핸들러 및 미들웨어 초기화 (의존성 주입)/////////////
	apiHandlers := api.NewHandlers(teleportService)
	authMiddleware := api.NewAuthMiddleware(cfg)
	authHandler := auth.NewHandler(cfg, teleportService, db)

	// Gin 라우터 설정
	router := gin.Default()

	// 라우트 등록
	router.GET("/login", authHandler.HandleLogin)
	router.POST("/register", authHandler.HandleReg)

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

	// 서버 시작
	log.Printf("통합 백엔드 서버를 %s 포트(HTTPS)에서 시작합니다.", cfg.ListenAddr)

	server := &http.Server{
		Addr:         cfg.ListenAddr,  // 서버가 수신 대기할 주소
		Handler:      router,          // Gin 라우터 엔진을 핸들러로 사용
		ReadTimeout:  0,               // 요청의 전체 내용을 읽는 데까지 허용하는 시간
		WriteTimeout: 5 * time.Minute, // 응답을 쓰는 데 허용하는 최대 시간.
		IdleTimeout:  0,               // Keep-Alive 연결에서 다음 요청을 기다리는 최대 시간
	}

	// 직접 생성한 서버 객체로 HTTP 서버를 시작합니다.
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("HTTP 서버 실행 실패: %v", err)
	}
}
