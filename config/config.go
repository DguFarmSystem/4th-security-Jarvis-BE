package config

import (
	"log"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// Config는 애플리케이션의 모든 설정을 담는 구조체입니다.
type Config struct {
	TeleportProxyAddr string
	TeleportAuthAddr  string
	GitHubOAuthConfig *oauth2.Config
	JWTSecretKey      []byte
	CertFile          string
	KeyFile           string
	ListenAddr        string

	LogstashURL      string // 데이터를 보낼 Logstash 주소
	AuditLogPath     string // 감시할 Teleport 감사 로그 경로
	GCPProjectID     string // GCP 프로젝트 ID
	GCPLocation      string // Vertex AI 리전 (e.g., "us-central1")
	GeminiModel      string // 사용할 Gemini 모델 (e.g., "gemini-1.5-flash-001")
	TbotIdentityFile string // tbot 신원 파일 경로
}

// LoadConfig는 환경 변수에서 설정을 읽어 Config 객체를 생성하고 반환합니다.
func LoadConfig() *Config {
	secretString := os.Getenv("JWT_SECRET_KEY")
	if secretString == "" {
		log.Fatal("치명적 오류: JWT_SECRET_KEY 환경 변수가 설정되지 않았습니다.")
	}
	cfg := &Config{
		TeleportProxyAddr: os.Getenv("TELEPORT_PROXY_ADDR"),
		TeleportAuthAddr:  os.Getenv("TELEPORT_AUTH_ADDR"),
		JWTSecretKey:      []byte(secretString),
		CertFile:          "/etc/letsencrypt/live/openswdev.duckdns.org/fullchain.pem",
		KeyFile:           "/etc/letsencrypt/live/openswdev.duckdns.org/privkey.pem",
		ListenAddr:        ":8080",
		GitHubOAuthConfig: &oauth2.Config{
			ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
			ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
			RedirectURL:  os.Getenv("GITHUB_CALLBACK_URL"),
			Endpoint:     github.Endpoint,
			Scopes:       []string{"read:user", "read:org"},
		},
		LogstashURL:      "http://event-listen_logstash_1:5001",
		AuditLogPath:     os.Getenv("TELEPORT_AUDIT_LOG_PATH"),
		GCPProjectID:     os.Getenv("GCP_PROJECT_ID"),
		GCPLocation:      os.Getenv("GCP_LOCATION"),
		GeminiModel:      os.Getenv("GEMINI_MODEL"),
		TbotIdentityFile: os.Getenv("TBOT_IDENTITY_FILE_PATH"),
	}

	if cfg.TeleportProxyAddr == "" || cfg.GitHubOAuthConfig.ClientID == "" {
		log.Println("경고: 일부 기능에 필요한 환경 변수가 설정되지 않았을 수 있습니다.")
	}
	// 새로 추가된 필수 환경 변수 확인
	if cfg.AuditLogPath == "" || cfg.GCPProjectID == "" || cfg.GCPLocation == "" || cfg.GeminiModel == "" || cfg.TbotIdentityFile == "" {
		log.Fatal("치명적 오류: AuditLogPath, GCP 관련, TbotIdentityFile 환경 변수 설정이 필요합니다.")
	}

	return cfg
}
