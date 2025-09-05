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
	LogstashURL       string // 데이터를 보낼 Logstash 주소
	AuditLogPath      string // 감시할 Teleport 감사 로그 경로
	GCPProjectID      string // GCP 프로젝트 ID
	GCPLocation       string // Vertex AI 리전 (e.g., "us-central1")
	GeminiModel       string // 사용할 Gemini 모델 (e.g., "gemini-1.5-flash-001")
	TbotIdentityFile  string // tbot 신원 파일 경로
	OrgName           string // github 조직 이름 (e.g., 4th-security-Jarvis)
	TeamSlug          string // github team slug (e.g., jarvis)
}

// LoadConfig는 환경 변수에서 설정을 읽어 Config 객체를 생성하고 반환합니다.
func LoadConfig() *Config {
	secretString := os.Getenv("JWT_SECRET_KEY") // JWT(JSON Web Token)를 서명하고 검증하는 데 사용되는 비밀 키입니다.
	if secretString == "" {
		log.Fatal("치명적 오류: JWT_SECRET_KEY 환경 변수가 설정되지 않았습니다.")
	}
	cfg := &Config{
		TeleportProxyAddr: os.Getenv("TELEPORT_PROXY_ADDR"), // 사용자가 접속하는 Teleport 프록시 서비스의 주소입니다. (예: your-proxy.example.com:443)
		TeleportAuthAddr:  os.Getenv("TELEPORT_AUTH_ADDR"),  // Teleport 인증 서비스의 주소입니다. API 호출 시 사용됩니다. (예: your-auth.example.com:3025)
		JWTSecretKey:      []byte(secretString),             // JWT 서명에 사용될 바이트 슬라이스 형태의 비밀 키입니다.
		CertFile:          "/etc/letsencrypt/fullchain.pem", // HTTPS 서버를 위한 SSL 인증서 파일의 경로입니다.
		KeyFile:           "/etc/letsencrypt/privkey.pem",   // HTTPS 서버를 위한 SSL 개인 키 파일의 경로입니다.
		ListenAddr:        ":8080",                          // 애플리케이션이 리스닝할 주소와 포트입니다.
		GitHubOAuthConfig: &oauth2.Config{ // GitHub OAuth 애플리케이션 설정입니다.
			ClientID:     os.Getenv("GITHUB_CLIENT_ID"),     // GitHub OAuth App의 클라이언트 ID입니다.
			ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"), // GitHub OAuth App의 클라이언트 시크릿입니다.
			RedirectURL:  os.Getenv("GITHUB_CALLBACK_URL"),  // GitHub에서 인증 후 리디렉션될 콜백 URL입니다.
			Endpoint:     github.Endpoint,
			Scopes:       []string{"read:user", "read:org"},
		},
		LogstashURL:      "http://event-listen_logstash_1:5001", // Teleport 이벤트 플러그인이 이벤트를 전송할 Logstash의 주소입니다.
		AuditLogPath:     os.Getenv("TELEPORT_AUDIT_LOG_PATH"),  //  Teleport 감사 로그 파일의 경로입니다.
		GCPProjectID:     os.Getenv("GCP_PROJECT_ID"),           // Google Cloud Platform 프로젝트의 ID입니다.
		GCPLocation:      os.Getenv("GCP_LOCATION"),             // Vertex AI (Gemini)를 사용할 GCP 리전입니다. (예: "us-central1")
		GeminiModel:      os.Getenv("GEMINI_MODEL"),             // 사용할 Gemini AI 모델의 이름입니다. (예: "gemini-1.5-flash-001")
		TbotIdentityFile: os.Getenv("TBOT_IDENTITY_FILE_PATH"),  // `tbot`이 생성하고 관리하는 서비스 계정의 ID 파일 경로입니다.
		OrgName:          os.Getenv("GITHUB_ORG_NAME"),          // github 조직 이름 (e.g., 4th-security-Jarvis)
		TeamSlug:         os.Getenv("GITHUB_TEAM_SLUG"),         // github team slug (e.g., jarvis)
	}

	if cfg.TeleportProxyAddr == "" || cfg.GitHubOAuthConfig.ClientID == "" {
		log.Println("경고: 일부 기능에 필요한 환경 변수가 설정되지 않았을 수 있습니다.")
	}

	if cfg.AuditLogPath == "" || cfg.TbotIdentityFile == "" {
		log.Fatal("치명적 오류: AuditLogPath, GCP 관련, TbotIdentityFile 환경 변수 설정이 필요합니다.")
	}
	if cfg.GCPProjectID == "" || cfg.GCPLocation == "" || cfg.GeminiModel == "" {
		log.Println("치명적 오류: GCP 관련 환경 변수가 설정되지 않았습니다")
	}

	return cfg
}
