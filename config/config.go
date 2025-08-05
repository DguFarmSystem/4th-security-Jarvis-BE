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
}

type UpdateUserRequest struct {
	Roles []string `json:"roles"`
}

type GenerateTokenRequest struct {
	TTL      string   `json:"ttl"`
	Roles    []string `json:"roles"`
	Nodename string   `json:"nodename"`
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
	}

	if cfg.TeleportProxyAddr == "" || cfg.TeleportAuthAddr == "" || cfg.GitHubOAuthConfig.ClientID == "" {
		log.Println("경고: 일부 기능에 필요한 환경 변수가 설정되지 않았을 수 있습니다.")
	}

	return cfg
}
