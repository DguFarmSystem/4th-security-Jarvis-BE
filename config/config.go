package config

import (
	"database/sql"
	"fmt"
)

// Config는 애플리케이션의 모든 설정을 담는 구조체입니다.
type Config struct {
	Domain            string
	TeleportProxyAddr string
	TeleportAuthAddr  string
	JWTSecretKey      []byte
	ListenAddr        string
}

// LoadConfig는 환경 변수에서 설정을 읽어 Config 객체를 생성하고 반환합니다.
func LoadConfig() *Config {
	cfg := &Config{
		Domain:            "localhost",       // 사용자의 웹 주소입니다. (예: your-proxy.example)
		TeleportProxyAddr: "localhost:3080",  // 사용자가 접속하는 Teleport 프록시 서비스의 주소입니다. (예: your-proxy.example.com:443)
		TeleportAuthAddr:  "localhost:3025",  // Teleport 인증 서비스의 주소입니다. API 호출 시 사용됩니다. (예: your-auth.example.com:3025)
		JWTSecretKey:      []byte("JWTTest"), // JWT 서명에 사용될 바이트 슬라이스 형태의 비밀 키입니다.
		ListenAddr:        ":8080",           // 애플리케이션이 리스닝할 주소와 포트입니다.
	}
	return cfg
}

func InitDB(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("sqlite3 오픈 실패: %w", err)
	}

	// users 테이블 생성 (없을 경우)
	createTableQuery := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		role TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`
	_, err = db.Exec(createTableQuery)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("users 테이블 생성 실패: %w", err)
	}

	return db, nil
}
