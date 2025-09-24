package config

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite" // Pure Go SQLite 드라이버
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
	return &Config{
		Domain:            "localhost",       // 사용자의 웹 주소입니다. (예: your-proxy.example)
		TeleportProxyAddr: "localhost:3080",  // Teleport 프록시 주소입니다.
		TeleportAuthAddr:  "localhost:3025",  // Teleport 인증 서비스 주소입니다.
		JWTSecretKey:      []byte("JWTTest"), // JWT 서명용 비밀 키
		ListenAddr:        ":8080",           // 애플리케이션 리스닝 주소
	}
}

// InitDB는 modernc.org/sqlite 드라이버로 SQLite 데이터베이스를 초기화합니다.
func InitDB(dbPath string) (*sql.DB, error) {
	// 드라이버 이름을 "sqlite"로 지정하고, 파일 모드 및 외래키 지원 옵션을 URL 파라미터로 전달
	dsn := fmt.Sprintf("file:%s?_foreign_keys=1", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("SQLite 오픈 실패: %w", err)
	}

	// users 테이블 생성 (없을 경우)
	createTableQuery := `
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`
	if _, err := db.Exec(createTableQuery); err != nil {
		db.Close()
		return nil, fmt.Errorf("users 테이블 생성 실패: %w", err)
	}

	return db, nil
}
