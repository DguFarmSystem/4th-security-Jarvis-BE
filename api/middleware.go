package api

import (
	"log"
	"net/http"
	"strings"

	"teleport-backend/config"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// NewAuthMiddleware는 JWT 인증을 처리하는 Gin 미들웨어를 생성합니다.
// JWT로 수정
func NewAuthMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1) Authorization 헤더에서 Bearer 토큰 확인
		authHeader := c.GetHeader("Authorization")
		var tokenString string
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenString = strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		}

		// 2) 헤더에 없으면 쿠키에서 확인
		if tokenString == "" {
			if cookie, err := c.Cookie("auth_token"); err == nil {
				tokenString = cookie
			}
		}

		if tokenString == "" {
			log.Println("인증 토큰 없음")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// 3) 토큰 파싱 및 서명 검증
		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			// cfg.JWTSecretKey를 그대로 반환 (프로젝트에서 설정한 타입과 일치해야 함)
			return cfg.JWTSecretKey, nil
		})
		if err != nil {
			log.Printf("JWT 파싱/검증 실패: %v", err)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		if !token.Valid {
			log.Println("유효하지 않은 JWT 토큰")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// 4) username 추출하여 context에 저장
		username, ok := claims["username"].(string)
		if !ok || username == "" {
			log.Println("JWT에 username 없음")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Set("username", username)
		c.Next()
	}
}
