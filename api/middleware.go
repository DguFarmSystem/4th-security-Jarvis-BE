package api

import (
	"log"
	"net/http"

	"teleport-backend/config"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// NewAuthMiddleware는 JWT 인증을 처리하는 Gin 미들웨어를 생성합니다.
func NewAuthMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := c.Cookie("auth_token")
		if err != nil {
			log.Println("쿠키에서 GitHub 사용자 정보를 찾을 수 없습니다. 로그인이 필요합니다.")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		claims := jwt.MapClaims{}
		_, err = jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return cfg.JWTSecretKey, nil
		})

		if err != nil {
			log.Printf("유효하지 않은 JWT 토큰입니다: %v", err)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		githubUser, ok := claims["username"].(string)
		if !ok || githubUser == "" {
			log.Println("JWT 토큰에 사용자 이름이 포함되어 있지 않습니다.")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.Set("username", githubUser)
		c.Next()
	}
}
