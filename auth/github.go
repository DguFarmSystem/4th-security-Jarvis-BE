package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"teleport-backend/config"
	"teleport-backend/teleport"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// Handler는 GitHub 인증 관련 핸들러를 관리합니다.
type Handler struct {
	Cfg             *config.Config
	TeleportService *teleport.Service
}

func NewHandler(cfg *config.Config, ts *teleport.Service) *Handler {
	return &Handler{Cfg: cfg, TeleportService: ts}
}

func (h *Handler) HandleGitHubLogin(c *gin.Context) {
	// ... (기존 handleGitHubLogin 로직과 동일, githubOAuthConfig -> h.Cfg.GitHubOAuthConfig) ...
	url := h.Cfg.GitHubOAuthConfig.AuthCodeURL("random-state-string", oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("scope", "read:org"))
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func (h *Handler) HandleGitHubCallback(c *gin.Context) {
	// ... (기존 handleGitHubCallback 로직과 동일, 필요한 부분을 h.Cfg와 h.TeleportService에서 가져옴) ...
	// 아래는 완성된 코드
	code := c.Query("code")
	oauthToken, err := h.Cfg.GitHubOAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		c.String(http.StatusInternalServerError, "GitHub 토큰 교환 실패: "+err.Error())
		return
	}

	client := h.Cfg.GitHubOAuthConfig.Client(context.Background(), oauthToken)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		c.String(http.StatusInternalServerError, "GitHub에서 사용자 정보 조회 실패: "+err.Error())
		return
	}
	defer resp.Body.Close()

	var user struct {
		Login string `json:"login"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		c.String(http.StatusInternalServerError, "사용자 데이터 파싱 실패")
		return
	}

	// 팀 멤버십 확인 로직
	orgName := "4th-security-Jarvis"
	teamSlug := "jarvis"
	teamMembershipURL := fmt.Sprintf("https://api.github.com/orgs/%s/teams/%s/memberships/%s", orgName, teamSlug, user.Login)
	req, _ := http.NewRequest("GET", teamMembershipURL, nil)
	teamResp, err := client.Do(req)
	if err != nil {
		c.String(http.StatusInternalServerError, "GitHub 팀 정보 조회 실패: "+err.Error())
		return
	}
	defer teamResp.Body.Close()

	if teamResp.StatusCode == http.StatusNotFound {
		c.String(http.StatusForbidden, "접근 거부: 허가된 팀의 멤버가 아닙니다.")
		return
	}
	if teamResp.StatusCode != http.StatusOK {
		c.String(http.StatusInternalServerError, "팀 정보를 확인하는 중 오류가 발생했습니다.")
		return
	}

	// 사용자 프로비저닝
	err = h.TeleportService.ProvisionTeleportUser(c.Request.Context(), user.Login)
	if err != nil {
		c.String(http.StatusInternalServerError, "사용자 계정을 준비하는 중 오류가 발생했습니다.")
		return
	}

	// JWT 생성 및 쿠키 설정
	claims := jwt.MapClaims{
		"username": user.Login,
		"exp":      time.Now().Add(time.Hour * 1).Unix(),
		"iat":      time.Now().Unix(),
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := jwtToken.SignedString(h.Cfg.JWTSecretKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "토큰 생성 실패"})
		return
	}

	c.SetCookie("auth_token", tokenString, 3600, "/", "", false, false)
	// c.Redirect(http.StatusFound, "https://jarvis-indol-omega.vercel.app")
	c.Redirect(http.StatusFound, "https://jarvis-indol-omega.vercel.app")
}
