package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"teleport-backend/config"
	"teleport-backend/teleport"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// Handler는 GitHub 인증 관련 핸들러를 관리합니다.
type Handler struct {
	Cfg             *config.Config
	TeleportService *teleport.Service
}

// NewHandler는 인증 핸들러 구조체를 생성하고 초기화합니다.
func NewHandler(cfg *config.Config, ts *teleport.Service) *Handler {
	return &Handler{Cfg: cfg, TeleportService: ts}
}

// HandleGitHubLogin은 사용자를 GitHub 인증 페이지로 리디렉션하여 로그인 절차를 시작합니다.
func (h *Handler) HandleGitHubLogin(c *gin.Context) {
	url := h.Cfg.GitHubOAuthConfig.AuthCodeURL("random-state-string", oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("scope", "read:org"))
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// HandleGitHubCallback은 GitHub로부터 인증 코드를 받아 사용자 정보를 처리하고 JWT를 발급합니다.
func (h *Handler) HandleGitHubCallback(c *gin.Context) {
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
	orgName := h.Cfg.OrgName
	teamSlug := h.Cfg.TeamSlug
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

	c.SetSameSite(http.SameSiteNoneMode)

	c.SetCookie("auth_token", tokenString, 3600, "/", "", true, false)

	c.Redirect(http.StatusFound, "https://openswdev.duckdns.org")
}
