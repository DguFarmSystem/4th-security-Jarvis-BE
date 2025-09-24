package auth

import (
	"database/sql"
	"net/http"
	"os/exec"
	"teleport-backend/config"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// Handler는 GitHub 인증 관련 핸들러를 관리합니다.
type Handler struct {
	Cfg *config.Config
	DB  *sql.DB
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// NewHandler는 인증 핸들러 구조체를 생성하고 초기화합니다.
func NewHandler(cfg *config.Config, db *sql.DB) *Handler {
	return &Handler{Cfg: cfg, DB: db}
}

// HandleLogin은 로그인 요청을 처리합니다.
func (h *Handler) HandleLogin(c *gin.Context) {
	var jwtSecret = h.Cfg.JWTSecretKey
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username와 password가 필요합니다"})
		return
	}

	// DB에서 사용자 비밀번호 해시 조회
	var storedHash string
	err := h.DB.QueryRow("SELECT password FROM users WHERE username = ?", req.Username).Scan(&storedHash)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "사용자를 찾을 수 없습니다."})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "서버 오류: " + err.Error()})
		return
	}

	// bcrypt 해시와 비교 (운영 시 비밀번호는 반드시 해시 저장해야 함)
	err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(req.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "비밀번호가 올바르지 않습니다."})
		return
	}

	// JWT 토큰 생성
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: req.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "토큰 생성 실패"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "로그인 성공",
		"token":   tokenString,
	})
}

// 관리자 api로 사용자를 DB에 등록합니다.
// TODO 접근제한, 비밀번호 해싱, 수정,삭제 핸들러 추가
func (h *Handler) HandleReg(c *gin.Context) {
	// 클라이언트에서 JSON으로 전달된 id, password 구조체 정의
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "username와 password가 필요합니다"})
		return
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(500, gin.H{"error": "비밀번호 해싱 실패: " + err.Error()})
		return
	}

	// 해시된 비밀번호 저장
	_, err = h.DB.Exec("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", req.Username, string(hashedPassword), "access")
	if err != nil {
		c.JSON(500, gin.H{"error": "사용자 등록 중 오류가 발생했습니다: " + err.Error()})
		return
	}

	cmd := exec.Command("tctl", "users", "add", req.Username, "--roles=access")
	output, err := cmd.CombinedOutput()
	if err != nil {
		c.JSON(500, gin.H{"error": "tctl users add 실패: " + err.Error() + ", 출력: " + string(output)})
		return
	}

	c.JSON(201, gin.H{"message": "회원가입이 완료되었습니다."})
}
