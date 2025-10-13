package auth

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
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

type DeleteRequest struct {
	Username string `json:"username" binding:"required"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// NewHandler는 인증 핸들러 구조체를 생성하고 초기화합니다. + 관리자 계정 생성
func NewHandler(cfg *config.Config, db *sql.DB) (*Handler, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("bcrypt 해시 실패: %w", err)
	}

	// 해시된 비밀번호 저장
	_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", "admin", string(hashedPassword))
	if err != nil {
		return nil, fmt.Errorf("DB에 admin 사용자 저장 실패: %w", err)
	}

	customRole := `
kind: role
version: v6
metadata:
  name: custom
spec:
  allow:
    logins: ["root,ubuntu"]
    node_labels: {"*": "*"}
  deny: {}
`
	roleFile := "/tmp/custom-role.yaml"
	// 임시 파일로 역할 정의 저장
	err = os.WriteFile(roleFile, []byte(customRole), 0644)
	if err != nil {
		return nil, fmt.Errorf("custom 역할 YAML 파일 저장 실패: %w", err)
	}
	// tctl로 role 추가 (존재시 업데이트)
	cmd := exec.Command("tctl", "create", "-f", roleFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("tctl role create 실패: %w, 출력: %s", err, string(output))
	}

	cmd = exec.Command("tctl", "users", "add", "admin", "--roles=custom,editor")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("tctl users add 실패: %w, 출력: %s", err, string(output))
	}

	// 핸들러 인스턴스 반환
	return &Handler{Cfg: cfg, DB: db}, nil
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
	expirationTime := time.Now().Add(1 * time.Hour)
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

// 관리자 api - 사용자를 DB에 등록합니다. 유저 초기 권한은 무조건 editor
// TODO db-teleport 트렌젝션, 인젝션 방지, 브루트포싱 방지
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
	_, err = h.DB.Exec("INSERT INTO users (username, password) VALUES (?, ?)", req.Username, string(hashedPassword))
	if err != nil {
		c.JSON(500, gin.H{"error": "사용자 등록 중 오류가 발생했습니다: " + err.Error()})
		return
	}

	cmd := exec.Command("tctl", "users", "add", req.Username, "--roles=custom,editor")
	output, err := cmd.CombinedOutput()
	if err != nil {
		c.JSON(500, gin.H{"error": "tctl users add 실패: " + err.Error() + ", 출력: " + string(output)})
		return
	}

	c.JSON(201, gin.H{"message": "회원가입이 완료되었습니다."})
}

func (h *Handler) HandleDel(c *gin.Context) {
	// 클라이언트에서 JSON으로 전달된 id, password 구조체 정의
	var req DeleteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "username이 필요합니다"})
		return
	}

	_, err := h.DB.Exec("DELETE FROM users WHERE username = ?", req.Username)
	if err != nil {
		c.JSON(500, gin.H{"error": "사용자 삭제 중 오류가 발생했습니다: " + err.Error()})
		return
	}

	cmd := exec.Command("tctl", "users", "rm", req.Username)
	output, err := cmd.CombinedOutput()
	if err != nil {
		c.JSON(500, gin.H{"error": "tctl users add 실패: " + err.Error() + ", 출력: " + string(output)})
		return
	}

	c.JSON(201, gin.H{"message": "삭제가 완료되었습니다."})
}
