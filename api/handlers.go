package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"teleport-backend/config"
	"teleport-backend/services"
	"teleport-backend/teleport"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/trace"
	"github.com/tidwall/gjson"
)

// Handlers는 모든 API 핸들러 메서드를 가집니다.
type Handlers struct {
	TeleportService *teleport.Service
	GeminiService   services.Analyzer
	HttpClient      *http.Client
}

func NewHandlers(ts *teleport.Service, gs services.Analyzer) *Handlers {
	return &Handlers{
		TeleportService: ts,
		GeminiService:   gs,
		HttpClient:      &http.Client{Timeout: 60 * time.Second},
	}
}

func (h *Handlers) GetUsers(c *gin.Context) {
	impersonatedUser := c.GetString("username")
	if impersonatedUser == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "인증된 사용자 정보를 찾을 수 없어 가장에 실패했습니다."})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	impersonatedClient, err := h.TeleportService.GetDynamicImpersonatedClient(ctx, impersonatedUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer impersonatedClient.Close()

	users, err := impersonatedClient.GetUsers(ctx, false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "사용자 목록 조회에 실패했습니다: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, users)
}

func (h *Handlers) DeleteUser(c *gin.Context) {
	impersonatedUser := c.GetString("username")
	if impersonatedUser == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "인증된 사용자 정보를 찾을 수 없어 가장에 실패했습니다."})
		return
	}

	userToDelete := c.Param("username")
	if userToDelete == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "삭제할 사용자의 이름(username)이 반드시 필요합니다."})
		return
	}

	//자기 자신을 삭제하려는 요청을 방지합니다.
	if userToDelete == impersonatedUser {
		c.JSON(http.StatusForbidden, gin.H{"error": "자기 자신을 삭제할 수 없습니다."})
		return
	}
	log.Printf("[DeleteUser] 요청 시작: 요청자='%s', 삭제 대상='%s'", impersonatedUser, userToDelete)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	impersonatedClient, err := h.TeleportService.GetDynamicImpersonatedClient(ctx, impersonatedUser)
	if err != nil {
		log.Printf("[DeleteUser] 클라이언트 생성 실패: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer impersonatedClient.Close()

	err = impersonatedClient.DeleteUser(ctx, userToDelete)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("'%s' 사용자 삭제에 실패했습니다: %s", userToDelete, err.Error())})
		return
	}
	log.Printf("[DeleteUser] 성공: 사용자 '%s'가 성공적으로 삭제되었습니다.", userToDelete)
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("사용자 '%s'이(가) 성공적으로 삭제되었습니다.", userToDelete)})

}

func (h *Handlers) UpdateUser(c *gin.Context) {
	userToUpdate := c.Param("username")
	if userToUpdate == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "업데이트할 사용자의 이름(username)이 반드시 필요합니다."})
		return
	}
	// 요청 본문(JSON)에서 업데이트할 데이터를 읽어옵니다.
	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "요청 본문이 잘못되었습니다: " + err.Error()})
		return
	}

	// 미들웨어로부터 현재 요청을 보낸 사용자의 이름을 가져옵니다.
	impersonatedUser := c.GetString("username")
	if impersonatedUser == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "인증된 사용자 정보를 찾을 수 없어 가장에 실패했습니다."})
		return
	}

	log.Printf("[UpdateUser] 요청 시작: 요청자='%s', 대상='%s', 요청 데이터: %+v", impersonatedUser, userToUpdate, req)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	impersonatedClient, err := h.TeleportService.GetDynamicImpersonatedClient(ctx, impersonatedUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer impersonatedClient.Close()

	// 업데이트를 위해 먼저 기존 사용자 정보를 가져옵니다.
	user, err := impersonatedClient.GetUser(ctx, userToUpdate, false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("사용자 '%s' 정보 조회에 실패했습니다: %s", userToUpdate, err.Error())})
		return
	}
	// 가져온 사용자 정보에 요청받은 데이터를 적용합니다. (예: 역할 업데이트)
	user.SetRoles(req.Roles)

	// 7. 변경된 사용자 객체로 업데이트 API를 호출합니다.
	_, err = impersonatedClient.UpdateUser(ctx, user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("사용자 '%s' 업데이트에 실패했습니다: %s", userToUpdate, err.Error())})
		return
	}

	// 8. 성공적으로 업데이트되었음을 응답합니다.
	log.Printf("[UpdateUser] 성공: 사용자 '%s'의 정보가 성공적으로 업데이트되었습니다.", userToUpdate)
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("사용자 '%s'의 정보가 성공적으로 업데이트되었습니다.", userToUpdate)})
}

func (h *Handlers) GetRoles(c *gin.Context) {
	impersonatedUser := c.GetString("username")
	if impersonatedUser == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "인증된 사용자 정보를 찾을 수 없어 가장에 실패했습니다."})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	impersonatedClient, err := h.TeleportService.GetDynamicImpersonatedClient(ctx, impersonatedUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer impersonatedClient.Close()

	roles, err := impersonatedClient.GetRoles(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "역할 목록을 가져오는 데 실패했습니다: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, roles)
}

func (h *Handlers) CreateRole(c *gin.Context) {
	impersonatedUser := c.GetString("username")
	if impersonatedUser == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "인증된 사용자 정보를 찾을 수 없어 가장에 실패했습니다."})
		return
	}

	// 1. 요청 본문(JSON)에서 역할 데이터를 읽어옵니다.
	// types.Role은 인터페이스이므로, 구체적인 타입인 RoleV6로 바인딩합니다.
	var role *types.RoleV6
	if err := c.ShouldBindJSON(&role); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "요청 본문(Role)이 잘못되었습니다: " + err.Error()})
		return
	}
	log.Printf("[CreateRole] 요청 시작: 요청자='%s', 생성할 역할명='%s'", impersonatedUser, role.GetName())

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	impersonatedClient, err := h.TeleportService.GetDynamicImpersonatedClient(ctx, impersonatedUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer impersonatedClient.Close()

	//  (1): 두 개의 값을 반환받도록 수정 ---
	// API가 (types.Role, error)를 반환하므로, createdRole 변수에 결과를 받습니다.
	createdRole, err := impersonatedClient.CreateRole(ctx, role)
	if err != nil {
		log.Printf("[CreateRole] API 호출 실패: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("역할 '%s' 생성에 실패했습니다: %s", role.GetName(), err.Error())})
		return
	}

	//  (2): 성공 시 생성된 객체 자체를 반환 ---
	log.Printf("[CreateRole] 성공: 역할 '%s'가 생성되었습니다.", createdRole.GetName())
	c.JSON(http.StatusCreated, createdRole) // 단순 메시지 대신, 생성된 Role 객체를 반환
}

func (h *Handlers) UpsertRole(c *gin.Context) {
	impersonatedUser := c.GetString("username")
	if impersonatedUser == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "인증된 사용자 정보를 찾을 수 없어 가장에 실패했습니다."})
		return
	}

	// 1. 요청 본문(JSON)에서 역할 데이터를 읽어옵니다.
	var role *types.RoleV6
	if err := c.ShouldBindJSON(&role); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "요청 본문(Role)이 잘못되었습니다: " + err.Error()})
		return
	}
	log.Printf("[UpsertRole] 요청 시작: 요청자='%s', 생성/수정할 역할명='%s'", impersonatedUser, role.GetName())

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	impersonatedClient, err := h.TeleportService.GetDynamicImpersonatedClient(ctx, impersonatedUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer impersonatedClient.Close()

	//  (1): 두 개의 값을 반환받도록 수정 ---
	upsertedRole, err := impersonatedClient.UpsertRole(ctx, role)
	if err != nil {
		log.Printf("[UpsertRole] API 호출 실패: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("역할 '%s' 생성/수정에 실패했습니다: %s", role.GetName(), err.Error())})
		return
	}

	//  (2): 성공 시 생성/수정된 객체 자체를 반환 ---
	log.Printf("[UpsertRole] 성공: 역할 '%s'가 생성/수정되었습니다.", upsertedRole.GetName())
	c.JSON(http.StatusOK, upsertedRole) // 단순 메시지 대신, 생성/수정된 Role 객체를 반환
}

func (h *Handlers) DeleteRole(c *gin.Context) {
	impersonatedUser := c.GetString("username")
	if impersonatedUser == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "인증된 사용자 정보를 찾을 수 없어 가장에 실패했습니다."})
		return
	}

	roleToDelete := c.Param("rolename")
	if roleToDelete == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "삭제할 역할의 이름(rolename)이 반드시 필요합니다."})
		return
	}

	log.Printf("[DeleteRole] 요청 시작: 요청자='%s', 삭제 대상 역할='%s'", impersonatedUser, roleToDelete)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	impersonatedClient, err := h.TeleportService.GetDynamicImpersonatedClient(ctx, impersonatedUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer impersonatedClient.Close()

	err = impersonatedClient.DeleteRole(ctx, roleToDelete)
	if err != nil {
		log.Printf("[DeleteRole] API 호출 실패: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("역할 '%s' 삭제에 실패했습니다: %s", roleToDelete, err.Error())})
		return
	}

	log.Printf("[DeleteRole] 성공: 역할 '%s'가 삭제되었습니다.", roleToDelete)
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("역할 '%s'이(가) 성공적으로 삭제되었습니다.", roleToDelete)})
}

func (h *Handlers) GetNodes(c *gin.Context) {
	impersonatedUser := c.GetString("username")
	if impersonatedUser == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "인증된 사용자 정보를 찾을 수 없어 가장에 실패했습니다."})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	impersonatedClient, err := h.TeleportService.GetDynamicImpersonatedClient(ctx, impersonatedUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer impersonatedClient.Close()

	nodes, err := impersonatedClient.GetNodes(ctx, "default")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "서버(노드) 목록을 가져오는 데 실패했습니다: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, nodes)
}

func (h *Handlers) GenerateNodeJoinToken(c *gin.Context) {
	impersonatedUser := c.GetString("username")
	if impersonatedUser == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "인증된 사용자 정보를 찾을 수 없습니다."})
		return
	}

	// 1. 요청 본문을 바인딩하고 유효성을 검사합니다.
	var req GenerateTokenRequest
	// 요청 값이 없을 경우 사용할 기본값 설정
	defaults := GenerateTokenRequest{
		TTL:   "15m",
		Roles: []string{"node"},
	}

	// 요청 본문이 비어있어도 오류로 처리하지 않고 기본값을 사용합니다.
	if err := c.ShouldBindJSON(&req); err != nil && err.Error() != "EOF" {
		log.Printf("[GenerateToken] JSON 바인딩 오류: %v. 요청자: %s", err, impersonatedUser)
		c.JSON(http.StatusBadRequest, gin.H{"error": "요청 형식이 잘못되었습니다: " + err.Error()})
		return
	}

	// 사용자가 값을 보내지 않은 경우 기본값으로 채웁니다.
	if req.TTL == "" {
		req.TTL = defaults.TTL
	}
	if len(req.Roles) == 0 {
		req.Roles = defaults.Roles
	}
	if req.Nodename == "" {
		// nodename이 없으면 랜덤 문자열을 생성하여 충돌을 방지합니다.
		randBytes := make([]byte, 4)
		rand.Read(randBytes)
		req.Nodename = "teleport-node-" + hex.EncodeToString(randBytes)
	}

	ttl, err := time.ParseDuration(req.TTL)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "유효하지 않은 TTL 형식입니다. '5m', '1h'와 같이 입력하세요."})
		return
	}

	log.Printf("[GenerateToken] 요청 시작: 요청자='%s', TTL='%s', Roles='%v', nodename='%s'", impersonatedUser, req.TTL, req.Roles, req.Nodename)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	impersonatedClient, err := h.TeleportService.GetDynamicImpersonatedClient(ctx, impersonatedUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "사용자 권한 클라이언트 생성에 실패했습니다: " + err.Error()})
		return
	}
	defer impersonatedClient.Close()

	// 2. [핵심] 클라이언트 측에서 안전한 랜덤 토큰 문자열 생성
	// 16바이트 -> 32자리 헥스(hex) 문자열
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "안전한 토큰 생성에 실패했습니다: " + err.Error()})
		return
	}
	tokenValue := hex.EncodeToString(tokenBytes)
	log.Printf("[GenerateToken] 새로운 토큰 값 생성 완료: %s", tokenValue)
	// 3. [핵심] 생성한 토큰 값으로 ProvisionToken 객체 생성
	token, err := types.NewProvisionToken(tokenValue, []types.SystemRole{types.RoleNode}, time.Now().Add(ttl))
	if err != nil {
		log.Printf("[GenerateToken] 랜덤 토큰 생성 실패: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ProvisionToken 객체 생성에 실패했습니다: " + err.Error()})
		return
	}

	log.Printf("[GenerateToken] 서버에 토큰(%s) 등록을 시도합니다.", tokenValue)
	// 4. [핵심] 올바른 메서드인 CreateToken을 사용하여 서버에 등록
	err = impersonatedClient.CreateToken(ctx, token)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "조인 토큰을 서버에 등록하는 데 실패했습니다: " + err.Error()})
		return
	}
	log.Printf("[GenerateToken] 토큰 등록 성공.")

	// 스크립트 URL에 토큰과 역할을 쿼리 파라미터로 전달합니다.
	scriptURL := fmt.Sprintf("https://%s/scripts/install.sh", config.LoadConfig().TeleportProxyAddr)

	// 최종적으로 사용자가 실행할 명령어
	oneLineInstallCommand := fmt.Sprintf(`curl %s | sudo bash`, scriptURL)

	manualStartCommand := fmt.Sprintf("sudo teleport start --roles=node --token=%s --auth-server=%s --nodename=%s", tokenValue, config.LoadConfig().TeleportProxyAddr, req.Nodename)
	// 5. 사용자에게 제공할 안내 정보 구성 (환경에 맞게 수정 필요)

	response := gin.H{
		"token":   tokenValue,
		"expires": token.GetMetadata().Expires.Format(time.RFC3339),
		"roles":   req.Roles,
		"commands": gin.H{
			"automatic_install": oneLineInstallCommand,
			"manual_start":      manualStartCommand,
		},
		"instructions": gin.H{
			"step1": "새 에이전트를 설치할 서버에서 'automatic_install' 명령어를 실행하여 Teleport 서비스를 설치 및 시작하세요.",
			"step2": "또는, 수동으로 Teleport를 설치한 후 'manual_start' 명령어를 실행하여 클러스터에 노드를 등록하세요.",
		},
	}
	c.JSON(http.StatusOK, response)
}

func (h *Handlers) DeleteNode(c *gin.Context) {
	impersonatedUser := c.GetString("username")
	if impersonatedUser == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "인증된 사용자 정보를 찾을 수 없어 가장에 실패했습니다."})
		return
	}

	nodeNameToDelete := c.Param("nodename")
	if nodeNameToDelete == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "삭제할 노드의 이름(nodename)이 필요합니다."})
		return
	}

	log.Printf("[DeleteNode] 요청 시작: 요청자='%s', 대상 노드='%s'", impersonatedUser, nodeNameToDelete)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	impersonatedClient, err := h.TeleportService.GetDynamicImpersonatedClient(ctx, impersonatedUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer impersonatedClient.Close()

	err = impersonatedClient.DeleteNode(ctx, "default", nodeNameToDelete)
	if err != nil {
		// trace.IsNotFound(err)를 사용해 노드가 이미 없는 경우를 구분할 수 있습니다.
		if trace.IsNotFound(err) {
			log.Printf("[DeleteNode] 삭제할 노드(%s)를 찾을 수 없음: %v", nodeNameToDelete, err)
			c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("노드 '%s'를 찾을 수 없습니다.", nodeNameToDelete)})
			return
		}

		log.Printf("[DeleteNode] 노드(%s) 삭제 실패: %v", nodeNameToDelete, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "노드 삭제에 실패했습니다: " + err.Error()})
		return
	}
	log.Printf("[DeleteNode] 성공: 노드 '%s'가 성공적으로 삭제되었습니다.", nodeNameToDelete)

	// 3. [개선] 성공 시 명확한 JSON 응답을 반환합니다.
	c.JSON(http.StatusOK, gin.H{
		"message":    "Node deleted successfully",
		"nodename":   nodeNameToDelete,
		"deleted_by": impersonatedUser,
	})
}

func (h *Handlers) GetAuditEvents(c *gin.Context) {

	impersonatedUser := c.GetString("username")
	if impersonatedUser == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "인증된 사용자 정보를 찾을 수 없어 가장에 실패했습니다."})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	impersonatedClient, err := h.TeleportService.GetDynamicImpersonatedClient(ctx, impersonatedUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer impersonatedClient.Close()

	events, _, err := impersonatedClient.SearchEvents(
		c.Request.Context(),
		time.Now().Add(-24*time.Hour),
		time.Now(),
		"",
		nil,
		100,
		types.EventOrderDescending,
		"",
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "감사 로그를 가져오는 데 실패했습니다: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, events)
}

func (h *Handlers) ListRecordedSessions(c *gin.Context) {

	impersonatedUser := c.GetString("username")
	if impersonatedUser == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "인증된 사용자 정보를 찾을 수 없어 가장에 실패했습니다."})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	impersonatedClient, err := h.TeleportService.GetDynamicImpersonatedClient(ctx, impersonatedUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer impersonatedClient.Close()

	events, _, err := impersonatedClient.SearchEvents(
		c.Request.Context(),
		time.Now().Add(-24*time.Hour),
		time.Now(),
		"",
		[]string{"session.end"}, // "session.end" 이벤트만 필터링
		100,
		types.EventOrderDescending,
		"", // 페이지네이션을 사용하지 않으므로 커서는 비워둡니다.
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "감사 로그를 가져오는 데 실패했습니다: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, events)
}

func (h *Handlers) processSessionLogic(ctx context.Context, sessionID string, logData string) {
	log.Printf("세션 처리 시작: %s", sessionID)
	// Race Conditionq, 서버 저장 중 요청 방지
	time.Sleep(15 * time.Second)

	// 실행할 tsh play 명령어 전체를 미리 출력합니다.
	log.Printf("[DEBUG] Executing command: tsh play --proxy=%s -i %s --format=text %s", h.TeleportService.Cfg.TeleportProxyAddr, h.TeleportService.Cfg.TbotIdentityFile, sessionID)
	cmd := exec.CommandContext(ctx, "tsh", "play",
		"--proxy="+h.TeleportService.Cfg.TeleportProxyAddr,
		"-i", h.TeleportService.Cfg.TbotIdentityFile,
		"--format=text",
		sessionID)

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		log.Printf("세션 %s의 로그 추출 실패 ('tsh play'): %v, Stderr: %s", sessionID, err, stderr.String())
		return
	}
	transcript := out.String()

	log.Printf("[DEBUG] Transcript for session %s extracted successfully. \n Sending script: %s \n", sessionID, transcript)

	// 2. Gemini 서비스로 분석 요청
	analysis, err := h.GeminiService.AnalyzeTranscript(ctx, transcript)
	if err != nil {
		log.Printf("세션 %s 분석 실패: %v", sessionID, err)
		return
	}

	log.Printf("[DEBUG] Gemini analysis for session %s completed.", sessionID)

	// 3. 최종 데이터 조합 및 Logstash 전송
	enrichedLog := EnrichedLog{
		SessionID:    sessionID,
		User:         gjson.Get(logData, "user").String(),
		ServerID:     gjson.Get(logData, "server_id").String(),
		ServerAddr:   gjson.Get(logData, "server_addr").String(),
		SessionStart: gjson.Get(logData, "session_start").String(),
		SessionEnd:   gjson.Get(logData, "time").String(),
		Transcript:   transcript,
		Analysis:     analysis,
	}

	payload, err := json.Marshal(enrichedLog)
	if err != nil {
		log.Printf("세션 %s의 로그 데이터 직렬화 실패: %v", sessionID, err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, "POST", h.TeleportService.Cfg.LogstashURL, bytes.NewReader(payload))
	if err != nil {
		log.Printf("세션 %s의 Logstash 요청 생성 실패: %v", sessionID, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.HttpClient.Do(req)
	if err != nil {
		log.Printf("세션 %s의 분석 로그를 Logstash로 전송 실패: %v", sessionID, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		log.Printf("세션 %s 전송 후 Logstash로부터 에러 응답 수신: %s", sessionID, resp.Status)
	} else {
		log.Printf("세션 %s의 분석 로그를 Logstash로 성공적으로 전송했습니다.", sessionID)
	}
}

// Logstash로부터 session.end 이벤트를 받아 처리하는 핸들러
func (h *Handlers) AnalyzeSession(c *gin.Context) {
	// Logstash가 보낸 JSON을 특정 타입이 아닌 일반 맵으로 받습니다.
	// 이렇게 하면 타입 불일치 오류를 피하고 유연하게 데이터를 받을 수 있습니다.
	var payload map[string]interface{}
	if err := c.ShouldBindJSON(&payload); err != nil {
		log.Printf("[AnalyzeSession] ERROR: Invalid JSON from Logstash: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Logstash로부터 받은 페이로드 전체를 로그로 남깁니다.
	requestBody, _ := json.Marshal(payload)
	log.Printf("[DEBUG-RECEIVE] Received payload from Logstash: %s", string(requestBody))

	// `requestBody`는 이미 []byte 타입이므로, 바로 사용합니다.
	logData := string(requestBody)

	// 원본 로그에서 세션 ID를 추출합니다.
	sessionID := gjson.Get(logData, "sid").String()
	if sessionID == "" {
		log.Printf("[AnalyzeSession] ERROR: 'sid' field missing in raw log data")
		c.JSON(http.StatusBadRequest, gin.H{"error": "'sid' field missing"})
		return
	}

	log.Printf("Logstash로부터 세션 처리 요청 수신: %s", sessionID)

	// 비동기로 실제 분석 로직을 실행합니다.
	go h.processSessionLogic(context.Background(), sessionID, logData)

	c.JSON(http.StatusAccepted, gin.H{"status": "request accepted, processing in background"})
}

// Server-Sent Events (SSE)를 사용하여 클라이언트에게 실시간으로 세션 이벤트를 전송합니다.
func (h *Handlers) StreamRecordedSession(c *gin.Context) {

	impersonatedUser := c.GetString("username")
	if impersonatedUser == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "인증된 사용자 정보를 찾을 수 없습니다."})
		return
	}

	sessionID := c.Param("sessionID")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "URL 파라미터로 sessionID가 필요합니다."})
		return
	}

	log.Printf("[StreamRecordedSession] 스트리밍 요청 시작: 요청자='%s', 대상 세션='%s'", impersonatedUser, sessionID)

	ctx, cancel := context.WithCancel(c.Request.Context())
	defer cancel()

	impersonatedClient, err := h.TeleportService.GetDynamicImpersonatedClient(ctx, impersonatedUser)
	if err != nil {
		log.Printf("ERROR: 가장 클라이언트 생성 실패: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "내부 서버 오류: 클라이언트 생성 실패"})
		return
	}
	defer impersonatedClient.Close()

	// 3. StreamSessionEvents를 올바르게 호출하여 두 개의 채널을 받음
	// startIndex 0은 녹화 시작부터 모든 이벤트를 가져옵니다.
	eventChan, errChan := impersonatedClient.StreamSessionEvents(ctx, sessionID, 0)

	// 4. SSE 스트리밍 설정
	// 클라이언트가 SSE 스트림을 받을 수 있도록 헤더를 설정합니다.
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")

	// [디버깅] SSE 연결 유지를 위한 keep-alive Ticker 설정 (15초마다 전송)
	keepAliveTicker := time.NewTicker(15 * time.Second)
	defer keepAliveTicker.Stop()

	var lastEventTime time.Time
	isFirstEvent := true
	log.Printf("[디버깅] 세션 '%s'에 대한 이벤트 스트리밍 루프 시작", sessionID)
	for {
		select {
		case event, ok := <-eventChan:
			if !ok {
				log.Printf("[StreamRecordedSession] 스트리밍 완료: 세션='%s'", sessionID)
				return
			}

			if printEvent, isPrintEvent := event.(*events.SessionPrint); isPrintEvent {
				var delay time.Duration
				if isFirstEvent {
					lastEventTime = printEvent.GetTime()
					isFirstEvent = false
				} else {
					delay = printEvent.GetTime().Sub(lastEventTime)
					lastEventTime = printEvent.GetTime()
				}

				payload, err := json.Marshal(gin.H{
					"type":  "print",
					"data":  string(printEvent.Data),
					"delay": delay.Milliseconds(),
					"time":  printEvent.Time.UTC(),
				})
				if err != nil {
					log.Printf("ERROR: SSE 이벤트 데이터 마샬링 실패: %v", err)
					continue
				}

				c.SSEvent("session_chunk", string(payload))
				c.Writer.Flush()
			}

		case err := <-errChan:
			// [디버깅] 에러 채널에서 수신된 내용을 명확히 로깅합니다. nil이라도 기록되어야 합니다.
			if err != nil {
				log.Printf("ERROR: 스트리밍 중 오류 발생 (errChan 수신): %v", err)
			} else {
				log.Printf("[디버깅] errChan에서 nil을 수신하여 스트리밍을 종료합니다.")
			}
			return

		case <-ctx.Done():
			log.Printf("[StreamRecordedSession] 클라이언트 연결 끊김 (ctx.Done()): 세션='%s'", sessionID)
			return

		// [디버깅] 주기적으로 keep-alive 메시지를 보내 연결 상태를 확인하고 타임아웃을 방지합니다.
		case <-keepAliveTicker.C:
			log.Printf("[디버깅] Keep-alive 핑 전송")
			c.SSEvent("keep-alive", "ping")
			c.Writer.Flush()
		}
	}
}
