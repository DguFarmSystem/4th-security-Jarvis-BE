package teleport

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"teleport-backend/config"

	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/trace"
	"google.golang.org/grpc"
)

const machineIDIdentityFile = "/opt/machine-id/identity"

// Service는 Teleport 클라이언트와 관련된 모든 작업을 처리합니다.
type Service struct {
	Client *client.Client
	Cfg    *config.Config
}

// NewService는 새로운 Teleport 서비스를 생성합니다.
func NewService(cfg *config.Config) (*Service, error) {
	creds := client.LoadIdentityFile(machineIDIdentityFile)
	mainClient, err := client.New(context.Background(), client.Config{
		Addrs:       []string{cfg.TeleportAuthAddr},
		Credentials: []client.Credentials{creds},
		DialOpts:    []grpc.DialOption{},
	})
	if err != nil {
		return nil, fmt.Errorf("Teleport API 클라이언트 생성 실패: %w", err)
	}

	return &Service{Client: mainClient, Cfg: cfg}, nil
}

func (s *Service) Close() {
	if s.Client != nil {
		s.Client.Close()
	}
}

// GetImpersonatedClient는 특정 사용자를 가장하는 클라이언트를 생성합니다.
func (s *Service) GetImpersonatedClient(ctx context.Context, username string) (*client.Client, string, error) {
	// ... (기존 GetImpersonatedClient 로직과 동일, t를 s로 변경) ...
	// 예: return t.Client.GetUser(...) -> return s.Client.GetUser(...)
	// 아래는 완성된 코드
	user, err := s.Client.GetUser(ctx, username, false)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get user info: %w", err)
	}

	userRoles := user.GetRoles()
	if len(userRoles) == 0 {
		return nil, "", fmt.Errorf("user '%s' has no assigned roles", username)
	}

	targetRole := userRoles[0]
	identityFilePath := fmt.Sprintf("/opt/machine-id/%s/identity", targetRole)
	creds := client.LoadIdentityFile(identityFilePath)

	impersonatedClient, err := client.New(ctx, client.Config{
		Addrs:       []string{s.Cfg.TeleportAuthAddr},
		Credentials: []client.Credentials{creds},
	})
	if err != nil {
		return nil, targetRole, fmt.Errorf("failed to create impersonated client with role %s: %w", targetRole, err)
	}
	return impersonatedClient, targetRole, nil
}

// ProvisionTeleportUser는 사용자가 없으면 생성하고, 있으면 넘어갑니다.
func (s *Service) ProvisionTeleportUser(ctx context.Context, githubUsername string) error {
	// ... (기존 ProvisionTeleportUser 로직과 동일, t를 s로 변경) ...
	// 아래는 완성된 코드
	defaultRoles := []string{"basic-user"}
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	_, err := s.Client.GetUser(reqCtx, githubUsername, false)
	if isCertExpiredError(err) {
		log.Printf("[INFO] 인증서 만료 감지, 클라이언트 갱신 시도...")
		if refreshErr := s.refreshClient(); refreshErr != nil {
			log.Printf("[ERROR] 클라이언트 갱신 실패: %v", refreshErr)
			return trace.Wrap(refreshErr)
		}
		_, err = s.Client.GetUser(reqCtx, githubUsername, false)
	}

	if err != nil {
		if trace.IsNotFound(err) || strings.Contains(err.Error(), "not found") {
			log.Printf("[INFO] 신규 사용자 '%s'를 생성합니다.", githubUsername)
			user, err := types.NewUser(githubUsername)
			if err != nil {
				return trace.Wrap(err)
			}
			user.SetRoles(defaultRoles)
			_, err = s.Client.CreateUser(reqCtx, user)
			if err != nil {
				return trace.Wrap(err)
			}
			log.Printf("[INFO] 사용자 '%s'가 역할 '%v'로 성공적으로 생성되었습니다.", githubUsername, defaultRoles)
			return nil
		}
		return trace.Wrap(err)
	}
	log.Printf("[INFO] 기존 사용자 '%s'의 로그인을 확인했습니다.", githubUsername)
	return nil
}

// isCertExpiredError와 refreshClient는 비공개 헬퍼 함수로 유지
func isCertExpiredError(err error) bool {
	// ... (기존 로직과 동일) ...
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "certificate has expired") ||
		strings.Contains(msg, "x509: certificate has expired") ||
		strings.Contains(msg, "expired certificate") ||
		strings.Contains(msg, "access denied: expired session")
}

func (s *Service) refreshClient() error {
	// ... (기존 로직과 동일, t를 s로 변경) ...
	creds := client.LoadIdentityFile(machineIDIdentityFile)
	newClient, err := client.New(context.Background(), client.Config{
		Addrs:       []string{s.Cfg.TeleportAuthAddr},
		Credentials: []client.Credentials{creds},
		DialOpts:    []grpc.DialOption{},
	})
	if err != nil {
		return err
	}
	if s.Client != nil {
		s.Client.Close()
	}
	s.Client = newClient
	return nil
}
