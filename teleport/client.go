package teleport

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"strings"
	"time"

	"teleport-backend/config"

	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"
)

// Service는 Teleport 클라이언트와 관련된 모든 작업을 처리합니다.
type Service struct {
	Client *client.Client
	Cfg    *config.Config
}

// CertificateConfig는 인증서 생성 시 사용할 설정입니다.
type CertificateConfig struct {
	TTL           time.Duration
	AccessLevel   string
	AllowedLogins []string
}

// NewService는 새로운 Teleport 서비스를 생성합니다.
// tbot이 생성한 ID 파일을 사용하여 Teleport에 연결합니다.
func NewService(cfg *config.Config) (*Service, error) {
	creds := client.LoadIdentityFile(cfg.TbotIdentityFile)
	mainClient, err := client.New(context.Background(), client.Config{
		Addrs:       []string{cfg.TeleportAuthAddr},
		Credentials: []client.Credentials{creds},
	})
	if err != nil {
		return nil, fmt.Errorf("Teleport API 클라이언트 생성 실패: %w", err)
	}

	// 연결 상태 확인
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := mainClient.Ping(ctx); err != nil {
		mainClient.Close()
		return nil, fmt.Errorf("Teleport 클러스터(%s) 연결 실패: %w", cfg.TeleportAuthAddr, err)
	}
	log.Printf("Teleport 클러스터(%s)에 성공적으로 연결되었습니다.", cfg.TeleportAuthAddr)

	return &Service{Client: mainClient, Cfg: cfg}, nil
}

func (s *Service) Close() {
	if s.Client != nil {
		s.Client.Close()
	}
}

// GetDynamicImpersonatedClient는 사용자의 역할을 동적으로 읽어와서
// 해당 역할에 맞는 단기 인증서를 발급받아 클라이언트를 생성합니다.
func (s *Service) GetDynamicImpersonatedClient(ctx context.Context, username string) (*client.Client, *CertificateConfig, error) {
	// 1. 사용자 정보를 동적으로 조회
	user, err := s.Client.GetUser(ctx, username, false)
	if err != nil {
		if trace.IsNotFound(err) {
			return nil, nil, fmt.Errorf("사용자 '%s'를 찾을 수 없습니다", username)
		}
		return nil, nil, fmt.Errorf("사용자 정보 조회 실패: %w", err)
	}

	// 2. 사용자의 현재 역할 가져오기
	userRoles := user.GetRoles()
	if len(userRoles) == 0 {
		return nil, nil, fmt.Errorf("사용자 '%s'에게 할당된 역할이 없습니다", username)
	}
	log.Printf("사용자 '%s'의 역할: %v", username, userRoles)

	// 3. 역할 기반으로 인증서 설정 결정 (요구사항의 핵심)
	certConfig := s.analyzeRolesAndGetCertConfig(userRoles)
	log.Printf("역할 분석 결과 -> AccessLevel: %s, TTL: %v", certConfig.AccessLevel, certConfig.TTL)

	// 4. 인증서 발급에 필요한 키 페어 생성
	sshPublicKey, _, err := generateSSHKeyPair() // sshPrivateKey는 사용되지 않으므로 무시
	if err != nil {
		return nil, nil, fmt.Errorf("SSH 키 페어 생성 실패: %w", err)
	}
	tlsPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("TLS 키 페어 생성 실패: %w", err)
	}
	tlsPublicKeyDER, _ := x509.MarshalPKIXPublicKey(&tlsPrivateKey.PublicKey)

	// 5. 단기 인증서 요청 생성
	certsReq := proto.UserCertsRequest{
		SSHPublicKey:   sshPublicKey,
		TLSPublicKey:   tlsPublicKeyDER,
		Username:       username,
		Expires:        time.Now().Add(certConfig.TTL),
		RouteToCluster: s.getClusterName(ctx),
		RoleRequests:   userRoles, // 사용자의 모든 역할을 그대로 요청
		Usage:          proto.UserCertsRequest_All,
		// 허용된 로그인 목록을 명시적으로 설정

	}

	// 6. 단기 인증서 생성 요청
	certs, err := s.Client.GenerateUserCerts(ctx, certsReq)
	if err != nil {
		return nil, nil, fmt.Errorf("사용자 '%s'의 단기 인증서 생성 실패: %w", username, err)
	}

	// 7. 받은 인증서로 새로운 클라이언트 생성
	impersonatedClient, err := createClientFromCerts(ctx, s.Cfg.TeleportAuthAddr, certs, tlsPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("인증서를 사용한 클라이언트 생성 실패: %w", err)
	}

	log.Printf("사용자 '%s'를 위한 동적 클라이언트 생성 성공 (역할: %v, 레벨: %s, TTL: %v)",
		username, userRoles, certConfig.AccessLevel, certConfig.TTL)

	return impersonatedClient, certConfig, nil
}

// analyzeRolesAndGetCertConfig는 역할 목록을 분석하여 인증서 설정을 결정합니다.
// "A(admin)로 요청하면 admin 권한, B(user)로 요청하면 일반 user 권한" 요구사항을 처리하는 핵심 함수입니다.
func (s *Service) analyzeRolesAndGetCertConfig(roleNames []string) *CertificateConfig {
	// 기본값: 가장 낮은 권한
	config := &CertificateConfig{
		TTL:           5 * time.Minute, // 일반 사용자는 5분
		AccessLevel:   "user",
		AllowedLogins: []string{"root", "ubuntu"}, // 기본적으로 허용할 로그인 계정
	}

	// 역할 이름에 'admin'이 포함되어 있으면 높은 권한 부여
	for _, roleName := range roleNames {
		if strings.Contains(strings.ToLower(roleName), "admin") {
			config.TTL = 60 * time.Minute // 관리자는 1시간
			config.AccessLevel = "admin"
			config.AllowedLogins = append(config.AllowedLogins, "administrator") // admin 전용 로그인 추가
			log.Printf("'%s' 역할 감지: 관리자(admin) 권한으로 설정합니다.", roleName)
			return config // admin 권한이 발견되면 즉시 반환
		}
	}

	log.Println("관리자 역할이 없습니다. 일반 사용자(user) 권한으로 설정합니다.")
	return config
}

// --- 유틸리티 함수 ---

func createClientFromCerts(ctx context.Context, authAddr string, certs *proto.Certs, tlsPrivateKey *rsa.PrivateKey) (*client.Client, error) {
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(tlsPrivateKey),
	})

	tlsCert, err := tls.X509KeyPair(certs.TLS, privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("TLS 키페어 파싱 실패: %w", err)
	}

	// 1. tls.Certificate로부터 tls.Config를 생성합니다.
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}

	// 2. tls.Config를 사용하여 Credentials 객체를 생성합니다.
	creds := client.LoadTLS(tlsConfig)

	// 3. 생성된 Credentials로 새로운 클라이언트를 초기화합니다.
	impersonatedClient, err := client.New(ctx, client.Config{
		Addrs:       []string{authAddr},

		Credentials: []client.Credentials{creds},
	})
	if err != nil {
		return nil, fmt.Errorf("인증서로 새 클라이언트 생성 실패: %w", err)
	}
	return impersonatedClient, nil
}

func (s *Service) refreshClient() error {
	// ... (기존 로직과 동일, t를 s로 변경) ...
	creds := client.LoadIdentityFile(s.Cfg.TbotIdentityFile)
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


func generateSSHKeyPair() ([]byte, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return ssh.MarshalAuthorizedKey(publicKey), privateKey, nil
}

func (s *Service) getClusterName(ctx context.Context) string {
	pingResp, err := s.Client.Ping(ctx)
	if err != nil {
		return ""
	}
	return pingResp.ClusterName
}
