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
	"time"

	"teleport-backend/config"

	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
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
func (s *Service) GetDynamicImpersonatedClient(ctx context.Context, username string) (*client.Client, error) {
	log.Printf("[DEBUG] GetDynamicImpersonatedClient 시작: 사용자 '%s'에 대한 클라이언트 생성 프로세스 개시", username)

	// 1. 사용자 정보를 동적으로 조회
	user, err := s.Client.GetUser(ctx, username, false)
	if err != nil {
		if trace.IsNotFound(err) {
			log.Printf("[ERROR] 사용자 '%s'를 찾을 수 없습니다: %v", username, err)
			return nil, fmt.Errorf("사용자 '%s'를 찾을 수 없습니다", username)
		}
		log.Printf("[ERROR] 사용자 정보 조회 실패: %v", err)
		return nil, fmt.Errorf("사용자 정보 조회 실패: %w", err)
	}
	log.Printf("[DEBUG] 1/7: 사용자 정보 조회 성공.")

	// 2. 사용자의 현재 역할 가져오기
	userRoles := user.GetRoles()
	if len(userRoles) == 0 {
		log.Printf("[ERROR] 사용자 '%s'에게 할당된 역할이 없습니다.", username)
		return nil, fmt.Errorf("사용자 '%s'에게 할당된 역할이 없습니다", username)
	}
	log.Printf("[DEBUG] 2/7: 사용자 '%s'의 역할 확인: %v", username, userRoles)

	// 3. 역할 기반으로 인증서 설정 결정 (요구사항의 핵심)
	certificateTTL := s.getTTLForRoles(userRoles)
	log.Printf("[DEBUG] 3/7: 결정된 TTL: %v", certificateTTL)

	// 4. 인증서 발급에 필요한 키 페어 생성
	sshPublicKey, _, err := generateSSHKeyPair() // sshPrivateKey는 사용되지 않으므로 무시
	if err != nil {
		log.Printf("[ERROR] SSH 키 페어 생성 실패: %v", err)
		return nil, fmt.Errorf("SSH 키 페어 생성 실패: %w", err)
	}
	tlsPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("[ERROR] TLS 키 페어 생성 실패: %v", err)
		return nil, fmt.Errorf("TLS 키 페어 생성 실패: %w", err)
	}
	tlsPublicKeyDER, _ := x509.MarshalPKIXPublicKey(&tlsPrivateKey.PublicKey)
	log.Printf("[DEBUG] 4/7: 키 페어 생성 완료.")

	// 5. 단기 인증서 요청 생성
	certsReq := proto.UserCertsRequest{
		SSHPublicKey:   sshPublicKey,
		TLSPublicKey:   tlsPublicKeyDER,
		Username:       username,
		Expires:        time.Now().Add(certificateTTL),
		RouteToCluster: s.getClusterName(ctx),
		Usage:          proto.UserCertsRequest_All,
		// 허용된 로그인 목록을 명시적으로 설정

	}
	log.Printf("[DEBUG] 5/7: 인증서 요청 생성 완료: Username=%s, Expires=%s", certsReq.Username, certsReq.Expires.Format(time.RFC3339))

	// 6. 단기 인증서 생성 요청
	log.Printf("[DEBUG] 6/7: Teleport에 단기 인증서 생성을 요청합니다.")
	certs, err := s.Client.GenerateUserCerts(ctx, certsReq)
	if err != nil {
		log.Printf("[ERROR] 사용자 '%s'의 단기 인증서 생성 실패: %v", username, err)
		return nil, fmt.Errorf("사용자 '%s'의 단기 인증서 생성 실패: %w", username, err)
	}
	log.Printf("[DEBUG] 6/7: 단기 인증서 생성 성공.")

	// 7. 받은 인증서로 새로운 클라이언트 생성
	log.Printf("[DEBUG] 7/7: 발급받은 인증서로 새로운 Teleport 클라이언트를 생성합니다.")
	impersonatedClient, err := createClientFromCerts(ctx, s.Cfg.TeleportAuthAddr, certs, tlsPrivateKey)
	if err != nil {
		log.Printf("[ERROR] 인증서를 사용한 클라이언트 생성 실패: %v", err)
		return nil, fmt.Errorf("인증서를 사용한 클라이언트 생성 실패: %w", err)
	}

	log.Printf("[SUCCESS] 사용자 '%s'를 위한 동적 클라이언트 생성 성공 (역할: %v, TTL: %v)",
		username, userRoles, certificateTTL)

	return impersonatedClient, nil
}

// role을 읽어 sso 사용자에게 인증서 반환
func (s *Service) getTTLForRoles(roleNames []string) time.Duration {
	const adminRole = "basic-user"

	// 사용자가 역할이 있는지 확인합니다.
	for _, roleName := range roleNames {
		if roleName == adminRole {
			log.Printf("'%s' 역할이 감지되어 TTL을 1시간으로 설정합니다.", adminRole)
			return 60 * time.Minute // 관리자는 1시간
		}
	}

	log.Println("기본 TTL인 5분으로 설정합니다.")
	return 5 * time.Minute // 그 외 사용자는 5분
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
		Addrs: []string{authAddr},

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
