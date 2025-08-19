package teleport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"strings"
	"teleport-backend/config"
	"time"

	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
)

// --- Teleport 서비스 ---
const machineIDIdentityFile = "/opt/jarvis-service-identity" // tbot이 생성한 ID 파일의 일반적인 경로
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
	log.Println("tbot ID 파일을 사용하여 Teleport 클라이언트 생성 시도...")
	creds := client.LoadIdentityFile(machineIDIdentityFile)
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

// GetImpersonatedClient 함수는 특정 사용자를 위해 지정된 단기 인증서를 발급하고, 그 인증서를 사용하는 새로운 Teleport 클라이언트를 반환합니다.
func (s *Service) GetImpersonatedClient(ctx context.Context, username string) (*client.Client, string, error) {

	log.Printf("[DEBUG] GetImpersonatedClient 호출됨 (사용자: %s)", username)
	// 1. 단기 인증서를 위한 새로운 키 쌍을 메모리에서 생성합니다.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Printf("[ERROR] 단계 1: 임시 키 쌍 생성 실패: %v", err)
		return nil, "", fmt.Errorf("임시 키 쌍 생성 실패: %w", err)
	}
	log.Println("[DEBUG] 단계 1: 임시 키 쌍 생성 성공")
	// 공개키를 OpenSSH authorized_keys 형식으로 변환합니다.
	sshPubKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		log.Printf("[ERROR] 단계 1.1: SSH 공개키 변환 실패: %v", err)
		return nil, "", fmt.Errorf("SSH 공개키 생성 실패: %w", err)
	}
	pubKeyBytes := ssh.MarshalAuthorizedKey(sshPubKey)
	log.Println("[DEBUG] 단계 1.1: SSH 공개키 변환 성공")

	// TLS 공개키를 위한 PEM 인코딩
	tlsPubKeyDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, "", fmt.Errorf("TLS 공개키 DER 인코딩 실패: %w", err)
	}
	tlsPubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: tlsPubKeyDER,
	})
	const clusterName = "mycluster.local"
	log.Printf("[DEBUG] 단계 1.2: 고정된 클러스터 이름 사용: %s", clusterName)
	// 2. 장기 인증서를 가진 클라이언트를 사용해 단기 인증서 발급을 요청합니다.

	log.Println("[DEBUG] 단계 2: Teleport Auth 서버에 사용자 인증서 발급 요청 시작...")
	certs, err := s.Client.GenerateUserCerts(ctx, proto.UserCertsRequest{
		SSHPublicKey:   pubKeyBytes,
		TLSPublicKey:   tlsPubKeyPEM,
		Username:       username,
		Expires:        time.Now().UTC().Add(5 * time.Minute),
		RouteToCluster: clusterName,
	})
	if err != nil {
		log.Printf("[ERROR] 단계 2: 사용자 인증서 발급 실패: %v", err)
		return nil, "", fmt.Errorf("%s 사용자의 인증서 발급 실패: %w", username, err)
	}
	log.Printf("[DEBUG] 단계 2.1: SSH 인증서(길이: %d), TLS 인증서(길이: %d) 유효성 확인", len(certs.SSH), len(certs.TLS))
	log.Printf("[DEBUG] SSH Cert 내용:\n%s", string(certs.SSH))
	log.Printf("[DEBUG] TLS Cert 내용:\n%s", string(certs.TLS))

	log.Println("[DEBUG] 단계 2: 사용자 인증서 발급 성공")
	// 3. 발급받은 단기 인증서와 생성한 개인키로 새로운 자격증명을 만듭니다.
	creds := &inMemoryCreds{
		privateKey: priv,
		tlsCert:    certs.TLS,
		sshCert:    certs.SSH,
	}
	log.Println("[DEBUG] 단계 3: 메모리 내 자격증명(creds) 생성 성공")
	log.Println("[DEBUG] 단계 4: Impersonated 클라이언트 생성 시작...")
	impersonatedClient, err := client.New(ctx, client.Config{
		Addrs:       []string{s.Cfg.TeleportAuthAddr},
		Credentials: []client.Credentials{creds},
	})
	if err != nil {
		log.Printf("[ERROR] 단계 4: Impersonated 클라이언트 생성 실패: %v", err)
		return nil, "", fmt.Errorf("%s 사용자를 위한 impersonated 클라이언트 생성 실패: %w", username, err)
	}
	log.Println("[DEBUG] 단계 4: Impersonated 클라이언트 생성 성공")
	return impersonatedClient, "", nil
}

// inMemoryCreds is a custom struct that holds credentials in memory
// and implements the client.Credentials interface. This avoids issues with
// library version mismatches.
type inMemoryCreds struct {
	privateKey ed25519.PrivateKey
	tlsCert    []byte
	sshCert    []byte
}

// TLSConfig creates a valid *tls.Config from the in-memory key and cert.
func (c *inMemoryCreds) TLSConfig() (*tls.Config, error) {
	log.Println("[DEBUG] inMemoryCreds: TLSConfig() 호출됨")

	// *** 해결책: "날것(raw)" 개인키를 PEM 형식으로 인코딩합니다. ***
	privDER, err := x509.MarshalPKCS8PrivateKey(c.privateKey)
	if err != nil {
		log.Printf("[ERROR] inMemoryCreds: 개인키를 DER 형식으로 변환 실패: %v", err)
		return nil, trace.Wrap(err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privDER,
	})

	// PEM으로 인코딩된 개인키(privPEM)를 사용합니다.
	cert, err := tls.X509KeyPair(c.tlsCert, privPEM)
	if err != nil {
		log.Printf("[ERROR] inMemoryCreds: tls.X509KeyPair 생성 실패: %v", err)
		return nil, trace.Wrap(err)
	}
	log.Println("[DEBUG] inMemoryCreds: TLSConfig() 성공")
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, nil
}

// SSHClientConfig creates an SSH client config.
func (c *inMemoryCreds) SSHClientConfig() (*ssh.ClientConfig, error) {
	log.Println("[DEBUG] inMemoryCreds: SSHClientConfig() 호출됨")
	signer, err := ssh.NewSignerFromKey(c.privateKey)
	if err != nil {
		log.Printf("[ERROR] inMemoryCreds: ssh.NewSignerFromKey 생성 실패: %v", err)
		return nil, trace.Wrap(err)
	}
	// *** 최종 해결책: ssh.ParseCertificate 대신 하위 호환성이 높은 ssh.ParsePublicKey를 사용합니다. ***
	pubKey, err := ssh.ParsePublicKey(c.sshCert)
	if err != nil {
		log.Printf("[ERROR] inMemoryCreds: SSH 인증서 파싱 실패: %v", err)
		return nil, trace.Wrap(err, "failed to parse ssh public key from certificate bytes")
	}
	// 파싱된 키가 실제 ssh.Certificate 타입인지 확인(타입 단언)합니다.
	parsedCert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		log.Println("[ERROR] inMemoryCreds: 파싱된 공개키가 SSH 인증서 타입이 아님")
		return nil, trace.BadParameter("parsed public key is not a valid ssh certificate")
	}
	// 파싱된 인증서 객체를 사용하여 CertSigner를 생성합니다.
	certSigner, err := ssh.NewCertSigner(parsedCert, signer)
	if err != nil {
		log.Printf("[ERROR] inMemoryCreds: ssh.NewCertSigner 생성 실패: %v", err)
		return nil, trace.Wrap(err)
	}
	log.Println("[DEBUG] inMemoryCreds: SSHClientConfig() 성공")
	return &ssh.ClientConfig{
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // For production, use a proper host key callback
	}, nil
}
func (c *inMemoryCreds) Expiry() (time.Time, bool) {
	return time.Time{}, false
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
