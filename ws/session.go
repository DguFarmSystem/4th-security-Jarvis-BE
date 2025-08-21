package ws

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"log"
	"net/http"
	"teleport-backend/teleport"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/gravitational/teleport/api/client/proto"
	"golang.org/x/crypto/ssh"
)

// upgrader는 일반 HTTP 연결을 양방향 통신이 가능한 WebSocket 연결로 전환(업그레이드)합니다.
var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

// HandleWebSocket은 웹소켓 연결을 처리하고 Teleport API 기반 SSH 세션을 중계합니다.
func HandleWebSocket(c *gin.Context) {
	githubUser := c.GetString("username")
	nodeHost := c.Query("node_host")
	loginUser := c.Query("login_user")
	if nodeHost == "" || loginUser == "" {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	// Teleport 서비스 생성
	svc, err := teleport.NewService(nil) // config.Config 넘겨야 함
	if err != nil {
		log.Printf("Teleport 서비스 초기화 실패: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	defer svc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 사용자 단기 인증서 발급 (API 방식)
	impersonatedClient, _, err := svc.GetImpersonatedClient(ctx, githubUser)
	if err != nil {
		log.Printf("임시 사용자 인증서 발급 실패: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	defer impersonatedClient.Close()

	// SSH 키/인증서 준비
	pub, priv, err := generateSSHKeyPair()
	if err != nil {
		log.Printf("SSH 키 쌍 생성 실패: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	certs, err := impersonatedClient.GenerateUserCerts(ctx, proto.UserCertsRequest{
		SSHPublicKey:   pub,
		Username:       githubUser,
		Expires:        time.Now().Add(5 * time.Minute).UTC(),
		RouteToCluster: "mycluster.local", // 실제 cluster name으로 변경
	})
	if err != nil {
		log.Printf("SSH 인증서 발급 실패: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// SSH signer 생성
	signer, err := sshSignerFromKeyAndCert(priv, certs.SSH)
	if err != nil {
		log.Printf("SSH signer 생성 실패: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	sshConfig := &ssh.ClientConfig{
		User:            githubUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: CA 검증으로 교체 가능
		Timeout:         10 * time.Second,
	}

	// 노드에 SSH 연결 (Teleport proxy 3022 또는 직접 노드 주소)
	// Teleport proxy 서비스는 기본적으로 3022 포트에서 SSH 연결을 프록시하므로, 노드의 22번 포트 대신 3022 포트에 연결합니다.
	target := fmt.Sprintf("%s:3022", nodeHost)
	conn, err := ssh.Dial("tcp", target, sshConfig)
	if err != nil {
		log.Printf("SSH 연결 실패 (%s): %v", target, err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		log.Printf("SSH 세션 생성 실패: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	defer session.Close()

	stdout, err := session.StdoutPipe()
	if err != nil {
		log.Printf("StdoutPipe 생성 실패: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		log.Printf("StdinPipe 생성 실패: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// PTY 할당 및 bash 실행
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		log.Printf("PTY 요청 실패: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	if err := session.Shell(); err != nil {
		log.Printf("bash 실행 실패: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// WebSocket 업그레이드
	feConn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("웹소켓 업그레이드 실패: %v", err)
		return
	}
	defer feConn.Close()

	log.Println("프론트엔드와 WebSocket 연결 성공. 데이터 중계를 시작합니다.")

	// SSH → WebSocket
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := stdout.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("SSH stdout 읽기 실패: %v", err)
				}
				return
			}
			if err := feConn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
				log.Printf("웹소켓으로 데이터 쓰기 실패: %v", err)
				return
			}
		}
	}()

	// WebSocket → SSH
	for {
		_, msg, err := feConn.ReadMessage()
		if err != nil {
			log.Printf("웹소켓에서 데이터 읽기 실패: %v", err)
			return
		}
		if _, err := stdin.Write(msg); err != nil {
			log.Printf("SSH stdin으로 데이터 쓰기 실패: %v", err)
			return
		}
	}
}

// generateSSHKeyPair는 Ed25519 SSH 키 쌍을 생성하고,
// 공개키는 SSH authorized_keys 형식으로, 개인키는 PEM 인코딩된 PKCS8 형식으로 반환합니다.
func generateSSHKeyPair() ([]byte, ed25519.PrivateKey, error) {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}

	// 공개키 SSH authorized_keys 형식으로 변환
	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return nil, nil, err
	}
	pubBytes := ssh.MarshalAuthorizedKey(sshPubKey)

	return pubBytes, privKey, nil
}

// sshSignerFromKeyAndCert는 ed25519 개인키와 SSH 인증서 바이트를 받아 signer를 만듭니다.
func sshSignerFromKeyAndCert(priv ed25519.PrivateKey, cert []byte) (ssh.Signer, error) {
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	certPubKey, err := ssh.ParsePublicKey(cert)
	if err != nil {
		return nil, err
	}
	return ssh.NewCertSigner(certPubKey.(*ssh.Certificate), signer)
}
