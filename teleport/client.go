package teleport

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"teleport-backend/config"
	"time"

	"github.com/gravitational/teleport/api/client"
)

const AdminIdentityFile = "./identity"

// Service는 Teleport 클라이언트와 관련된 모든 작업을 처리합니다.
type Service struct {
	Client      *client.Client
	Cfg         *config.Config
	ClusterName string
}

func NewService(cfg *config.Config, username string) (*client.Client, error) {
	//tctl로 identityFile 받기 중요한건 (사용자 이름)identity 이름
	cmd := exec.Command("tctl", "auth", "sign", "--user="+username, "--out="+AdminIdentityFile+username, "--auth-server=localhost:3025", "--overwrite", "--ttl=10s")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("tctl auth sign 실행 실패: %w, 출력: %s", err, string(output))
	}

	creds := client.LoadIdentityFile(AdminIdentityFile + username)
	mainClient, err := client.New(context.Background(), client.Config{
		Addrs:       []string{cfg.TeleportAuthAddr},
		Credentials: []client.Credentials{creds},
	})
	if err != nil {
		return nil, fmt.Errorf("%sTeleport API 클라이언트 생성 실패: %w", username, err)
	}
	// 연결 상태 확인
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ping, err := mainClient.Ping(ctx)
	if err != nil {
		mainClient.Close()
		return nil, fmt.Errorf("Teleport 클러스터(%s) 연결 실패: %w", cfg.TeleportAuthAddr, err)
	}
	log.Printf("%s Teleport 클러스터(%s)에 성공적으로 연결되었습니다.", username, ping.ClusterName)
	return mainClient, nil
}
