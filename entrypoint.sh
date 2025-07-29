#!/bin/bash
# entrypoint.sh
set -e

echo "[DEBUG] Final /etc/tbot.yaml content:"
cat /etc/tbot.yaml

envsubst < /etc/tbot.yaml.template > /etc/tbot.yaml

# 1. 환경 변수로 전달된 일회용 조인 토큰을 사용하여 tbot을 백그라운드로 실행합니다.
#    tbot은 인증서를 /opt/machine-id 디렉터리에 자동으로 생성하고 갱신합니다.
# tbot 실행: 환경변수 JOIN_TOKEN을 tbot.yaml 내에서 치환해서 사용하므로 -c 옵션만 사용
tbot start -c /etc/tbot.yaml &

# 2. tbot이 처음 인증서를 생성할 때까지 잠시 대기합니다 (안정성을 위해).
echo "Waiting 10 seconds for identity files to be generated..."
sleep 10

# 3. (선택적이지만 권장)
#    Go 애플리케이션이 sudo 없이 인증서 파일을 읽을 수 있도록 소유권을 변경합니다.
#    Dockerfile의 최종 이미지가 root 사용자로 실행되므로, 이 단계는 현재 필수는 아니지만
#    나중에 일반 사용자로 전환할 경우를 대비해 남겨두는 것이 좋습니다.
# chown -R your-go-app-user:your-go-app-user /opt/machine-id

# 4. 모든 준비가 끝나면 Go 웹 애플리케이션을 실행합니다.
echo "Starting Go application server..."
exec /app/server