# Dockerfile

# --- 1단계: 빌드 환경 ---
# Go 공식 이미지를 빌더로 사용하여 Go 코드를 컴파일합니다.
FROM golang:1.24-alpine AS builder

WORKDIR /app

# go.mod와 go.sum을 먼저 복사하여 종속성을 캐시합니다.
COPY go.mod go.sum ./
# go.mod 파일을 기반으로 모든 종속성을 다운로드합니다.
RUN go mod download

# 나머지 소스 코드를 복사합니다.
COPY . .

# CGO_ENABLED=0: C 라이브러리 없이 정적으로 링크된 바이너리를 생성합니다.
# -ldflags="-s -w": 디버깅 정보를 제거하여 바이너리 크기를 줄입니다.
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags="-s -w" -o /app/server .

# --- 2단계: 최종 실행 환경 ---
FROM ubuntu:latest

# [추가] Teleport 버전을 변수로 정의하여 관리 용이성을 높입니다.
# 클러스터 버전에 맞춰 이 값을 수정할 수 있습니다.
ARG TELEPORT_VERSION=17.5.4

# [추가] tsh 설치에 필요한 도구(curl, tar)와 HTTPS 통신을 위한 ca-certificates를 설치합니다.
# [수정] apt-get을 사용하여 필수 도구를 설치합니다.
#         - apt-get update로 패키지 목록을 먼저 갱신해야 합니다.
#         - --no-install-recommends로 불필요한 패키지 설치를 막아 용량을 줄입니다.
RUN apt-get update && apt-get install -y \
    curl \
    tar \
    sudo \
    ca-certificates \
    --no-install-recommends && \
    # 설치 후 캐시를 삭제하여 최종 이미지 용량을 최적화합니다.
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt

RUN curl -o teleport.tar.gz "https://cdn.teleport.dev/teleport-v${TELEPORT_VERSION}-linux-amd64-bin.tar.gz" && \
    tar -xzf teleport.tar.gz && \
    # 필요한 바이너리들만 실행 경로에 직접 복사합니다.
    cp teleport/tsh teleport/tctl teleport/tbot /usr/local/bin/ && \
    # 설치 후 남은 파일들을 깨끗하게 정리합니다.
    rm -rf teleport teleport.tar.gz

WORKDIR /app

# 1단계(빌더)에서 컴파일된 Go 바이너리만 복사합니다.
COPY --from=builder /app/server /app/server

# [추가] 컨테이너 시작 시 실행될 스크립트를 복사하고 실행 권한을 부여합니다.
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080

# [수정] 컨테이너 시작 시 entrypoint.sh를 실행하도록 변경합니다.
ENTRYPOINT ["/entrypoint.sh"]
