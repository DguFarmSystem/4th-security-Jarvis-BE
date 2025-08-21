# Dockerfile

# 빌드 환경
# Go 공식 이미지를 빌더로 사용하여 Go 코드를 컴파일합니다.
FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

# CGO_ENABLED=0: C 라이브러리 없이 정적으로 링크된 바이너리를 생성합니다.
# -ldflags="-s -w": 디버깅 정보를 제거하여 바이너리 크기를 줄입니다.
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags="-s -w" -o /app/server .

# 실행 환경
FROM ubuntu:latest

ARG TELEPORT_VERSION=17.5.4

RUN apt-get update && apt-get install -y \
    curl \
    tar \
    sudo \
    ca-certificates \
    gettext-base \
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

# 컴파일된 Go 바이너리만 복사합니다.
COPY --from=builder /app/server /app/server
# tbot.yaml.template 파일을 이미지에 포함 
COPY tbot.yaml.template /etc/tbot.yaml.template

# 컨테이너 시작 시 실행될 스크립트를 복사하고 실행 권한을 부여합니다.
COPY entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && \
    chmod +x /entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
