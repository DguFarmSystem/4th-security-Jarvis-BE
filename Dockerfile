# Dockerfile

# --- 1단계: 빌드 환경 ---
# Go 공식 이미지를 빌더로 사용하여 Go 코드를 컴파일합니다.
FROM golang:1.24-alpine AS builder

WORKDIR /app

# go.mod와 go.sum을 먼저 복사하여 종속성을 캐시합니다.
COPY go.mod go.sum ./
RUN go mod download

# 나머지 소스 코드를 복사합니다.
COPY . .

# CGO_ENABLED=0: C 라이브러리 없이 정적으로 링크된 바이너리를 생성합니다.
# -ldflags="-s -w": 디버깅 정보를 제거하여 바이너리 크기를 줄입니다.
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags="-s -w" -o /app/server .

# --- 2단계: 최종 실행 환경 ---
# 프로덕션 환경을 위해 경량화된 alpine 이미지를 사용합니다.
FROM alpine:3.18

# ca-certificates는 HTTPS 통신 등에 필요할 수 있습니다.
RUN apk --no-cache add ca-certificates

# 빌드 환경에서 컴파일된 실행 파일을 복사합니다.
COPY --from=builder /app/server /usr/local/bin/server

# 실행 파일에 실행 권한을 부여합니다.
RUN chmod +x /usr/local/bin/server

# 중요: auth.pem 파일은 이미지에 포함시키지 않습니다.

# 컨테이너가 시작될 때 API 서버를 실행합니다.
ENTRYPOINT ["/usr/local/bin/server"]
