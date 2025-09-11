# Jarvis Backend API

이 저장소는 Jarvis 프로젝트의 백엔드 API 서버입니다. Teleport 클러스터와 상호작용하여 사용자 인증, 역할 기반 접근 제어(RBAC), 보안 SSH 세션 중계, AI 기반 감사 로그 분석 등 핵심 기능을 처리합니다.

## ✨ 주요 기능 (Features)

* **Teleport API 연동**: `tbot` ID를 사용한 서비스 계정 인증 및 사용자 가장(Impersonation)을 통해 Teleport 리소스를 프로그래밍 방식으로 관리합니다.
* **RESTful API**: 사용자, 역할(Role), 노드(Node), 감사 로그 등 Teleport의 주요 리소스를 관리하기 위한 CRUD API 엔드포인트를 제공합니다.
* **WebSocket 기반 SSH 중계**: 웹 클라이언트와 Teleport SSH 세션 간의 실시간 양방향 통신을 중계합니다.
* **GitHub SSO 인증**: GitHub OAuth2를 사용하여 사용자를 인증하고, 특정 팀 멤버십을 확인하여 접근을 제어합니다.
* **AI 기반 세션 분석**: SSH 세션 종료 시, 해당 세션의 스크립트를 추출하여 Google Gemini API로 전송하고 잠재적 위협을 분석합니다.

## 🚀 설치 가이드

<details>
<summary><strong>⚙️ 환경변수 설정 가이드 (클릭해서 열기)</strong></summary>

---

프로젝트를 실행하기 위해 필요한 환경변수 목록입니다. 

### 📋 전체 환경변수 목록

| 변수명 | 설명 | 예시 |
| :--- | :--- | :--- |
| `CLIENT_ID` | GitHub OAuth App에서 발급받은 클라이언트 ID입니다. | `iv1.1234567890abcdef` |
| `CLIENT_SECRET` | GitHub OAuth App에서 발급받은 클라이언트 시크릿입니다. | `gho_a1b2c3d4e5f6...` |
| `DOCKERHUB_USERNAME` | Docker Hub 사용자 이름입니다. | `my-docker-id` |
| `DOCKERHUB_TOKEN` | Docker Hub의 `Account Settings > Security`에서 생성한 Access Token입니다. | `dckr_pat_abcdefg...` |
| `JWT_SECRET_KEY` | JWT 토큰 암호화를 위한 무작위 비밀 키입니다. (`openssl rand -base64 32` 명령어로 생성) | `AbcDef/123+gHiJkL...` |
| `GCP_SA_KEY` | GCP `IAM > 서비스 계정`에서 생성한 JSON 형식의 서비스 계정 키입니다. | `{ "type": "service_account", ... }` |
| `GEMINI_MODEL` | 사용할 Google Gemini AI 모델의 이름입니다. | `gemini-1.5-pro-latest` |
| `ORG_NAME` | 연동할 GitHub 조직(Organization)의 이름입니다. | `my-github-org` |
| `TEAM_SLUG` | 조직 내 특정 팀의 슬러그(URL용 이름)입니다. | `my-awesome-team` |
| `CALLBACK_URL` | GitHub OAuth 인증 후 리디렉션될 주소입니다. | `https://mydomain.com:8080/callback` |
| `VITE_API_URL` | 사용자의 웹 주소입니다. | `mydomain.com` |
| `GCP_PROJECT_ID` | 사용 중인 GCP 프로젝트의 고유 ID입니다. | `my-gcp-project-12345` |
| `GCP_HOST` | 배포된 GCP VM 인스턴스의 외부 IP 주소입니다. | `34.56.78.90` |
| `GCP_LOCATION` | GCP 리소스가 위치한 리전입니다. | `asia-northeast3` |
| `GCP_USERNAME` | GCP VM 인스턴스 접속용 사용자 이름입니다. | `ubuntu` |
| `GCP_SSH_KEY` | GCP VM 인스턴스 접속을 위한 비공개 SSH 키입니다. | `-----BEGIN OPENSSH PRIVATE KEY-----...` |
| `TELEPORT_PROXY_ADDR` | Teleport 프록시 서비스 접속 주소입니다. | `https://mydomain.com:3080` |
| `TELEPORT_AUTH_ADDR` | Teleport 인증 서버 접속 주소입니다. | `https://mydomain.com:3025` |

### 주요 환경변수 상세 설정 가이드

일반적으로 설정하기 헷갈리는 주요 환경변수에 대한 상세 가이드입니다.

#### **1. GitHub OAuth 인증 (`CLIENT_ID`, `CLIENT_SECRET`)**
1. GitHub **Settings > Developer settings > OAuth Apps** 페이지로 이동합니다.
2. **New OAuth App** 버튼을 클릭하여 새 앱을 등록합니다.
3. 생성 후 발급된 **CLIENT_ID**와 **CLIENT_SECRET**을 환경변수에 등록합니다.

#### **2. Docker Hub 접근 토큰 (`DOCKERHUB_TOKEN`)**
GitHub Actions가 빌드된 이미지를 Docker Hub에 푸시(push)하기 위해 필요합니다.
1. Docker Hub에 로그인 후, 우측 상단 프로필 > **Account Settings**로 이동합니다.
2. **Security** 탭 > **New Access Token** 버튼을 클릭합니다.
3. 생성된 토큰을 복사하여 환경변수에 등록합니다.

#### **3. GCP 서비스 계정 키 (`GCP_SA_KEY`)**
1. **인스턴스 생성**: Compute Engine에서 `Ubuntu 24.04`, `e2-standard-8` (vCPU 8, 32GB RAM) 이상의 사양으로 VM 인스턴스를 생성합니다.
2. **방화벽 설정**: 생성된 인스턴스의 네트워크 방화벽 규칙에서 `80`,`5601`, `8080`, `3080` 포트에 대한 TCP 인그레스(Ingress)를 허용합니다.
3. **서비스 계정 생성 및 권한 부여**: **IAM & Admin > Service Accounts**에서 새 서비스 계정을 생성하고, **Vertex AI User** 역할을 부여합니다.
4. **JSON 키 생성**: 생성된 서비스 계정의 **Keys** 탭 > **Add Key > Create new key**를 선택하고, **JSON** 타입을 선택하여 키를 생성하고 다운로드합니다.
5. 다운로드한 JSON 파일의 **전체 텍스트**를 복사하여 환경변수에 등록합니다.

---
</details>

## 🛠️ 기술 스택 (Tech Stack)

* **언어**: Go
* **웹 프레임워크**: Gin
* **인증/인가**: Teleport, GitHub OAuth2, JWT
* **인프라**: Docker, Docker Compose
* **로깅/분석**: ELK Stack, Google Gemini API
