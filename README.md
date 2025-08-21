# Jarvis Backend API

이 저장소는 Jarvis 프로젝트의 백엔드 API 서버입니다. Teleport 클러스터와 상호작용하여 사용자 인증, 역할 기반 접근 제어(RBAC), 보안 SSH 세션 중계, AI 기반 감사 로그 분석 등 핵심 기능을 처리합니다.


✨ 주요 기능 (Features)

Teleport API 연동: tbot ID를 사용한 서비스 계정 인증 및 사용자 가장(Impersonation)을 통해 Teleport 리소스를 프로그래밍 방식으로 관리합니다.

RESTful API: 사용자, 역할(Role), 노드(Node), 감사 로그 등 Teleport의 주요 리소스를 관리하기 위한 CRUD API 엔드포인트를 제공합니다.

WebSocket 기반 SSH 중계: 웹 클라이언트와 Teleport SSH 세션 간의 실시간 양방향 통신을 중계합니다.

GitHub SSO 인증: GitHub OAuth2를 사용하여 사용자를 인증하고, 특정 팀 멤버십을 확인하여 접근을 제어합니다.

AI 기반 세션 분석: SSH 세션 종료 시, 해당 세션의 스크립트를 추출하여 Google Gemini API로 전송하고 잠재적 위협을 분석합니다.



🛠️ 기술 스택 (Tech Stack)

언어: Go

웹 프레임워크: Gin

인증/인가: Teleport, GitHub OAuth2, JWT

인프라: Docker, Docker Compose

로깅/분석: ELK Stack, Google Gemini API