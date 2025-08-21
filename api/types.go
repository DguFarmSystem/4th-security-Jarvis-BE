package api

import (
	"teleport-backend/services"
)

// UpdateUserRequest는 사용자 정보 업데이트 시 요청 본문을 위한 구조체입니다.
type UpdateUserRequest struct {
	Roles []string `json:"roles"`
}

// GenerateTokenRequest는 노드 조인 토큰 생성 시 요청 본문을 위한 구조체입니다.
type GenerateTokenRequest struct {
	TTL      string   `json:"ttl"`
	Roles    []string `json:"roles"`
	Nodename string   `json:"nodename"`
}

// EnrichedLog는 AI 분석 결과를 포함하여 Logstash로 보낼 최종 로그 구조체입니다.
type EnrichedLog struct {
	SessionID    string             `json:"session_id"`
	User         string             `json:"teleport_user"`
	ServerID     string             `json:"server_id"`
	ServerAddr   string             `json:"server_addr"`
	SessionStart string             `json:"session_start"`
	SessionEnd   string             `json:"session_end"`
	Transcript   string             `json:"session_transcript"`
	Analysis     *services.Analysis `json:"ai_analysis"`
}
