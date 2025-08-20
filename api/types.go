package api

import (
	"teleport-backend/services"
)

type UpdateUserRequest struct {
	Roles []string `json:"roles"`
}

type GenerateTokenRequest struct {
	TTL      string   `json:"ttl"`
	Roles    []string `json:"roles"`
	Nodename string   `json:"nodename"`
}

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
