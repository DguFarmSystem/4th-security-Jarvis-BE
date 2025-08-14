package api

import (
	"teleport-backend/services"
	"time"
)

type UpdateUserRequest struct {
	Roles []string `json:"roles"`
}

type GenerateTokenRequest struct {
	TTL      string   `json:"ttl"`
	Roles    []string `json:"roles"`
	Nodename string   `json:"nodename"`
}

type SessionInfo struct {
	ID              string    `json:"id"`
	TeleportUser    string    `json:"teleport_user"`
	Login           string    `json:"os_login"`
	TargetNode      string    `json:"target_node"`
	StartTime       time.Time `json:"start_time"`
	EndTime         time.Time `json:"end_time"`
	DurationSeconds float64   `json:"duration_seconds"`
}

type PaginatedSessionResponse struct {
	Sessions   []SessionInfo `json:"sessions"`
	NextCursor string        `json:"next_cursor,omitempty"`
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
