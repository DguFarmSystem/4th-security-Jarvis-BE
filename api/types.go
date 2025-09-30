package api

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

// SessionDataForAnalysis는 AI 분석을 위해 분석기 서비스로 보낼 세션 데이터 구조체입니다.
type SessionDataForAnalysis struct {
	SessionID    string `json:"SessionID"`
	User         string `json:"User"`
	ServerID     string `json:"ServerID"`
	ServerAddr   string `json:"ServerAddr"`
	SessionStart string `json:"SessionStart"`
	SessionEnd   string `json:"SessionEnd"`
	Transcript   string `json:"Transcript"`
}
