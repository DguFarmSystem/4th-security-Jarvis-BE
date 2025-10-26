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
