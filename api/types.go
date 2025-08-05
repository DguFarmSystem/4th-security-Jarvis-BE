package api

type UpdateUserRequest struct {
	Roles []string `json:"roles"`
}

type GenerateTokenRequest struct {
	TTL      string   `json:"ttl"`
	Roles    []string `json:"roles"`
	Nodename string   `json:"nodename"`
}
