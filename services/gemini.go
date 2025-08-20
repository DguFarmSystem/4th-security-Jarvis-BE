// services/gemini.go
package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"teleport-backend/config"

	"cloud.google.com/go/vertexai/genai"
)

// Gemini API 응답을 위한 구조체
type Analysis struct {
	IsAnomaly bool   `json:"is_anomaly"`
	Reason    string `json:"reason"`
	Summary   string `json:"summary"`
}

type GeminiService struct {
	client *genai.Client
	model  string
}

type Analyzer interface {
	AnalyzeTranscript(ctx context.Context, transcript string) (*Analysis, error)
}

func NewGeminiService(ctx context.Context, cfg *config.Config) (*GeminiService, error) {
	client, err := genai.NewClient(ctx, cfg.GCPProjectID, cfg.GCPLocation)
	if err != nil {
		return nil, fmt.Errorf("Gemini 클라이언트 생성 실패: %w", err)
	}

	log.Println("Gemini 서비스가 성공적으로 초기화되었습니다.")
	return &GeminiService{client: client, model: cfg.GeminiModel}, nil
}

// 세션 내용을 받아 Gemini API로 분석 요청
func (s *GeminiService) AnalyzeTranscript(ctx context.Context, transcript string) (*Analysis, error) {
	//log.Printf("[DEBUG] AnalyzeTranscript 시작. 수신된 Transcript 길이: %d", len(transcript))
	if len(transcript) == 0 {
		log.Println("[WARN] Transcript 내용이 비어있어 분석을 건너뜁니다.")
		return &Analysis{Summary: "입력된 명령어가 없습니다."}, nil // 비어있는 경우 에러 대신 기본값 반환
	}
	//log.Printf("[DEBUG] Gemini 사용 모델: %s", s.model)
	model := s.client.GenerativeModel(s.model)

	finalPrompt := buildPrompt(transcript)

	// log.Printf("[DEBUG] 생성된 최종 프롬프트 (최대 200자): %.20s...", finalPrompt)
	prompt := genai.Text(finalPrompt)

	cs := model.StartChat()

	log.Println("[DEBUG] Gemini API로 GenerateContent 요청을 전송합니다...")
	resp, err := cs.SendMessage(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("Gemini 콘텐츠 생성 실패: %w", err)
	}

	// 6. 응답 파싱 및 최종 결과 로깅
	analysis, err := parseGeminiResponse(resp)
	if err != nil {
		log.Printf("[ERROR] Gemini 응답 파싱 중 에러 발생: %v", err)
		return nil, err // 파싱 에러는 그대로 반환
	}

	// %+v 포맷으로 구조체의 필드와 값을 함께 출력
	log.Printf("[DEBUG] 분석 완료. 최종 결과: %+v", analysis)
	return analysis, nil
}

func buildPrompt(transcript string) string {
	// 보안 전문가 역할 부여 및 명확한 지시를 포함한 프롬프트
	return fmt.Sprintf(`
You are a senior cybersecurity expert specializing in analyzing shell session transcripts for anomalous and potentially malicious behavior. Your task is to analyze the provided session transcript and determine if it contains any security risks.

Analyze the following shell command transcript. Based on your analysis, provide a response in a raw JSON format without any markdown formatting.

The JSON object must contain the following fields:
- "is_anomaly": A boolean value (true or false) indicating if you detected any anomalous or suspicious activity.
- "summary": A brief one-sentence summary of the user's activities during the session.
- "reason": A detailed explanation of your conclusion. If "is_anomaly" is true, describe the specific commands or patterns that are suspicious and why. If it's false, explain why the activities are considered normal.

Transcript:
---
%s
---
`, transcript)
}

func parseGeminiResponse(resp *genai.GenerateContentResponse) (*Analysis, error) {
	var analysis Analysis
	if len(resp.Candidates) > 0 && len(resp.Candidates[0].Content.Parts) > 0 {
		// 응답에서 JSON 문자열만 깔끔하게 추출
		rawJSON := string(resp.Candidates[0].Content.Parts[0].(genai.Text))
		rawJSON = strings.TrimSpace(rawJSON)
		if strings.HasPrefix(rawJSON, "```json") {
			rawJSON = strings.TrimPrefix(rawJSON, "```json")
			rawJSON = strings.TrimSuffix(rawJSON, "```")
		}
		rawJSON = strings.TrimSpace(rawJSON)
		sanitizedJSON := strings.ReplaceAll(rawJSON, "\b", "")
		if err := json.Unmarshal([]byte(sanitizedJSON), &analysis); err != nil {
			log.Printf("Gemini 응답 JSON 파싱 실패: %v, 원본 응답: %s", err, rawJSON)
			return nil, fmt.Errorf("Gemini 응답 JSON 파싱 실패: %w", err)
		}
		return &analysis, nil
	}
	return nil, fmt.Errorf("Gemini로부터 받은 응답이 비어있습니다")
}
