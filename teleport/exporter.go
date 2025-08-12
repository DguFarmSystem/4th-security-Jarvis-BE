// teleport/exporter.go
package teleport

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os/exec"
	"time"

	"teleport-backend/config"
	"teleport-backend/services"

	"github.com/hpcloud/tail"
	"github.com/tidwall/gjson"
)

// Elasticsearch에 저장될 최종 로그 구조체
type EnrichedLog struct {
	SessionID    string               `json:"session_id"`
	User         string               `json:"teleport_user"`
	ServerID     string               `json:"server_id"`
	ServerAddr   string               `json:"server_addr"`
	SessionStart string               `json:"session_start"`
	SessionEnd   string               `json:"session_end"`
	Transcript   string               `json:"session_transcript"`
	Analysis     *services.AIAnalysis `json:"ai_analysis"`
}

type LogExporter struct {
	cfg           *config.Config
	geminiService *services.GeminiService
	httpClient    *http.Client
}

func NewLogExporter(cfg *config.Config, gs *services.GeminiService) *LogExporter {
	return &LogExporter{
		cfg:           cfg,
		geminiService: gs,
		httpClient:    &http.Client{Timeout: 30 * time.Second},
	}
}

// main.go에서 고루틴으로 실행될 함수
func (e *LogExporter) Start(ctx context.Context) {
	log.Println("Teleport 로그 익스포터를 시작합니다...")
	t, err := tail.TailFile(e.cfg.AuditLogPath, tail.Config{Follow: true, ReOpen: true, Location: &tail.SeekInfo{Offset: 0, Whence: 2}})
	if err != nil {
		log.Fatalf("감사 로그 파일(%s)을 Tailing 할 수 없습니다: %v", e.cfg.AuditLogPath, err)
	}

	log.Println("[DEBUG] 감사 로그 파일 Tailing 시작. 새 로그를 기다립니다...")

	for line := range t.Lines {
		// tail로 읽어들인 모든 로그 라인을 출력합니다.
		log.Printf("[DEBUG-TAIL] New line received: %s", line.Text)

		if gjson.Get(line.Text, "event").String() == "session.end" {
			if !gjson.Get(line.Text, "forwarded_by").Exists() {
				sessionID := gjson.Get(line.Text, "sid").String()
				log.Printf("[DEBUG] 'session.end' event detected. Starting goroutine... sessionID = %s ", sessionID)
				logData := line.Text
				go e.processSession(ctx, sessionID, logData)
			} else {
				// 전달된 노드 세션 이벤트는 무시합니다.
				log.Printf("[DEBUG] Ignoring forwarded node session.end event for sid: %s", gjson.Get(line.Text, "sid").String())

			}
		}
	}
	log.Println("[DEBUG] Tailing loop finished.") // 루프가 종료되면 이 로그가 보입니다.
}

func (e *LogExporter) processSession(ctx context.Context, sessionID string, logData string) {
	log.Printf("세션 처리 시작: %s", sessionID)

	// 실행할 tsh play 명령어 전체를 미리 출력합니다.
	log.Printf("[DEBUG] Executing command: tsh play --proxy=%s -i %s --format=text %s", e.cfg.TeleportProxyAddr, e.cfg.TbotIdentityFile, sessionID)

	cmd := exec.CommandContext(ctx, "tsh", "play",
		"--proxy="+e.cfg.TeleportProxyAddr,
		"-i", e.cfg.TbotIdentityFile,
		"--format=text",
		sessionID)

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		log.Printf("세션 %s의 로그 추출 실패 ('tsh play'): %v, Stderr: %s", sessionID, err, stderr.String())
		return
	}
	transcript := out.String()

	log.Printf("[DEBUG] Transcript for session %s extracted successfully. Length: %d", sessionID, len(transcript))

	// 2. Gemini 서비스로 분석 요청
	analysis, err := e.geminiService.AnalyzeTranscript(ctx, transcript)
	if err != nil {
		log.Printf("세션 %s 분석 실패: %v", sessionID, err)
		return
	}

	log.Printf("[DEBUG] Gemini analysis for session %s completed.", sessionID)

	// 3. 최종 데이터 조합 및 Logstash 전송
	enrichedLog := EnrichedLog{
		SessionID:    sessionID,
		User:         gjson.Get(logData, "user").String(),
		ServerID:     gjson.Get(logData, "server_id").String(),
		ServerAddr:   gjson.Get(logData, "server_addr").String(),
		SessionStart: gjson.Get(logData, "session_start").String(),
		SessionEnd:   gjson.Get(logData, "time").String(),
		Transcript:   transcript,
		Analysis:     analysis,
	}

	payload, err := json.Marshal(enrichedLog)
	if err != nil {
		log.Printf("세션 %s의 로그 데이터 직렬화 실패: %v", sessionID, err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, "POST", e.cfg.LogstashURL, bytes.NewReader(payload))
	if err != nil {
		log.Printf("세션 %s의 Logstash 요청 생성 실패: %v", sessionID, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		log.Printf("세션 %s의 분석 로그를 Logstash로 전송 실패: %v", sessionID, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		log.Printf("세션 %s 전송 후 Logstash로부터 에러 응답 수신: %s", sessionID, resp.Status)
	} else {
		log.Printf("세션 %s의 분석 로그를 Logstash로 성공적으로 전송했습니다.", sessionID)
	}
}
