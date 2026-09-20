package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"

	"github.com/codex2api/auth"
)

// 线上只见泛化502且无刷新日志；相同错误信息无法区分缺头与WS上游失败。
func TestStrict292VerificationFailureExposesSafeReason(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ws     bool
		body   string
		reason string
	}{
		{"HTTP missing header", false, "private-body-never-log", "header missing or ambiguous"},
		{"WS no current state", true, "data: {\"type\":\"response.completed\"}\n\n", "missing state or successful terminal"},
		{"WS upstream error", true, "data: {\"type\":\"response.failed\",\"response\":{\"error\":{\"message\":\"private-body-never-log\"}}}\n\n", "unsuccessful event response.failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			previous := log.Writer()
			log.SetOutput(&logs)
			defer log.SetOutput(previous)
			account := &auth.Account{DBID: 42, CodexTurnStateRequire292: true, CodexTurnState: strings.Repeat("s", 292)}
			resp, err := executeWithCodex292Gate(context.Background(), account, "", func(ctx context.Context) (*http.Response, error) {
				strict292Attempt(ctx).websocket = tc.ws
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})
			if resp != nil {
				t.Fatal("unverified response released")
			}
			var structured *Error
			if !errors.As(err, &structured) || !strings.Contains(structured.Message, tc.reason) {
				t.Fatalf("client cannot identify cause: %v", err)
			}
			if !strings.Contains(logs.String(), "[turn-state-gate]") || !strings.Contains(logs.String(), tc.reason) {
				t.Fatal("server log lacks verification failure reason")
			}
			if strings.Contains(structured.Message, "private-body") || strings.Contains(logs.String(), "private-body") || strings.Contains(logs.String(), account.CodexTurnState) {
				t.Fatal("diagnostic leaked body or token")
			}
		})
	}
}

func TestCodex292FailureSummaryDoesNotEchoPrivateError(t *testing.T) {
	known := []byte(`{"type":"response.failed","response":{"status_code":429,"error":{"code":"rate_limit_exceeded","message":"private-prompt"}}}`)
	summary := codex292FailureSummary(known)
	if !strings.Contains(summary, "upstream_status=429") || !strings.Contains(summary, "rate_limit_exceeded") || strings.Contains(summary, "private-prompt") {
		t.Fatalf("bad safe summary: %s", summary)
	}
	unknown := []byte(`{"error":{"code":"secret-credential","type":"secret-type","message":"secret-body","status_code":999}}`)
	summary = codex292FailureSummary(unknown)
	if strings.Contains(summary, "secret") || summary != "upstream_status=0 upstream_code=unknown_or_absent" {
		t.Fatal("unknown fields escaped diagnostic whitelist")
	}
}
