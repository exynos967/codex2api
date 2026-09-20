package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codex2api/auth"
)

// 请求拒绝不能和正常响应未携带 token 混为一谈。
func TestTurnStateProbeHTTPErrorIsNotEmptyMiss(t *testing.T) {
	for _, status := range []int{400, 401, 403, 407, 429, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// 即使错误页带了形状合规的头，也不能作为正常结果保存。
				w.Header().Set(codexTurnStateHeader, strings.Repeat("a", auth.CodexTurnStateGoodLength))
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"error":{"code":"invalid_request_error","message":"do not leak sensitive echoed input"}}`))
			}))
			defer srv.Close()
			old := codexTurnStateProbeURL
			codexTurnStateProbeURL = srv.URL
			defer func() { codexTurnStateProbeURL = old }()
			h, account := newTurnStateTestHandler(t)
			state, got, err := h.probeCodexTurnState(context.Background(), account, "test", "model", "")
			if got != status || state != "" || err == nil || !strings.Contains(err.Error(), http.StatusText(status)) {
				t.Fatalf("HTTP %d was swallowed: state length=%d status=%d err=%v", status, len(state), got, err)
			}
		})
	}
}

func TestTurnStateProbeUsesOfficialMessageInput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			return
		}
		input, ok := body["input"].([]any)
		if !ok || len(input) != 1 {
			t.Errorf("official input must be one message array, got %T", body["input"])
			w.WriteHeader(400)
			return
		}
		message := input[0].(map[string]any)
		content, ok := message["content"].([]any)
		if message["role"] != "user" || !ok || len(content) != 1 {
			t.Errorf("invalid input message")
			return
		}
		part := content[0].(map[string]any)
		if part["type"] != "input_text" || part["text"] != "ts" {
			t.Errorf("invalid input content part")
		}
		w.Header().Set(codexTurnStateHeader, strings.Repeat("b", auth.CodexTurnStateDegradedLength))
	}))
	defer srv.Close()
	old := codexTurnStateProbeURL
	codexTurnStateProbeURL = srv.URL
	defer func() { codexTurnStateProbeURL = old }()
	h, account := newTurnStateTestHandler(t)
	_, _, _ = h.probeCodexTurnState(context.Background(), account, "test", "model", "")
}

// 候选好 token 必须等流确认完成才采信：292 头挂起时不应立即返回，
// 直到 response.completed 才固定；这是与"读头即走"旧契约的刻意差异。
func TestTurnStateProbeGoodHeaderWaitsForCompletion(t *testing.T) {
	unblock := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(codexTurnStateHeader, strings.Repeat("a", auth.CodexTurnStateGoodLength))
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		select {
		case <-unblock:
		case <-r.Context().Done():
			return
		}
		_, _ = w.Write([]byte("data: {\"type\":\"response.completed\"}\n\n"))
	}))
	defer srv.Close()
	old := codexTurnStateProbeURL
	codexTurnStateProbeURL = srv.URL
	defer func() { codexTurnStateProbeURL = old }()
	h, account := newTurnStateTestHandler(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	type outcome struct {
		state string
		err   error
	}
	done := make(chan outcome, 1)
	go func() {
		state, _, err := h.probeCodexTurnState(ctx, account, "test", "model", "")
		done <- outcome{state, err}
	}()
	// 头已 flush 但流未完成：probe 必须仍在等待，不能凭头先返回。
	select {
	case out := <-done:
		t.Fatalf("probe returned before stream completion: state length=%d err=%v", len(out.state), out.err)
	case <-time.After(100 * time.Millisecond):
	}
	close(unblock)
	select {
	case out := <-done:
		if out.err != nil || len(out.state) != auth.CodexTurnStateGoodLength {
			t.Fatalf("probe did not pin after completion: state length=%d err=%v", len(out.state), out.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("probe did not return after stream completed")
	}
}

// 永久请求错误应退出；原实现把每轮400全记成空结果，持续重发。
func TestTurnStateRefineStopsOnRejectedRequest(t *testing.T) {
	t.Setenv("CODEX_TURN_STATE_REFINE_PARALLEL", "1")
	oldDelay, oldURL := codexTurnStateProbeDelay, codexTurnStateProbeURL
	codexTurnStateProbeDelay = time.Millisecond
	defer func() { codexTurnStateProbeDelay, codexTurnStateProbeURL = oldDelay, oldURL }()
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":{"code":"invalid_request_error"}}`))
	}))
	defer srv.Close()
	codexTurnStateProbeURL = srv.URL
	h, account := newTurnStateTestHandler(t)
	account.CodexTurnStateRefineEnabled = true
	if !h.StartCodexTurnStateRefine(account) {
		t.Fatal("start failed")
	}
	// 即使断言失败，也要先等循环退出再还原包级测试配置。
	defer func() { h.StopCodexTurnStateRefine(account.ID()); waitRefineStopped(t, h, account.ID()) }()
	deadline := time.After(300 * time.Millisecond)
	for h.CodexTurnStateRefining(account.ID()) {
		select {
		case <-deadline:
			t.Fatalf("HTTP 400 still refreshing after %d attempts", calls.Load())
		default:
			time.Sleep(time.Millisecond)
		}
	}
	waitRefineStopped(t, h, account.ID())
	if calls.Load() != 1 {
		t.Errorf("attempts=%d, want one rejected request", calls.Load())
	}
}

// 候选好 token 必须本次响应正常完成才采信：头报 292 但回合 failed 不固定。
func TestTurnStateProbeGoodHeaderRequiresCompletedStream(t *testing.T) {
	good := strings.Repeat("a", auth.CodexTurnStateGoodLength)
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"completed 采信", `data: {"type":"response.completed"}` + "\n\n", good},
		{"正常EOF采信", "data: {}\n\n", good},
		{"failed 不采信", `data: {"type":"response.failed"}` + "\n\n", ""},
		{"error 不采信", `data: {"type":"error"}` + "\n\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(codexTurnStateHeader, good)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			old := codexTurnStateProbeURL
			codexTurnStateProbeURL = srv.URL
			defer func() { codexTurnStateProbeURL = old }()
			h, account := newTurnStateTestHandler(t)
			state, _, err := h.probeCodexTurnState(context.Background(), account, "test", "model", "")
			if err != nil {
				t.Fatal(err)
			}
			if state != tc.want {
				t.Errorf("state length=%d, want %d（%s）", len(state), len(tc.want), tc.name)
			}
		})
	}
}

func TestTurnStateProbeDiscardsConfiguredRoutingState(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(codexTurnStateHeader) != "" || r.Header.Get(codexResponsesLiteHeader) != "" {
			t.Error("fresh non-Lite probe inherited custom state or Lite flag")
		}
		w.Header().Set(codexTurnStateHeader, strings.Repeat("b", auth.CodexTurnStateDegradedLength))
	}))
	defer srv.Close()
	old := codexTurnStateProbeURL
	codexTurnStateProbeURL = srv.URL
	defer func() { codexTurnStateProbeURL = old }()
	h, account := newTurnStateTestHandler(t)
	account.CustomHeaders = map[string]string{codexTurnStateHeader: "old-state", codexResponsesLiteHeader: "true"}
	_, _, err := h.probeCodexTurnState(context.Background(), account, "test", "model", "")
	if err != nil {
		t.Fatal(err)
	}
}

func TestTurnStateRefreshRetriesTransientHTTPFailures(t *testing.T) {
	t.Setenv("CODEX_TURN_STATE_REFRESH_ATTEMPTS", "2")
	oldDelay := codexTurnStateProbeDelay
	codexTurnStateProbeDelay = 0
	defer func() { codexTurnStateProbeDelay = oldDelay }()
	for _, status := range []int{403, 408, 429, 502} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					w.WriteHeader(status)
					return
				}
				w.Header().Set(codexTurnStateHeader, strings.Repeat("a", auth.CodexTurnStateGoodLength))
			}))
			defer srv.Close()
			old := codexTurnStateProbeURL
			codexTurnStateProbeURL = srv.URL
			defer func() { codexTurnStateProbeURL = old }()
			h, account := newTurnStateTestHandler(t)
			result, _ := h.RefreshCodexTurnState(context.Background(), account)
			// 此处只验证重试到292；真实落库由独立SQLite测试覆盖。
			if calls.Load() != 2 || result.Length != auth.CodexTurnStateGoodLength {
				t.Fatalf("retry failed: calls=%d token length=%d", calls.Load(), result.Length)
			}
		})
	}
}
