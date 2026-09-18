package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/codex2api/auth"
	"github.com/codex2api/database"
)

func newTurnStateTestHandler(t *testing.T) (*Handler, *auth.Account) {
	t.Helper()
	store := auth.NewStore(nil, nil, &database.SystemSettings{MaxConcurrency: 2})
	t.Cleanup(store.Stop)
	account := &auth.Account{
		DBID:         77,
		UpstreamType: auth.UpstreamOpenAIResponses,
		AccessToken:  "codex-token",
		Status:       auth.StatusReady,
	}
	account.CodexTurnStateRefreshEnabled = true
	account.CodexTurnStateModels = "gpt-6-astra"
	store.AddAccount(account)
	return &Handler{store: store}, account
}

// TestCodexTurnStateRefreshClassification 探测结果按形态分类：312 降智拒绝回写、
// 无 token 报错、292 走到持久化（测试库为空时落库失败但长度判定正确）。
func TestCodexTurnStateRefreshClassification(t *testing.T) {
	// 重试循环提速：测试里探测间隔归零、次数收窄。
	oldDelay := codexTurnStateProbeDelay
	codexTurnStateProbeDelay = 0
	defer func() { codexTurnStateProbeDelay = oldDelay }()
	t.Setenv("CODEX_TURN_STATE_REFRESH_ATTEMPTS", "3")

	good := strings.Repeat("a", auth.CodexTurnStateGoodLength)
	degraded := strings.Repeat("b", auth.CodexTurnStateDegradedLength)

	cases := []struct {
		name       string
		state      string
		wantLen    int
		wantErrSub string
	}{
		{"降智312刷满次数拒绝", degraded, auth.CodexTurnStateDegradedLength, "降智"},
		{"空token报错", "", 0, "未回传"},
		{"正常292尝试回写", good, auth.CodexTurnStateGoodLength, "存储未就绪"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.state != "" {
					w.Header().Set(codexTurnStateHeader, tc.state)
				}
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte("data: {}\n\n"))
			}))
			defer srv.Close()

			old := codexTurnStateProbeURL
			codexTurnStateProbeURL = srv.URL
			defer func() { codexTurnStateProbeURL = old }()

			h, account := newTurnStateTestHandler(t)
			result, err := h.RefreshCodexTurnState(context.Background(), account)
			if err == nil {
				t.Fatalf("期望错误（%s）", tc.wantErrSub)
			}
			if result.Length != tc.wantLen {
				t.Errorf("Length = %d, want %d", result.Length, tc.wantLen)
			}
			if !strings.Contains(result.Error, tc.wantErrSub) {
				t.Errorf("Error = %q, want 包含 %q", result.Error, tc.wantErrSub)
			}
		})
	}
}

// TestCodexTurnStateRefreshRetriesUntilGood 轮换池前几次给 312、之后给 292：
// 循环应提前停在 292，不再多探测。
func TestCodexTurnStateRefreshRetriesUntilGood(t *testing.T) {
	oldDelay := codexTurnStateProbeDelay
	codexTurnStateProbeDelay = 0
	defer func() { codexTurnStateProbeDelay = oldDelay }()
	t.Setenv("CODEX_TURN_STATE_REFRESH_ATTEMPTS", "8")

	degraded := strings.Repeat("b", auth.CodexTurnStateDegradedLength)
	good := strings.Repeat("a", auth.CodexTurnStateGoodLength)
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n <= 2 {
			w.Header().Set(codexTurnStateHeader, degraded)
		} else {
			w.Header().Set(codexTurnStateHeader, good)
		}
		_, _ = w.Write([]byte("data: {}\n\n"))
	}))
	defer srv.Close()

	old := codexTurnStateProbeURL
	codexTurnStateProbeURL = srv.URL
	defer func() { codexTurnStateProbeURL = old }()

	h, account := newTurnStateTestHandler(t)
	result, err := h.RefreshCodexTurnState(context.Background(), account)
	// 无真实 DB，落库必然失败；关键是第 3 次探测就拿到 292 并停下。
	if err == nil || !strings.Contains(err.Error(), "存储未就绪") {
		t.Fatalf("应在落库阶段失败, err = %v", err)
	}
	if result.Length != auth.CodexTurnStateGoodLength {
		t.Errorf("Length = %d, want %d", result.Length, auth.CodexTurnStateGoodLength)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("探测次数 = %d, want 3（拿到 292 即停）", got)
	}
}

// TestCodexTurnStateRefreshGuards 前置守卫：未开启刷新、无模型名单都拒绝。
func TestCodexTurnStateRefreshGuards(t *testing.T) {
	h, account := newTurnStateTestHandler(t)

	account.CodexTurnStateRefreshEnabled = false
	if _, err := h.RefreshCodexTurnState(context.Background(), account); err == nil ||
		!strings.Contains(err.Error(), "未开启") {
		t.Errorf("未开启时应拒绝, err = %v", err)
	}

	account.CodexTurnStateRefreshEnabled = true
	account.CodexTurnStateModels = ""
	if _, err := h.RefreshCodexTurnState(context.Background(), account); err == nil ||
		!strings.Contains(err.Error(), "模型名单") {
		t.Errorf("无模型名单时应拒绝, err = %v", err)
	}

	account.AccessToken = ""
	account.CodexTurnStateModels = "gpt-6-astra"
	if _, err := h.RefreshCodexTurnState(context.Background(), account); err == nil ||
		!strings.Contains(err.Error(), "access_token") {
		t.Errorf("无 token 时应拒绝, err = %v", err)
	}
}

// TestFirstCodexTurnStateModel 名单取第一个模型。
func TestFirstCodexTurnStateModel(t *testing.T) {
	if got := firstCodexTurnStateModel("gpt-6-astra, gpt-5.3-codex"); got != "gpt-6-astra" {
		t.Errorf("got %q", got)
	}
	if got := firstCodexTurnStateModel(""); got != "" {
		t.Errorf("空名单应为空, got %q", got)
	}
	if got := firstCodexTurnStateModel("solo"); got != "solo" {
		t.Errorf("单模型原样返回, got %q", got)
	}
}
