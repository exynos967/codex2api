package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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

// waitRefineStopped 轮询死磕循环真正退出（goroutine 结束、两个槽位都清空）。
// 不能只看 CodexTurnStateRefining：Stop 同步删 refine 条目后循环还在收尾，
// 测试提前结束会让 defer 恢复全局变量与循环读取撞出竞态（CI race 实测）。
func waitRefineStopped(t *testing.T, h *Handler, id int64) {
	t.Helper()
	r := h.turnStateRefresher()
	for i := 0; i < 1000; i++ {
		r.mu.Lock()
		_, running := r.running[id]
		_, refining := r.refine[id]
		r.mu.Unlock()
		if !running && !refining {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("死磕循环未在预期时间内退出")
}

// TestCodexTurnStateRefinePins292AndExits 死磕循环：312 继续磨，拿到 292 固定后退出。
func TestCodexTurnStateRefinePins292AndExits(t *testing.T) {
	oldDelay := codexTurnStateProbeDelay
	codexTurnStateProbeDelay = 0
	defer func() { codexTurnStateProbeDelay = oldDelay }()

	degraded := strings.Repeat("b", auth.CodexTurnStateDegradedLength)
	good := strings.Repeat("a", auth.CodexTurnStateGoodLength)
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) <= 3 {
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
	account.CodexTurnStateRefineEnabled = true
	if !h.StartCodexTurnStateRefine(account) {
		t.Fatal("死磕循环应成功启动")
	}
	if !h.CodexTurnStateRefining(account.ID()) {
		t.Fatal("启动后 refining 应为 true")
	}
	// 幂等：重复启动不报错、不重复起循环。
	if !h.StartCodexTurnStateRefine(account) {
		t.Fatal("重复启动应幂等返回 true")
	}
	waitRefineStopped(t, h, account.ID())
	if got := atomic.LoadInt32(&calls); got != 4 {
		t.Errorf("探测次数 = %d, want 4（3 次 312 后第 4 次拿 292 退出）", got)
	}
}

// TestCodexTurnStateRefineStopsOnDemand 停止按钮路径：循环磨 312 中被 Stop 后退出。
func TestCodexTurnStateRefineStopsOnDemand(t *testing.T) {
	oldDelay := codexTurnStateProbeDelay
	codexTurnStateProbeDelay = 10 * time.Millisecond
	defer func() { codexTurnStateProbeDelay = oldDelay }()

	degraded := strings.Repeat("b", auth.CodexTurnStateDegradedLength)
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set(codexTurnStateHeader, degraded)
		_, _ = w.Write([]byte("data: {}\n\n"))
	}))
	defer srv.Close()
	old := codexTurnStateProbeURL
	codexTurnStateProbeURL = srv.URL
	defer func() { codexTurnStateProbeURL = old }()

	h, account := newTurnStateTestHandler(t)
	account.CodexTurnStateRefineEnabled = true
	if !h.StartCodexTurnStateRefine(account) {
		t.Fatal("死磕循环应成功启动")
	}
	for i := 0; i < 200 && atomic.LoadInt32(&calls) == 0; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if !h.StopCodexTurnStateRefine(account.ID()) {
		t.Fatal("Stop 应返回 true（确有循环在跑）")
	}
	if h.StopCodexTurnStateRefine(account.ID()) {
		t.Fatal("循环已停后 Stop 应返回 false")
	}
	waitRefineStopped(t, h, account.ID())
}

// TestCodexTurnStateRefineSwitchOffExits 开关被关（PATCH 保存 false）后循环自行退出。
func TestCodexTurnStateRefineSwitchOffExits(t *testing.T) {
	oldDelay := codexTurnStateProbeDelay
	codexTurnStateProbeDelay = 10 * time.Millisecond
	defer func() { codexTurnStateProbeDelay = oldDelay }()

	degraded := strings.Repeat("b", auth.CodexTurnStateDegradedLength)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(codexTurnStateHeader, degraded)
		_, _ = w.Write([]byte("data: {}\n\n"))
	}))
	defer srv.Close()
	old := codexTurnStateProbeURL
	codexTurnStateProbeURL = srv.URL
	defer func() { codexTurnStateProbeURL = old }()

	h, account := newTurnStateTestHandler(t)
	account.CodexTurnStateRefineEnabled = true
	if !h.StartCodexTurnStateRefine(account) {
		t.Fatal("死磕循环应成功启动")
	}
	account.Mu().Lock()
	account.CodexTurnStateRefineEnabled = false
	account.Mu().Unlock()
	waitRefineStopped(t, h, account.ID())
}

