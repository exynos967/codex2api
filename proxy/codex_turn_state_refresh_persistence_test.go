package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/cache"
	"github.com/codex2api/database"
)

func TestCodexTurnStateRefinePersists292AndStops(t *testing.T) {
	// 单 worker 让请求数确定；持久化与退出仍走实际 refine 入口。
	t.Setenv("CODEX_TURN_STATE_REFINE_PARALLEL", "1")
	ctx := context.Background()
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "turn-state.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	oldState := strings.Repeat("b", 312)
	oldSetAt := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	id, err := db.InsertAccountWithCredentials(ctx, "turn-state-persistence-test", map[string]any{
		"access_token":                                "local-test-token",
		"upstream_type":                               auth.UpstreamOpenAIResponses,
		auth.CodexTurnStateCredentialKey:              oldState,
		auth.CodexTurnStateModelsCredentialKey:        "gpt-6-astra",
		auth.CodexTurnStateSetAtCredentialKey:         oldSetAt.Format(time.RFC3339),
		auth.CodexTurnStateRefineEnabledCredentialKey: "true",
	}, "")
	if err != nil {
		t.Fatalf("InsertAccountWithCredentials: %v", err)
	}
	store := auth.NewStore(db, cache.NewMemory(16), &database.SystemSettings{MaxConcurrency: 2})
	t.Cleanup(store.Stop)
	if err := store.LoadAccountByID(ctx, id); err != nil {
		t.Fatalf("LoadAccountByID: %v", err)
	}
	account := store.FindByID(id)
	if account == nil {
		t.Fatal("loaded account missing from store")
	}
	if state, models, setAt := account.CodexTurnStateConfig(); state != oldState || models != "gpt-6-astra" || !setAt.Equal(oldSetAt) {
		t.Fatal("store did not load the initial turn-state credentials")
	}
	// 与管理端保存开关相同，向已加载账号发布运行时配置。
	store.ApplyAccountCodexTurnStateRefine(id, true)
	h := &Handler{store: store, db: db}

	good := strings.Repeat("a", 292)
	requests := make(chan struct{}, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		select {
		case requests <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		w.Header().Set(codexTurnStateHeader, good)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {}\n\n"))
	}))
	t.Cleanup(srv.Close)

	oldURL, oldDelay := codexTurnStateProbeURL, codexTurnStateProbeDelay
	codexTurnStateProbeURL, codexTurnStateProbeDelay = srv.URL, 5*time.Millisecond
	// Fatal 路径也先取消并等待 worker/loop 收尾，再恢复全局探测配置。
	// Stop 会立即删 refine 条目，必须同时等待 running 槽位清空。
	t.Cleanup(func() {
		h.StopCodexTurnStateRefine(id)
		unblock()
		waitRefineStopped(t, h, id)
		codexTurnStateProbeURL, codexTurnStateProbeDelay = oldURL, oldDelay
	})

	started := time.Now().UTC()
	if !h.StartCodexTurnStateRefine(account) {
		t.Fatal("StartCodexTurnStateRefine returned false")
	}
	select {
	case <-requests:
	case <-time.After(5 * time.Second):
		t.Fatal("refine did not send a local probe")
	}
	if !h.CodexTurnStateRefining(id) {
		t.Fatal("refine must be running while the response is blocked")
	}
	unblock()
	// 正常路径不调用 Stop：应在 292 成功保存后自行退出。
	waitRefineStopped(t, h, id)
	finished := time.Now().UTC()

	row, err := db.GetAccountByID(ctx, id)
	if err != nil {
		t.Fatalf("GetAccountByID: %v", err)
	}
	if got := row.GetCredential(auth.CodexTurnStateCredentialKey); got != good {
		t.Fatalf("persisted turn-state was not replaced with the local 292 response (length=%d)", len(got))
	}
	savedAt, err := time.Parse(time.RFC3339, row.GetCredential(auth.CodexTurnStateSetAtCredentialKey))
	if err != nil {
		t.Fatalf("persisted set_at is not RFC3339: %v", err)
	}
	if savedAt.Before(started.Truncate(time.Second)) || savedAt.After(finished) {
		t.Fatalf("persisted set_at = %v, outside refine interval [%v, %v]", savedAt, started, finished)
	}
	state, models, runtimeSetAt := account.CodexTurnStateConfig()
	if state != good {
		t.Fatalf("runtime turn-state was not updated (length=%d)", len(state))
	}
	if runtimeSetAt.Before(started) || runtimeSetAt.After(finished) || runtimeSetAt.Format(time.RFC3339) != savedAt.Format(time.RFC3339) {
		t.Fatalf("runtime set_at = %v, persisted set_at = %v", runtimeSetAt, savedAt)
	}
	if models != "gpt-6-astra" || row.GetCredential(auth.CodexTurnStateModelsCredentialKey) != models {
		t.Fatal("refresh changed the configured model scope")
	}
	if h.CodexTurnStateRefining(id) {
		t.Fatal("refine still running after persistence")
	}
	// 等过多个探测间隔，确认成功后没有再开启下一轮。
	select {
	case <-requests:
		t.Fatal("refine sent another request after receiving 292")
	case <-time.After(50 * time.Millisecond):
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("local probe requests = %d, want 1", got)
	}
}
