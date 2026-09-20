package proxy

import (
	"context"
	"encoding/json"
	"io"
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

func strictRefreshFixture(t *testing.T, handler http.HandlerFunc) (*Handler, *auth.Account, *database.DB) {
	t.Helper()
	t.Setenv("CODEX_TURN_STATE_REFRESH_INTERVAL", "0")
	t.Setenv("CODEX_TURN_STATE_REFINE_PARALLEL", "8")
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "strict.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	id, err := db.InsertAccountWithCredentials(context.Background(), "strict-local-test", map[string]any{
		"access_token":                             "local-test-token",
		"upstream_type":                            auth.UpstreamOpenAIResponses,
		auth.CodexTurnStateModelsCredentialKey:     "gpt-*",
		auth.CodexTurnStateRequire292CredentialKey: "true",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	store := auth.NewStore(db, cache.NewMemory(16), &database.SystemSettings{MaxConcurrency: 2})
	t.Cleanup(store.Stop)
	if err := store.LoadAccountByID(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	h := &Handler{store: store, db: db}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	oldURL, oldDelay := codexTurnStateProbeURL, codexTurnStateProbeDelay
	codexTurnStateProbeURL, codexTurnStateProbeDelay = server.URL, 5*time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	previous := strictTurnStateRefreshHandler.Load()
	previousObserver := degradedTurnStateObserver.Load()
	h.StartCodexTurnStateRefresh(ctx)
	t.Cleanup(func() {
		cancel()
		h.StopCodexTurnStateRefine(id)
		waitRefineStopped(t, h, id)
		strictTurnStateRefreshHandler.Store(previous)
		if previousObserver != nil {
			degradedTurnStateObserver.Store(previousObserver)
		} else {
			degradedTurnStateObserver.Store(func(int64) {})
		}
		codexTurnStateProbeURL, codexTurnStateProbeDelay = oldURL, oldDelay
	})
	return h, store.FindByID(id), db
}

func TestStrictTurnStateSharedRefreshPersistsAndIsolatesCancel(t *testing.T) {
	good := strings.Repeat("s", 292)
	arrived := make(chan struct{}, 32)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	var calls atomic.Int32
	h, account, db := strictRefreshFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		arrived <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		w.Header().Set(codexTurnStateHeader, good)
	})
	canceled, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() {
		_, err := refreshCodexTurnStateForStrictRequest(canceled, account, "gpt-6-astra", "")
		first <- err
	}()
	for i := 0; i < 8; i++ {
		select {
		case <-arrived:
		case <-time.After(5 * time.Second):
			t.Fatal("eight probes did not start")
		}
	}
	second := make(chan error, 1)
	go func() {
		state, err := refreshCodexTurnStateForStrictRequest(context.Background(), account, "gpt-6-astra", "")
		if err == nil && state != good {
			err = context.Canceled
		}
		second <- err
	}()
	waitStrict292Condition(t, func() bool {
		r := h.turnStateRefresher()
		r.mu.Lock()
		defer r.mu.Unlock()
		task := r.strict[account.ID()]
		return task != nil && task.models["gpt-6-astra"] != nil && task.models["gpt-6-astra"].refs == 2
	})
	cancel()
	if err := <-first; err == nil {
		t.Fatal("canceled waiter succeeded")
	}
	unblock()
	select {
	case err := <-second:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shared waiter stuck")
	}
	if got := calls.Load(); got != 8 {
		t.Fatalf("probes = %d, want exactly one batch of eight", got)
	}
	row, err := db.GetAccountByID(context.Background(), account.ID())
	if err != nil {
		t.Fatal(err)
	}
	if row.GetCredential(auth.CodexTurnStateCredentialKey) != good {
		t.Fatal("success returned before SQLite persistence")
	}
}

func waitStrict292Condition(t *testing.T, ready func() bool) {
	t.Helper()
	until := time.Now().Add(5 * time.Second)
	for !ready() {
		if time.Now().After(until) {
			t.Fatal("strict refresh condition timed out")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestStrictTurnStateAllCancelThenNewRequest(t *testing.T) {
	t.Setenv("CODEX_TURN_STATE_REFINE_PARALLEL", "1")
	var succeed atomic.Bool
	arrived := make(chan struct{}, 16)
	h, account, _ := strictRefreshFixture(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if succeed.Load() {
			w.Header().Set(codexTurnStateHeader, strings.Repeat("s", 292))
			return
		}
		select {
		case arrived <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	})
	t.Setenv("CODEX_TURN_STATE_REFINE_PARALLEL", "1")
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := refreshCodexTurnStateForStrictRequest(ctx, account, "model-a", ""); result <- err }()
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("probe did not start")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled request succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled waiter stuck")
	}
	// 不等旧任务收尾，立即到来的新请求也不能继承它的context.Canceled。
	succeed.Store(true)
	state, err := refreshCodexTurnStateForStrictRequest(context.Background(), account, "model-a", "")
	if err != nil || len(state) != 292 {
		t.Fatalf("new request failed after cancellation: length=%d err=%v", len(state), err)
	}
	waitRefineStopped(t, h, account.ID())
}

func TestStrictTurnStateStopCancelsQueuedModels(t *testing.T) {
	arrived := make(chan struct{}, 16)
	h, account, _ := strictRefreshFixture(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case arrived <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	})
	t.Setenv("CODEX_TURN_STATE_REFINE_PARALLEL", "1")
	results := make(chan error, 2)
	go func() {
		_, err := refreshCodexTurnStateForStrictRequest(context.Background(), account, "model-a", "")
		results <- err
	}()
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("probe did not start")
	}
	go func() {
		_, err := refreshCodexTurnStateForStrictRequest(context.Background(), account, "model-b", "")
		results <- err
	}()
	waitStrict292Condition(t, func() bool {
		r := h.turnStateRefresher()
		r.mu.Lock()
		defer r.mu.Unlock()
		task := r.strict[account.ID()]
		return task != nil && len(task.models) == 2
	})
	if !h.StopCodexTurnStateRefine(account.ID()) {
		t.Fatal("stop did not find task")
	}
	for i := 0; i < 2; i++ {
		select {
		case err := <-results:
			if err == nil {
				t.Fatal("stop released success")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("stop waiter stuck")
		}
	}
	waitRefineStopped(t, h, account.ID())
}

func TestStrictTurnStateDifferentModelsAreSerialized(t *testing.T) {
	arrived := make(chan string, 4)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	h, account, _ := strictRefreshFixture(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		model, _ := body["model"].(string)
		arrived <- model
		if model == "model-a" {
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		state := strings.Repeat("a", 292)
		if model == "model-b" {
			state = strings.Repeat("b", 292)
		}
		w.Header().Set(codexTurnStateHeader, state)
	})
	t.Setenv("CODEX_TURN_STATE_REFINE_PARALLEL", "1")
	type result struct {
		state string
		err   error
	}
	first, second := make(chan result, 1), make(chan result, 1)
	go func() {
		s, e := refreshCodexTurnStateForStrictRequest(context.Background(), account, "model-a", "")
		first <- result{s, e}
	}()
	select {
	case model := <-arrived:
		if model != "model-a" {
			t.Fatal("wrong first model")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first model never probed")
	}
	go func() {
		s, e := refreshCodexTurnStateForStrictRequest(context.Background(), account, "model-b", "")
		second <- result{s, e}
	}()
	waitStrict292Condition(t, func() bool {
		r := h.turnStateRefresher()
		r.mu.Lock()
		defer r.mu.Unlock()
		task := r.strict[account.ID()]
		return task != nil && len(task.models) == 2
	})
	select {
	case <-arrived:
		t.Fatal("different model ran concurrently in same account")
	default:
	}
	unblock()
	for index, ch := range []chan result{first, second} {
		select {
		case out := <-ch:
			expected := strings.Repeat("a", 292)
			if index == 1 {
				expected = strings.Repeat("b", 292)
			}
			if out.err != nil || out.state != expected {
				t.Fatalf("wrong model result index=%d err=%v", index, out.err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("queued model never completed")
		}
	}
	waitRefineStopped(t, h, account.ID())
}

func TestStrictTurnStateDisablingFlagCancelsProbe(t *testing.T) {
	arrived := make(chan struct{}, 16)
	h, account, _ := strictRefreshFixture(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case arrived <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	})
	t.Setenv("CODEX_TURN_STATE_REFINE_PARALLEL", "1")
	done := make(chan error, 1)
	go func() {
		_, err := refreshCodexTurnStateForStrictRequest(context.Background(), account, "model-a", "")
		done <- err
	}()
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("probe never started")
	}
	h.store.ApplyAccountCodexTurnStateRequire292(account.ID(), false)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("disabled strict mode released result")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("disabled probe stuck")
	}
	waitRefineStopped(t, h, account.ID())
}
