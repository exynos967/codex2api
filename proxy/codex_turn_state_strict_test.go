package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/cache"
	"github.com/codex2api/database"
	"github.com/tidwall/gjson"
)

func newStrict292ExecutorFixture(t *testing.T) (*Handler, *auth.Account) {
	t.Helper()
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "strict.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	id, err := db.InsertAccountWithCredentials(context.Background(), "strict-account", map[string]any{
		"access_token": "test-token",
		auth.CodexTurnStateRequire292CredentialKey: "true",
		auth.CodexTurnStateModelsCredentialKey:     "different-model",
		auth.CodexTurnStateCredentialKey:           strings.Repeat("d", 312),
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	store := auth.NewStore(db, cache.NewMemory(16), &database.SystemSettings{MaxConcurrency: 2})
	t.Cleanup(store.Stop)
	if err = store.LoadAccountByID(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	h := &Handler{store: store, db: db}
	old := strictTurnStateRefreshHandler.Load()
	strictTurnStateRefreshHandler.Store(h)
	t.Cleanup(func() { strictTurnStateRefreshHandler.Store(old) })
	return h, store.FindByID(id)
}

func strict292FixtureSSE(state, text string) string {
	frame, _ := json.Marshal(map[string]any{"type": "codex.response.metadata", "metadata": map[string]string{"x-codex-turn-state": state}})
	delta, _ := json.Marshal(map[string]any{"type": "response.output_text.delta", "delta": text})
	return "data: " + string(frame) + "\n\ndata: " + string(delta) + "\n\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n\n"
}

// 真实执行器+真实SQLite：312的响应被关闭，刷新保存后重发原请求，最后只返回新292响应。
func TestExecuteCodexStrict292ReplaysAfterRefresh(t *testing.T) {
	for _, transport := range []string{"http", "websocket", "websocket-continuation", "compact"} {
		t.Run(transport, func(t *testing.T) {
			t.Setenv("CODEX_TURN_STATE_REFINE_PARALLEL", "1")
			h, account := newStrict292ExecutorFixture(t)
			good, degraded := strings.Repeat("g", 292), strings.Repeat("d", 312)
			var probes, sends atomic.Int64
			probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				probes.Add(1)
				var body map[string]any
				_ = json.NewDecoder(r.Body).Decode(&body)
				if body["model"] != "gpt-6-astra" {
					t.Errorf("probe used wrong model: %v", body["model"])
				}
				w.Header().Set(codexTurnStateHeader, good)
			}))
			defer probe.Close()
			oldURL := codexTurnStateProbeURL
			codexTurnStateProbeURL = probe.URL
			defer func() { codexTurnStateProbeURL = oldURL }()
			checkInjection := func(n int64, state string) {
				t.Helper()
				if n == 1 && state != "" {
					t.Error("first strict request inherited unverified state")
				}
				if n > 1 && state != good {
					t.Error("replayed request failed to inject freshly persisted292 across scope")
				}
			}
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := sends.Add(1)
				checkInjection(n, r.Header.Get(codexTurnStateHeader))
				state, text := good, "ALLOWED"
				if n == 1 {
					state, text = degraded, "BLOCKED"
				}
				w.Header().Set(codexTurnStateHeader, state)
				_, _ = io.WriteString(w, text)
			}))
			defer upstream.Close()
			oldResin := resinCfg.Load()
			SetResinConfig(&ResinConfig{BaseURL: upstream.URL, PlatformName: "test"})
			clientPool.Delete(fmt.Sprintf("resin|%d", account.ID()))
			defer func() { resinCfg.Store(oldResin); clientPool.Delete(fmt.Sprintf("resin|%d", account.ID())) }()
			oldWS := WebsocketExecuteFunc
			defer func() { WebsocketExecuteFunc = oldWS }()
			WebsocketExecuteFunc = func(ctx context.Context, a *auth.Account, body []byte, session, proxyURL, key string, cfg *DeviceProfileConfig, headers http.Header, pool string) (*http.Response, error) {
				n := sends.Add(1)
				if transport == "websocket-continuation" && n > 1 {
					if gjson.GetBytes(body, "previous_response_id").Exists() || !strings.Contains(gjson.GetBytes(body, "input").Raw, "retained-history") {
						t.Error("strict replay lost continuation context")
					}
				}
				checkInjection(n, gjson.GetBytes(body, "client_metadata.x-codex-turn-state").String())
				state, text := good, "ALLOWED"
				if n == 1 {
					state, text = degraded, "BLOCKED"
				}
				// 旧握手292不能让本次帧312漏出。
				header := make(http.Header)
				header.Set(codexTurnStateHeader, good)
				return &http.Response{StatusCode: 200, Header: header, Body: io.NopCloser(strings.NewReader(strict292FixtureSSE(state, text)))}, nil
			}
			body := []byte(`{"model":"gpt-6-astra","input":[{"role":"user","content":"hi"}],"client_metadata":{"x-codex-turn-state":"downstream-old"}}`)
			ctx := context.Background()
			if transport == "websocket-continuation" {
				body = []byte(`{"model":"gpt-6-astra","previous_response_id":"prev-on-old-connection","input":[{"role":"user","content":"new"}]}`)
				ctx = withCodex292ReplaySource(ctx, newResponsesWSReplaySourceFromInput(`[{"role":"user","content":"retained-history"},{"role":"assistant","content":"prior reply"},{"role":"user","content":"new"}]`))
			}
			original := string(body)
			account.CustomHeaders = map[string]string{codexTurnStateHeader: "custom-old"}
			headers := make(http.Header)
			headers.Set(codexTurnStateHeader, "downstream-old")
			var resp *http.Response
			var err error
			if transport == "compact" {
				resp, err = ExecuteCompactRequest(context.Background(), account, body, "session", "", "key", nil, headers)
			} else {
				resp, err = ExecuteRequest(ctx, account, body, "session", "", "key", nil, headers, strings.HasPrefix(transport, "websocket"))
			}
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			data, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "BLOCKED") || !strings.Contains(string(data), "ALLOWED") {
				t.Fatal("incorrect business response returned")
			}
			if sends.Load() != 2 || probes.Load() != 1 {
				t.Fatalf("sends=%d probes=%d", sends.Load(), probes.Load())
			}
			row, err := h.db.GetAccountByID(context.Background(), account.ID())
			if err != nil {
				t.Fatal(err)
			}
			if row.GetCredential(auth.CodexTurnStateCredentialKey) != good {
				t.Fatal("refresh not persisted")
			}
			if string(body) != original || headers.Get(codexTurnStateHeader) != "downstream-old" {
				t.Fatal("mutated caller request during replay")
			}
		})
	}
}

func TestCodexStrict292DisabledAndMissingState(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			account := &auth.Account{DBID: 1, CodexTurnStateRequire292: enabled}
			body := io.NopCloser(strings.NewReader("UNVERIFIED"))
			resp, err := executeWithCodex292Gate(context.Background(), account, "", func(context.Context) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: body}, nil
			})
			if enabled {
				if err == nil || resp != nil {
					t.Fatal("strict mode leaked unverified response")
				}
			} else {
				if err != nil || resp == nil {
					t.Fatal("disabled mode changed existing behavior")
				}
				_ = resp.Body.Close()
			}
		})
	}
}

func TestCodexStrict292TerminalCannotBeRevivedByContinuousRetry(t *testing.T) {
	policies := []database.ContinuousRetryPolicy{
		{Enabled: true, CatchAll: true},
		{Enabled: true, Categories: []string{"http_5xx"}},
		{Enabled: true, StatusCodes: []int{502}},
	}
	for _, policy := range policies {
		for _, cause := range []error{context.Canceled, errors.New("missing response proof"), nil} {
			err := errCodex292Gate("strict gate ended", cause)
			if isRetryableRequestErrorForContext(context.Background(), err, policy) || continuousRetryRequestErrorSelected(policy, err) {
				t.Fatal("continuous retry revived strict gate")
			}
		}
	}
}

func TestCodexStrict292ReplayRestoresHistoryAndRejectsLoss(t *testing.T) {
	body := []byte(`{"previous_response_id":"old-connection","input":[{"role":"user","content":"new"}],"model":"model-a"}`)
	_, err := prepareCodex292ReplayBody(context.Background(), body)
	if err == nil {
		t.Fatal("missing history silently replayed without context")
	}
	history := `[{"role":"user","content":"history"},{"role":"assistant","content":"prior reply"},{"role":"user","content":"new"}]`
	ctx := withCodex292ReplaySource(context.Background(), newResponsesWSReplaySourceFromInput(history))
	replay, err := prepareCodex292ReplayBody(ctx, body)
	if err != nil {
		t.Fatal(err)
	}
	if gjson.GetBytes(replay, "previous_response_id").Exists() {
		t.Fatal("replay still requires evictable WS connection")
	}
	if gjson.GetBytes(replay, "input").Raw != history {
		t.Fatal("replay lost prior conversation")
	}
	if !gjson.GetBytes(body, "previous_response_id").Exists() {
		t.Fatal("mutated original request")
	}
}

func TestTurnStateSweepKeepsPinned292RegardlessOfAge(t *testing.T) {
	h, account := newTurnStateTestHandler(t)
	account.CodexTurnState = strings.Repeat("p", 292)
	account.CodexTurnStateSetAt = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer server.Close()
	oldURL := codexTurnStateProbeURL
	codexTurnStateProbeURL = server.URL
	defer func() { codexTurnStateProbeURL = oldURL }()
	h.refreshAllEnabledAccounts(context.Background())
	if calls.Load() != 0 {
		t.Fatal("periodic sweep reprobed a retained292 based on age")
	}
	if len(account.CodexTurnStateInjection()) != 292 {
		t.Fatal("old292 no longer injected")
	}
}
