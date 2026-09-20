package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codex2api/auth"
	"github.com/gin-gonic/gin"
)

func TestParseAccountSchedulerRequire292(t *testing.T) {
	absent, err := parseAccountSchedulerUpdate(updateAccountSchedulerReq{})
	if err != nil || absent.hasChanges() || absent.CodexTurnStateRequire292.Set {
		t.Fatal("omitted strict switch must not change defaults")
	}
	for _, tc := range []struct{ raw, want string }{
		{`"true"`, "true"}, {`" YES "`, "true"}, {`"1"`, "true"}, {`"on"`, "true"},
		{`"false"`, "false"}, {`"off"`, "false"}, {`"0"`, "false"}, {`""`, "false"}, {`null`, "false"},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			update, err := parseAccountSchedulerUpdate(updateAccountSchedulerReq{CodexTurnStateRequire292: json.RawMessage(tc.raw)})
			if err != nil {
				t.Fatal(err)
			}
			if !update.hasChanges() || !update.CodexTurnStateRequire292.Set || update.CodexTurnStateRequire292.Value != tc.want || update.CredentialUpdates[auth.CodexTurnStateRequire292CredentialKey] != tc.want {
				t.Fatal("strict 292 flag was not validated/normalized/persisted")
			}
			if len(update.CredentialUpdates) != 1 {
				t.Fatal("strict switch edit must not mutate token or other switches")
			}
		})
	}
	if _, err := parseAccountSchedulerUpdate(updateAccountSchedulerReq{CodexTurnStateRequire292: json.RawMessage(`"invalid"`)}); err == nil {
		t.Fatal("invalid strict switch must be rejected")
	}
}

func TestCodexTurnStateRequire292SaveLifecycle(t *testing.T) {
	db := newTestAdminDB(t)
	store := auth.NewStore(db, nil, nil)
	t.Cleanup(store.Stop)
	h := &Handler{db: db, store: store}
	ctx := context.Background()
	id, err := db.InsertAccountWithCredentials(ctx, "strict-292", map[string]any{
		"upstream_type": auth.UpstreamOpenAIResponses, "access_token": "local-test-token",
		auth.CodexTurnStateCredentialKey:               "retained-state",
		auth.CodexTurnStateModelsCredentialKey:         "gpt-6-astra",
		auth.CodexTurnStateRefreshEnabledCredentialKey: "true",
		auth.CodexTurnStateRefineEnabledCredentialKey:  "true",
		auth.CodexTurnStateRefreshProxyCredentialKey:   "http://127.0.0.1:12345",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.LoadAccountByID(ctx, id); err != nil {
		t.Fatal(err)
	}
	account := store.FindByID(id)
	if account.IsCodexTurnStateRequire292() {
		t.Fatal("strict switch must initially be disabled")
	}
	for _, tc := range []struct{ payload, want string }{
		{`{"codex_turn_state_require_292":"YES"}`, "true"},
		{`{"codex_turn_state_models":"gpt-6-astra"}`, "true"},
		{`{"codex_turn_state_require_292":"false"}`, "false"},
	} {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Params = gin.Params{{Key: "id", Value: fmt.Sprint(id)}}
		c.Request = httptest.NewRequest(http.MethodPatch, fmt.Sprintf("/api/admin/accounts/%d/scheduler", id), strings.NewReader(tc.payload))
		h.UpdateAccountScheduler(c)
		if rec.Code != http.StatusOK {
			t.Fatalf("save = %d: %s", rec.Code, rec.Body.String())
		}
		row, err := db.GetAccountByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if row.GetCredential(auth.CodexTurnStateRequire292CredentialKey) != tc.want || account.IsCodexTurnStateRequire292() != (tc.want == "true") {
			t.Fatal("strict switch save did not reach database and runtime")
		}
		resp := h.buildAccountResponse(row, account, nil, nil, nil, true)
		if resp.CodexTurnStateRequire292 != tc.want {
			t.Fatal("account detail omitted persisted strict switch")
		}
		encoded, err := json.Marshal(resp)
		if err != nil || !strings.Contains(string(encoded), `"codex_turn_state_require_292":"`+tc.want+`"`) {
			t.Fatal("account response must expose strict switch as a string")
		}
		enabled, proxy := account.CodexTurnStateRefreshConfig()
		if !enabled || !account.IsCodexTurnStateRefineEnabled() || proxy != "http://127.0.0.1:12345" || row.GetCredential(auth.CodexTurnStateCredentialKey) != "retained-state" {
			t.Fatal("strict switch save changed unrelated injection/refresh fields")
		}
		reloaded := auth.NewStore(db, nil, nil)
		t.Cleanup(reloaded.Stop)
		if err := reloaded.LoadAccountByID(ctx, id); err != nil {
			t.Fatal(err)
		}
		if reloaded.FindByID(id).IsCodexTurnStateRequire292() != (tc.want == "true") {
			t.Fatal("strict switch did not survive runtime reload")
		}
	}
}
