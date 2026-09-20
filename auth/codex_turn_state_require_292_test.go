package auth

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/codex2api/database"
)

func TestCodexTurnStateRequire292DefaultAndNoTTL(t *testing.T) {
	var nilAccount *Account
	if nilAccount.IsCodexTurnStateRequire292() || (&Account{}).IsCodexTurnStateRequire292() {
		t.Fatal("strict 292 must default to false")
	}
	account := &Account{CodexTurnState: "historical-manual-state", CodexTurnStateSetAt: time.Now().Add(-24 * time.Hour)}
	if account.CodexTurnStateInjection() != "historical-manual-state" {
		t.Fatal("set_at is metadata, not a local expiry policy")
	}
}

func TestLoadAccountCodexTurnStateSwitches(t *testing.T) {
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "turn-state-load.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := NewStore(db, nil, nil)
	t.Cleanup(store.Stop)
	ctx := context.Background()
	for _, tc := range []struct {
		value   string
		enabled bool
	}{
		{"", false}, {"false", false}, {"true", true}, {"  YES  ", true}, {"on", true}, {"1", true}, {"off", false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			id, err := db.InsertAccountWithCredentials(ctx, "turn-state-load", map[string]any{
				"access_token": "local-test-token", "upstream_type": UpstreamOpenAIResponses,
				CodexTurnStateCredentialKey: "retained-state", CodexTurnStateModelsCredentialKey: "gpt-6-astra",
				CodexTurnStateRequire292CredentialKey:     tc.value,
				CodexTurnStateRefreshEnabledCredentialKey: tc.value,
				CodexTurnStateRefineEnabledCredentialKey:  tc.value,
				CodexTurnStateRefreshProxyCredentialKey:   "http://127.0.0.1:12345",
			}, "")
			if err != nil {
				t.Fatal(err)
			}
			if err := store.LoadAccountByID(ctx, id); err != nil {
				t.Fatal(err)
			}
			account := store.FindByID(id)
			enabled, proxy := account.CodexTurnStateRefreshConfig()
			if account.IsCodexTurnStateRequire292() != tc.enabled || account.IsCodexTurnStateRefineEnabled() != tc.enabled || enabled != tc.enabled || proxy != "http://127.0.0.1:12345" {
				t.Fatal("initial DB load did not restore all turn-state switches/proxy")
			}
			value, models, _ := account.CodexTurnStateConfig()
			if value != "retained-state" || models != "gpt-6-astra" {
				t.Fatal("initial load changed injection configuration")
			}
			store.ApplyAccountCodexTurnStateRequire292(id, !tc.enabled)
			if account.IsCodexTurnStateRequire292() == tc.enabled {
				t.Fatal("runtime apply did not update strict 292 switch")
			}
		})
	}
	// Reconcile 使用同一加载函数，必须恢复 DB 开关而非保留上面的 runtime-only 翻转。
	if _, err := store.ReconcileDispatchState(ctx); err != nil {
		t.Fatal(err)
	}
	for _, account := range store.Accounts() {
		row, err := db.GetAccountByID(ctx, account.DBID)
		if err != nil {
			t.Fatal(err)
		}
		if account.IsCodexTurnStateRequire292() != parseTruthyCredential(row.GetCredential(CodexTurnStateRequire292CredentialKey)) {
			t.Fatal("reconcile failed to restore persisted strict 292 switch")
		}
	}
}
