package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/database"
	"github.com/codex2api/proxy"

	"github.com/gin-gonic/gin"
)

func TestParseAccountSchedulerUpdateCodexTurnState(t *testing.T) {
	update, err := parseAccountSchedulerUpdate(updateAccountSchedulerReq{
		CodexTurnState:       json.RawMessage(`"  state-one "`),
		CodexTurnStateModels: json.RawMessage(`" GPT-5.5, gpt-5* ,gpt-5.5"`),
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !update.hasChanges() {
		t.Fatal("turn state fields must count as changes")
	}
	if got := update.CredentialUpdates[auth.CodexTurnStateCredentialKey]; got != "state-one" {
		t.Fatalf("value credential = %#v", got)
	}
	if got := update.CredentialUpdates[auth.CodexTurnStateModelsCredentialKey]; got != "gpt-5.5, gpt-5*" {
		t.Fatalf("models credential = %#v", got)
	}
	setAt, _ := update.CredentialUpdates[auth.CodexTurnStateSetAtCredentialKey].(string)
	if auth.ParseCodexTurnStateSetAt(setAt).IsZero() {
		t.Fatalf("set_at must default to now for a fresh value, got %q", setAt)
	}

	cleared, err := parseAccountSchedulerUpdate(updateAccountSchedulerReq{CodexTurnState: json.RawMessage(`null`)})
	if err != nil {
		t.Fatalf("parse null: %v", err)
	}
	if got := cleared.CredentialUpdates[auth.CodexTurnStateCredentialKey]; got != "" {
		t.Fatalf("null must clear the value, got %#v", got)
	}
	if got := cleared.CredentialUpdates[auth.CodexTurnStateSetAtCredentialKey]; got != "" {
		t.Fatalf("clearing must reset set_at, got %#v", got)
	}

	modelsOnly, err := parseAccountSchedulerUpdate(updateAccountSchedulerReq{CodexTurnStateModels: json.RawMessage(`"gpt-5"`)})
	if err != nil {
		t.Fatalf("parse models only: %v", err)
	}
	if _, touched := modelsOnly.CredentialUpdates[auth.CodexTurnStateSetAtCredentialKey]; touched {
		t.Fatal("models-only edit must not touch set_at")
	}

	if _, err := parseAccountSchedulerUpdate(updateAccountSchedulerReq{CodexTurnState: json.RawMessage(`"a\nb"`)}); err == nil {
		t.Fatal("multi-line value must be rejected")
	}
}

// 时效起点只在注入值真正换掉时重置：原样重提同一个值保留旧起点，存量行没有起点时补一次。
func TestRefineCodexTurnStateSetAt(t *testing.T) {
	previous := time.Date(2026, 9, 17, 9, 0, 0, 0, time.UTC).Format(time.RFC3339)
	row := &database.AccountRow{Credentials: map[string]interface{}{
		auth.CodexTurnStateCredentialKey:      "state-one",
		auth.CodexTurnStateSetAtCredentialKey: previous,
	}}

	same, _ := parseAccountSchedulerUpdate(updateAccountSchedulerReq{CodexTurnState: json.RawMessage(`"state-one"`)})
	refineCodexTurnStateSetAt(row, same)
	if _, touched := same.CredentialUpdates[auth.CodexTurnStateSetAtCredentialKey]; touched {
		t.Fatal("re-submitting the same value must keep the old set_at")
	}

	replaced, _ := parseAccountSchedulerUpdate(updateAccountSchedulerReq{CodexTurnState: json.RawMessage(`"state-two"`)})
	refineCodexTurnStateSetAt(row, replaced)
	if got, _ := replaced.CredentialUpdates[auth.CodexTurnStateSetAtCredentialKey].(string); got == "" || got == previous {
		t.Fatalf("replacing the value must reset set_at, got %q", got)
	}

	legacy := &database.AccountRow{Credentials: map[string]interface{}{auth.CodexTurnStateCredentialKey: "state-one"}}
	backfill, _ := parseAccountSchedulerUpdate(updateAccountSchedulerReq{CodexTurnState: json.RawMessage(`"state-one"`)})
	refineCodexTurnStateSetAt(legacy, backfill)
	if got, _ := backfill.CredentialUpdates[auth.CodexTurnStateSetAtCredentialKey].(string); got == "" {
		t.Fatal("legacy row without set_at must be backfilled on re-save")
	}
}

// TestCodexTurnStateRefreshConfigSaveLifecycle 钉死"保存自动刷新配置 → 刷新生效"
// 闭环：PATCH 写入凭据后，运行时账号必须立刻能过刷新开关守卫——否则管理端
// 点了保存却刷不动的坑会反复出现。
func TestCodexTurnStateRefreshConfigSaveLifecycle(t *testing.T) {
	db := newTestAdminDB(t)
	store := auth.NewStore(db, nil, nil)
	t.Cleanup(store.Stop)
	h := &Handler{db: db, store: store}

	id, err := db.InsertAccountWithCredentials(context.Background(), "codex-a", map[string]interface{}{
		"upstream_type": auth.UpstreamOpenAIResponses,
		"access_token":  "test-access-token",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.LoadAccountByID(context.Background(), id); err != nil {
		t.Fatal(err)
	}

	// 只改刷新配置也应算变更（hasChanges 不能把刷新字段漏掉）。
	update, err := parseAccountSchedulerUpdate(updateAccountSchedulerReq{
		CodexTurnStateRefreshEnabled: json.RawMessage(`"true"`),
		CodexTurnStateRefreshProxy:   json.RawMessage(`"socks5h://user:pass@127.0.0.1:1080"`),
		CodexTurnStateModels:         json.RawMessage(`"gpt-5.5, gpt-5*"`),
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !update.hasChanges() {
		t.Fatal("refresh-only update must count as changes")
	}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Params = gin.Params{{Key: "id", Value: fmt.Sprint(id)}}
	c.Request = httptest.NewRequest(http.MethodPatch, fmt.Sprintf("/api/admin/accounts/%d/scheduler", id),
		strings.NewReader(`{
			"codex_turn_state_refresh_enabled": "true",
			"codex_turn_state_refresh_proxy": "socks5h://user:pass@127.0.0.1:1080",
			"codex_turn_state_models": "gpt-5.5, gpt-5*"
		}`))
	h.UpdateAccountScheduler(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("保存失败: %d %s", rec.Code, rec.Body.String())
	}

	// 1) 落库
	row, err := db.GetAccountByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if got := row.GetCredential(auth.CodexTurnStateRefreshEnabledCredentialKey); got != "true" {
		t.Fatalf("enabled 未落库: %q", got)
	}
	if got := row.GetCredential(auth.CodexTurnStateRefreshProxyCredentialKey); got != "socks5h://user:pass@127.0.0.1:1080" {
		t.Fatalf("proxy 未落库: %q", got)
	}

	// 2) 运行时同步（刷新守卫读的就是这里）
	account := store.FindByID(id)
	if account == nil {
		t.Fatal("运行时账号不存在")
	}
	enabled, proxy := account.CodexTurnStateRefreshConfig()
	if !enabled || proxy != "socks5h://user:pass@127.0.0.1:1080" {
		t.Fatalf("运行时未同步: enabled=%v proxy=%q", enabled, proxy)
	}
	_, models, _ := account.CodexTurnStateConfig()
	if models != "gpt-5.5, gpt-5*" {
		t.Fatalf("模型名单未同步: %q", models)
	}
}

// TestCodexTurnStateRefineLifecycle 钉死"保存死磕开关 → 运行时同步 → 停止端点"闭环。
func TestCodexTurnStateRefineLifecycle(t *testing.T) {
	db := newTestAdminDB(t)
	store := auth.NewStore(db, nil, nil)
	t.Cleanup(store.Stop)
	h := &Handler{db: db, store: store, authCacheProxy: &proxy.Handler{}}

	id, err := db.InsertAccountWithCredentials(context.Background(), "codex-b", map[string]interface{}{
		"upstream_type": auth.UpstreamOpenAIResponses,
		"access_token":  "test-access-token",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.LoadAccountByID(context.Background(), id); err != nil {
		t.Fatal(err)
	}

	// 只改死磕开关也算变更。
	update, err := parseAccountSchedulerUpdate(updateAccountSchedulerReq{
		CodexTurnStateRefineEnabled: json.RawMessage(`"true"`),
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !update.hasChanges() {
		t.Fatal("refine-only update must count as changes")
	}
	if got := update.CredentialUpdates[auth.CodexTurnStateRefineEnabledCredentialKey]; got != "true" {
		t.Fatalf("refine credential = %#v", got)
	}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Params = gin.Params{{Key: "id", Value: fmt.Sprint(id)}}
	c.Request = httptest.NewRequest(http.MethodPatch, fmt.Sprintf("/api/admin/accounts/%d/scheduler", id),
		strings.NewReader(`{"codex_turn_state_refine_enabled": "true"}`))
	h.UpdateAccountScheduler(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("保存失败: %d %s", rec.Code, rec.Body.String())
	}

	// 落库 + 运行时同步。
	row, err := db.GetAccountByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if got := row.GetCredential(auth.CodexTurnStateRefineEnabledCredentialKey); got != "true" {
		t.Fatalf("refine 开关未落库: %q", got)
	}
	account := store.FindByID(id)
	if account == nil || !account.IsCodexTurnStateRefineEnabled() {
		t.Fatal("运行时死磕开关未同步")
	}

	// 停止端点：无循环在跑时 stopped=false、refining=false（不报错）。
	rec2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(rec2)
	c2.Params = gin.Params{{Key: "id", Value: fmt.Sprint(id)}}
	c2.Request = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/admin/accounts/%d/codex-turn-state/refine/stop", id), nil)
	h.StopCodexTurnStateRefine(c2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("停止端点失败: %d %s", rec2.Code, rec2.Body.String())
	}
	if !strings.Contains(rec2.Body.String(), `"stopped":false`) {
		t.Fatalf("无循环时应 stopped=false: %s", rec2.Body.String())
	}
}
