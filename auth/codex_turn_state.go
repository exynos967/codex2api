package auth

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// 凭据级 X-Codex-Turn-State 强制注入。运维把一个上游铸造的回合状态值粘到账号上，
// 网关在该账号的每个出站 Codex 请求上强制携带它（HTTP 头与 WebSocket 帧体两条路都
// 覆盖），优先于客户端回带值与账号自定义头。它不是身份：改它不影响在途请求归属，
// 也不进调度。与 proxy/codex_turn_state.go 的"跨账号回声剥离"互补——那边处理客户端
// 自己回带的值，这边处理运维显式配置的值。
const (
	CodexTurnStateCredentialKey       = "codex_turn_state"
	CodexTurnStateModelsCredentialKey = "codex_turn_state_models"
	// CodexTurnStateSetAtCredentialKey 记录注入值最后一次被换掉的时刻（RFC3339）。
	// 只服务于界面上的 1 小时时效倒计时：换值时重置，只改模型名单时保持不变。
	CodexTurnStateSetAtCredentialKey = "codex_turn_state_set_at"

	// CodexTurnStateRefreshEnabledCredentialKey / CodexTurnStateRefreshProxyCredentialKey
	// 控制 turn-state 自动刷新（见 proxy/codex_turn_state_refresh.go）：开启后网关
	// 定期/在观测到降智 token（长度 312）时，经专用代理向上游探测新 token，
	// 只接受不降智形态（长度 292）并回写注入值。专用代理用于换出口 IP——312 形态
	// 与铸造 IP 绑定，换 IP 是拿到 292 的前提。
	CodexTurnStateRefreshEnabledCredentialKey = "codex_turn_state_refresh_enabled"
	CodexTurnStateRefreshProxyCredentialKey   = "codex_turn_state_refresh_proxy"

	// Codex turn-state token 形态（参考 turnstate 过滤器实测）：292 可复用不降智，
	// 312 为 IP 绑定的降智形态。
	CodexTurnStateGoodLength     = 292
	CodexTurnStateDegradedLength = 312

	// maxCodexTurnStateBytes：实测值在 300 字符上下，留一个数量级余量即可。
	maxCodexTurnStateBytes       = 4096
	maxCodexTurnStateModelsBytes = 1024
)

// ValidateCodexTurnState 只放行能原样进 HTTP 头的单行 ASCII 可见字符串。不做截断——
// 截断后的 state 上游必然拒收，不如让操作者自己看见长度超限。
func ValidateCodexTurnState(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if len(value) > maxCodexTurnStateBytes {
		return fmt.Errorf("codex_turn_state 长度不能超过 %d 字节", maxCodexTurnStateBytes)
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] > 0x7e {
			return fmt.Errorf("codex_turn_state 只能包含单行 ASCII 可见字符")
		}
	}
	return nil
}

// NormalizeCodexTurnStateModels 把模型名单规整成"逗号+空格"分隔、小写、去重的形态；
// 空串表示不限模型。
func NormalizeCodexTurnStateModels(value string) string {
	seen := make(map[string]struct{})
	entries := make([]string, 0, 4)
	for _, entry := range strings.Split(value, ",") {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry == "" {
			continue
		}
		if _, dup := seen[entry]; dup {
			continue
		}
		seen[entry] = struct{}{}
		entries = append(entries, entry)
	}
	return strings.Join(entries, ", ")
}

func ValidateCodexTurnStateModels(value string) error {
	if len(value) > maxCodexTurnStateModelsBytes {
		return fmt.Errorf("codex_turn_state_models 长度不能超过 %d 字节", maxCodexTurnStateModelsBytes)
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] > 0x7e {
			return fmt.Errorf("codex_turn_state_models 只能包含 ASCII 可见字符")
		}
	}
	return nil
}

// CodexTurnStateModelsMatch 判定模型名单是否命中。名单为空表示不限模型；条目大小写
// 不敏感，结尾的 * 做前缀匹配。传入的多个模型名（客户端模型、上游模型）任一命中即
// 算命中——映射改写之后两者常常不是同一个名字，而操作者填的通常是自己请求时用的那个。
//
// 一个模型名都拿不到时按命中处理：名单是用来"缩小"注入范围的，筛不动的时候应该
// 放行而不是静默吞掉注入（补全/生图等不带 model 的出站请求会走到这里）。
func CodexTurnStateModelsMatch(scope string, models ...string) bool {
	entries := make([]string, 0, 4)
	for _, entry := range strings.Split(scope, ",") {
		if entry = strings.TrimSpace(entry); entry != "" {
			entries = append(entries, entry)
		}
	}
	if len(entries) == 0 {
		return true
	}
	known := false
	for _, model := range models {
		if strings.TrimSpace(model) != "" {
			known = true
			break
		}
	}
	if !known {
		return true
	}
	for _, entry := range entries {
		prefix, wildcard := strings.CutSuffix(entry, "*")
		for _, model := range models {
			model = strings.TrimSpace(model)
			if model == "" {
				continue
			}
			if wildcard && strings.HasPrefix(strings.ToLower(model), strings.ToLower(prefix)) {
				return true
			}
			if !wildcard && strings.EqualFold(model, entry) {
				return true
			}
		}
	}
	return false
}

// ParseCodexTurnStateSetAt 解析凭据里的设置时刻；空或非法返回零值。
func ParseCodexTurnStateSetAt(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	if ts, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return ts
	}
	if ts, err := time.Parse(time.RFC3339, raw); err == nil {
		return ts
	}
	return time.Time{}
}

// CodexTurnStateInjection 返回本次请求真正要注入的值，空串表示不注入（没配、或被
// 模型名单挡掉）。转发与用量日志都走这一个入口，两边不会对"注入了没有"给出不同答案。
func (a *Account) CodexTurnStateInjection(models ...string) string {
	if a == nil {
		return ""
	}
	a.mu.RLock()
	value, scope := a.CodexTurnState, a.CodexTurnStateModels
	a.mu.RUnlock()
	value = strings.TrimSpace(value)
	if value == "" || !CodexTurnStateModelsMatch(scope, models...) {
		return ""
	}
	return value
}

// CodexTurnStateConfig 返回配置快照（值、模型名单、设置时刻）。
func (a *Account) CodexTurnStateConfig() (value, models string, setAt time.Time) {
	if a == nil {
		return "", "", time.Time{}
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.CodexTurnState, a.CodexTurnStateModels, a.CodexTurnStateSetAt
}

func (a *Account) setCodexTurnStateFromRowLocked(row interface {
	GetCredential(string) string
}) {
	a.CodexTurnState = strings.TrimSpace(row.GetCredential(CodexTurnStateCredentialKey))
	a.CodexTurnStateModels = NormalizeCodexTurnStateModels(row.GetCredential(CodexTurnStateModelsCredentialKey))
	a.CodexTurnStateSetAt = ParseCodexTurnStateSetAt(row.GetCredential(CodexTurnStateSetAtCredentialKey))
	a.CodexTurnStateRefreshEnabled = parseTruthyCredential(row.GetCredential(CodexTurnStateRefreshEnabledCredentialKey))
	a.CodexTurnStateRefreshProxy = strings.TrimSpace(row.GetCredential(CodexTurnStateRefreshProxyCredentialKey))
}

// parseTruthyCredential 解析凭据里的布尔开关（"1"/"true"/"yes"/"on" 为真）。
func parseTruthyCredential(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// CodexTurnStateRefreshConfig 返回自动刷新配置快照（是否开启、专用探测代理）。
func (a *Account) CodexTurnStateRefreshConfig() (enabled bool, proxy string) {
	if a == nil {
		return false, ""
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.CodexTurnStateRefreshEnabled, a.CodexTurnStateRefreshProxy
}

// ApplyAccountCodexTurnState 把管理端保存的注入配置立即发布到运行时账号。
func (s *Store) ApplyAccountCodexTurnState(id int64, value, models string, setAt time.Time) {
	if a := s.FindByID(id); a != nil {
		a.mu.Lock()
		a.CodexTurnState = strings.TrimSpace(value)
		a.CodexTurnStateModels = NormalizeCodexTurnStateModels(models)
		a.CodexTurnStateSetAt = setAt
		a.mu.Unlock()
	}
}

// ApplyCodexTurnStateRefreshResult 把自动刷新探测到的非降智 token 持久化并发布
// 到运行时（只动注入值与设置时刻，不碰模型名单）。CAS 失败（凭据代际已变）返回
// 错误，由调用方决定重试或放弃——宁可丢一次刷新也不能覆盖并发写入。
func (s *Store) ApplyCodexTurnStateRefreshResult(ctx context.Context, id int64, value string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("存储未就绪")
	}
	a := s.FindByID(id)
	if a == nil {
		return fmt.Errorf("账号 %d 不存在", id)
	}
	value = strings.TrimSpace(value)
	setAt := time.Now().UTC()
	_, applied, err := s.db.UpdateAccountCredentialsCAS(ctx, id, a.GetCredentialGeneration(), map[string]any{
		CodexTurnStateCredentialKey:      value,
		CodexTurnStateSetAtCredentialKey: setAt.Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	if !applied {
		return fmt.Errorf("账号 %d 凭据代际冲突，刷新结果未落库", id)
	}
	a.mu.Lock()
	a.CodexTurnState = value
	a.CodexTurnStateSetAt = setAt
	a.mu.Unlock()
	return nil
}

// ApplyAccountCodexTurnStateRefresh 把管理端保存的自动刷新配置发布到运行时账号。
func (s *Store) ApplyAccountCodexTurnStateRefresh(id int64, enabled bool, proxyURL string) {
	if a := s.FindByID(id); a != nil {
		a.mu.Lock()
		a.CodexTurnStateRefreshEnabled = enabled
		a.CodexTurnStateRefreshProxy = strings.TrimSpace(proxyURL)
		a.mu.Unlock()
	}
}
