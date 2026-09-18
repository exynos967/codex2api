package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/codex2api/auth"
)

// X-Codex-Turn-State 自动刷新器。
//
// 背景：上游铸造的 turn-state 有两种形态——292 字节的可复用正常形态，与 312
// 字节的 IP 绑定降智形态（拿到 312 的账号会被路由到降级模型）。本组件对开启
// 了刷新的账号做最小化探测请求（POST /responses，store=false 的几 token 输入），
// 经账号配置的专用代理换出口 IP，直到拿到 292 形态就回写为凭据级注入值
// （auth.CodexTurnStateCredentialKey），之后该账号所有出站请求自动携带。
//
// 触发方式：周期巡检（CODEX_TURN_STATE_REFRESH_INTERVAL，默认 45m，0 关闭）、
// 观测到降智 token 时的反应式触发（见 notifyDegradedTurnState）、管理端手动触发。

// codexTurnStateRefreshInterval 从环境变量读巡检周期。
func codexTurnStateRefreshInterval() time.Duration {
	raw := strings.TrimSpace(os.Getenv("CODEX_TURN_STATE_REFRESH_INTERVAL"))
	if raw == "" {
		return 45 * time.Minute
	}
	if d, err := time.ParseDuration(raw); err == nil && d > 0 {
		return d
	}
	return 0 // 显式的 0 / 非法值都视为关闭周期巡检
}

// codexTurnStateProbeDelay 连续探测间的间隔；测试可调小。
var codexTurnStateProbeDelay = 2 * time.Second

// codexTurnStateRefreshAttempts 单次触发内的最大探测次数（轮换代理池每次连接
// 换 IP，连探几次就该撞上正常出口；探测是真实请求，必须封顶）。
func codexTurnStateRefreshAttempts() int {
	raw := strings.TrimSpace(os.Getenv("CODEX_TURN_STATE_REFRESH_ATTEMPTS"))
	if raw == "" {
		return 8
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 8
	}
	if n > 30 {
		return 30
	}
	return n
}

// TurnStateRefreshResult 一次探测的结果。
type TurnStateRefreshResult struct {
	Length int    `json:"length"`
	Pinned bool   `json:"pinned"` // true = 拿到 292 并已回写
	State  string `json:"state,omitempty"`
	Error  string `json:"error,omitempty"`
}

// degradedTurnStateObserver 由 StartCodexTurnStateRefresh 安装：trace 链路
// （HTTP 响应头 / WS 帧）观测到降智形态 token 时回调。包级变量而非接口注入——
// trace 采集点是自由函数，拿不到 Handler。
var degradedTurnStateObserver atomic.Value // func(accountID int64)

// observeDegradedTurnState 在观测点调用：值为降智形态时通知刷新器（异步、带冷却）。
func observeDegradedTurnState(accountID int64, state string) {
	if len(strings.TrimSpace(state)) != auth.CodexTurnStateDegradedLength || accountID == 0 {
		return
	}
	if fn, ok := degradedTurnStateObserver.Load().(func(int64)); ok && fn != nil {
		go fn(accountID)
	}
}

// turnStateRefresher 挂在 Handler 上，持有去重/冷却状态。
type turnStateRefresher struct {
	h *Handler

	mu       sync.Mutex
	cooldown map[int64]time.Time // accountID -> 下次可反应式刷新的时刻
	running  map[int64]bool      // accountID -> 是否有刷新在途
}

func newTurnStateRefresher(h *Handler) *turnStateRefresher {
	return &turnStateRefresher{
		h:        h,
		cooldown: make(map[int64]time.Time),
		running:  make(map[int64]bool),
	}
}

// StartCodexTurnStateRefresh 启动周期巡检并安装降智观测回调。幂等；间隔为 0 时
// 只保留反应式/手动触发。
func (h *Handler) StartCodexTurnStateRefresh(ctx context.Context) {
	if h == nil || h.store == nil {
		return
	}
	h.turnStateRefreshStartOnce.Do(func() {
		// 降智观测回调：HTTP 响应头 / WS 帧里出现 312 形态时反应式刷新。
		// 与周期巡检独立安装——巡检关了，反应式触发仍然有效。
		degradedTurnStateObserver.Store(func(accountID int64) {
			if account := h.store.FindByID(accountID); account != nil {
				h.notifyDegradedTurnState(account)
			}
		})
		interval := codexTurnStateRefreshInterval()
		if interval <= 0 {
			return
		}
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
				h.refreshAllEnabledAccounts(ctx)
			}
		}()
	})
}

// refreshAllEnabledAccounts 巡检所有开启刷新的账号（并发 1，避免探测风暴）。
func (h *Handler) refreshAllEnabledAccounts(ctx context.Context) {
	for _, account := range h.store.Accounts() {
		if ctx.Err() != nil {
			return
		}
		enabled, _ := account.CodexTurnStateRefreshConfig()
		if !enabled {
			continue
		}
		if _, err := h.RefreshCodexTurnState(ctx, account); err != nil {
			log.Printf("[turn-state-refresh] account=%d 刷新失败: %v", account.ID(), err)
		}
	}
}

// notifyDegradedTurnState 观测到降智形态（312）token 时调用：带 2 分钟逐账号冷却的
// 反应式刷新。只通知开启刷新的账号。
func (h *Handler) notifyDegradedTurnState(account *auth.Account) {
	if h == nil || account == nil {
		return
	}
	enabled, _ := account.CodexTurnStateRefreshConfig()
	if !enabled {
		return
	}
	r := h.turnStateRefresher()
	now := time.Now()
	r.mu.Lock()
	if r.running[account.ID()] || now.Before(r.cooldown[account.ID()]) {
		r.mu.Unlock()
		return
	}
	r.cooldown[account.ID()] = now.Add(2 * time.Minute)
	r.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if _, err := h.RefreshCodexTurnState(ctx, account); err != nil {
			log.Printf("[turn-state-refresh] account=%d 反应式刷新失败: %v", account.ID(), err)
		}
	}()
}

func (h *Handler) turnStateRefresher() *turnStateRefresher {
	h.turnStateRefresherOnce.Do(func() {
		h.turnStateRefresh = newTurnStateRefresher(h)
	})
	return h.turnStateRefresh
}

// RefreshCodexTurnState 对单个账号执行一次探测刷新：成功拿到 292 形态即回写。
// 并发安全：同一账号同时在途的刷新只有一个。
func (h *Handler) RefreshCodexTurnState(ctx context.Context, account *auth.Account) (TurnStateRefreshResult, error) {
	if h == nil || h.store == nil {
		return TurnStateRefreshResult{}, fmt.Errorf("handler 未就绪")
	}
	if account == nil {
		return TurnStateRefreshResult{}, fmt.Errorf("账号为空")
	}
	r := h.turnStateRefresher()
	r.mu.Lock()
	if r.running[account.ID()] {
		r.mu.Unlock()
		return TurnStateRefreshResult{}, fmt.Errorf("该账号已有刷新在途")
	}
	r.running[account.ID()] = true
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.running, account.ID())
		r.mu.Unlock()
	}()

	enabled, refreshProxy := account.CodexTurnStateRefreshConfig()
	if !enabled {
		return TurnStateRefreshResult{}, fmt.Errorf("账号未开启 turn-state 自动刷新")
	}
	if account.IsCodexAgentIdentity() {
		return TurnStateRefreshResult{}, fmt.Errorf("Agent Identity 账号无 access_token，跳过")
	}

	account.Mu().RLock()
	accessToken := account.AccessToken
	account.Mu().RUnlock()
	if strings.TrimSpace(accessToken) == "" {
		return TurnStateRefreshResult{}, fmt.Errorf("账号无 access_token")
	}

	// 探测模型：注入的模型名单第一个（token 按模型不通用，探测谁就对谁生效）；
	// 未限定模型时无法确定探测对象，拒绝猜测。
	_, models, _ := account.CodexTurnStateConfig()
	model := firstCodexTurnStateModel(models)
	if model == "" {
		return TurnStateRefreshResult{}, fmt.Errorf("未配置 codex_turn_state_models 模型名单，无法确定探测对象")
	}

	// 探测走专用代理（刷 IP 的意义所在）；未配置时退回账号自身代理。
	proxyURL := refreshProxy
	if proxyURL == "" {
		account.Mu().RLock()
		proxyURL = account.ProxyURL
		account.Mu().RUnlock()
	}

	// 轮换代理池每次连接换出口 IP：单次触发内连续探测，拿到 292 立即停；
	// 次数有上限（探测是真实请求，烧少量 token，不能无限刷）。
	maxAttempts := codexTurnStateRefreshAttempts()
	var lastErr error
	lastLength := 0
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if ctx.Err() != nil {
			return TurnStateRefreshResult{Error: ctx.Err().Error()}, ctx.Err()
		}
		if attempt > 1 {
			select {
			case <-ctx.Done():
				return TurnStateRefreshResult{Error: ctx.Err().Error()}, ctx.Err()
			case <-time.After(codexTurnStateProbeDelay):
			}
		}
		state, status, err := h.probeCodexTurnState(ctx, account, accessToken, model, proxyURL)
		if err != nil {
			lastErr = err
			continue
		}
		lastLength = len(state)
		result := TurnStateRefreshResult{Length: len(state)}
		switch len(state) {
		case auth.CodexTurnStateGoodLength:
			if err := h.store.ApplyCodexTurnStateRefreshResult(ctx, account.ID(), state); err != nil {
				result.Error = err.Error()
				return result, err
			}
			result.Pinned = true
			log.Printf("[turn-state-refresh] account=%d model=%s 第 %d/%d 次探测固定 292 token", account.ID(), model, attempt, maxAttempts)
			return result, nil
		case auth.CodexTurnStateDegradedLength:
			lastErr = fmt.Errorf("上游返回降智形态（312）")
		case 0:
			lastErr = fmt.Errorf("上游未回传 turn-state（HTTP %d）", status)
		default:
			lastErr = fmt.Errorf("未知形态长度 %d（HTTP %d）", len(state), status)
		}
	}
	result := TurnStateRefreshResult{Length: lastLength, Error: fmt.Sprintf("%d 次探测均未拿到非降智 token：%v；请检查专用代理出口 IP 池", maxAttempts, lastErr)}
	return result, fmt.Errorf("%s", result.Error)
}

// codexTurnStateProbeURL 探测端点；测试可替换为本地 httptest 服务。
var codexTurnStateProbeURL = CodexBaseURL + "/responses"

// probeCodexTurnState 发一次最小化 Responses 请求，只为读响应头的 turn-state。
// 传输与头部走与真实推理完全相同的链路（rustls 指纹 + Codex 头），探测本身
// 就是一次真实客户端形态的回话。
func (h *Handler) probeCodexTurnState(ctx context.Context, account *auth.Account, accessToken, model, proxyURL string) (state string, status int, err error) {
	body, _ := json.Marshal(map[string]any{
		"model":  model,
		"stream": true,
		"store":  false,
		"input":  "ts",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, codexTurnStateProbeURL, bytes.NewReader(body))
	if err != nil {
		return "", 0, err
	}
	deviceCfg := h.deviceCfg
	if deviceCfg == nil {
		deviceCfg = &DeviceProfileConfig{}
	}
	applyCodexRequestHeaders(req, account, accessToken, "", "", deviceCfg, nil)

	client := &http.Client{Transport: newCodexTransport(proxyURL), Timeout: 30 * time.Second}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	// 只关心响应头；SSE 体读一点即弃。
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	return strings.TrimSpace(resp.Header.Get(codexTurnStateHeader)), resp.StatusCode, nil
}

// firstCodexTurnStateModel 取注入模型名单的第一个（名单是"逗号+空格"分隔的规整形态）。
func firstCodexTurnStateModel(models string) string {
	models = strings.TrimSpace(models)
	if models == "" {
		return ""
	}
	if i := strings.Index(models, ","); i >= 0 {
		return strings.TrimSpace(models[:i])
	}
	return models
}
