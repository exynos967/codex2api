package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

	mu           sync.Mutex
	cooldown     map[int64]time.Time          // accountID -> 下次可反应式刷新的时刻
	running      map[int64]bool               // accountID -> 是否有刷新在途
	refine       map[int64]context.CancelFunc // accountID -> 死磕循环的取消函数
	done         map[int64]chan struct{}
	strict       map[int64]*strictTurnStateTask
	lifecycle    context.Context
	refineProbes map[int64]int64 // accountID -> 死磕已发探测数（UI 计数）
}

func newTurnStateRefresher(h *Handler) *turnStateRefresher {
	return &turnStateRefresher{
		h:            h,
		done:         make(map[int64]chan struct{}),
		strict:       make(map[int64]*strictTurnStateTask),
		lifecycle:    context.Background(),
		cooldown:     make(map[int64]time.Time),
		running:      make(map[int64]bool),
		refine:       make(map[int64]context.CancelFunc),
		refineProbes: make(map[int64]int64),
	}
}

// StartCodexTurnStateRefresh 启动周期巡检并安装降智观测回调。幂等；间隔为 0 时
// 只保留反应式/手动触发。
func (h *Handler) StartCodexTurnStateRefresh(ctx context.Context) {
	if h == nil || h.store == nil {
		return
	}
	h.turnStateRefreshStartOnce.Do(func() {
		r := h.turnStateRefresher()
		r.mu.Lock()
		r.lifecycle = ctx
		r.mu.Unlock()
		strictTurnStateRefreshHandler.Store(h)
		// 降智观测回调：HTTP 响应头 / WS 帧里出现 312 形态时反应式刷新。
		// 与周期巡检独立安装——巡检关了，反应式触发仍然有效。
		degradedTurnStateObserver.Store(func(accountID int64) {
			if account := h.store.FindByID(accountID); account != nil {
				h.notifyDegradedTurnState(account)
			}
		})
		// 启动扫描：死磕开关已开的账号立即起循环（不依赖巡检间隔——
		// 巡检可能被 CODEX_TURN_STATE_REFRESH_INTERVAL=0 关闭，死磕独立）。
		for _, account := range h.store.Accounts() {
			pinned, _, _ := account.CodexTurnStateConfig()
			if len(pinned) == auth.CodexTurnStateGoodLength {
				continue
			}
			if account.IsCodexTurnStateRefineEnabled() {
				h.StartCodexTurnStateRefine(account)
			}
		}
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
		// 已有292不按保存时间换掉；实际响应出现312由观测路径触发刷新。
		pinned, _, _ := account.CodexTurnStateConfig()
		if len(pinned) == auth.CodexTurnStateGoodLength {
			continue
		}
		if h.CodexTurnStateRefining(account.ID()) {
			continue // 死磕循环已在同一条探测通道上跑
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
	if account.IsCodexTurnStateRefineEnabled() {
		h.StartCodexTurnStateRefine(account)
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

// failRefreshResult 守卫类失败的统一出口：错误文案必须进 result.Error——
// HTTP 层只序列化 result，Go error 到不了客户端，否则前端只能展示裸 JSON。
func failRefreshResult(err error) (TurnStateRefreshResult, error) {
	return TurnStateRefreshResult{Error: err.Error()}, err
}

// RefreshCodexTurnState 自动刷新入口（周期巡检/反应式触发）：遵守账号开关，
// 探测参数全部取已保存配置。成功拿到 292 形态即回写。
func (h *Handler) RefreshCodexTurnState(ctx context.Context, account *auth.Account) (TurnStateRefreshResult, error) {
	enabled, refreshProxy := account.CodexTurnStateRefreshConfig()
	if !enabled {
		return failRefreshResult(fmt.Errorf("账号未开启 turn-state 自动刷新"))
	}
	_, models, _ := account.CodexTurnStateConfig()
	return h.refreshCodexTurnStateWith(ctx, account, refreshProxy, models)
}

// RefreshCodexTurnStateManual 管理端手动刷新入口：不看开关（点击本身就是授权），
// 代理与模型名单从请求带入——表单里改了没保存也能用当前值探测，避免
// "先保存才能刷"的操作陷阱。空值回落到已保存配置。
func (h *Handler) RefreshCodexTurnStateManual(ctx context.Context, account *auth.Account, proxyOverride, modelsOverride string) (TurnStateRefreshResult, error) {
	proxyURL := strings.TrimSpace(proxyOverride)
	if proxyURL == "" {
		_, proxyURL = account.CodexTurnStateRefreshConfig()
	}
	models := strings.TrimSpace(modelsOverride)
	if models == "" {
		_, models, _ = account.CodexTurnStateConfig()
	}
	return h.refreshCodexTurnStateWith(ctx, account, proxyURL, models)
}

// refreshCodexTurnStateWith 探测刷新核心。并发安全：同一账号同时在途的刷新只有一个。
func (h *Handler) refreshCodexTurnStateWith(ctx context.Context, account *auth.Account, refreshProxy, models string) (TurnStateRefreshResult, error) {
	if h == nil || h.store == nil {
		return failRefreshResult(fmt.Errorf("handler 未就绪"))
	}
	if account == nil {
		return failRefreshResult(fmt.Errorf("账号为空"))
	}
	r := h.turnStateRefresher()
	r.mu.Lock()
	if r.running[account.ID()] || r.strict[account.ID()] != nil {
		r.mu.Unlock()
		return failRefreshResult(fmt.Errorf("该账号已有刷新在途"))
	}
	r.running[account.ID()] = true
	r.done[account.ID()] = make(chan struct{})
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.running, account.ID())
		close(r.done[account.ID()])
		delete(r.done, account.ID())
		r.mu.Unlock()
	}()

	if account.IsCodexAgentIdentity() {
		return failRefreshResult(fmt.Errorf("Agent Identity 账号无 access_token，跳过"))
	}

	account.Mu().RLock()
	accessToken := account.AccessToken
	account.Mu().RUnlock()
	if strings.TrimSpace(accessToken) == "" {
		return failRefreshResult(fmt.Errorf("账号无 access_token"))
	}

	// 探测模型：注入的模型名单第一个（token 按模型不通用，探测谁就对谁生效）；
	// 未限定模型时无法确定探测对象，拒绝猜测。
	model := firstCodexTurnStateModel(models)
	if model == "" {
		return failRefreshResult(fmt.Errorf("未配置 codex_turn_state_models 模型名单，无法确定探测对象"))
	}

	// 探测走专用代理（刷 IP 的意义所在）；未配置时退回账号自身代理。
	proxyURL := strings.TrimSpace(refreshProxy)
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
			if codexTurnStateProbeRequiresCorrection(status) {
				return failRefreshResult(err)
			}
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
			result.State = state
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

// —— 死磕刷新（refine）：不限次数连续探测，拿到 292 不降智 token 才停 ——
//
// 与自动刷新的关系：自动刷新是"定时/触发式、单次触发有次数上限"的温和策略；
// 死磕是运维明确授权的持续探测（每次探测都是真实请求、烧少量 token），用于
// 轮换代理池 IP 命中率低、需要在后台一直磨的场景。死磕期间占用与刷新相同的
// running 槽位——同一账号的探测通道只有一条，周期/反应式/手动刷新会报
// "已有刷新在途"。

// StartCodexTurnStateRefine 启动死磕循环。幂等：已在跑的账号返回 true 不重复起。
func (h *Handler) StartCodexTurnStateRefine(account *auth.Account) bool {
	if h == nil || h.store == nil || account == nil {
		return false
	}
	r := h.turnStateRefresher()
	id := account.ID()
	r.mu.Lock()
	if _, ok := r.refine[id]; ok {
		r.mu.Unlock()
		return true
	}
	// 与刷新互斥：有刷新在途时不抢占（刷新结束后调用方重开即可）。
	if r.running[id] || r.strict[id] != nil {
		r.mu.Unlock()
		return false
	}
	r.running[id] = true
	r.done[id] = make(chan struct{})
	r.refineProbes[id] = 0
	loopCtx, cancel := context.WithCancel(r.lifecycle)
	r.refine[id] = cancel
	r.mu.Unlock()
	log.Printf("[turn-state-refresh] account=%d 死磕刷新启动", id)
	go h.refineTurnStateLoop(loopCtx, id)
	return true
}

// StopCodexTurnStateRefine 停止死磕循环；返回是否真有在跑的循环被停。
func (h *Handler) StopCodexTurnStateRefine(accountID int64) bool {
	if h == nil {
		return false
	}
	r := h.turnStateRefresher()
	r.mu.Lock()
	cancel, ok := r.refine[accountID]
	strict := r.strict[accountID]
	if ok {
		delete(r.refine, accountID)
		cancel()
	}
	if strict != nil && !strict.stopped {
		strict.stopped = true
		strict.cancel()
		// 旧等待者仍持任务指针并返回取消，新请求可排队等待槽位真正释放。
		delete(r.strict, accountID)
		ok = true
	}
	r.mu.Unlock()
	if !ok {
		return false
	}
	log.Printf("[turn-state-refresh] account=%d 死磕刷新已手动停止", accountID)
	return true
}

// CodexTurnStateRefining 报告账号是否在死磕中（管理端 UI 状态轮询用）。
func (h *Handler) CodexTurnStateRefining(accountID int64) bool {
	refining, _ := h.CodexTurnStateRefineStats(accountID)
	return refining
}

// CodexTurnStateRefineStats 返回死磕循环的运行状态与累计探测数（UI"已刷新 N 次"）。
func (h *Handler) CodexTurnStateRefineStats(accountID int64) (refining bool, probes int64) {
	if h == nil {
		return false, 0
	}
	r := h.turnStateRefresher()
	r.mu.Lock()
	_, refining = r.refine[accountID]
	if task := r.strict[accountID]; task != nil && !task.stopped {
		refining = true
	}
	probes = r.refineProbes[accountID]
	r.mu.Unlock()
	return refining, probes
}

// codexTurnStateRefineParallel 死磕单轮并发探测数。轮换代理池每次连接换出口
// IP，但是否实际轮换取决于代理配置；取消前已经发出的请求仍可能消耗额度。
// CODEX_TURN_STATE_REFINE_PARALLEL 可调（1-8，默认 8；1 = 退回串行形态）。
func codexTurnStateRefineParallel() int {
	raw := strings.TrimSpace(os.Getenv("CODEX_TURN_STATE_REFINE_PARALLEL"))
	if raw == "" {
		return 8
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 8
	}
	if n > 8 {
		return 8
	}
	return n
}

// refineProbeOutcome 一发并发探测的结果。
type refineProbeOutcome struct {
	state  string
	status int
	err    error
}

func (h *Handler) refineTurnStateLoop(ctx context.Context, accountID int64) {
	r := h.turnStateRefresher()
	defer func() {
		r.mu.Lock()
		delete(r.refine, accountID)
		delete(r.running, accountID)
		delete(r.refineProbes, accountID)
		close(r.done[accountID])
		delete(r.done, accountID)
		r.mu.Unlock()
	}()
	_, err := h.probeCodexTurnStateUntilGood(ctx, accountID, "", "", false)
	if err != nil {
		log.Printf("[turn-state-refresh] account=%d 死磕退出: %v", accountID, err)
	}
}

// probeCodexTurnStateUntilGood 供后台死磕与严格请求共享；成功必须先完成持久化。
func (h *Handler) probeCodexTurnStateUntilGood(ctx context.Context, accountID int64, requestModel, proxyOverride string, strict bool) (string, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// 开关和账号变更没有通知通道；轮询授权以取消正在等待响应头的请求，不设任务 TTL。
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := h.turnStateProbeAccount(accountID, strict); err != nil {
					cancel()
					return
				}
			}
		}
	}()
	defer func() { cancel(); <-watchDone }()
	parallel := codexTurnStateRefineParallel()
	r := h.turnStateRefresher()
	for round := 1; ; round++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		account, err := h.turnStateProbeAccount(accountID, strict)
		if err != nil {
			return "", err
		}
		model := requestModel
		if !strict {
			_, models, _ := account.CodexTurnStateConfig()
			model = firstCodexTurnStateModel(models)
		}
		if model == "" {
			return "", fmt.Errorf("未配置探测模型")
		}
		account.Mu().RLock()
		accessToken, accountProxy := account.AccessToken, account.ProxyURL
		account.Mu().RUnlock()
		if strings.TrimSpace(accessToken) == "" {
			return "", fmt.Errorf("账号无 access_token")
		}
		_, refreshProxy := account.CodexTurnStateRefreshConfig()
		proxyURL := strings.TrimSpace(refreshProxy)
		if proxyURL == "" {
			proxyURL = strings.TrimSpace(proxyOverride)
		}
		if proxyURL == "" {
			proxyURL = accountProxy
		}
		roundCtx, cancelRound := context.WithCancel(ctx)
		results := make(chan refineProbeOutcome, parallel)
		r.mu.Lock()
		r.refineProbes[accountID] += int64(parallel)
		r.mu.Unlock()
		var wg sync.WaitGroup
		for i := 0; i < parallel; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				state, status, err := h.probeCodexTurnState(roundCtx, account, accessToken, model, proxyURL)
				results <- refineProbeOutcome{state: state, status: status, err: err}
			}()
		}
		var hit string
		var correctionErr, lastErr error
		statuses := make(map[int]int)
		degraded, empty, other, failed := 0, 0, 0, 0
		for i := 0; i < parallel; i++ {
			out := <-results
			if out.status != 0 {
				statuses[out.status]++
			}
			if out.err != nil {
				failed++
				if lastErr == nil && roundCtx.Err() == nil {
					lastErr = out.err
				}
			} else {
				switch len(out.state) {
				case auth.CodexTurnStateDegradedLength:
					degraded++
				case 0:
					empty++
				case auth.CodexTurnStateGoodLength:
				default:
					other++
				}
			}
			if out.err != nil && codexTurnStateProbeRequiresCorrection(out.status) {
				correctionErr = out.err
				cancelRound()
			}
			if out.err == nil && len(out.state) == auth.CodexTurnStateGoodLength && hit == "" {
				hit = out.state
				cancelRound()
			}
		}
		wg.Wait()
		cancelRound()
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if _, err := h.turnStateProbeAccount(accountID, strict); err != nil {
			return "", err
		}
		if correctionErr != nil {
			return "", correctionErr
		}
		if hit != "" {
			if err := h.store.ApplyCodexTurnStateRefreshResult(ctx, accountID, hit); err != nil {
				return "", err
			}
			if err := ctx.Err(); err != nil {
				return "", err
			}
			log.Printf("[turn-state-refresh] account=%d model=%s 第 %d 轮固定 292 token", accountID, model, round)
			return hit, nil
		}
		log.Printf("[turn-state-refresh] account=%d 第 %d 轮（%d 并发）HTTP=%v 312=%d 空=%d 其他=%d 失败=%d 错误=%v", accountID, round, parallel, statuses, degraded, empty, other, failed, lastErr)
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(codexTurnStateProbeDelay):
		}
	}
}

func (h *Handler) turnStateProbeAccount(accountID int64, strict bool) (*auth.Account, error) {
	account := h.store.FindByID(accountID)
	if account == nil {
		return nil, fmt.Errorf("账号已删除")
	}
	if strict && !account.IsCodexTurnStateRequire292() {
		return nil, fmt.Errorf("严格 292 开关已关闭")
	}
	if !strict && !account.IsCodexTurnStateRefineEnabled() {
		return nil, fmt.Errorf("死磕开关已关闭")
	}
	if account.IsCodexAgentIdentity() {
		return nil, fmt.Errorf("Agent Identity 账号无 access_token")
	}
	return account, nil
}

// codexTurnStateProbeURL 探测端点；测试可替换为本地 httptest 服务。
var codexTurnStateProbeURL = CodexBaseURL + "/responses"

// probeCodexTurnState 发一次最小化 Responses 请求，只为读响应头的 turn-state。
// 传输与头部走与真实推理完全相同的链路（rustls 指纹 + Codex 头），探测本身
// 就是一次真实客户端形态的回话。
func (h *Handler) probeCodexTurnState(ctx context.Context, account *auth.Account, accessToken, model, proxyURL string) (state string, status int, err error) {
	// 此处直连官方，使用消息数组；不是中转网关可接收的 input 字符串。
	body, _ := json.Marshal(map[string]any{
		"model":        model,
		"stream":       true,
		"store":        false,
		"instructions": "",
		"input": []any{map[string]any{
			"type": "message", "role": "user",
			"content": []any{map[string]any{"type": "input_text", "text": "ts"}},
		}},
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
	// 索取新state不能被自定义旧state钉住；最小探测请求使用非Lite协议。
	req.Header.Del(codexTurnStateHeader)
	req.Header.Del(codexResponsesLiteHeader)
	client := &http.Client{Transport: newCodexTransport(proxyURL), Timeout: 30 * time.Second}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	// 只取头并关闭流，不等SSE正文；不输出可能含敏感回显的响应体。
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", resp.StatusCode, fmt.Errorf("turn-state 探测被拒绝：HTTP %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	return strings.TrimSpace(resp.Header.Get(codexTurnStateHeader)), resp.StatusCode, nil
}

// 403可能是出口拦截，408/429可重试；其它4xx需修正请求或凭据。
// TLS及5xx仍保留可取消重试，不能当作有效的token获取。
func codexTurnStateProbeRequiresCorrection(status int) bool {
	return status >= 400 && status < 500 && status != http.StatusForbidden && status != http.StatusRequestTimeout && status != http.StatusTooManyRequests
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
