package proxy

import (
	"context"
	"net/http"
	"strings"
	"sync"

	"github.com/codex2api/auth"
	"github.com/codex2api/database"
	"github.com/codex2api/security"
	"github.com/gin-gonic/gin"
)

type upstreamTraceContextKey struct{}
type upstreamTraceAttempt struct {
	accountID int64
	requestID string
	proxy     auth.ProxyAuditLabel
	// injectedTurnState 是本次尝试实际注入到出站请求上的凭据级 X-Codex-Turn-State；
	// upstreamTurnState 是上游响应回带的观测值。均为空串表示没有。
	injectedTurnState string
	upstreamTurnState string
	// upstreamResponseModel 是上游自报的实际出活模型（openai-model 响应头 /
	// WS response.metadata 帧），空串表示未观测。
	upstreamResponseModel string
}

type upstreamTraceSnapshot struct {
	RequestID         string
	accountID         int64
	UpstreamRequestID string
	Proxy             auth.ProxyAuditLabel
	InjectedTurnState string
	UpstreamTurnState string
	UpstreamModel     string
}

func snapshotUpstreamTrace(ctx context.Context) upstreamTraceSnapshot {
	a := upstreamTraceFromContext(ctx)
	if a == nil {
		return upstreamTraceSnapshot{}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	result := upstreamTraceSnapshot{RequestID: a.requestID}
	if a.current != nil {
		result.accountID = a.current.accountID
		result.UpstreamRequestID = a.current.requestID
		result.Proxy = a.current.proxy
		result.InjectedTurnState = a.current.injectedTurnState
		result.UpstreamTurnState = a.current.upstreamTurnState
		result.UpstreamModel = a.current.upstreamResponseModel
	}
	return result
}

// upstreamModelMismatch 比对发往上游的模型与上游自报的实际出活模型。
// 三态：未观测（上游没报）→ nil；不一致 → true。大小写不敏感等值判一致
// （与真实 codex 客户端读 openai-model 头的口径一致）。
func upstreamModelMismatch(sentModel, upstreamModel string) *bool {
	upstreamModel = strings.TrimSpace(upstreamModel)
	if upstreamModel == "" {
		return nil
	}
	mismatch := !strings.EqualFold(strings.TrimSpace(sentModel), upstreamModel)
	return &mismatch
}

func (s upstreamTraceSnapshot) apply(input *database.UsageLogInput) {
	input.RequestID = s.RequestID
	if s.accountID == input.AccountID {
		input.UpstreamRequestID = s.UpstreamRequestID
		input.UpstreamProxyID = s.Proxy.ID
		input.UpstreamProxyName = s.Proxy.Name
		input.InjectedTurnState = s.InjectedTurnState
		input.UpstreamTurnState = s.UpstreamTurnState
		input.UpstreamResponseModel = s.UpstreamModel
		input.UpstreamModelMismatch = upstreamModelMismatch(input.EffectiveModel, s.UpstreamModel)
	}
}

type upstreamTraceAudit struct {
	mu        sync.Mutex
	requestID string
	store     *auth.Store
	current   *upstreamTraceAttempt
}

func upstreamTraceFromContext(ctx context.Context) *upstreamTraceAudit {
	if ctx == nil {
		return nil
	}
	a, _ := ctx.Value(upstreamTraceContextKey{}).(*upstreamTraceAudit)
	return a
}

func attachUpstreamTrace(c *gin.Context, store *auth.Store) {
	if c == nil || c.Request == nil {
		return
	}
	a := &upstreamTraceAudit{requestID: NewUpstreamSessionUUID(), store: store}
	c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), upstreamTraceContextKey{}, a))
	c.Header("X-Codex2API-Request-ID", a.requestID)
}

func resetUpstreamRequestTrace(c *gin.Context) {
	if c == nil || c.Request == nil {
		return
	}
	if a := upstreamTraceFromContext(c.Request.Context()); a != nil {
		a.mu.Lock()
		a.requestID = NewUpstreamSessionUUID()
		a.current = nil
		a.mu.Unlock()
	}
}

func resetUpstreamAttemptTrace(ctx context.Context) {
	if a := upstreamTraceFromContext(ctx); a != nil {
		a.mu.Lock()
		a.current = nil
		a.mu.Unlock()
	}
}

func beginUpstreamTrace(ctx context.Context, account *auth.Account, proxyURL string, ws bool) func(*http.Response) {
	a := upstreamTraceFromContext(ctx)
	if a == nil || account == nil {
		return func(*http.Response) {}
	}
	label := a.store.ProxyAuditForURL(proxyURL)
	if ws && proxyURL == "" {
		label = auth.ProxyAuditLabel{Name: "unknown"}
	}
	if resinCarriesEgress(account) {
		label = auth.ProxyAuditLabel{Name: "resin"}
	}
	label.Name = security.MaskSensitiveData(label.Name)
	attempt := &upstreamTraceAttempt{accountID: account.ID(), proxy: label, injectedTurnState: CodexTurnStateInjectionFromContext(ctx)}
	a.mu.Lock()
	a.current = attempt
	a.mu.Unlock()
	header := account.GetUpstreamRequestIDHeader()
	return func(resp *http.Response) {
		if resp == nil || ws {
			return
		} // A WS handshake ID is not a per-turn ID; WS turn state arrives per frame, see ObserveCodexTurnStateFrame.
		turnState := observedCodexTurnState(resp.Header.Get(codexTurnStateHeader))
		upstreamModel := strings.TrimSpace(resp.Header.Get(codexOpenAIModelHeader))
		id := ""
		if header != "" && auth.ValidateUpstreamRequestIDHeader(header) == nil {
			id = resp.Header.Get(header)
		} else if header == "" {
			for _, name := range []string{"X-Request-Id", "Request-Id", "X-Goog-Request-Id"} {
				if id = resp.Header.Get(name); strings.TrimSpace(id) != "" {
					break
				}
			}
		}
		id = security.SafeTruncate(strings.TrimSpace(id), 128)
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.current == attempt {
			attempt.requestID = id
			if turnState != "" {
				attempt.upstreamTurnState = turnState
			}
			if upstreamModel != "" {
				attempt.upstreamResponseModel = security.SafeTruncate(upstreamModel, 128)
			}
		}
	}
}

// codexOpenAIModelHeader 是上游自报实际出活模型的响应头（真实 codex-rs 读它
// 作为 ServerModel）。
const codexOpenAIModelHeader = "openai-model"

// noteUpstreamResponseModel 把观测到的上游实际出活模型记到当前尝试上；
// WS 路径逐帧调用（response.metadata 事件的 headers 里携带）。
func noteUpstreamResponseModel(ctx context.Context, model string) {
	a := upstreamTraceFromContext(ctx)
	if a == nil || strings.TrimSpace(model) == "" {
		return
	}
	a.mu.Lock()
	if a.current != nil {
		a.current.upstreamResponseModel = security.SafeTruncate(strings.TrimSpace(model), 128)
	}
	a.mu.Unlock()
}

// noteUpstreamTurnState 把上游回带的 turn state 记到当前尝试上；WS 路径逐帧调用，
// 后到的值覆盖先到的。
func noteUpstreamTurnState(ctx context.Context, state string) {
	a := upstreamTraceFromContext(ctx)
	if a == nil || state == "" {
		return
	}
	a.mu.Lock()
	if a.current != nil {
		a.current.upstreamTurnState = state
	}
	a.mu.Unlock()
}

func doTracedUpstreamRequest(client *http.Client, req *http.Request, account *auth.Account, proxyURL string) (*http.Response, error) {
	record := beginUpstreamTrace(req.Context(), account, proxyURL, false)
	resp, err := client.Do(req)
	record(resp)
	return resp, err
}

func populateUpstreamTrace(c *gin.Context, input *database.UsageLogInput) {
	if c == nil || c.Request == nil || input == nil {
		return
	}
	if input.RequestID != "" {
		return
	} // Hidden continuation rounds carry their own snapshot.
	a := upstreamTraceFromContext(c.Request.Context())
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	input.RequestID = a.requestID
	if current := a.current; current != nil && current.accountID == input.AccountID {
		input.UpstreamRequestID = current.requestID
		input.UpstreamProxyID = current.proxy.ID
		input.UpstreamProxyName = current.proxy.Name
		input.InjectedTurnState = current.injectedTurnState
		input.UpstreamTurnState = current.upstreamTurnState
		input.UpstreamResponseModel = current.upstreamResponseModel
		input.UpstreamModelMismatch = upstreamModelMismatch(input.EffectiveModel, current.upstreamResponseModel)
	}
}
