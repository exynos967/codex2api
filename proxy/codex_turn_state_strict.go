package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/codex2api/auth"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// 每次上游尝试独享；在请求定稿处记录实际模型/传输，不能用旧握手或注入值证明响应。
type codexStrict292Attempt struct {
	token                string
	model                string
	websocket            bool
	preserveContinuation bool
}
type codexStrict292AttemptKey struct{}

func strict292Attempt(ctx context.Context) *codexStrict292Attempt {
	if ctx == nil {
		return nil
	}
	value, _ := ctx.Value(codexStrict292AttemptKey{}).(*codexStrict292Attempt)
	return value
}

// 强制292仅包裹账号明确开启的推理请求；默认分支不增加读取/等待或改变流式行为。
func executeWithCodex292Gate(ctx context.Context, account *auth.Account, proxyOverride string, send func(context.Context) (*http.Response, error), beforeRetry ...func() error) (*http.Response, error) {
	if account == nil || account.IsRelayStyle() || !account.IsCodexTurnStateRequire292() {
		return send(ctx)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	pinned, _, _ := account.CodexTurnStateConfig()
	token := ""
	if len(strings.TrimSpace(pinned)) == auth.CodexTurnStateGoodLength {
		token = strings.TrimSpace(pinned)
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !account.IsCodexTurnStateRequire292() {
			return nil, errCodex292Gate("强制292等待已取消：账号开关已关闭", nil)
		}
		attempt := &codexStrict292Attempt{token: token}
		attemptCtx, cancel := context.WithCancel(context.WithValue(ctx, codexStrict292AttemptKey{}, attempt))
		resp, err := send(attemptCtx)
		if err != nil {
			cancel()
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
			return nil, err
		}
		accepted, err := verifyCodex292Response(attemptCtx, resp, attempt.websocket)
		if err != nil {
			cancel()
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
			transport := "http"
			if attempt.websocket {
				transport = "ws"
			}
			status, headerCount, headerLength := 0, 0, 0
			if resp != nil {
				status = resp.StatusCode
				headerCount = len(resp.Header.Values(codexTurnStateHeader))
				headerLength = len(strings.TrimSpace(resp.Header.Get(codexTurnStateHeader)))
			}
			// verify仅生成固定原因/长度/计数，不含token、帧正文或底层私密错误。
			// WS header是握手快照，日志仅辅助诊断，仍不能作为本轮验证依据。
			log.Printf("[turn-state-gate] account=%d transport=%s http_status=%d state_header_count=%d state_header_length=%d injected_length=%d verify_failed=%v", account.ID(), transport, status, headerCount, headerLength, len(attempt.token), err)
			message := fmt.Sprintf("强制292验证失败，未转发上游内容（%s）：%v", transport, err)
			return nil, errCodex292Gate(message, err)
		}
		if accepted {
			if resp == nil || resp.Body == nil {
				cancel()
				return resp, nil
			}
			// HTTP成功后仍需边读边流式转发，不能在返回响应时取消其上游请求。
			resp.Body = &codexStrict292Body{ReadCloser: resp.Body, cancel: cancel}
			return resp, nil
		}
		// 已确认312：关闭旧响应再刷新；绝不把该响应缓存为可回放的成功结果。
		cancel()
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		if len(beforeRetry) > 0 && beforeRetry[0] != nil {
			if err := beforeRetry[0](); err != nil {
				return nil, errCodex292Gate("强制292重试无法恢复完整续聊上下文", err)
			}
		}
		log.Printf("[turn-state-gate] account=%d observed_length=312 action=refresh_then_replay", account.ID())
		token, err = refreshCodexTurnStateForStrictRequest(ctx, account, attempt.model, proxyOverride)
		if err != nil {
			return nil, errCodex292Gate("强制292刷新未完成，未转发被拦截响应", err)
		}
		if len(strings.TrimSpace(token)) != auth.CodexTurnStateGoodLength {
			return nil, errCodex292Gate("强制292刷新返回未验证状态", nil)
		}
		// 再发一次原请求，由新响应自己的头/帧重新验证；新token不能给旧响应背书。
	}
}

type codexStrict292Body struct {
	io.ReadCloser
	cancel context.CancelFunc
	once   sync.Once
}

func (b *codexStrict292Body) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.once.Do(b.cancel)
	}
	return n, err
}
func (b *codexStrict292Body) Close() error {
	b.once.Do(b.cancel)
	return b.ReadCloser.Close()
}

const codex292GateErrorCode = "codex_turn_state_gate"

func errCodex292Gate(message string, cause error) *Error {
	err := ErrUpstream(http.StatusBadGateway, message, cause)
	err.Code = codex292GateErrorCode
	return err
}

func isCodex292GateError(err error) bool {
	var structured *Error
	return errors.As(err, &structured) && structured.Code == codex292GateErrorCode
}

type codex292ReplaySourceKey struct{}

// 原生WS入口已按API Key归属固定祖先快照；严格重试复用它，不能跨用户查历史。
func withCodex292ReplaySource(ctx context.Context, source *responsesWSReplaySource) context.Context {
	return context.WithValue(ctx, codex292ReplaySourceKey{}, source)
}

func prepareCodex292ReplayBody(ctx context.Context, body []byte) ([]byte, error) {
	if strings.TrimSpace(gjson.GetBytes(body, "previous_response_id").String()) == "" {
		return body, nil
	}
	var source *responsesWSReplaySource
	if ctx != nil {
		source, _ = ctx.Value(codex292ReplaySourceKey{}).(*responsesWSReplaySource)
	}
	if source == nil {
		return nil, errors.New("continuation snapshot unavailable")
	}
	input := source.Input()
	if input == "" || source.err != nil {
		return nil, errors.New("complete continuation history unavailable")
	}
	updated, err := sjson.SetRawBytes(body, "input", []byte(input))
	if err != nil {
		return nil, errors.New("could not restore continuation input")
	}
	updated, err = sjson.DeleteBytes(updated, "previous_response_id")
	if err != nil {
		return nil, errors.New("could not detach restored continuation")
	}
	return updated, nil
}
