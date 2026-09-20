package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/codex2api/auth"
	"github.com/tidwall/gjson"
)

const maxCodex292ResponseBytes = 32 << 20

// verifyCodex292Response 只由严格 292 路径调用。HTTP 只信本次真实响应头，
// 不使用请求注入值；非 2xx 留给现有错误处理，292 的 HTTP body 保持流式直通。
// WS Header 是旧握手快照，必须检查本次所有 SSE 帧，直到成功终态及 EOF。
// 因此严格 WS 会等待完整响应，最多缓存 32 MiB 原始 SSE；超限直接报错，
// 不落盘、不释放任何业务帧。312通常立即拒绝；WS续链须安全读至终态，
// 让原连接保留previous_response_id上下文，再刷新重发。
func verifyCodex292Response(ctx context.Context, resp *http.Response, websocket bool) (accepted bool, err error) {
	if resp == nil {
		return false, errors.New("codex 292 response missing")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return true, nil
	}
	if !websocket {
		values := resp.Header.Values(codexTurnStateHeader)
		if len(values) != 1 {
			return false, errors.New("codex 292 response header missing or ambiguous")
		}
		length := len(observedCodexTurnState(values[0]))
		switch length {
		case auth.CodexTurnStateGoodLength:
			return true, nil
		case auth.CodexTurnStateDegradedLength:
			return false, nil
		default:
			return false, fmt.Errorf("codex 292 response state length %d", length)
		}
	}
	if resp.Body == nil {
		return false, errors.New("codex 292 response body missing")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}

	original := resp.Body
	// Close 必须能打断 Read（http.Response.Body 和 WS 的 io.Pipe 均满足）。
	// 等待已启动的取消回调结束，避免交付 replay 后仍有回调操作原 body。
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(closed)
		_ = original.Close()
	})
	defer func() {
		if !stop() {
			<-closed
		}
		if ctx.Err() != nil {
			accepted, err = false, ctx.Err()
		}
	}()

	reader := bufio.NewReader(original)
	var raw, data bytes.Buffer
	lineStart := 0
	saw292, terminal := false, false
	rejected := false
	preserveContinuation := strict292Attempt(ctx) != nil && strict292Attempt(ctx).preserveContinuation
	verifiedState := ""
	hasData := false
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		fragment, readErr := reader.ReadSlice('\n')
		if len(fragment) > maxCodex292ResponseBytes-raw.Len() {
			return false, fmt.Errorf("codex 292 response exceeds %d bytes", maxCodex292ResponseBytes)
		}
		_, _ = raw.Write(fragment)
		if readErr == bufio.ErrBufferFull {
			continue
		}
		if readErr != nil && readErr != io.EOF {
			// 底层错误可能包含私密帧或 token，不把错误原文带入日志。
			return false, errors.New("codex 292 response stream read failed")
		}
		if readErr == io.EOF {
			if raw.Len() != lineStart || hasData {
				return false, errors.New("codex 292 response truncated SSE frame")
			}
			if !terminal {
				return false, errors.New("codex 292 response missing successful terminal")
			}
			if rejected {
				return false, nil
			}
			if !saw292 {
				return false, errors.New("codex 292 response missing state or successful terminal")
			}
			resp.Body = &codex292ReplayBody{Reader: bytes.NewReader(raw.Bytes()), original: original}
			// 响应头也更新为本轮已验证值，不能把连接建立时的旧312继续交给下游。
			if resp.Header == nil {
				resp.Header = make(http.Header)
			}
			resp.Header.Set(codexTurnStateHeader, verifiedState)
			return true, nil
		}

		line := bytes.TrimSuffix(raw.Bytes()[lineStart:], []byte{'\n'})
		line = bytes.TrimSuffix(line, []byte{'\r'})
		lineStart = raw.Len()
		if len(line) == 0 {
			if !hasData {
				continue
			}
			payload := data.Bytes()
			if !gjson.ValidBytes(payload) || !gjson.ParseBytes(payload).IsObject() {
				return false, errors.New("codex 292 response invalid JSON frame")
			}
			state := codexTurnStateFromFrame(payload)
			// 同帧多个承载位置不能以先遇到的 292 掩盖另一个 312。
			degraded, stateErr := codex292FrameStateConflict(payload)
			if degraded {
				if !preserveContinuation {
					return false, nil
				}
				// 续链历史只在原WS连接内；读完终态后让wsrelay归还连接，重试另外展开历史快照。
				// 被拒绝帧始终只在门禁内，绝不交付下游。
				rejected = true
			}
			if stateErr != nil {
				return false, stateErr
			}
			if state != "" {
				switch len(state) {
				case auth.CodexTurnStateGoodLength:
					saw292 = true
					verifiedState = state
				case auth.CodexTurnStateDegradedLength:
					if !preserveContinuation {
						return false, nil
					}
					rejected = true
				default:
					return false, fmt.Errorf("codex 292 response state length %d", len(state))
				}
			}
			eventType := gjson.GetBytes(payload, "type")
			if eventType.Type != gjson.String || eventType.String() == "" {
				return false, errors.New("codex 292 response missing event type")
			}
			if terminal {
				return false, errors.New("codex 292 response frame after terminal")
			}
			switch eventType.String() {
			case "response.failed", "response.incomplete", "error":
				return false, fmt.Errorf("codex 292 response unsuccessful event %s", eventType.String())
			case "response.completed", "response.done":
				status := gjson.GetBytes(payload, "response.status")
				if status.Exists() && status.String() != "completed" {
					return false, errors.New("codex 292 response unsuccessful terminal status")
				}
				if gjson.GetBytes(payload, "response.error").Type != gjson.Null || gjson.GetBytes(payload, "error").Type != gjson.Null {
					return false, errors.New("codex 292 response terminal error")
				}
				terminal = true
			}
			data.Reset()
			hasData = false
			continue
		}
		if line[0] == ':' {
			continue
		}
		field, value, found := bytes.Cut(line, []byte{':'})
		if !found {
			return false, errors.New("codex 292 response invalid SSE field")
		}
		value = bytes.TrimPrefix(value, []byte{' '})
		switch string(field) {
		case "data":
			if hasData {
				_ = data.WriteByte('\n')
			}
			_, _ = data.Write(value)
			hasData = true
		case "event", "id", "retry":
			// 保留原始 SSE 字节，业务事件类型仍以 JSON 帧为准。
		default:
			return false, errors.New("codex 292 response invalid SSE field")
		}
	}
}

// 与 codexTurnStateFromFrame 使用相同的承载位置，仅补充严格模式的冲突检查。
func codex292FrameStateConflict(payload []byte) (degraded bool, err error) {
	root := gjson.ParseBytes(payload)
	for _, path := range []string{"headers", "response.headers", "response.client_metadata", "client_metadata", "response.metadata", "metadata", "response.metadata.headers", "metadata.headers", "response", ""} {
		object := root
		if path != "" {
			object = root.Get(path)
		}
		if !object.IsObject() {
			continue
		}
		object.ForEach(func(key, value gjson.Result) bool {
			if !strings.EqualFold(key.String(), codexTurnStateHeader) {
				return true
			}
			length := 0
			if value.Type == gjson.String {
				length = len(observedCodexTurnState(value.String()))
			}
			switch length {
			case auth.CodexTurnStateDegradedLength:
				degraded = true
			case auth.CodexTurnStateGoodLength:
			default:
				err = fmt.Errorf("codex 292 response state length %d", length)
			}
			return true
		})
		if degraded {
			return true, nil
		}
	}
	return false, err
}

// replay 不串接未经验证的原始流；Close 仍释放原 body 所持有的传输资源。
type codex292ReplayBody struct {
	*bytes.Reader
	original io.ReadCloser
	once     sync.Once
	closeErr error
}

func (b *codex292ReplayBody) Close() error {
	b.once.Do(func() { b.closeErr = b.original.Close() })
	return b.closeErr
}
