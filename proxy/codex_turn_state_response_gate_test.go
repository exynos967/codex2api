package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func gate292Frame(event string, stateLength int) string {
	if stateLength == 0 {
		return fmt.Sprintf("data: {\"type\":%q}\n\n", event)
	}
	return fmt.Sprintf("data: {\"type\":%q,\"headers\":{\"x-codex-turn-state\":%q}}\n\n", event, strings.Repeat("s", stateLength))
}

type gate292TrackedBody struct {
	io.ReadCloser
	closes atomic.Int32
	reads  atomic.Int32
}

func (b *gate292TrackedBody) Read(p []byte) (int, error) {
	b.reads.Add(1)
	return b.ReadCloser.Read(p)
}

func (b *gate292TrackedBody) Close() error {
	b.closes.Add(1)
	return b.ReadCloser.Close()
}

func TestVerifyCodex292ResponseHTTP(t *testing.T) {
	for _, tc := range []struct {
		name              string
		status, length    int
		accepted, wantErr bool
	}{
		{"292", 200, 292, true, false},
		{"312", 200, 312, false, false},
		{"missing", 200, 0, false, true},
		{"unknown", 200, 300, false, true},
		{"non2xx", 429, 0, true, false},
		{"non2xx312", 503, 312, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.length != 0 {
					w.Header().Set(codexTurnStateHeader, strings.Repeat("s", tc.length))
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, "original body")
			}))
			defer server.Close()
			resp, err := server.Client().Get(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			original := &gate292TrackedBody{ReadCloser: resp.Body}
			resp.Body = original
			ctx := withCodexTurnStateInjection(context.Background(), strings.Repeat("s", 292))
			accepted, err := verifyCodex292Response(ctx, resp, false)
			if accepted != tc.accepted || (err != nil) != tc.wantErr {
				t.Fatalf("accepted=%v err=%v", accepted, err)
			}
			if resp.Body != original || original.reads.Load() != 0 {
				t.Fatal("native HTTP gate consumed or replaced body")
			}
			if err != nil && strings.Contains(err.Error(), strings.Repeat("s", 20)) {
				t.Fatal("error exposed token")
			}
		})
	}
}

func TestVerifyCodex292ResponseWS(t *testing.T) {
	good := gate292Frame("response.metadata", 292)
	terminal := gate292Frame("response.completed", 0)
	for _, tc := range []struct {
		name, stream      string
		accepted, wantErr bool
	}{
		{"stale handshake 292 frame312", gate292Frame("response.created", 312), false, false},
		{"business before 312", gate292Frame("response.created", 0) + gate292Frame("response.output_text.delta", 0) + gate292Frame("response.function_call_arguments.delta", 0) + gate292Frame("response.metadata", 312), false, false},
		{"292 then 312", good + gate292Frame("response.output_text.delta", 0) + gate292Frame("response.metadata", 312), false, false},
		{"terminal312 vetoes 292", good + gate292Frame("response.completed", 312), false, false},
		{"completed then312", good + terminal + gate292Frame("response.metadata", 312), false, false},
		{"same frame conflict", fmt.Sprintf("data: {\"type\":\"response.completed\",\"headers\":{\"x-codex-turn-state\":%q},\"response\":{\"headers\":{\"x-codex-turn-state\":%q}}}\n\n", strings.Repeat("s", 292), strings.Repeat("s", 312)), false, false},
		{"complete", good + gate292Frame("response.output_text.delta", 0) + terminal, true, false},
		{"terminal state only", gate292Frame("response.completed", 292), true, false},
		{"done alias", good + gate292Frame("response.done", 0), true, false},
		{"null terminal error", good + "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"error\":null}}\n\n", true, false},
		{"no frame proof", terminal, false, true},
		{"no terminal", good, false, true},
		{"failed", good + gate292Frame("response.failed", 0), false, true},
		{"error", good + gate292Frame("error", 0), false, true},
		{"incomplete", good + gate292Frame("response.incomplete", 0), false, true},
		{"failed done status", good + "data: {\"type\":\"response.done\",\"response\":{\"status\":\"failed\"}}\n\n", false, true},
		{"terminal error", good + "data: {\"type\":\"response.completed\",\"error\":{\"message\":\"private-error\"}}\n\n", false, true},
		{"unknown length", good + gate292Frame("response.metadata", 300) + terminal, false, true},
		{"invalid state", good + "data: {\"type\":\"response.metadata\",\"headers\":{\"x-codex-turn-state\":42}}\n\n" + terminal, false, true},
		{"nonjson", "data: private-token\n\n", false, true},
		{"bad JSON", "data: {broken-private-token}\n\n", false, true},
		{"array", "data: []\n\n", false, true},
		{"missing type", "data: {}\n\n", false, true},
		{"truncated frame", good + strings.TrimSuffix(terminal, "\n"), false, true},
		{"invalid field", good + "private-token\n\n" + terminal, false, true},
		{"done sentinel only", good + "data: [DONE]\n\n", false, true},
		{"business after terminal", good + terminal + gate292Frame("response.created", 0), false, true},
		{"SSE metadata CRLF multiline", ": keepalive\r\nevent: response.metadata\r\nid: 1\r\nretry: 100\r\ndata: {\"type\":\"response.metadata\",\r\ndata: \"headers\":{\"x-codex-turn-state\":\"" + strings.Repeat("s", 292) + "\"}}\r\n\r\n" + terminal, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := &gate292TrackedBody{ReadCloser: io.NopCloser(strings.NewReader(tc.stream))}
			resp := &http.Response{StatusCode: 200, Header: http.Header{codexTurnStateHeader: []string{strings.Repeat("h", 292)}}, Body: original}
			accepted, err := verifyCodex292Response(context.Background(), resp, true)
			if accepted != tc.accepted || (err != nil) != tc.wantErr {
				t.Fatalf("accepted=%v err=%v", accepted, err)
			}
			if err != nil && (strings.Contains(err.Error(), "private-") || strings.Contains(err.Error(), strings.Repeat("s", 20))) {
				t.Fatal("error exposed private payload")
			}
			if !accepted {
				if resp.Body != original {
					t.Fatal("rejected response received replay body")
				}
				_ = resp.Body.Close()
				return
			}
			replay, err := io.ReadAll(resp.Body)
			if err != nil || string(replay) != tc.stream {
				t.Fatalf("replay changed bytes: len=%d want=%d err=%v", len(replay), len(tc.stream), err)
			}
			if original.closes.Load() != 0 {
				t.Fatal("body was closed before replay Close")
			}
			_ = resp.Body.Close()
			_ = resp.Body.Close()
			if original.closes.Load() != 1 {
				t.Fatal("replay Close did not release original body exactly once")
			}
		})
	}
}

func TestVerifyCodex292ResponseWSWaitsWithoutLeaking(t *testing.T) {
	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()
	resp := &http.Response{StatusCode: 200, Body: pr}
	type outcome struct {
		accepted bool
		err      error
	}
	done := make(chan outcome, 1)
	var downstream bytes.Buffer
	go func() {
		accepted, err := verifyCodex292Response(context.Background(), resp, true)
		if accepted && err == nil {
			_, err = io.Copy(&downstream, resp.Body)
		}
		done <- outcome{accepted, err}
	}()
	prefix := gate292Frame("response.metadata", 292) + gate292Frame("response.created", 0) + gate292Frame("response.output_text.delta", 0) + gate292Frame("response.function_call_arguments.delta", 0)
	if _, err := io.WriteString(pw, prefix); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		t.Fatal("gate returned before terminal")
	case <-time.After(30 * time.Millisecond):
	}
	if _, err := io.WriteString(pw, gate292Frame("response.metadata", 312)); err != nil {
		t.Fatal(err)
	}
	// 保持 pipe 开启：312 必须立即返回，不能继续等 EOF 或耗尽流。
	select {
	case result := <-done:
		if result.accepted || result.err != nil || downstream.Len() != 0 {
			t.Fatalf("accepted=%v err=%v leaked=%d", result.accepted, result.err, downstream.Len())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("gate drained rejected stream")
	}
}

func TestVerifyCodex292ResponseWSCancelRead(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	original := &gate292TrackedBody{ReadCloser: pr}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		accepted, err := verifyCodex292Response(ctx, &http.Response{StatusCode: 200, Body: original}, true)
		if accepted {
			done <- errors.New("canceled gate accepted")
			return
		}
		done <- err
	}()
	if _, err := io.WriteString(pw, gate292Frame("response.metadata", 292)); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || original.closes.Load() != 1 {
			t.Fatalf("err=%v closes=%d", err, original.closes.Load())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancel did not interrupt blocked body read")
	}
}

func TestVerifyCodex292ResponseWSBufferLimit(t *testing.T) {
	prefix := gate292Frame("response.metadata", 292)
	terminal := gate292Frame("response.completed", 0)
	for _, extra := range []int{0, 1} {
		t.Run(fmt.Sprint(extra), func(t *testing.T) {
			padding := strings.Repeat("x", maxCodex292ResponseBytes-len(prefix)-len(terminal)-3+extra)
			stream := prefix + ":" + padding + "\n\n" + terminal
			resp := &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(stream))}
			defer resp.Body.Close()
			accepted, err := verifyCodex292Response(context.Background(), resp, true)
			if extra == 0 {
				if !accepted || err != nil {
					t.Fatalf("exact limit rejected: accepted=%v err=%v", accepted, err)
				}
				replay, err := io.ReadAll(resp.Body)
				if err != nil || string(replay) != stream {
					t.Fatal("exact-limit replay changed")
				}
			} else if accepted || err == nil || !strings.Contains(err.Error(), "exceeds 33554432 bytes") {
				t.Fatalf("oversize accepted=%v err=%v", accepted, err)
			}
		})
	}
}

type gate292ErrorReader struct{}

func (gate292ErrorReader) Read([]byte) (int, error) { return 0, errors.New("private-upstream-token") }
func (gate292ErrorReader) Close() error             { return nil }

func TestVerifyCodex292ResponseWSReadErrorRedacted(t *testing.T) {
	resp := &http.Response{StatusCode: 200, Body: gate292ErrorReader{}}
	accepted, err := verifyCodex292Response(context.Background(), resp, true)
	if accepted || err == nil || strings.Contains(err.Error(), "private-") {
		t.Fatalf("accepted=%v err=%v", accepted, err)
	}
}

func TestVerifyCodex292ResponseUsesCurrentNestedMetadata(t *testing.T) {
	state := strings.Repeat("a", 292)
	frame := `data: {"type":"codex.response.metadata","metadata":{"headers":{"x-codex-turn-state":"` + state + `"}}}` + "\n\n"
	resp := &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(frame + gate292Frame("response.completed", 0)))}
	resp.Header.Set(codexTurnStateHeader, strings.Repeat("b", 312))
	accepted, err := verifyCodex292Response(context.Background(), resp, true)
	if !accepted || err != nil {
		t.Fatalf("current metadata rejected: %v", err)
	}
	defer resp.Body.Close()
	if resp.Header.Get(codexTurnStateHeader) != state {
		t.Fatal("stale handshake state remained in verified response headers")
	}
}

func TestVerifyCodex292ContinuationDrainsBeforeRejecting(t *testing.T) {
	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()
	ctx := context.WithValue(context.Background(), codexStrict292AttemptKey{}, &codexStrict292Attempt{preserveContinuation: true})
	done := make(chan error, 1)
	go func() {
		accepted, err := verifyCodex292Response(ctx, &http.Response{StatusCode: 200, Body: pr}, true)
		if accepted {
			err = errors.New("312 continuation accepted")
		}
		done <- err
	}()
	if _, err := io.WriteString(pw, gate292Frame("response.metadata", 312)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		t.Fatal("continuation rejected before draining terminal; would discard its connection")
	case <-time.After(20 * time.Millisecond):
	}
	if _, err := io.WriteString(pw, gate292Frame("response.completed", 0)); err != nil {
		t.Fatal(err)
	}
	_ = pw.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("gate did not finish after terminal")
	}
}
