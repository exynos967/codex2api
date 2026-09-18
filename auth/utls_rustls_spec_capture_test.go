//go:build integration

package auth

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// TestRustlsSpecCapture 把 CodexRustlsClientHelloSpec 的 ClientHello 发往本地
// 抓包服务器（tools/tlsprobe/capture），由抓包服务器输出逐项字段供人工与
// 真实 codex（rustls+aws_lc_rs）抓包做 diff。
//
// 运行方式（两个终端）：
//
//	go run ./tools/tlsprobe/capture 127.0.0.1:8443
//	RUSTLS_CAPTURE_ADDR=127.0.0.1:8443 go test -tags=integration -v -run TestRustlsSpecCapture ./auth/
func TestRustlsSpecCapture(t *testing.T) {
	addr := strings.TrimSpace(os.Getenv("RUSTLS_CAPTURE_ADDR"))
	if addr == "" {
		t.Skip("未设置 RUSTLS_CAPTURE_ADDR，跳过抓包验证")
	}

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("连接抓包服务器失败: %v", err)
	}
	defer conn.Close()
	counting := &countingConn{Conn: conn}

	// OmitEmptyPsk 必须与生产配置一致：否则 spec 末尾的 PSK 扩展在无缓存
	// 会话时直接报 ErrEmptyPsk，一个字节都发不出去。
	tlsConn := utls.UClient(counting, &utls.Config{ServerName: "chatgpt.com", OmitEmptyPsk: true}, utls.HelloCustom)
	if err := tlsConn.ApplyPreset(CodexRustlsClientHelloSpec()); err != nil {
		t.Fatalf("应用 rustls 指纹失败: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// 抓包服务器不真实握手，失败属预期；ClientHello 已完整发出。
	_ = tlsConn.HandshakeContext(ctx)
	if counting.written < 200 {
		t.Fatalf("ClientHello 疑似未发出：仅写入 %d 字节", counting.written)
	}
}

// countingConn 统计写出的字节数，用于断言 ClientHello 确实上线。
type countingConn struct {
	net.Conn
	written int
}

func (c *countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.written += n
	return n, err
}
