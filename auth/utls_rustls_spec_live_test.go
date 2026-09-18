//go:build integration

package auth

import (
	"net"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// TestRustlsSpecLiveHandshake 用洗牌后的最终 spec 对真实 TLS 服务器完成握手，
// 证明扩展洗牌、SNI 与 key_share 生成在真实协商中可用。
// 默认打 www.cloudflare.com（MLKEM 支持方，历史上会触发 HRR 场景）。
//
//	go test -tags=integration -v -run TestRustlsSpecLiveHandshake ./auth/
func TestRustlsSpecLiveHandshake(t *testing.T) {
	host := "www.cloudflare.com"
	conn, err := net.DialTimeout("tcp", host+":443", 10*time.Second)
	if err != nil {
		t.Skipf("网络不可达: %v", err)
	}
	defer conn.Close()

	tlsConn := utls.UClient(conn, &utls.Config{ServerName: host}, utls.HelloCustom)
	if err := tlsConn.ApplyPreset(CodexRustlsClientHelloSpec()); err != nil {
		t.Fatalf("应用 rustls 指纹失败: %v", err)
	}
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("真实握手失败: %v", err)
	}
	state := tlsConn.ConnectionState()
	t.Logf("握手成功: version=%x cipher=%x alpn=%s", state.Version, state.CipherSuite, state.NegotiatedProtocol)
	if state.Version != 0x0304 {
		t.Errorf("version = %x, want TLS1.3(0x0304)", state.Version)
	}
	if !strings.EqualFold(state.NegotiatedProtocol, "h2") {
		t.Errorf("ALPN = %q, want h2", state.NegotiatedProtocol)
	}
}
