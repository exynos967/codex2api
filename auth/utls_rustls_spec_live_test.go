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

	tlsConn := utls.UClient(conn, &utls.Config{ServerName: host, OmitEmptyPsk: true}, utls.HelloCustom)
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

// TestRustlsSpecSessionResumption 验证 TLS 1.3 会话复用：对同一服务器连握
// 两次（共享会话缓存），第二次必须 DidResume=true 且不出错——即 spec 末尾的
// UtlsPreSharedKeyExtension + OmitEmptyPsk 组合在真实协商中可用。
//
//	go test -tags=integration -v -run TestRustlsSpecSessionResumption ./auth/
func TestRustlsSpecSessionResumption(t *testing.T) {
	host := "www.cloudflare.com"
	cache := utls.NewLRUClientSessionCache(8)

	dial := func() utls.ConnectionState {
		conn, err := net.DialTimeout("tcp", host+":443", 10*time.Second)
		if err != nil {
			t.Skipf("网络不可达: %v", err)
		}
		defer conn.Close()
		tlsConn := utls.UClient(conn, &utls.Config{
			ServerName:         host,
			ClientSessionCache: cache,
			OmitEmptyPsk:       true,
		}, utls.HelloCustom)
		if err := tlsConn.ApplyPreset(CodexRustlsClientHelloSpec()); err != nil {
			t.Fatalf("应用 rustls 指纹失败: %v", err)
		}
		if err := tlsConn.Handshake(); err != nil {
			t.Fatalf("握手失败: %v", err)
		}
		// NewSessionTicket 是握手后的 post-handshake 消息，必须读一轮让
		// utls 处理 ticket 并写入会话缓存，否则第二次握手无票可复用。
		_ = tlsConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, _ = tlsConn.Read(make([]byte, 4096))
		return tlsConn.ConnectionState()
	}

	first := dial()
	t.Logf("首次握手: version=%x didResume=%v", first.Version, first.DidResume)
	second := dial()
	t.Logf("二次握手: version=%x didResume=%v", second.Version, second.DidResume)
	if !second.DidResume {
		t.Error("第二次握手未复用会话（DidResume=false），会话复用未生效")
	}
}
