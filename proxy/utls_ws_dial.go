package proxy

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	xproxy "golang.org/x/net/proxy"

	"github.com/codex2api/auth"
)

// WebSocket 上游腿的 TLS 拨号：真实 codex 0.155 的 WS 客户端是 rustls 且
// http1-only（ClientHello 无 ALPN 扩展），而 gorilla 默认走 Go crypto/tls——
// 两者 JA4 完全不同。这里用 uTLS rustls 无 ALPN spec 终结 TLS，与真实抓包
// （tlsprobe/codex.flows，JA4 t13d100900_...）对齐。会话缓存与 POST 腿共享，
// 重连走 TLS 1.3 resumption，与 rustls 行为一致。

// CodexWSTLSDialSupported 报告该 WS URL 是否适用 uTLS rustls 指纹拨号。
// 仅官方上游（chatgpt.com）启用；Resin 反代等自定义地址由对端终止 TLS，
// 保持默认 Go TLS 行为不变。
func CodexWSTLSDialSupported(wsURL string) bool {
	u, err := url.Parse(strings.TrimSpace(wsURL))
	if err != nil {
		return false
	}
	if u.Scheme != "wss" && u.Scheme != "https" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return host == "chatgpt.com" || strings.HasSuffix(host, ".chatgpt.com")
}

// NewCodexWSTLSDialer 返回 gorilla websocket.Dialer.NetDialTLSContext 兼容的
// 拨号函数：proxyURL 非空时经代理（http/https/socks5/socks5h）建立 TCP，
// 然后以 rustls 无 ALPN 指纹完成 TLS 握手。调用方须先以
// CodexWSTLSDialSupported 判定适用范围。
func NewCodexWSTLSDialer(proxyURL string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("WS TLS 拨号地址解析失败: %w", err)
		}

		// 1. TCP 层：与探测/POST 腿同一套代理拨号器（socks5h 远端解析等语义一致）。
		var conn net.Conn
		if strings.TrimSpace(proxyURL) != "" {
			dialer, dErr := buildProxyDialer(proxyURL)
			if dErr != nil {
				return nil, fmt.Errorf("WS TLS 代理拨号器构建失败: %w", dErr)
			}
			if cd, ok := dialer.(xproxy.ContextDialer); ok {
				conn, err = cd.DialContext(ctx, network, addr)
			} else {
				conn, err = dialer.Dial(network, addr)
			}
		} else {
			d := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
			conn, err = d.DialContext(ctx, network, addr)
		}
		if err != nil {
			return nil, fmt.Errorf("WS TLS TCP 连接失败: %w", err)
		}

		// 2. TLS 层：rustls 无 ALPN spec + 共享会话缓存（全新握手省略空 PSK）。
		tlsConfig := &utls.Config{
			ServerName:         host,
			ClientSessionCache: utlsSessionCache,
			OmitEmptyPsk:       true,
		}
		tlsConn := utls.UClient(conn, tlsConfig, utls.HelloCustom)
		if err := tlsConn.ApplyPreset(auth.CodexRustlsWSClientHelloSpec()); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("WS TLS 指纹应用失败: %w", err)
		}
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("WS TLS 握手失败: %w", err)
		}
		return tlsConn, nil
	}
}
