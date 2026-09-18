package auth

import (
	"encoding/binary"
	"net"
	"time"

	"golang.org/x/net/http2"
)

// HTTP/2 连接前导指纹，对齐真实 Codex 客户端的 hyper(h2 crate) 默认行为
// （hyper 1.11 proto/h2/client.rs Config::Default + h2 0.4 Settings 序列化序）：
//
//	SETTINGS [ENABLE_PUSH=0, INITIAL_WINDOW_SIZE=2097152, MAX_FRAME_SIZE=16384,
//	          MAX_HEADER_LIST_SIZE=16384]
//	WINDOW_UPDATE(0, 5177345)   // 连接窗口 5MB - 65535
//
// Go x/net/http2 的默认前导不同（INITIAL_WINDOW_SIZE=4MB、MAX_FRAME_SIZE=1MB、
// 无 MAX_HEADER_LIST_SIZE、WINDOW_UPDATE=1GB），是应用层之上可观测的指纹差异。
// 参数顺序两者天然一致（h2 按固定字段序序列化，Go 的构造顺序恰好相同）。
const (
	h2InitialStreamWindow = 2 << 20  // 2MB（hyper DEFAULT_STREAM_WINDOW）
	h2MaxFrameSize        = 16 << 10 // 16KB（hyper DEFAULT_MAX_FRAME_SIZE）
	h2MaxHeaderListSize   = 16 << 10 // 16KB（hyper DEFAULT_MAX_HEADER_LIST_SIZE）
	h2ConnWindow          = 5 << 20  // 5MB（hyper DEFAULT_CONN_WINDOW）
	// 连接级 WINDOW_UPDATE 增量：h2 连接窗口 5MB 减去协议默认 65535。
	h2ConnWindowIncrement = h2ConnWindow - 65535
)

// NewCodexHTTP2Transport 创建前导指纹与真实 Codex（hyper/h2）一致的
// http2.Transport。uTLS 的两处传输（推理 / auth 端点）共用，避免两处配置漂移。
//
// 参数名的语义陷阱：x/net/http2 把 MaxUploadBufferPerStream 同时用作
// 客户端 SETTINGS 的 INITIAL_WINDOW_SIZE（初始接收窗口），把
// MaxUploadBufferPerConnection 直接作为连接级 WINDOW_UPDATE 增量发出——
// 名字说的是 upload，实际控的是前导指纹，赋值以 h2 的线值为基准。
//
// 注意：v0.55 起这两个窗口参数只能从 net/http 侧的 HTTP2Config 透传，
// 独立使用的 Transport 拿不到（t1 未导出）。因此 INITIAL_WINDOW_SIZE 与
// WINDOW_UPDATE 的改写由 WrapCodexH2PrefaceConn 在字节层完成，两者必须
// 搭配使用。
func NewCodexHTTP2Transport(readIdleTimeout, pingTimeout, idleConnTimeout time.Duration) *http2.Transport {
	return &http2.Transport{
		ReadIdleTimeout:   readIdleTimeout,
		PingTimeout:       pingTimeout,
		IdleConnTimeout:   idleConnTimeout,
		MaxReadFrameSize:  h2MaxFrameSize,
		MaxHeaderListSize: h2MaxHeaderListSize,
	}
}

// ==================== H2 前导字节改写 ====================
//
// Go x/net/http2 客户端前导与 hyper/h2 的两处残余差异无法在配置层消除
// （窗口参数在 v0.55 只能从 net/http HTTP2Config 透传，独立 Transport 无入口）：
//
//	SETTINGS INITIAL_WINDOW_SIZE:  Go 4MB   → h2 2MB
//	WINDOW_UPDATE(0) 增量:         Go 1GB   → h2 5MB-65535
//
// WrapCodexH2PrefaceConn 在连接最初几次写里缓冲并改写这两个标量，之后完全
// 透传。功能安全：Go 的流控补窗粒度是 4KB 连续补发（inflowMinRefresh），
// 把线上声明窗口改小不会死锁——服务端窗口耗尽前客户端早已持续补窗。
const h2ClientPrefaceLen = len("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// WrapCodexH2PrefaceConn 包装 TLS 连接，把客户端 H2 前导改写成 hyper/h2 的
// 线值。只用于 rustls 指纹路径；Chrome 指纹路径应自行对齐浏览器前导。
func WrapCodexH2PrefaceConn(c net.Conn) net.Conn {
	return &h2PrefaceConn{Conn: c}
}

type h2PrefaceConn struct {
	net.Conn
	buf  []byte
	done bool
}

func (c *h2PrefaceConn) Write(p []byte) (int, error) {
	if c.done {
		return c.Conn.Write(p)
	}
	c.buf = append(c.buf, p...)
	if out, ok := patchH2Preface(c.buf); ok {
		c.buf = nil
		c.done = true
		if _, err := c.Conn.Write(out); err != nil {
			return 0, err
		}
	}
	// 缓冲期间对上层报告已写入；字节会在缓冲攒齐后一次性发出。
	return len(p), nil
}

// patchH2Preface 尝试改写前导。返回 ok=false 表示字节未攒齐，继续缓冲；
// ok=true 时返回应上线的字节（已改写或原样放行）。无法识别的前导原样放行。
func patchH2Preface(buf []byte) ([]byte, bool) {
	if len(buf) < h2ClientPrefaceLen {
		return nil, false
	}
	if string(buf[:h2ClientPrefaceLen]) != "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
		return buf, true // 不是 H2 前导，放行
	}
	if len(buf) < h2ClientPrefaceLen+9 {
		return nil, false
	}
	settingsLen := int(buf[h2ClientPrefaceLen])<<16 | int(buf[h2ClientPrefaceLen+1])<<8 | int(buf[h2ClientPrefaceLen+2])
	if buf[h2ClientPrefaceLen+3] != 0x4 { // SETTINGS
		return buf, true
	}
	if settingsLen%6 != 0 || settingsLen > 64 {
		return buf, true // 畸形 SETTINGS，不动
	}
	settingsEnd := h2ClientPrefaceLen + 9 + settingsLen
	if len(buf) < settingsEnd {
		return nil, false
	}
	// 改写 SETTINGS 载荷里的 INITIAL_WINDOW_SIZE。
	for off := h2ClientPrefaceLen + 9; off+6 <= settingsEnd; off += 6 {
		id := binary.BigEndian.Uint16(buf[off:])
		if id == 4 { // INITIAL_WINDOW_SIZE
			binary.BigEndian.PutUint32(buf[off+2:], h2InitialStreamWindow)
		}
	}
	// 紧跟的连接级 WINDOW_UPDATE（同一 Flush 内）：改写增量。
	if len(buf) < settingsEnd+9 {
		return nil, false
	}
	if buf[settingsEnd+3] == 0x8 && // WINDOW_UPDATE
		binary.BigEndian.Uint32(buf[settingsEnd+5:])&0x7fffffff == 0 {
		if len(buf) < settingsEnd+13 {
			return nil, false
		}
		binary.BigEndian.PutUint32(buf[settingsEnd+9:], h2ConnWindowIncrement)
	}
	return buf, true
}
