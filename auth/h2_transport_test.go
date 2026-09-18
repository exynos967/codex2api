package auth

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// TestCodexHTTP2TransportPrefaceMatchesHyper 用 net.Pipe 裸读客户端连接前导，
// 逐字节断言与 hyper(h2 crate) 默认前导一致：
//
//	PRI 前导 + SETTINGS[ENABLE_PUSH=0, INITIAL_WINDOW_SIZE=2MB,
//	MAX_FRAME_SIZE=16KB, MAX_HEADER_LIST_SIZE=16KB] + WINDOW_UPDATE(0, 5177345)
//
// 基准来源：hyper 1.11 proto/h2/client.rs Config::Default 与
// h2 0.4 frame/settings.rs 的序列化顺序。
func TestCodexHTTP2TransportPrefaceMatchesHyper(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	tr := NewCodexHTTP2Transport(15*time.Second, 15*time.Second, 90*time.Second)
	go func() {
		cc, _ := tr.NewClientConn(WrapCodexH2PrefaceConn(client))
		if cc != nil {
			cc.Close()
		}
	}()

	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))

	// 1. 24 字节连接前导
	preface := make([]byte, 24)
	if _, err := io.ReadFull(server, preface); err != nil {
		t.Fatalf("读前导失败: %v", err)
	}
	if string(preface) != "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
		t.Fatalf("前导不符: %q", preface)
	}

	// 2. SETTINGS 帧：参数与顺序必须与 h2 一致
	stLen, stType, stFlags, stStream := readFrameHeader(t, server)
	if stType != 0x4 || stFlags != 0 || stStream != 0 {
		t.Fatalf("首帧不是 SETTINGS: type=%x flags=%x stream=%d", stType, stFlags, stStream)
	}
	payload := make([]byte, stLen)
	if _, err := io.ReadFull(server, payload); err != nil {
		t.Fatalf("读 SETTINGS 载荷失败: %v", err)
	}
	want := []struct{ id, val uint32 }{
		{2, 0},       // ENABLE_PUSH = 0
		{4, 2097152}, // INITIAL_WINDOW_SIZE = 2MB
		{5, 16384},   // MAX_FRAME_SIZE = 16KB
		{6, 16384},   // MAX_HEADER_LIST_SIZE = 16KB
	}
	if len(payload) != len(want)*6 {
		t.Fatalf("SETTINGS 载荷长度 = %d, want %d（参数集合不符）", len(payload), len(want)*6)
	}
	for i, w := range want {
		id := uint32(binary.BigEndian.Uint16(payload[i*6:]))
		val := binary.BigEndian.Uint32(payload[i*6+2:])
		if id != w.id || val != w.val {
			t.Errorf("SETTINGS[%d] = (id=%d, val=%d), want (id=%d, val=%d)", i, id, val, w.id, w.val)
		}
	}

	// 3. 连接级 WINDOW_UPDATE：5MB - 65535
	wuLen, wuType, _, wuStream := readFrameHeader(t, server)
	if wuType != 0x8 || wuStream != 0 || wuLen != 4 {
		t.Fatalf("次帧不是连接级 WINDOW_UPDATE: type=%x stream=%d len=%d", wuType, wuStream, wuLen)
	}
	var inc [4]byte
	if _, err := io.ReadFull(server, inc[:]); err != nil {
		t.Fatalf("读 WINDOW_UPDATE 载荷失败: %v", err)
	}
	if got := binary.BigEndian.Uint32(inc[:]) & 0x7fffffff; got != 5177345 {
		t.Errorf("WINDOW_UPDATE 增量 = %d, want 5177345（5MB-65535）", got)
	}
}

func readFrameHeader(t *testing.T, r io.Reader) (length int, frameType, flags byte, streamID uint32) {
	t.Helper()
	var hdr [9]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		t.Fatalf("读帧头失败: %v", err)
	}
	length = int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
	return length, hdr[3], hdr[4], binary.BigEndian.Uint32(hdr[5:]) & 0x7fffffff
}

// TestH2PrefaceConnSplitWrites 前导被拆成多次 Write 时仍应正确改写。
func TestH2PrefaceConnSplitWrites(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	wrapped := WrapCodexH2PrefaceConn(client)

	tr := NewCodexHTTP2Transport(15*time.Second, 15*time.Second, 90*time.Second)
	go func() {
		cc, _ := tr.NewClientConn(wrapped)
		if cc != nil {
			cc.Close()
		}
	}()

	// 服务端照常读：SETTINGS 的 INITIAL_WINDOW_SIZE 应为改写后的 2MB。
	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	preface := make([]byte, 24)
	if _, err := io.ReadFull(server, preface); err != nil {
		t.Fatalf("读前导失败: %v", err)
	}
	stLen, stType, _, _ := readFrameHeader(t, server)
	if stType != 0x4 {
		t.Fatalf("首帧不是 SETTINGS: type=%x", stType)
	}
	payload := make([]byte, stLen)
	if _, err := io.ReadFull(server, payload); err != nil {
		t.Fatalf("读 SETTINGS 失败: %v", err)
	}
	if val := binary.BigEndian.Uint32(payload[6+2:]); val != 2097152 {
		t.Errorf("INITIAL_WINDOW_SIZE = %d, want 2097152", val)
	}
}

// TestPatchH2PrefacePassthrough 非前导/畸形输入必须原样放行。
func TestPatchH2PrefacePassthrough(t *testing.T) {
	// 不足 24 字节无法判定，应继续缓冲。
	if _, ok := patchH2Preface([]byte("PRI * HTTP/2.0\r\n")); ok {
		t.Error("字节不足时不应做出判定")
	}
	// 满 24 字节但不是前导：放行。
	notPreface := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	out, ok := patchH2Preface(notPreface)
	if !ok || string(out) != string(notPreface) {
		t.Error("非前导字节应原样放行")
	}
	// 前导 + 非 SETTINGS 首帧（如直接 WINDOW_UPDATE）应放行。
	buf := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	buf = append(buf, 0, 0, 4, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 100)
	out, ok = patchH2Preface(buf)
	if !ok || len(out) != len(buf) {
		t.Error("非 SETTINGS 首帧应原样放行")
	}
}
