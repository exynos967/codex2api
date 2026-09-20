package auth

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// 构造一个合法 Fernet 封装的假 token（仅结构合法，密文是填充字节）。
// 真实 token 是带 padding 的标准 base64url：57+16n 字节编码后恰为
// 292/312/332/356 字符。
func makeFernetTurnState(t *testing.T, blocks int, issued int64) string {
	t.Helper()
	raw := make([]byte, codexTurnStateFernetOverhead+16*blocks)
	raw[0] = codexTurnStateFernetVersion
	binary.BigEndian.PutUint64(raw[1:9], uint64(issued))
	for i := codexTurnStateFernetOverhead - 32; i < len(raw); i++ {
		raw[i] = byte(i % 251)
	}
	return base64.URLEncoding.EncodeToString(raw)
}

func TestParseCodexTurnStateFernet(t *testing.T) {
	issued := time.Date(2026, 9, 18, 18, 28, 17, 0, time.UTC).Unix()
	for _, tc := range []struct {
		blocks  int
		wantLen int
		wantCl  CodexTurnStateClass
	}{
		{10, 292, CodexTurnStateClassGood},
		{11, 312, CodexTurnStateClassDegraded},
		{12, 332, CodexTurnStateClassGood},
		{13, 356, CodexTurnStateClassDegraded},
		{9, 0, CodexTurnStateClassUnknown},
	} {
		token := makeFernetTurnState(t, tc.blocks, issued)
		if tc.wantLen > 0 && len(token) != tc.wantLen {
			t.Fatalf("blocks=%d token len=%d, want %d（长度应是封装的编码表象）", tc.blocks, len(token), tc.wantLen)
		}
		class, info := ClassifyCodexTurnState(token)
		if class != tc.wantCl {
			t.Errorf("blocks=%d class=%v, want %v", tc.blocks, class, tc.wantCl)
		}
		if tc.wantCl != CodexTurnStateClassUnknown {
			if info.Blocks != tc.blocks || info.Issued.Unix() != issued {
				t.Errorf("blocks=%d info=%+v, want blocks=%d issued=%d", tc.blocks, info, tc.blocks, issued)
			}
		}
	}
}

func TestClassifyCodexTurnStateLengthFallback(t *testing.T) {
	// 无法解析的存量/测试值按长度规则回落，行为与旧版一致。
	if !IsCodexTurnStateGood(strings.Repeat("a", 292)) {
		t.Error("292 非 Fernet 值应回落长度规则判 Good")
	}
	if !IsCodexTurnStateDegraded(strings.Repeat("b", 312)) {
		t.Error("312 非 Fernet 值应回落长度规则判 Degraded")
	}
	if !IsCodexTurnStateGood(strings.Repeat("c", 332)) {
		t.Error("332 非 Fernet 值应回落长度规则判 Good（Team）")
	}
	if IsCodexTurnStateGood(strings.Repeat("d", 300)) {
		t.Error("未知长度不应判 Good")
	}
}

func TestCodexTurnStateIssueTimeRules(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	fresh := makeFernetTurnState(t, 10, now.Add(-10*time.Minute).Unix())
	old := makeFernetTurnState(t, 10, now.Add(-50*time.Minute).Unix())
	expired := makeFernetTurnState(t, 10, now.Add(-2*time.Hour).Unix())

	if CodexTurnStateExpiredByIssue(fresh, now) {
		t.Error("签发 10 分钟不应过期")
	}
	if CodexTurnStateRefreshDueByIssue(fresh, now) {
		t.Error("签发 10 分钟不应到提前刷新窗口")
	}
	if !CodexTurnStateRefreshDueByIssue(old, now) {
		t.Error("签发 50 分钟应到提前刷新窗口（20 分钟）")
	}
	if CodexTurnStateExpiredByIssue(old, now) {
		t.Error("签发 50 分钟不应过期（TTL 1 小时）")
	}
	if !CodexTurnStateExpiredByIssue(expired, now) {
		t.Error("签发 2 小时应过期")
	}
	// 解析不出的值不判过期、不判到期（保持旧行为）。
	if CodexTurnStateExpiredByIssue(strings.Repeat("a", 292), now) || CodexTurnStateRefreshDueByIssue(strings.Repeat("a", 292), now) {
		t.Error("非 Fernet 值不应按时间判定")
	}
}

func TestParseCodexTurnStateRejectsGarbage(t *testing.T) {
	issued := time.Now().Unix()
	good := makeFernetTurnState(t, 10, issued)
	if _, err := ParseCodexTurnState(good); err != nil {
		t.Fatalf("合法封装应通过: %v", err)
	}
	for _, bad := range []string{
		"",
		strings.Repeat("x", 292), // 非 base64 字符外的随机串
		"not-base64!!!",
		makeFernetTurnState(t, 10, 100), // 时间戳超出合理范围
	} {
		if _, err := ParseCodexTurnState(bad); err == nil {
			t.Errorf("应拒绝: %.30q", bad)
		}
	}
}
