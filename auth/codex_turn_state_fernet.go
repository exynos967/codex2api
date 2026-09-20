package auth

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"time"
)

// X-Codex-Turn-State 的 Fernet 封装解析。
//
// 实测（tlsprobe/codex.flows 真实 312 token）：base64url 解码后是标准 Fernet
// 结构——0x80 版本字节 + 8 字节大端签发时间 + 16 字节 IV + 16 倍数密文 + 32
// 字节 HMAC，总长 57+16n。块数 n 是账号形态与降智形态的真实分野：
//
//	10 块（292 字符）个人正常；11 块（312 字符）个人降智
//	12 块（332 字符）Team 正常；13 块（356 字符）Team 降智
//
// 长度只是这个结构的编码表象；解析还能读出 token 内嵌的签发时间——这是
// token 的真实寿命起点，与"何时保存进本网关"无关（重新粘贴不续命）。
const (
	// CodexTurnStateTTL 是 token 内嵌签发时间的寿命（与社区实测一致：1 小时）。
	CodexTurnStateTTL = time.Hour
	// CodexTurnStateRefreshAge 是签发后主动提前刷新的窗口（sleep-state 同款
	// 1200s）：好 token 用满这么久就该在降智出现前换掉，而不是等 312。
	CodexTurnStateRefreshAge = 20 * time.Minute
	// codexTurnStateClockSkew 容忍上下游时钟偏差。
	codexTurnStateClockSkew = 30 * time.Second

	codexTurnStateFernetVersion  = 0x80
	codexTurnStateFernetOverhead = 57 // 1 版本 + 8 时间 + 16 IV + 32 HMAC
)

// CodexTurnStateInfo 是一次成功解析的结构化结果。
type CodexTurnStateInfo struct {
	Issued time.Time // token 内嵌签发时间（UTC）
	Blocks int       // Fernet 密文块数
}

// codexTurnStateGoodBlocks / codexTurnStateDegradedBlocks 是块数形态分类。
func codexTurnStateGoodBlocks(blocks int) bool     { return blocks == 10 || blocks == 12 }
func codexTurnStateDegradedBlocks(blocks int) bool { return blocks == 11 || blocks == 13 }

// ParseCodexTurnState 严格解析 Fernet 封装；不是合法封装返回 error。
func ParseCodexTurnState(value string) (CodexTurnStateInfo, error) {
	var info CodexTurnStateInfo
	value = strings.TrimSpace(value)
	core := strings.TrimRight(value, "=")
	if value == "" || len(value)-len(core) > 2 {
		return info, errors.New("invalid state padding")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(core)
	if err != nil || len(raw) < codexTurnStateFernetOverhead {
		return info, errors.New("unrecognized state envelope")
	}
	if raw[0] != codexTurnStateFernetVersion || (len(raw)-codexTurnStateFernetOverhead)%16 != 0 {
		return info, errors.New("unrecognized state envelope")
	}
	issued := binary.BigEndian.Uint64(raw[1:9])
	// 签发时间做合理性范围校验（2020-01-01 ～ 2100-01-01），防垃圾字段。
	if issued < 1577836800 || issued >= 4102444800 {
		return info, errors.New("state timestamp out of range")
	}
	info.Issued = time.Unix(int64(issued), 0).UTC()
	info.Blocks = (len(raw) - codexTurnStateFernetOverhead) / 16
	return info, nil
}

// CodexTurnStateClass 是 turn-state 的形态分类。
type CodexTurnStateClass int

const (
	CodexTurnStateClassUnknown  CodexTurnStateClass = iota // 无法判定（含无法解析的未知长度）
	CodexTurnStateClassGood                                // 正常可复用（个人 292 / Team 332）
	CodexTurnStateClassDegraded                            // IP 绑定降智（个人 312 / Team 356）
)

// ClassifyCodexTurnState 判定形态。长度快速预检 + Fernet 解析确认：
// 真实 token 全走解析（拿块数与签发时间）；解析失败时按长度规则回落，
// 上游改格式或存量非标值不至于误判。返回值同时给出解析信息（可能为零值）。
func ClassifyCodexTurnState(value string) (CodexTurnStateClass, CodexTurnStateInfo) {
	value = strings.TrimSpace(value)
	info, err := ParseCodexTurnState(value)
	if err == nil {
		switch {
		case codexTurnStateGoodBlocks(info.Blocks):
			return CodexTurnStateClassGood, info
		case codexTurnStateDegradedBlocks(info.Blocks):
			return CodexTurnStateClassDegraded, info
		default:
			return CodexTurnStateClassUnknown, info
		}
	}
	// 回落：长度规则（兼容无法解析的存量/测试值）。
	switch len(value) {
	case CodexTurnStateGoodLength, CodexTurnStateTeamGoodLength:
		return CodexTurnStateClassGood, CodexTurnStateInfo{}
	case CodexTurnStateDegradedLength, CodexTurnStateTeamDegradedLength:
		return CodexTurnStateClassDegraded, CodexTurnStateInfo{}
	default:
		return CodexTurnStateClassUnknown, CodexTurnStateInfo{}
	}
}

// IsCodexTurnStateGood 判定是否为可固定的正常形态（含 Team 332）。
func IsCodexTurnStateGood(value string) bool {
	class, _ := ClassifyCodexTurnState(value)
	return class == CodexTurnStateClassGood
}

// IsCodexTurnStateDegraded 判定是否为降智形态（含 Team 356）。
func IsCodexTurnStateDegraded(value string) bool {
	class, _ := ClassifyCodexTurnState(value)
	return class == CodexTurnStateClassDegraded
}

// CodexTurnStateExpiredByIssue 按 token 内嵌签发时间判定是否已过期。
// 解析不出的值（无签发时间）不判过期——保持旧行为，不误伤存量。
func CodexTurnStateExpiredByIssue(value string, now time.Time) bool {
	info, err := ParseCodexTurnState(value)
	if err != nil {
		return false
	}
	return !now.Before(info.Issued.Add(CodexTurnStateTTL - codexTurnStateClockSkew))
}

// CodexTurnStateRefreshDueByIssue 判定好 token 是否已过提前刷新窗口。
// 只用于"已有好 token 是否该主动换"，签发时间缺失时按不到期处理。
func CodexTurnStateRefreshDueByIssue(value string, now time.Time) bool {
	info, err := ParseCodexTurnState(value)
	if err != nil {
		return false
	}
	return !now.Before(info.Issued.Add(CodexTurnStateRefreshAge))
}
