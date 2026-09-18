// Package hostenv 在进程启动时快照宿主机环境，用于生成与部署机一致的
// Codex 客户端身份字段（UA 环境段 / 终端令牌）。
//
// 为什么要从宿主机提取而不是硬编码：被动 TCP 指纹（p0f 等）能识别出口机器的
// OS 家族，UA 声明 "Mac OS" 而 TCP 栈是 Linux 是应用层与传输层自相矛盾的指纹，
// 风控可直接据此判定造假。身份必须与部署机一致——在哪部署就提取哪的。
//
// 字段命名与真实 codex-rs 对齐（login/src/auth/default_client.rs）：
// OSName/OSVersion 来自 os_info crate 的语义（Linux 取 /etc/os-release 的
// NAME 与 VERSION_ID 原文），Arch 为 os_info 风格（amd64→x86_64，arm64 不变），
// Terminal 复刻 codex-rs terminal-detection 的探测顺序。
package hostenv

import (
	"os"
	"runtime"
	"strings"
	"sync"
)

// Environment 是宿主机环境的启动快照。
type Environment struct {
	OSName    string // os_info 风格："Ubuntu"、"Debian GNU/Linux"、"Windows"、"Mac OS"
	OSVersion string // "24.04" / "10.0.26100" / "15.5.0"；未知为 "Unknown"
	Arch      string // os_info 风格："x86_64" / "arm64"
	Terminal  string // codex 终端令牌："xterm-256color" / "WindowsTerminal" / "unknown"
}

var (
	currentOnce sync.Once
	current     Environment
)

// Current 返回进程级环境快照（首次调用时探测，之后恒定——与真实客户端一致：
// codex-rs 的 UA 也是进程启动时固化，不会随环境变量中途变化）。
func Current() Environment {
	currentOnce.Do(func() {
		current = detect()
	})
	return current
}

func detect() Environment {
	return Environment{
		OSName:    detectOSName(),
		OSVersion: detectOSVersion(),
		Arch:      detectArch(),
		Terminal:  detectTerminal(),
	}
}

// Family 返回 OS 家族标识："linux" / "darwin" / "windows" / 其他（如 "freebsd"）。
// 用于把画像池约束到与宿主 TCP 指纹一致的家族。
func (e Environment) Family() string {
	return runtime.GOOS
}

// CodexOSSegment 返回 codex UA 的 "({os} {version}; {arch})" 段（不含括号）。
func (e Environment) CodexOSSegment() string {
	return strings.TrimSpace(e.OSName+" "+e.OSVersion) + "; " + e.Arch
}

func detectArch() string {
	// os_info::Info::architecture() 的命名风格
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	default:
		// arm64、386、riscv64 等 os_info 原样输出
		return runtime.GOARCH
	}
}

func detectTerminal() string {
	// 复刻 codex-rs terminal-detection 的探测顺序（仅环境变量部分）：
	// TERM_PROGRAM(+VERSION) → 终端专属变量 → TERM → unknown。
	if program := envNonEmpty("TERM_PROGRAM"); program != "" && !strings.EqualFold(program, "tmux") {
		version := envNonEmpty("TERM_PROGRAM_VERSION")
		return sanitizeTerminalToken(terminalProgramToken(program, version))
	}
	if envNonEmpty("GHOSTTY_RESOURCES_DIR") != "" {
		return "Ghostty"
	}
	if v := envNonEmpty("WEZTERM_VERSION"); v != "" {
		return sanitizeTerminalToken("WezTerm/" + v)
	}
	if envNonEmpty("ITERM_SESSION_ID") != "" || envNonEmpty("ITERM_PROFILE") != "" || envNonEmpty("ITERM_PROFILE_NAME") != "" {
		return "iTerm.app"
	}
	if envNonEmpty("TERM_SESSION_ID") != "" {
		return "Apple_Terminal"
	}
	if envNonEmpty("KITTY_WINDOW_ID") != "" {
		return "kitty"
	}
	if envNonEmpty("ALACRITTY_SOCKET") != "" || envNonEmpty("ALACRITTY_LOG") != "" {
		return "Alacritty"
	}
	if envNonEmpty("WT_SESSION") != "" {
		return "WindowsTerminal"
	}
	if term := envNonEmpty("TERM"); term != "" {
		return sanitizeTerminalToken(term)
	}
	return "unknown"
}

func terminalProgramToken(program, version string) string {
	// 与 codex-rs TerminalInfo::user_agent_token 的 TERM_PROGRAM 分支一致：
	// 有版本输出 program/version，无版本只输出 program。
	if version != "" {
		return program + "/" + version
	}
	return program
}

// sanitizeTerminalToken 对齐 codex-rs sanitize_header_value：UA 头值不允许
// 控制字符、空格、括号、分号，统一替换为下划线。
func sanitizeTerminalToken(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		if r < 0x21 || r == 0x7f || strings.ContainsRune("();\"\\", r) {
			b.WriteByte('_')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func envNonEmpty(name string) string {
	return strings.TrimSpace(os.Getenv(name))
}
