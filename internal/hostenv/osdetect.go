package hostenv

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// detectOSName 对齐 os_info::Type 的 Display 输出：
// macOS → "Mac OS"，Windows → "Windows"，Linux → /etc/os-release 的 NAME 原文。
func detectOSName() string {
	switch runtime.GOOS {
	case "darwin":
		return "Mac OS"
	case "windows":
		return "Windows"
	case "linux":
		if name := osReleaseField("NAME"); name != "" {
			return name
		}
		return "Linux"
	default:
		return "Linux"
	}
}

// detectOSVersion 对齐 os_info::Info::version() 的 Display 输出。
func detectOSVersion() string {
	switch runtime.GOOS {
	case "darwin":
		// os_info 在 macOS 上语义化为三段版本（"15.5" → "15.5.0"）。
		if out, err := exec.Command("sw_vers", "-productVersion").Output(); err == nil {
			return normalizeSemanticVersion(strings.TrimSpace(string(out)))
		}
		return "Unknown"
	case "windows":
		if v := windowsVersion(); v != "" {
			return v
		}
		return "Unknown"
	case "linux":
		// os_info 把 VERSION_ID 解析为语义化版本再 Display："24.04" → "24.4.0"。
		if v := osReleaseField("VERSION_ID"); v != "" {
			return normalizeSemanticVersion(v)
		}
		return "Unknown"
	default:
		return "Unknown"
	}
}

// normalizeSemanticVersion 对齐 os_info Version::Semantic 的 Display：
// 逐段按整数解析（前导零消失），不足三段补零（"24.04" → "24.4.0"）；
// 任一段非纯数字时按 Version::Custom 处理，原文返回（如 "rolling"）。
func normalizeSemanticVersion(v string) string {
	if v == "" {
		return "Unknown"
	}
	segments := strings.Split(v, ".")
	normalized := make([]string, 0, len(segments))
	for _, seg := range segments {
		numeric := strings.TrimLeft(seg, "0")
		if numeric == "" && seg != "" {
			numeric = "0"
		}
		if numeric == "" || !isAllDigits(seg) {
			return v // Version::Custom：原文输出
		}
		normalized = append(normalized, numeric)
	}
	for len(normalized) < 3 {
		normalized = append(normalized, "0")
	}
	return strings.Join(normalized, ".")
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

// osReleaseField 解析 /etc/os-release（回退 /usr/lib/os-release）的字段，
// 处理引号包裹的值。与 os_info 的解析行为一致。
func osReleaseField(key string) string {
	for _, path := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok || k != key {
				continue
			}
			return strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return ""
}
