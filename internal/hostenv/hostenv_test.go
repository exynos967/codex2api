package hostenv

import (
	"runtime"
	"strings"
	"testing"
)

func TestCurrentSnapshotIsStable(t *testing.T) {
	first := Current()
	second := Current()
	if first != second {
		t.Fatalf("Current() 不稳定: %+v vs %+v", first, second)
	}
}

func TestCurrentFieldsNonEmpty(t *testing.T) {
	env := Current()
	if env.OSName == "" || env.OSVersion == "" || env.Arch == "" || env.Terminal == "" {
		t.Fatalf("快照字段不得为空: %+v", env)
	}
}

func TestCurrentMatchesRuntimePlatform(t *testing.T) {
	env := Current()
	switch runtime.GOOS {
	case "darwin":
		if env.OSName != "Mac OS" {
			t.Fatalf("darwin OSName = %q, want Mac OS", env.OSName)
		}
	case "windows":
		if env.OSName != "Windows" {
			t.Fatalf("windows OSName = %q, want Windows", env.OSName)
		}
		if !strings.HasPrefix(env.OSVersion, "10.") && env.OSVersion != "Unknown" {
			t.Fatalf("windows OSVersion = %q, want 10.0.xxxxx 形态", env.OSVersion)
		}
	default:
		if env.OSName == "Mac OS" || env.OSName == "Windows" {
			t.Fatalf("linux 上 OSName 不应为 %q", env.OSName)
		}
	}
	if runtime.GOARCH == "amd64" && env.Arch != "x86_64" {
		t.Fatalf("amd64 Arch = %q, want x86_64", env.Arch)
	}
}

func TestCodexOSSegmentShape(t *testing.T) {
	env := Environment{OSName: "Ubuntu", OSVersion: "24.4.0", Arch: "x86_64", Terminal: "xterm-256color"}
	if got := env.CodexOSSegment(); got != "Ubuntu 24.4.0; x86_64" {
		t.Fatalf("CodexOSSegment() = %q", got)
	}
}

func TestNormalizeSemanticVersion(t *testing.T) {
	cases := map[string]string{
		"24.04":     "24.4.0",
		"22.04":     "22.4.0",
		"15.5":      "15.5.0",
		"10.0.26100": "10.0.26100",
		"12":        "12.0.0",
		"rolling":   "rolling",
		"":          "Unknown",
	}
	for in, want := range cases {
		if got := normalizeSemanticVersion(in); got != want {
			t.Errorf("normalizeSemanticVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSanitizeTerminalToken(t *testing.T) {
	if got := sanitizeTerminalToken("xterm-256color"); got != "xterm-256color" {
		t.Fatalf("普通 TERM 被改写: %q", got)
	}
	if got := sanitizeTerminalToken("bad term;()"); strings.ContainsAny(got, " ();") {
		t.Fatalf("非法字符未被替换: %q", got)
	}
}
