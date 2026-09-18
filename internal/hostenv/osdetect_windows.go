//go:build windows

package hostenv

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// windowsVersion 对齐 os_info 在 Windows 上的输出版本："10.0.26100"。
func windowsVersion() string {
	v := windows.RtlGetVersion()
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
}
