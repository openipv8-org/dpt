// SPDX-License-Identifier: MIT

package selfinstall

import (
	"path/filepath"
	"runtime"
	"strings"
)

// A dpt a package manager installed is that manager's to upgrade: dpt
// upgrade runs it, and dpt install leaves it where it is.

// WingetID is dpt's winget package.
const WingetID = "OpenIPv8.dpt"

// Manager is the package manager that installed the dpt at exe: "winget"
// (a portable package under ...\WinGet\Packages, or its link in
// ...\WinGet\Links), or "" when none did.
func Manager(exe string) string {
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	return manager(runtime.GOOS, exe)
}

func manager(goos, exe string) string {
	if goos != "windows" {
		return ""
	}
	p := strings.ToLower(strings.ReplaceAll(exe, "/", `\`))
	if strings.Contains(p, `\winget\packages\`) || strings.Contains(p, `\winget\links\`) {
		return "winget"
	}
	return ""
}

// ManagerUpgrade is the command that upgrades dpt through manager m.
func ManagerUpgrade(m string) []string {
	switch m {
	case "winget":
		return []string{"winget", "upgrade", "--id", WingetID, "--exact"}
	}
	return nil
}
