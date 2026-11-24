// SPDX-License-Identifier: MIT

package selfinstall

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"v0.1.9", "v0.1.8", true},
		{"v0.1.10", "v0.1.9", true},
		{"v0.2.0", "v0.1.99", true},
		{"v0.1.8", "v0.1.8", false},
		{"v0.1.7", "v0.1.8", false},
		{"v0.1.8", "dev", true},
		{"v0.1.8", "v0.1.7-3-gabc-dirty", true},
		{"dev", "v0.1.8", false},
		{"v0.1.8", "", true},
		// test pre-releases: before their release, after the one before
		{"v0.3.2-rc1", "v0.3.1", true},
		{"v0.3.1", "v0.3.2-rc1", false},
		{"v0.3.2", "v0.3.2-rc1", true},
		{"v0.3.2-rc1", "v0.3.2", false},
		{"v0.3.2-rc2", "v0.3.2-rc1", true},
		{"v0.3.2-rc1", "v0.3.2-beta3", true},
		{"v0.3.2-rc1", "v0.3.2-rc1", false},
		{"v0.3.2-rc1-2-gabc", "v0.3.1", false}, // a git describe
		{"v0.3.2-x1", "v0.3.1", false},
	} {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

func TestSumFor(t *testing.T) {
	h := "0623fa89ee5a5d98bd7a0a5bdbac238095fcd098baae7edd52fae03b0c7a7861"
	sums := h + "  dpt-linux-amd64\n" + "abcd  dpt-short\n"
	if got, ok := SumFor(sums, "dpt-linux-amd64"); !ok || got != h {
		t.Errorf("%q %v", got, ok)
	}
	if _, ok := SumFor(sums, "dpt-darwin-amd64"); ok {
		t.Error("absent found")
	}
	if _, ok := SumFor(sums, "dpt-short"); ok {
		t.Error("short hash taken")
	}
}

func TestPath(t *testing.T) {
	p := `C:\Windows\system32;C:\Program Files\dpt\;C:\Tools`
	if !PathHas(p, `c:\program files\dpt`) || PathHas(p, `C:\Program Files\other`) {
		t.Error("PathHas")
	}
	if got := PathAppend(`C:\A;`, `C:\B`); got != `C:\A;C:\B` {
		t.Error(got)
	}
	if got := PathAppend("", `C:\B`); got != `C:\B` {
		t.Error(got)
	}
}

func TestInstallAndVersion(t *testing.T) {
	d := t.TempDir()
	src := filepath.Join(d, "src")
	os.WriteFile(src, []byte("#!/bin/sh\necho 'dpt v0.1.5 (linux/amd64)'\n"), 0o644)
	dest := filepath.Join(d, "bin", "dpt")
	if !Writable(dest) {
		t.Fatal("temp dir not writable")
	}
	if err := Install(src, dest); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	// the version is asked of the program: here shell scripts stand in for
	// it, which Windows cannot run (scripts/ci-test.sh installs the real
	// dpt there and asks it), nor has it Unix permissions
	if runtime.GOOS != "windows" {
		if st.Mode().Perm() != 0o755 {
			t.Fatalf("mode %v", st.Mode())
		}
		if v, err := InstalledVersion(dest); v != "v0.1.5" || err != nil {
			t.Errorf("installed version %q %v", v, err)
		}
		// something there that does not say: never taken for "not installed"
		other := filepath.Join(d, "other")
		os.WriteFile(other, []byte("#!/bin/sh\nexit 3\n"), 0o755)
		if v, err := InstalledVersion(other); v != "" || err != ErrUnknownVersion {
			t.Errorf("unknown: %q %v", v, err)
		}
		if v, err := InstalledVersion(filepath.Join(d, "none")); v != "" || err != nil {
			t.Errorf("none: %q %v", v, err)
		}
	}
	// again, over the top
	if err := Install(src, dest); err != nil {
		t.Fatal(err)
	}
	left, _ := filepath.Glob(filepath.Join(d, "bin", ".dpt-*"))
	if len(left) != 0 {
		t.Errorf("left behind: %v", left)
	}
	if ParseVersionLine("dpt v0.1.8 (windows/amd64)\r\n") != "v0.1.8" || ParseVersionLine("nope") != "" {
		t.Error("ParseVersionLine")
	}
}

func TestIsDownloadName(t *testing.T) {
	for n, want := range map[string]bool{
		"dpt-windows-amd64.exe":                       true,
		`C:\Users\me\Downloads\dpt-windows-arm64.exe`: true,
		"/home/me/Downloads/dpt-linux-amd64":          true,
		"./dpt-darwin-arm64":                          true,
		"dpt-windows-amd64 (1).exe":                   true,
		"DPT-Windows-AMD64.EXE":                       true,
		"dpt":                                         false,
		"dpt.exe":                                     false,
		"/usr/local/bin/dpt":                          false,
		"dpt-linux-386":                               false,
		"dpt-freebsd-amd64":                           false,
		".dpt-download-123":                           false,
	} {
		if got := IsDownloadName(n); got != want {
			t.Errorf("%s: %v", n, got)
		}
	}
}

func TestManager(t *testing.T) {
	for _, c := range []struct {
		goos, exe, want string
	}{
		{"windows", `C:\Users\me\AppData\Local\Microsoft\WinGet\Packages\OpenIPv8.dpt_Microsoft.Winget.Source_8wekyb3d8bbwe\dpt-windows-amd64.exe`, "winget"},
		{"windows", `C:\Users\me\AppData\Local\Microsoft\WinGet\Links\dpt.exe`, "winget"},
		{"windows", `C:\Program Files\WinGet\Packages\OpenIPv8.dpt_Microsoft.Winget.Source_8wekyb3d8bbwe\dpt.exe`, "winget"},
		{"windows", `C:\Program Files\dpt\dpt.exe`, ""},
		{"windows", `C:\Users\me\Downloads\dpt-windows-amd64.exe`, ""},
		{"linux", "/usr/local/bin/dpt", ""},
	} {
		if got := manager(c.goos, c.exe); got != c.want {
			t.Errorf("%s %s: %q", c.goos, c.exe, got)
		}
	}
	if u := ManagerUpgrade("winget"); strings.Join(u, " ") != "winget upgrade --id OpenIPv8.dpt --exact" {
		t.Errorf("%v", u)
	}
}
