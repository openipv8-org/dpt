// SPDX-License-Identifier: MIT

package selfinstall

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
)

// ManPath is where dpt install puts dpt(1), where man finds it; "" on
// Windows, which has no man.
func ManPath() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	return "/usr/local/share/man/man1/dpt.1"
}

// ManCurrent: there is no man here, or the page installed is page.
func ManCurrent(page []byte) bool {
	p := ManPath()
	if p == "" {
		return true
	}
	b, err := os.ReadFile(p)
	return err == nil && bytes.Equal(b, page)
}

// InstallMan writes page to ManPath, making its directory.
func InstallMan(page []byte) error {
	p := ManPath()
	if p == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".dpt.1-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(page); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}
