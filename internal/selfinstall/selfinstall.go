// SPDX-License-Identifier: MIT

// Package selfinstall puts dpt where the system finds it (dpt install)
// and replaces it with the newest release (dpt upgrade): /usr/local/bin
// on Linux and macOS, C:\Program Files\dpt on Windows (added to PATH).
package selfinstall

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Repo is where releases come from.
const Repo = "openipv8-org/dpt"

// Writable: this process may write the directory dest goes in (creating
// it when missing).
func Writable(dest string) bool {
	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false
	}
	f, err := os.CreateTemp(dir, ".dpt-write-test-*")
	if err != nil {
		return false
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return true
}

// SameFile: a and b are the one file.
func SameFile(a, b string) bool {
	sa, err1 := os.Stat(a)
	sb, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(sa, sb)
}

// Install copies src to dest: written beside it first, then put in place
// in one step, so a half-copied dpt is never what runs.
func Install(src, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".dpt-new-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // gone once renamed
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return err
	}
	return replace(tmpName, dest)
}

// ErrUnknownVersion: there is a file at dest, but it does not say which
// dpt it is.
var ErrUnknownVersion = errors.New("does not say its version")

// InstalledVersion is what the dpt at dest says it is ("v0.1.8"); "" with
// no error when nothing is there.
func InstalledVersion(dest string) (string, error) {
	if _, err := os.Stat(dest); err != nil {
		return "", nil
	}
	for _, flag := range []string{versionFlag(), "--version", "/version"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out, err := exec.CommandContext(ctx, dest, flag).Output()
		cancel()
		if err == nil {
			if v := ParseVersionLine(string(out)); v != "" {
				return v, nil
			}
		}
	}
	return "", ErrUnknownVersion
}

// ParseVersionLine reads "dpt v0.1.8 (linux/amd64)".
func ParseVersionLine(s string) string {
	f := strings.Fields(s)
	if len(f) >= 2 && f[0] == "dpt" {
		return f[1]
	}
	return ""
}

// Newer: version a is a later release than b (v0.1.10 > v0.1.9).  Words
// that are not vX.Y.Z (dev, a git describe) are older than any release.
func Newer(a, b string) bool {
	pa, oka := parseV(a)
	pb, okb := parseV(b)
	switch {
	case !oka:
		return false
	case !okb:
		return true
	}
	for i := range pa {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func parseV(s string) ([3]int, bool) {
	var v [3]int
	s = strings.TrimPrefix(s, "v")
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

// AssetName is the release file for this system.
func AssetName() string {
	n := "dpt-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		n += ".exe"
	}
	return n
}

// SumFor finds name's SHA-256 in a SHA256SUMS file.
func SumFor(sums, name string) (string, bool) {
	sc := bufio.NewScanner(strings.NewReader(sums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name && len(f[0]) == 64 {
			return strings.ToLower(f[0]), true
		}
	}
	return "", false
}

var client = &http.Client{Timeout: 5 * time.Minute}

// LatestTag is the newest release's tag.
func LatestTag(ctx context.Context) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/repos/"+Repo+"/releases/latest", nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("GitHub: %s", resp.Status)
	}
	var r struct {
		Tag string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r); err != nil {
		return "", err
	}
	if _, ok := parseV(r.Tag); !ok {
		return "", fmt.Errorf("GitHub: release tag %q is not a version", r.Tag)
	}
	return r.Tag, nil
}

// Download fetches tag's build for this system into a file in dir,
// checked against the release's SHA256SUMS, showing its progress on w.
func Download(ctx context.Context, tag, dir string, w io.Writer) (string, error) {
	base := "https://github.com/" + Repo + "/releases/download/" + tag + "/"
	name := AssetName()
	sums, err := get(ctx, base+"SHA256SUMS", 1<<16)
	if err != nil {
		return "", fmt.Errorf("SHA256SUMS: %w", err)
	}
	want, ok := SumFor(string(sums), name)
	if !ok {
		return "", fmt.Errorf("%s has no %s", tag, name)
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", base+name, nil)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("%s: %s", name, resp.Status)
	}
	f, err := os.CreateTemp(dir, ".dpt-download-*")
	if err != nil {
		return "", err
	}
	h := sha256.New()
	p := &progress{w: w, name: name + " " + tag, total: resp.ContentLength}
	_, err = io.Copy(io.MultiWriter(f, h, p), io.LimitReader(resp.Body, 64<<20))
	p.done()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		os.Remove(f.Name())
		return "", fmt.Errorf("checksum does not match (%s, want %s): not installed", got[:12], want[:12])
	}
	fmt.Fprintln(w, "checksum OK")
	return f.Name(), nil
}

func get(ctx context.Context, url string, max int64) ([]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New(resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, max))
}

// progress shows a download as it goes: a percentage every 10%.
type progress struct {
	w     io.Writer
	name  string
	total int64
	n     int64
	shown int
}

func (p *progress) Write(b []byte) (int, error) {
	if p.n == 0 {
		size := ""
		if p.total > 0 {
			size = fmt.Sprintf(" (%.1f MB)", float64(p.total)/1e6)
		}
		fmt.Fprintf(p.w, "downloading %s%s ", p.name, size)
	}
	p.n += int64(len(b))
	if p.total > 0 {
		for pct := int(p.n * 100 / p.total); p.shown+10 <= pct; {
			p.shown += 10
			fmt.Fprintf(p.w, "%d%% ", p.shown)
		}
	}
	return len(b), nil
}

func (p *progress) done() {
	if p.n > 0 {
		fmt.Fprintln(p.w)
	}
}
