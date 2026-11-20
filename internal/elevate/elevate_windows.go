// SPDX-License-Identifier: MIT

//go:build windows

package elevate

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Possible: not elevated already.
func Possible() bool { return !windows.GetCurrentProcessToken().IsElevated() }

// shellExecuteInfo is SHELLEXECUTEINFOW.
type shellExecuteInfo struct {
	cbSize       uint32
	fMask        uint32
	hwnd         uintptr
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     uintptr
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    uintptr
	dwHotKey     uint32
	hIcon        uintptr
	hProcess     windows.Handle
}

const (
	seeMaskNoCloseProcess = 0x00000040
	seeMaskNoAsync        = 0x00000100
	seeMaskFlagNoUI       = 0x00000400
	swHide                = 0
)

var procShellExecuteExW = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")

// Run asks UAC to run dpt <args> elevated with no window of its own; what
// it writes comes back through a named pipe and is printed here.  It
// returns the elevated copy's exit code.
func Run(what string, args []string, color bool) (int, error) {
	self, err := os.Executable()
	if err != nil {
		return 0, err
	}
	var rb [12]byte
	if _, err := rand.Read(rb[:]); err != nil {
		return 0, err
	}
	pipe := `\\.\pipe\dpt-` + hex.EncodeToString(rb[:])
	p16, _ := windows.UTF16PtrFromString(pipe)
	ph, err := windows.CreateNamedPipe(p16, windows.PIPE_ACCESS_INBOUND|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, 0, 64<<10, 0, nil)
	if err != nil {
		return 0, err
	}
	c := "0"
	if color {
		c = "1"
	}
	params := []string{windows.EscapeArg(RelayFlag + pipe + "," + c)}
	for _, a := range args {
		params = append(params, windows.EscapeArg(a))
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(self)
	par, _ := windows.UTF16PtrFromString(strings.Join(params, " "))
	sei := shellExecuteInfo{fMask: seeMaskNoCloseProcess | seeMaskNoAsync | seeMaskFlagNoUI,
		lpVerb: verb, lpFile: file, lpParameters: par, nShow: swHide}
	sei.cbSize = uint32(unsafe.Sizeof(sei))
	fmt.Fprintln(os.Stderr, what+" needs an Administrator prompt: asking Windows (UAC)")
	if r, _, e := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&sei))); r == 0 {
		windows.CloseHandle(ph)
		if e == windows.ERROR_CANCELLED {
			return 0, errors.New("not allowed")
		}
		return 0, e
	}
	defer windows.CloseHandle(sei.hProcess)
	// copy what the elevated copy writes until it closes the pipe
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := windows.ConnectNamedPipe(ph, nil); err != nil && err != windows.ERROR_PIPE_CONNECTED {
			return
		}
		io.Copy(os.Stdout, os.NewFile(uintptr(ph), pipe))
	}()
	windows.WaitForSingleObject(sei.hProcess, windows.INFINITE)
	var code uint32
	windows.GetExitCodeProcess(sei.hProcess, &code)
	// if it never connected, connecting here ends ConnectNamedPipe and the
	// copy reads nothing; if it did, this fails and the copy drains
	if f, err := os.OpenFile(pipe, os.O_WRONLY, 0); err == nil {
		f.Close()
	}
	<-done
	return int(code), nil
}

// Relay: in the elevated copy, send stdout and stderr down the pipe that
// arg (the value of RelayFlag) names; it says whether colour is on.
func Relay(arg string) (bool, error) {
	pipe, c, _ := strings.Cut(arg, ",")
	if !strings.HasPrefix(pipe, `\\.\pipe\dpt-`) {
		return false, errors.New("bad relay")
	}
	f, err := os.OpenFile(pipe, os.O_WRONLY, 0)
	if err != nil {
		return false, err
	}
	os.Stdout, os.Stderr = f, f
	return c == "1", nil
}
