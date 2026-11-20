// SPDX-License-Identifier: MIT

//go:build windows

package selfinstall

import (
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Dest is where dpt is installed.
func Dest() string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "dpt", "dpt.exe")
}

func versionFlag() string { return "/version" }

// replace: Windows will not overwrite a program that is running, but it
// will rename it, so the old one moves to dpt.exe.old first (removed the
// next time, when nothing runs it).
func replace(tmp, dest string) error {
	old := dest + ".old"
	os.Remove(old)
	if _, err := os.Stat(dest); err == nil {
		if err := os.Rename(dest, old); err != nil {
			return err
		}
	}
	if err := os.Rename(tmp, dest); err != nil {
		os.Rename(old, dest) // put the old one back
		return err
	}
	return nil
}

const envKey = `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`

// AddToPath adds dir to the system PATH when it is not there; true when
// it added it (programs started after see it).
func AddToPath(dir string) (bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, envKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return false, err
	}
	defer k.Close()
	v, typ, err := k.GetStringValue("Path")
	if err != nil && err != registry.ErrNotExist {
		return false, err
	}
	if PathHas(v, dir) {
		return false, nil
	}
	nv := PathAppend(v, dir)
	if typ == registry.EXPAND_SZ || err == registry.ErrNotExist {
		err = k.SetExpandStringValue("Path", nv)
	} else {
		err = k.SetStringValue("Path", nv)
	}
	if err != nil {
		return false, err
	}
	broadcastEnv()
	return true, nil
}

// broadcastEnv tells running programs (Explorer) that the environment
// changed, so windows opened from now on have the new PATH.
func broadcastEnv() {
	user32 := windows.NewLazySystemDLL("user32.dll")
	send := user32.NewProc("SendMessageTimeoutW")
	env, _ := windows.UTF16PtrFromString("Environment")
	var result uintptr
	const hwndBroadcast, wmSettingChange, smtoAbortIfHung = 0xffff, 0x001A, 0x0002
	send.Call(hwndBroadcast, wmSettingChange, 0, uintptr(unsafe.Pointer(env)), smtoAbortIfHung, 5000, uintptr(unsafe.Pointer(&result)))
}
