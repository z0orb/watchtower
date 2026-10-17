package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/z0orb/watchtower/internal/arpguard"
	"github.com/z0orb/watchtower/internal/store"
	"github.com/z0orb/watchtower/internal/tray"
)

const uninstallKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Watchtower`

const idYes = 6

var procShellExecuteEx = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")

// shellExecuteInfo is SHELLEXECUTEINFOW.
type shellExecuteInfo struct {
	cbSize       uint32
	fMask        uint32
	hwnd         uintptr
	verb         *uint16
	file         *uint16
	parameters   *uint16
	directory    *uint16
	show         int32
	instApp      uintptr
	idList       uintptr
	class        *uint16
	keyClass     uintptr
	hotKey       uint32
	iconOrMonitr uintptr
	process      windows.Handle
}

func messageBox(text string, flags uint32) int32 {
	t, _ := windows.UTF16PtrFromString(text)
	c, _ := windows.UTF16PtrFromString("Watchtower")
	r, _ := windows.MessageBox(0, t, c, flags|windows.MB_SETFOREGROUND)
	return r
}

// runElevated runs this exe with args as admin (UAC prompt), hidden, and waits for it.
// Declining the prompt returns windows.ERROR_CANCELLED.
func runElevated(args string) (uint32, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, err
	}
	info := shellExecuteInfo{fMask: 0x40 /* SEE_MASK_NOCLOSEPROCESS */, show: windows.SW_HIDE}
	info.cbSize = uint32(unsafe.Sizeof(info))
	info.verb, _ = windows.UTF16PtrFromString("runas")
	info.file, _ = windows.UTF16PtrFromString(exe)
	info.parameters, _ = windows.UTF16PtrFromString(args)
	if r, _, err := procShellExecuteEx.Call(uintptr(unsafe.Pointer(&info))); r == 0 {
		return 0, err
	}
	defer windows.CloseHandle(info.process)
	windows.WaitForSingleObject(info.process, windows.INFINITE)
	var code uint32
	err = windows.GetExitCodeProcess(info.process, &code)
	return code, err
}

// noWindow starts a console program without flashing a console window.
func noWindow(name string, args ...string) *exec.Cmd {
	c := exec.Command(name, args...)
	c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	return c
}

func installedVersion() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstallKey, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, _ := k.GetStringValue("DisplayVersion")
	return v
}

// launch is a start without arguments, e.g. a double-click: install or update if needed, then show the tray.
func launch() {
	self, _ := os.Executable()
	dst := installedExe()
	_, statErr := os.Stat(dst)
	act, prompt := launchAction(version, installedVersion(), statErr == nil, strings.EqualFold(self, dst))
	switch act {
	case actTray:
		tray.Run(filepath.Join(store.Dir(), "watchtower.log"))
		return
	case actOpenInstalled:
		noWindow(dst, "tray").Start() // if it already runs, its single-instance toast says so
		return
	}
	if messageBox(prompt, windows.MB_YESNO|windows.MB_ICONQUESTION) != idYes {
		return
	}
	code, err := runElevated("install")
	if err != nil {
		if !errors.Is(err, windows.ERROR_CANCELLED) {
			messageBox("Couldn't start the installer: "+err.Error(), windows.MB_ICONERROR)
		}
		return
	}
	if code != 0 {
		return // the elevated install showed its error
	}
	// Close the old tray in this session only (never the service, never other users), then start the new one
	// as this user: the elevated install must not start it, it may even be a different account.
	var session uint32
	windows.ProcessIdToSessionId(uint32(os.Getpid()), &session)
	noWindow("taskkill", "/F", "/IM", "watchtower.exe", "/FI", "PID ne "+strconv.Itoa(os.Getpid()),
		"/FI", "SESSION eq "+strconv.Itoa(int(session))).Run()
	noWindow(dst, "tray").Start()

	msg := "Watchtower is installed and protecting this PC. Its shield is in the notification area."
	if arpguard.NpcapAvailable() {
		messageBox(msg, windows.MB_ICONINFORMATION)
		return
	}
	if messageBox(msg+"\n\nNpcap is needed for live attack detection and can't be bundled. Open npcap.com to "+
		"install it?", windows.MB_YESNO|windows.MB_ICONQUESTION) == idYes {
		windows.ShellExecute(0, windows.StringToUTF16Ptr("open"), windows.StringToUTF16Ptr("https://npcap.com"), nil, nil, windows.SW_SHOWNORMAL)
	}
}

// adminCommand runs install or uninstall. Started from the GUI (its own console: the double-click flow or
// Settings › Apps) it asks for elevation itself and reports in message boxes instead of the console.
func adminCommand(cmd string, run func() error) error {
	if !ownsConsole() {
		return run()
	}
	procFreeConsole.Call()
	if !windows.GetCurrentProcessToken().IsElevated() {
		code, err := runElevated(cmd)
		if err != nil && !errors.Is(err, windows.ERROR_CANCELLED) {
			messageBox("Couldn't get administrator permission: "+err.Error(), windows.MB_ICONERROR)
		}
		os.Exit(int(code))
	}
	var out strings.Builder
	sayTo = &out
	if err := run(); err != nil {
		messageBox("Watchtower "+cmd+" failed: "+err.Error(), windows.MB_ICONERROR)
		os.Exit(1)
	}
	if cmd == "uninstall" { // after install, the launching process reports
		messageBox(strings.TrimSpace(out.String()), windows.MB_ICONINFORMATION)
	}
	return nil
}
