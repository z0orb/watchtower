package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/z0orb/watchtower/internal/arpguard"
	"github.com/z0orb/watchtower/internal/store"
)

const runKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

// The SYSTEM service runs this copy: Program Files is admin-only, unlike wherever the user downloaded it.
func installedExe() string {
	return filepath.Join(os.Getenv("ProgramFiles"), "Watchtower", "watchtower.exe")
}

func requireAdmin() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("run it from an elevated (Administrator) terminal")
	}
	return nil
}

func install() (err error) {
	if err := requireAdmin(); err != nil {
		return err
	}
	src, err := os.Executable()
	if err != nil {
		return err
	}
	dst := installedExe()
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err == nil { // reinstall: stop it to free the exe, keep its config
		defer s.Close()
		if err := stopService(s); err != nil {
			return err
		}
		defer func() {
			if err != nil {
				s.Start() // don't leave protection off because the update failed
			}
		}()
	}
	if !strings.EqualFold(src, dst) {
		if err := copyExe(src, dst); err != nil {
			return fmt.Errorf("copy to %s: %w", dst, err)
		}
	}
	if s == nil {
		s, err = m.CreateService(serviceName, dst, mgr.Config{
			StartType:   mgr.StartAutomatic,
			DisplayName: "Watchtower",
			Description: "Pins the gateway's MAC against ARP spoofing and auto-recovers the connection.",
		}, "service")
		if err != nil {
			return fmt.Errorf("create service: %w", err)
		}
		defer s.Close()
		restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: 5 * time.Second}
		if err := s.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, 24*60*60); err != nil {
			return fmt.Errorf("set recovery: %w", err)
		}
		if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil { // runGuard errors exit with code 1
			return fmt.Errorf("set recovery: %w", err)
		}
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.SetStringValue(serviceName, `"`+dst+`" tray`); err != nil {
		return fmt.Errorf("tray autostart: %w", err)
	}

	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	fmt.Println("Installed to", dst, "and started the Watchtower service.")
	fmt.Println("The tray starts at next sign-in; to start it now, run (not as admin):", `"`+dst+`" tray`)
	if !arpguard.NpcapAvailable() {
		fmt.Println("Npcap is missing, so live ARP-spoof detection is off. Install it from https://npcap.com,")
		fmt.Println("then restart the service: sc stop Watchtower && sc start Watchtower")
	}
	return nil
}

// copyExe works while the old copy still runs (e.g. the tray): a running exe can be renamed, not overwritten.
func copyExe(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	old := fmt.Sprintf("%s.%d.old", dst, time.Now().UnixNano()) // unique: an older .old may still be running
	if err := os.Rename(dst, old); err == nil {
		removeNowOrAtReboot(old)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.WriteFile(dst, b, 0o755)
}

// removeNowOrAtReboot deletes path, or schedules that for the next boot if a process still runs it.
func removeNowOrAtReboot(path string) {
	if os.Remove(path) != nil {
		p16, _ := windows.UTF16PtrFromString(path)
		windows.MoveFileEx(p16, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
	}
}

func stopService(s *mgr.Service) error {
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State != svc.Stopped && st.State != svc.StopPending {
		if _, err := s.Control(svc.Stop); err != nil {
			return fmt.Errorf("stop service: %w", err)
		}
	}
	for range 60 {
		if st, err = s.Query(); err != nil || st.State == svc.Stopped {
			return err
		}
		time.Sleep(500 * time.Millisecond)
	}
	return errors.New("service didn't stop within 30 s")
}

func uninstall() error {
	if err := requireAdmin(); err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		err := stopService(s) // the service unpins the gateway and restores DNS as it stops
		if err == nil {
			err = s.Delete()
		}
		s.Close()
		if err != nil {
			return err
		}
	}

	if err := revertTuning(); err != nil {
		fmt.Println("Couldn't revert all adapter tuning (see", tuningPath()+"):", err)
	}

	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, runKey, registry.SET_VALUE); err == nil {
		if err := k.DeleteValue(serviceName); err != nil && !errors.Is(err, registry.ErrNotExist) {
			k.Close()
			return err
		}
		k.Close()
	}
	// Close trays (any user) so their exe can be deleted; spare this process.
	exec.Command("taskkill", "/F", "/IM", "watchtower.exe", "/FI", "PID ne "+strconv.Itoa(os.Getpid())).Run()
	time.Sleep(time.Second)

	dir := filepath.Dir(installedExe())
	if err := os.RemoveAll(dir); err != nil { // we may be running from it: delete what's left at reboot
		left, _ := filepath.Glob(filepath.Join(dir, "*"))
		for _, p := range append(left, dir) { // dir last: it must be empty by then
			removeNowOrAtReboot(p)
		}
		fmt.Println("Some files in", dir, "are in use and will be deleted at the next reboot.")
	}
	fmt.Println("Uninstalled. Settings and logs are kept in", store.Dir(), "(delete it to remove them).")
	return nil
}
