package tray

import (
	"bufio"
	"cmp"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"fyne.io/systray"
	toast "git.sr.ht/~jackmordaunt/go-toast/v2"
	"golang.org/x/sys/windows"

	"github.com/z0orb/watchtower/internal/ipc"
)

var (
	//go:embed icon_ok.ico
	iconOK []byte
	//go:embed icon_warn.ico
	iconWarn []byte
	//go:embed icon_bad.ico
	iconBad []byte

	icons = map[Level][]byte{OK: iconOK, Warn: iconWarn, Bad: iconBad}
)

var procSHQueryUserNotificationState = windows.NewLazySystemDLL("shell32.dll").NewProc("SHQueryUserNotificationState")

// busy reports whether a fullscreen game, presentation or quiet hours would make a toast intrusive.
func busy() bool {
	var st uint32
	r, _, _ := procSHQueryUserNotificationState.Call(uintptr(unsafe.Pointer(&st)))
	// QUNS_BUSY, QUNS_RUNNING_D3D_FULL_SCREEN, QUNS_PRESENTATION_MODE, QUNS_QUIET_TIME, QUNS_APP
	return r == 0 && (st == 2 || st == 3 || st == 4 || st == 6 || st == 7)
}

const appID = "Watchtower"

var labels = map[string]string{"retrust": "Re-trust gateway", "restore_dns": "Restore DNS",
	"optimize_adapter": "Optimize adapter", "revert_tuning": "Revert tuning", "selftest": "Test protection"}

// done is the success message; the default is "Done".
var done = map[string]string{
	"optimize_adapter": "Done. Takes effect after a reboot.",
	"revert_tuning":    "Done. Takes effect after a reboot.",
	"selftest":         "Protection works.",
}

type tray struct {
	status *systray.MenuItem

	hold hold

	mu   sync.Mutex
	conn net.Conn    // nil while the service is unreachable
	last *ipc.Status // last status shown, to redraw when DnD changes
}

// Run blocks until the user quits the tray. A second tray in the same session only points to the first.
func Run(logPath string) {
	name, _ := windows.UTF16PtrFromString(`Local\WatchtowerTray`)
	if _, err := windows.CreateMutex(nil, false, name); err == windows.ERROR_ALREADY_EXISTS {
		notify("Watchtower is already running", "Look for the shield in the tray (^ hidden icons).")
		return
	}
	// Registers the app name shown on toasts (HKCU); toasts still work if this fails.
	toast.SetAppData(toast.AppData{AppID: appID, GUID: "{7d1d6f9f-57f8-4ec8-a038-7c6a9fea5c1f}"})
	systray.Run(func() { onReady(logPath) }, nil)
}

func onReady(logPath string) {
	t := &tray{status: systray.AddMenuItem("", "")}
	t.status.Disable()
	t.show(nil)
	systray.AddSeparator()
	selftest := systray.AddMenuItem(labels["selftest"], "Send a harmless forged packet and check that it's caught")
	retrust := systray.AddMenuItem(labels["retrust"], "Only after replacing your router: trusts the MAC it answers with now")
	dns := systray.AddMenuItem(labels["restore_dns"], "Switch back to the router's DNS servers")
	optimize := systray.AddMenuItem(labels["optimize_adapter"], "Turn off adapter power saving (applies after a reboot)")
	revert := systray.AddMenuItem(labels["revert_tuning"], "Restore the adapter settings changed by Optimize")
	dnd := systray.AddMenuItemCheckbox("Do Not Disturb", "Hold alert toasts; they're still logged", false)
	report := systray.AddMenuItem("Connection report", "Outages in the last 24 hours and 7 days")
	openLog := systray.AddMenuItem("Open log", "")
	systray.AddSeparator()
	quit := systray.AddMenuItem("Quit tray", "Protection keeps running in the service")

	go t.connectLoop()
	go func() {
		for range time.Tick(10 * time.Second) {
			t.flush()
		}
	}()
	go func() {
		for {
			select {
			case <-selftest.ClickedCh:
				t.send("selftest")
			case <-retrust.ClickedCh:
				t.send("retrust")
			case <-dns.ClickedCh:
				t.send("restore_dns")
			case <-optimize.ClickedCh:
				t.send("optimize_adapter")
			case <-revert.ClickedCh:
				t.send("revert_tuning")
			case <-dnd.ClickedCh:
				if dnd.Checked() {
					dnd.Uncheck()
				} else {
					dnd.Check()
				}
				t.hold.setDND(dnd.Checked())
				t.mu.Lock()
				st := t.last
				t.mu.Unlock()
				t.show(st)
				t.flush()
			case <-report.ClickedCh:
				if err := openReport(logPath); err != nil {
					notify("Connection report failed", err.Error())
				}
			case <-openLog.ClickedCh:
				exec.Command("notepad.exe", logPath).Start()
			case <-quit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}

func (t *tray) show(st *ipc.Status) {
	t.mu.Lock()
	t.last = st
	t.mu.Unlock()
	s, l := Summary(st)
	if t.hold.on() {
		s += " · Do Not Disturb"
	}
	systray.SetIcon(icons[l])
	t.status.SetTitle(s)
	systray.SetTooltip("Watchtower: " + s)
}

// startService starts the stopped Watchtower service; install lets interactive users do that without UAC.
func startService() {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return
	}
	defer windows.CloseServiceHandle(m)
	name, _ := windows.UTF16PtrFromString("Watchtower")
	s, err := windows.OpenService(m, name, windows.SERVICE_START)
	if err != nil {
		return // not installed, or installed by a version before 0.1.3
	}
	defer windows.CloseServiceHandle(s)
	windows.StartService(s, 0, nil)
}

func (t *tray) connectLoop() {
	var lastStart time.Time
	for {
		c, err := ipc.Dial(2 * time.Second)
		// No pipe at all means the service is stopped (a pipe owned by `watchtower run` is a different error).
		// At most once a minute, so a service that keeps failing isn't restarted in a tight loop.
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) && time.Since(lastStart) > time.Minute {
			lastStart = time.Now()
			startService()
		}
		if err == nil {
			t.mu.Lock()
			t.conn = c
			t.mu.Unlock()
			t.read(c)
			t.mu.Lock()
			t.conn = nil
			t.mu.Unlock()
			c.Close()
			t.show(nil)
		}
		time.Sleep(5 * time.Second)
	}
}

func (t *tray) read(c net.Conn) {
	sc := bufio.NewScanner(c)
	for sc.Scan() {
		var m ipc.Msg
		if json.Unmarshal(sc.Bytes(), &m) != nil {
			continue
		}
		switch m.Type {
		case "status":
			t.show(m.Status)
		case "alert":
			t.alert(m.Name, m.Text)
		case "result":
			if m.Text != "" {
				notify(labels[m.Name]+" failed", m.Text)
			} else {
				notify(labels[m.Name], cmp.Or(done[m.Name], "Done"))
			}
		}
	}
}

func (t *tray) send(cmd string) {
	t.mu.Lock()
	c := t.conn
	t.mu.Unlock()
	if c == nil || json.NewEncoder(c).Encode(ipc.Msg{Type: "cmd", Name: cmd}) != nil {
		notify(labels[cmd]+" failed", "The Watchtower service isn't running")
	}
}

// alert toasts now, or counts it while Do Not Disturb is on or a game or presentation runs; command results
// are never held.
func (t *tray) alert(kind, text string) {
	if t.hold.alert(busy()) {
		notify(alertToast(kind, text))
	}
}

// flush shows one summary of the held alerts once neither Do Not Disturb nor busy() holds them.
func (t *tray) flush() {
	if n := t.hold.release(busy()); n > 0 {
		notify(heldToast(n))
	}
}

func openReport(logPath string) error {
	var logs []io.Reader
	for _, p := range []string{logPath + ".2", logPath + ".1", logPath} {
		if f, err := os.Open(p); err == nil {
			defer f.Close()
			logs = append(logs, f)
		}
	}
	out := filepath.Join(os.TempDir(), "watchtower-report.txt")
	if err := os.WriteFile(out, []byte(Report(logs, time.Now())), 0o644); err != nil {
		return err
	}
	return exec.Command("notepad.exe", out).Start()
}

func notify(title, body string) {
	n := toast.Notification{AppID: appID, Title: title, Body: body}
	n.Push()
}
