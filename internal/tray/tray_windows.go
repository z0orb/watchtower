package tray

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"net"
	"os/exec"
	"sync"
	"time"

	"fyne.io/systray"
	toast "git.sr.ht/~jackmordaunt/go-toast/v2"

	"github.com/z0orb/watchtower/internal/ipc"
)

//go:embed icon.ico
var icon []byte

const appID = "Watchtower"

var labels = map[string]string{"retrust": "Re-trust gateway", "restore_dns": "Restore DNS"}

type tray struct {
	status *systray.MenuItem

	mu   sync.Mutex
	conn net.Conn // nil while the service is unreachable
}

// Run blocks until the user quits the tray.
func Run(logPath string) {
	// Registers the app name shown on toasts (HKCU); toasts still work if this fails.
	toast.SetAppData(toast.AppData{AppID: appID, GUID: "{7d1d6f9f-57f8-4ec8-a038-7c6a9fea5c1f}"})
	systray.Run(func() { onReady(logPath) }, nil)
}

func onReady(logPath string) {
	systray.SetIcon(icon)
	t := &tray{status: systray.AddMenuItem("", "")}
	t.status.Disable()
	t.show(nil)
	systray.AddSeparator()
	retrust := systray.AddMenuItem(labels["retrust"], "Only after replacing your router: trusts the MAC it answers with now")
	dns := systray.AddMenuItem(labels["restore_dns"], "Switch back to the router's DNS servers")
	openLog := systray.AddMenuItem("Open log", "")
	systray.AddSeparator()
	quit := systray.AddMenuItem("Quit tray", "Protection keeps running in the service")

	go t.connectLoop()
	go func() {
		for {
			select {
			case <-retrust.ClickedCh:
				t.send("retrust")
			case <-dns.ClickedCh:
				t.send("restore_dns")
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
	s := Summary(st)
	t.status.SetTitle(s)
	systray.SetTooltip("Watchtower: " + s)
}

func (t *tray) connectLoop() {
	for {
		if c, err := ipc.Dial(2 * time.Second); err == nil {
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
			notify("Watchtower alert", m.Text)
		case "result":
			if m.Text != "" {
				notify(labels[m.Name]+" failed", m.Text)
			} else {
				notify(labels[m.Name], "Done")
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

func notify(title, body string) {
	n := toast.Notification{AppID: appID, Title: title, Body: body}
	n.Push()
}
