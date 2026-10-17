package tray

import (
	"sync"
	"testing"

	"github.com/z0orb/watchtower/internal/ipc"
)

func TestSummary(t *testing.T) {
	ok := ipc.Status{Network: "home|192.168.1.1", Trusted: "98:da:c4:cb:41:da", Npcap: true,
		Link: true, Gateway: true, Internet: true, DNS: true}
	with := func(f func(*ipc.Status)) *ipc.Status { s := ok; f(&s); return &s }
	for _, c := range []struct {
		st    *ipc.Status
		want  string
		level Level
	}{
		{nil, "Service not running", Bad},
		{&ok, "Protected", OK},
		{with(func(s *ipc.Status) { s.Network = "" }), "Not connected", Warn},
		{with(func(s *ipc.Status) { s.Gateway = false }), "Protected", OK}, // gateway may just drop ICMP
		{with(func(s *ipc.Status) { s.Gateway, s.Internet = false, false }), "Connection down, recovering", Bad},
		{with(func(s *ipc.Status) { s.Internet = false }), "Internet down (ISP or modem)", Bad},
		{with(func(s *ipc.Status) { s.DNS, s.PublicDNS = false, true }), "DNS failing, recovering · public DNS", Bad},
		{with(func(s *ipc.Status) { s.PublicDNS = true }), "Protected · public DNS", Warn},
		{with(func(s *ipc.Status) { s.Trusted, s.Npcap = "", false }), "Online, gateway NOT pinned · degraded: install Npcap", Warn},
	} {
		if got, l := Summary(c.st); got != c.want || l != c.level {
			t.Errorf("Summary(%+v) = %q, %d; want %q, %d", c.st, got, l, c.want, c.level)
		}
	}
}

func TestHeldToast(t *testing.T) {
	if title, body := heldToast(1); title != "1 alert while notifications were paused" || body != "Details are in the log (Open log)." {
		t.Errorf("one: %q %q", title, body)
	}
	if title, _ := heldToast(6); title != "6 alerts while notifications were paused" {
		t.Errorf("many: %q", title)
	}
}

func TestHold(t *testing.T) {
	var h hold
	if !h.alert(false) || h.release(false) != 0 {
		t.Error("neither DnD nor busy: should toast now and hold nothing")
	}

	if h.alert(true) || h.release(true) != 0 || h.release(false) != 1 || h.release(false) != 0 {
		t.Error("busy: should hold, release once when no longer busy")
	}

	h.setDND(true)
	for range 3 {
		if h.alert(false) {
			t.Fatal("DnD: alert shown")
		}
	}
	if h.release(false) != 0 {
		t.Error("DnD: released while on")
	}
	h.setDND(false)
	if n := h.release(false); n != 3 || h.release(false) != 0 {
		t.Errorf("DnD off: released %d, want 3 once", n)
	}

	h.setDND(true)
	h.alert(false)
	h.setDND(false)
	if h.release(true) != 0 || h.release(false) != 1 {
		t.Error("DnD off while busy: should wait until not busy")
	}

	h.setDND(true)
	h.setDND(false)
	if h.release(false) != 0 {
		t.Error("toggle with nothing held: empty summary")
	}
}

func TestHoldConcurrent(t *testing.T) {
	var h hold
	h.setDND(true)
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() { h.alert(false) })
	}
	wg.Wait()
	h.setDND(false)
	if n := h.release(false); n != 100 {
		t.Errorf("held %d, want 100", n)
	}
}

func TestAlertToast(t *testing.T) {
	if title, body := alertToast("arp_scan", "long text"); title != "Network scan" || body != "A device is scanning your network." {
		t.Errorf("known: %q %q", title, body)
	}
	if title, body := alertToast("new_kind", "long text"); title != "Watchtower alert" || body != "long text" {
		t.Errorf("unknown: %q %q", title, body)
	}
}
