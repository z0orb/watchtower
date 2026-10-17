package tray

import (
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
	if title, body := heldToast([]string{"a"}); title != "Watchtower alert while you were busy" || body != "a" {
		t.Errorf("one: %q %q", title, body)
	}
	title, body := heldToast([]string{"a", "b", "a", "c", "d", "e"})
	if title != "6 Watchtower alerts while you were busy" || body != "a\nb\nc\n…and 2 more in the log" {
		t.Errorf("many: %q %q", title, body)
	}
}
