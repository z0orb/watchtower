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
		st   *ipc.Status
		want string
	}{
		{nil, "Service not running"},
		{&ok, "Protected"},
		{with(func(s *ipc.Status) { s.Network = "" }), "Not connected"},
		{with(func(s *ipc.Status) { s.Gateway = false }), "Protected"}, // gateway may just drop ICMP
		{with(func(s *ipc.Status) { s.Gateway, s.Internet = false, false }), "Connection down, recovering"},
		{with(func(s *ipc.Status) { s.Internet = false }), "Internet down (ISP or modem)"},
		{with(func(s *ipc.Status) { s.DNS, s.PublicDNS = false, true }), "DNS failing, recovering · public DNS"},
		{with(func(s *ipc.Status) { s.Trusted, s.Npcap = "", false }), "Online, gateway NOT pinned · degraded: install Npcap"},
	} {
		if got := Summary(c.st); got != c.want {
			t.Errorf("Summary(%+v) = %q, want %q", c.st, got, c.want)
		}
	}
}
