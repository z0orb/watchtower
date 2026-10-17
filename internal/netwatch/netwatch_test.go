package netwatch

import (
	"math/rand"
	"slices"
	"testing"
	"time"
)

const tick = 5 * time.Second

var (
	ok     = Probe{Network: "home", Link: true, Gateway: true, Internet: true, DNS: true, RouterDNS: true}
	deadP  = Probe{Network: "home", Link: true}
	upP    = Probe{Network: "home", Link: true, Gateway: true, DNS: true}
	dnsP   = Probe{Network: "home", Link: true, Gateway: true, Internet: true}
	movedP = Probe{Network: "home", Link: true, GatewayMACChanged: true}
	t0     = time.Unix(1_000_000, 0)
)

// run feeds probes one tick apart and returns the actions emitted at each tick (only non-empty ones).
func run(m *Machine, start time.Time, ps ...Probe) (got []Action) {
	for i, p := range ps {
		got = append(got, m.Step(p, start.Add(time.Duration(i)*tick))...)
	}
	return got
}

func repeat(p Probe, n int) []Probe { return slices.Repeat([]Probe{p}, n) }

func TestDeadLadder(t *testing.T) {
	got := run(New(DefaultConfig), t0, repeat(deadP, 8)...)
	want := []Action{RenewDHCP, RestartAdapter, AlertGiveUp} // ticks 3, 5, 7 (10s gaps)
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestLadderRetriesAfterRetryWindow(t *testing.T) {
	m := New(DefaultConfig)
	run(m, t0, repeat(deadP, 8)...)
	if a := m.Step(deadP, t0.Add(8*tick+DefaultConfig.Retry)); !slices.Equal(a, []Action{RenewDHCP}) {
		t.Fatalf("after retry window got %v", a)
	}
}

func TestShortBlipDoesNothing(t *testing.T) {
	if got := run(New(DefaultConfig), t0, deadP, deadP, ok, deadP, deadP, ok); len(got) != 0 {
		t.Fatalf("blips triggered %v", got)
	}
}

func TestUpstreamOnlyAlerts(t *testing.T) {
	if got := run(New(DefaultConfig), t0, repeat(upP, 20)...); !slices.Equal(got, []Action{AlertUpstream}) {
		t.Fatalf("got %v", got)
	}
}

func TestGatewayChangedOnlyAlerts(t *testing.T) {
	if got := run(New(DefaultConfig), t0, repeat(movedP, 20)...); !slices.Equal(got, []Action{AlertGatewayChanged}) {
		t.Fatalf("got %v", got)
	}
}

func TestDNSFallbackAndRevert(t *testing.T) {
	m := New(DefaultConfig)
	got := run(m, t0, repeat(dnsP, 6)...)
	if !slices.Equal(got, []Action{FlushDNS, SetPublicDNS}) {
		t.Fatalf("fallback: got %v", got)
	}
	start := t0.Add(6 * tick)
	routerDown := ok
	routerDown.RouterDNS = false
	got = run(m, start, ok, ok, routerDown, ok, ok)
	if len(got) != 0 {
		t.Fatalf("reverted before %d straight good router checks: %v", DefaultConfig.RevertOK, got)
	}
	if a := m.Step(ok, start.Add(5*tick)); !slices.Equal(a, []Action{RestoreDNS}) {
		t.Fatalf("revert: got %v", a)
	}
}

func TestNetworkChangeRestoresDNS(t *testing.T) {
	m := New(DefaultConfig)
	run(m, t0, repeat(dnsP, 6)...)
	cafe := ok
	cafe.Network = "cafe"
	if a := m.Step(cafe, t0.Add(6*tick)); !slices.Equal(a, []Action{RestoreDNS}) {
		t.Fatalf("got %v", a)
	}
}

// TestGameSafety: across random probe sequences, no disruptive action ever runs while
// the gateway or the internet is still reachable.
func TestGameSafety(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for seq := 0; seq < 2000; seq++ {
		m := New(DefaultConfig)
		now := t0
		for i := 0; i < 200; i++ {
			p := Probe{
				Network: []string{"home", "cafe"}[r.Intn(20)/19], Link: r.Intn(8) > 0,
				Gateway: r.Intn(2) == 0, Internet: r.Intn(2) == 0, DNS: r.Intn(2) == 0,
				RouterDNS: r.Intn(2) == 0, GatewayMACChanged: r.Intn(4) == 0,
			}
			now = now.Add(time.Duration(1+r.Intn(60)) * time.Second)
			for _, a := range m.Step(p, now) {
				if a.Disruptive() && (p.Gateway || p.Internet) {
					t.Fatalf("seq %d step %d: %v emitted with probe %+v", seq, i, a, p)
				}
			}
		}
	}
}

func TestDiagnosis(t *testing.T) {
	m := New(DefaultConfig)
	for p, want := range map[*Probe]string{&ok: "healthy", &deadP: "dead", &upP: "upstream", &dnsP: "dns_broken",
		&movedP: "gateway_changed", {Network: "home"}: "link_down"} {
		m.Step(*p, t0)
		if got := m.Diagnosis(); got != want {
			t.Errorf("Diagnosis after %+v = %q, want %q", *p, got, want)
		}
	}
}
