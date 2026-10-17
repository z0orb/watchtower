// Package netwatch turns periodic connectivity probes into recovery actions.
package netwatch

import "time"

// Probe is one round of connectivity checks.
type Probe struct {
	Network           string // SSID (or "wired") + gateway IP; a change resets everything
	Link              bool   // adapter connected
	Gateway           bool   // gateway answers ICMP
	Internet          bool   // 1.1.1.1 or 8.8.8.8 answers ICMP
	DNS               bool   // system resolver works
	RouterDNS         bool   // DHCP-provided DNS server answers a direct query
	GatewayMACChanged bool   // gateway unreachable and a single different MAC now answers ARP
}

type Action int

const (
	FlushDNS Action = iota
	SetPublicDNS
	RestoreDNS
	RenewDHCP
	RestartAdapter
	AlertUpstream
	AlertGatewayChanged
	AlertGiveUp
)

// Disruptive actions drop live sessions; they may only run when the connection is already dead.
func (a Action) Disruptive() bool { return a == RenewDHCP || a == RestartAdapter }

type Config struct {
	Fails    int           // consecutive failing probes before acting
	StepGap  time.Duration // wait between ladder steps
	Retry    time.Duration // wait before re-running a finished ladder
	RevertOK int           // consecutive good router-DNS checks before restoring DHCP DNS
}

var DefaultConfig = Config{Fails: 3, StepGap: 10 * time.Second, Retry: 5 * time.Minute, RevertOK: 3}

type diagnosis int

const (
	healthy diagnosis = iota
	linkDown
	dead
	gatewayChanged
	upstream
	dnsBroken
)

func diagnose(p Probe) diagnosis {
	switch {
	case !p.Link:
		return linkDown
	case !p.Gateway && !p.Internet && p.GatewayMACChanged:
		return gatewayChanged
	case !p.Gateway && !p.Internet:
		return dead
	case !p.Internet:
		return upstream
	case !p.DNS:
		return dnsBroken
	}
	return healthy
}

var ladders = map[diagnosis][]Action{
	linkDown:       {RestartAdapter, AlertGiveUp},
	dead:           {RenewDHCP, RestartAdapter, AlertGiveUp},
	gatewayChanged: {AlertGatewayChanged},
	upstream:       {AlertUpstream},
	dnsBroken:      {FlushDNS, SetPublicDNS, AlertGiveUp},
}

// Machine is not safe for concurrent use; the service drives it from one probe loop.
type Machine struct {
	Cfg Config

	network   string
	diag      diagnosis
	streak    int
	step      int
	nextAt    time.Time
	publicDNS bool
	routerOK  int
}

func New(cfg Config) *Machine { return &Machine{Cfg: cfg} }

// Step feeds one probe result and returns the actions to run now.
func (m *Machine) Step(p Probe, now time.Time) []Action {
	var out []Action
	if p.Network != m.network {
		if m.publicDNS {
			out = append(out, RestoreDNS)
			m.publicDNS = false
		}
		m.network, m.diag, m.streak, m.step, m.nextAt, m.routerOK = p.Network, healthy, 0, 0, time.Time{}, 0
	}
	d := diagnose(p)
	if d != m.diag {
		m.diag, m.streak, m.step, m.nextAt = d, 0, 0, time.Time{}
	}
	if d == healthy {
		if m.publicDNS {
			m.routerOK++
			if !p.RouterDNS {
				m.routerOK = 0
			}
			if m.routerOK >= m.Cfg.RevertOK {
				out = append(out, RestoreDNS)
				m.publicDNS, m.routerOK = false, 0
			}
		}
		return out
	}

	m.streak++
	if m.streak < m.Cfg.Fails || now.Before(m.nextAt) {
		return out
	}
	ladder := ladders[d]
	a := ladder[m.step]
	m.step++
	m.nextAt = now.Add(m.Cfg.StepGap)
	if m.step == len(ladder) {
		m.step, m.nextAt = 0, now.Add(m.Cfg.Retry)
	}
	// Game-safety invariant: never drop a session that is still alive.
	if a.Disruptive() && (p.Gateway || p.Internet) {
		return out
	}
	if a == SetPublicDNS {
		m.publicDNS, m.routerOK = true, 0
	}
	return append(out, a)
}
