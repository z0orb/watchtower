package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"sync"
	"time"

	"github.com/gopacket/gopacket/layers"

	"github.com/z0orb/watchtower/internal/arpguard"
	"github.com/z0orb/watchtower/internal/ipc"
	"github.com/z0orb/watchtower/internal/netwatch"
	"github.com/z0orb/watchtower/internal/store"
	"github.com/z0orb/watchtower/internal/winnet"
)

// probeEvery must match the tick netwatch.DefaultConfig.Fails is counted in.
const probeEvery = 5 * time.Second

// state is persisted to state.json.
type state struct {
	Trusted     map[string]string `json:"trusted"`       // network key -> gateway MAC
	PublicDNSIf int               `json:"public_dns_if"` // adapter we switched to public DNS; 0 = none
	RouterDNS   string            `json:"router_dns"`    // its DHCP DNS server, checked to know when to switch back
}

type guard struct {
	log   *slog.Logger
	path  string
	st    state
	m     *netwatch.Machine
	npcap bool
	srv   *ipc.Server

	selftest chan struct{} // the capture goroutine signals here when it sees the self-test packet

	cur        winnet.Adapter
	key        string // SSID (or "wired") + "|" + gateway IP
	trusted    net.HardwareAddr
	capt       *arpguard.Capture
	newGateway net.HardwareAddr // MAC the gateway answers with when it differs from trusted
	last       netwatch.Probe   // latest probe, for tray status
	pinFails   int              // consecutive ticks the pin was found missing or wrong
	out        outage           // the outage in progress; zero start = none

	detMu sync.Mutex // det is used from the capture goroutine
	det   *arpguard.Detector
}

func runGuard(ctx context.Context, log *slog.Logger) error {
	g := &guard{
		log:   log,
		path:  filepath.Join(store.Dir(), "state.json"),
		m:     netwatch.New(netwatch.DefaultConfig),
		npcap: arpguard.NpcapAvailable(),
		srv:   ipc.NewServer(),

		selftest: make(chan struct{}, 1),
	}
	if err := store.Load(g.path, &g.st); err != nil {
		return fmt.Errorf("load %s: %w", g.path, err)
	}
	if g.st.Trusted == nil {
		g.st.Trusted = map[string]string{}
	}
	log.Info("started", "npcap", g.npcap)
	if l, err := ipc.Listen(); err != nil {
		log.Error("ipc listen; tray won't connect", "err", err) // protection still runs
	} else {
		defer l.Close()
		go g.srv.Serve(l)
	}
	if !g.npcap {
		g.alert("npcap_missing", "Npcap is not installed: live ARP monitoring is off. Install it from https://npcap.com")
	}
	g.restoreDNS() // left over from a crash or power loss, if any
	defer g.shutdown()

	t := time.NewTicker(probeEvery)
	defer t.Stop()
	g.tick(time.Now())
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			g.tick(time.Now())
		case c := <-g.srv.Cmds: // run here so guard state stays single-goroutine
			err := g.command(c.Name)
			g.log.Info("tray command", "cmd", c.Name, "err", err)
			c.Reply(err)
			g.sendStatus()
		}
	}
}

func (g *guard) command(name string) error {
	switch name {
	case "retrust":
		if g.cur.Index == 0 {
			return errors.New("not connected")
		}
		replies, perr := g.probeGateway()
		mac, err := arpguard.ChooseTrusted(replies)
		if err != nil {
			return fmt.Errorf("%w (probe: %v); keeping the old pin", err, perr)
		}
		g.st.Trusted[g.key] = mac.String()
		g.save()
		g.log.Info("re-trusted gateway", "network", g.key, "mac", mac.String())
		g.pin(mac)
		return nil
	case "restore_dns":
		return g.restoreDNS()
	case "optimize_adapter":
		if g.cur.Index == 0 {
			return errors.New("not connected")
		}
		return optimizeAdapter(g.cur.GUID)
	case "revert_tuning":
		return revertTuning()
	case "selftest":
		return g.selfTest()
	}
	return fmt.Errorf("unknown command %q", name)
}

func (g *guard) sendStatus() {
	st := ipc.Status{Network: g.key, Adapter: g.cur.Name, Npcap: g.npcap, PublicDNS: g.st.PublicDNSIf != 0,
		Link: g.last.Link, Gateway: g.last.Gateway, Internet: g.last.Internet, DNS: g.last.DNS}
	if g.trusted != nil {
		st.Trusted = g.trusted.String()
	}
	g.srv.Send(ipc.Msg{Type: "status", Status: &st})
}

func (g *guard) tick(now time.Time) {
	defer g.sendStatus()
	ads, err := winnet.Adapters()
	if err != nil {
		g.log.Error("list adapters", "err", err)
		return
	}
	if best, ok := pickAdapter(ads); ok && (best.Index != g.cur.Index || !best.Gateway.Equal(g.cur.Gateway)) {
		g.connect(best)
	} else if g.cur.Index == 0 {
		return // never connected yet
	} else {
		g.cur.Up = false
		for _, a := range ads {
			if a.Index == g.cur.Index && a.Up {
				g.cur.Up, g.cur.IP, g.cur.DNS = true, a.IP, a.DNS
			}
		}
	}
	g.checkPin()
	g.last = g.probe()
	acts := g.m.Step(g.last, now)
	g.trackOutage(now)
	for _, a := range acts {
		g.do(a)
	}
}

type outage struct {
	start   time.Time
	diag    string
	actions []string
}

// trackOutage logs one "outage" line per outage, for the tray's connection report.
func (g *guard) trackOutage(now time.Time) {
	d := g.m.Diagnosis()
	switch {
	case d != "healthy" && g.out.start.IsZero():
		g.out = outage{start: now, diag: d}
	case d == "healthy" && !g.out.start.IsZero():
		// shorter than the failures needed to act is a blip, not an outage
		if now.Sub(g.out.start) >= time.Duration(g.m.Cfg.Fails)*probeEvery {
			fixed := ""
			if n := len(g.out.actions); n > 0 {
				fixed = g.out.actions[n-1]
			}
			g.log.Info("outage", "start", g.out.start, "seconds", int(now.Sub(g.out.start).Seconds()),
				"diagnosis", g.out.diag, "actions", g.out.actions, "fixed_by", fixed)
		}
		g.out = outage{}
	}
}

// pickAdapter returns the connected physical adapter with a gateway and the lowest metric.
func pickAdapter(ads []winnet.Adapter) (winnet.Adapter, bool) {
	var best winnet.Adapter
	found := false
	for _, a := range ads {
		if a.Up && a.Physical && a.IP != nil && a.Gateway != nil && !a.Gateway.IsUnspecified() &&
			(!found || a.Metric < best.Metric) {
			best, found = a, true
		}
	}
	return best, found
}

func (g *guard) connect(a winnet.Adapter) {
	g.disconnect()
	g.cur, g.pinFails = a, 0
	ssid := "wired"
	if a.Wireless {
		ssid = winnet.SSID(a.GUID)
	}
	g.key = ssid + "|" + a.Gateway.String()
	g.log.Info("connected", "adapter", a.Name, "network", g.key)

	if g.npcap {
		c, err := arpguard.OpenCapture(a.GUID, a.MAC, a.IP)
		if err != nil {
			g.log.Error("open capture", "adapter", a.Name, "err", err)
		} else {
			g.capt = c
			go c.Run(g.onARP)
		}
	}

	mac, err := net.ParseMAC(g.st.Trusted[g.key])
	if err != nil { // first visit to this network: trust on first use
		replies, perr := g.probeGateway()
		if mac, err = arpguard.ChooseTrusted(replies); err != nil {
			g.alert("trust_failed", "can't establish the gateway's real MAC; not pinning",
				"network", g.key, "replies", fmt.Sprint(replies), "err", err, "probe_err", perr)
			return
		}
		g.st.Trusted[g.key] = mac.String()
		g.save()
		g.log.Info("trusted gateway", "network", g.key, "mac", mac.String())
	}
	g.pin(mac)
}

func (g *guard) pin(mac net.HardwareAddr) {
	g.trusted = mac
	if err := winnet.PinGateway(g.cur.Index, g.cur.Gateway, mac); err != nil {
		g.log.Error("pin gateway", "err", err)
	} else {
		g.log.Info("pinned gateway", "ip", g.cur.Gateway, "mac", mac.String())
	}
	g.detMu.Lock()
	g.det = &arpguard.Detector{Gateway: g.cur.Gateway, Trusted: mac, Self: g.cur.IP, SelfMAC: g.cur.MAC,
		Cooldown: 5 * time.Minute}
	g.detMu.Unlock()
}

// checkPin restores the pin if it vanished or changed (arp -d, a driver reset, a netsh failure netsh didn't report).
func (g *guard) checkPin() {
	if g.trusted == nil || !g.cur.Up {
		return
	}
	mac, static, err := winnet.PinnedMAC(g.cur.Index, g.cur.Gateway)
	if err != nil {
		g.log.Error("read arp table", "err", err)
		return
	}
	if static && bytes.Equal(mac, g.trusted) {
		g.pinFails = 0
		return
	}
	g.pinFails++
	g.log.Warn("pin missing, re-pinning", "found", mac.String(), "static", static)
	if g.pinFails == 2 {
		g.alert("pin_failed", "can't keep the gateway pinned; ARP spoofing protection is off")
	}
	if err := winnet.PinGateway(g.cur.Index, g.cur.Gateway, g.trusted); err != nil {
		g.log.Error("pin gateway", "err", err)
	}
}

func (g *guard) disconnect() {
	if g.capt != nil {
		g.capt.Close()
		g.capt = nil
	}
	g.detMu.Lock()
	g.det = nil
	g.detMu.Unlock()
	if g.trusted != nil {
		if err := winnet.UnpinGateway(g.cur.Index, g.cur.Gateway); err != nil {
			g.log.Warn("unpin gateway", "err", err)
		}
		g.trusted = nil
	}
}

func (g *guard) shutdown() {
	g.disconnect()
	g.restoreDNS()
	g.log.Info("stopped")
}

// probeGateway lists every MAC answering for the gateway.
func (g *guard) probeGateway() ([]net.HardwareAddr, error) {
	if g.capt != nil {
		return g.capt.Probe(g.cur.Gateway, 2*time.Second)
	}
	// shortcut: without Npcap only Windows' single answer is seen, so a racing attacker can win TOFU; install Npcap.
	mac, err := winnet.ResolveMAC(g.cur.Gateway)
	if err != nil {
		return nil, err
	}
	return []net.HardwareAddr{mac}, nil
}

// selftestMAC marks the self-test's forged packet so it doesn't raise a real alert.
var selftestMAC = net.HardwareAddr{0x02, 0x57, 0x57, 0, 0, 0x01}

// selfTest forges a gateway claim and checks that detection sees it and the pin holds.
func (g *guard) selfTest() error {
	if g.capt == nil {
		return errors.New("live detection needs Npcap: install it from https://npcap.com")
	}
	if g.trusted == nil {
		return errors.New("the gateway isn't pinned")
	}
	select {
	case <-g.selftest: // drop a stale signal
	default:
	}
	if err := g.capt.SendForged(g.cur.Gateway, selftestMAC); err != nil {
		return err
	}
	select {
	case <-g.selftest:
	case <-time.After(2 * time.Second):
		return errors.New("detection didn't see the forged test packet")
	}
	mac, static, err := winnet.PinnedMAC(g.cur.Index, g.cur.Gateway)
	if err != nil {
		return err
	}
	if !static || !bytes.Equal(mac, g.trusted) {
		return errors.New("the forged packet was detected, but the gateway pin is missing")
	}
	return nil
}

// spoofAlerts maps a Spoof kind to its alert kind and message.
var spoofAlerts = map[string][2]string{
	arpguard.KindGateway: {"arp_spoof", "forged ARP packet claims to be the gateway (blocked by the pin)"},
	arpguard.KindSelf: {"arp_spoof_self", "another device claims your IP address: it may be cutting you off or " +
		"intercepting your traffic, which the pin can't block. Enable ARP binding or a DHCP reservation on the router"},
	arpguard.KindScan: {"arp_scan", "a device is scanning the network, often the first step of an ARP attack"},
}

func (g *guard) onARP(a *layers.ARP) {
	g.detMu.Lock()
	var s arpguard.Spoof
	bad := false
	if g.det != nil {
		s, bad = g.det.Check(a, time.Now())
	}
	g.detMu.Unlock()
	switch {
	case bad && s.Kind == arpguard.KindGateway && bytes.Equal(s.Attacker, selftestMAC):
		select {
		case g.selftest <- struct{}{}:
		default:
		}
	case bad && s.Notify:
		g.alert(spoofAlerts[s.Kind][0], spoofAlerts[s.Kind][1], "attacker", s.Attacker.String(),
			"claimed_ip", net.IP(a.SourceProtAddress))
	case bad:
		g.log.Warn("arp spoof repeat", "kind", s.Kind, "attacker", s.Attacker.String())
	}
}

func (g *guard) probe() netwatch.Probe {
	p := netwatch.Probe{Network: g.key, Link: g.cur.Up}
	if !p.Link {
		return p
	}
	var wg sync.WaitGroup // each goroutine writes its own field of p
	wg.Go(func() { p.Gateway = winnet.Ping(g.cur.Gateway, time.Second) })
	wg.Go(func() {
		p.Internet = winnet.Ping(net.IPv4(1, 1, 1, 1), time.Second) || winnet.Ping(net.IPv4(8, 8, 8, 8), time.Second)
	})
	wg.Go(func() { p.DNS = dnsWorks("", 2*time.Second) })
	if g.st.PublicDNSIf != 0 && g.st.RouterDNS != "" {
		wg.Go(func() { p.RouterDNS = dnsWorks(g.st.RouterDNS, 2*time.Second) })
	}
	wg.Wait()

	g.newGateway = nil
	if !p.Gateway && !p.Internet && g.trusted != nil && g.capt != nil {
		replies, _ := g.capt.Probe(g.cur.Gateway, 2*time.Second)
		if mac, err := arpguard.ChooseTrusted(replies); err == nil && !bytes.Equal(mac, g.trusted) {
			p.GatewayMACChanged, g.newGateway = true, mac
		}
	}
	return p
}

func (g *guard) do(a netwatch.Action) {
	if !g.out.start.IsZero() {
		g.out.actions = append(g.out.actions, a.String())
	}
	var err error
	switch a {
	case netwatch.FlushDNS:
		err = winnet.FlushDNS()
	case netwatch.SetPublicDNS:
		if g.st.PublicDNSIf == 0 && len(g.cur.DNS) > 0 {
			g.st.RouterDNS = g.cur.DNS[0].String()
		}
		g.st.PublicDNSIf = g.cur.Index
		g.save() // before switching, so a crash still gets restored on the next start
		err = winnet.SetPublicDNS(g.cur.Index)
	case netwatch.RestoreDNS:
		err = g.restoreDNS()
	case netwatch.RenewDHCP:
		err = winnet.RenewDHCP(g.cur.Name)
	case netwatch.RestartAdapter:
		err = winnet.RestartAdapter(g.cur.Name)
	case netwatch.AlertUpstream:
		g.alert("upstream", "router is reachable but the internet isn't: ISP or modem problem")
	case netwatch.AlertGatewayChanged:
		g.alert("gateway_changed", "gateway answers with a new MAC; re-trust it if you replaced the router",
			"trusted", g.trusted.String(), "now", g.newGateway.String())
	case netwatch.AlertGiveUp:
		g.alert("recovery_failed", "automatic recovery didn't fix the connection; retrying in 5 minutes")
	}
	if err != nil {
		g.log.Error("action failed", "action", a.String(), "err", err)
	} else {
		g.log.Info("action", "action", a.String())
	}
}

func (g *guard) restoreDNS() error {
	if g.st.PublicDNSIf == 0 {
		return nil // already restored, e.g. from the tray
	}
	err := winnet.RestoreDNS(g.st.PublicDNSIf)
	g.st.PublicDNSIf, g.st.RouterDNS = 0, ""
	g.save()
	return err
}

func (g *guard) save() {
	if err := store.Save(g.path, g.st); err != nil {
		g.log.Error("save state", "err", err)
	}
}

// alert is a user-facing event: logged, and shown by the tray as a toast.
func (g *guard) alert(kind, msg string, args ...any) {
	g.log.Warn(msg, append([]any{"alert", kind}, args...)...)
	g.srv.Send(ipc.Msg{Type: "alert", Name: kind, Text: msg})
}
