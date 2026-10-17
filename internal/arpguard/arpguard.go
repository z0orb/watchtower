// Package arpguard decides which gateway MAC to trust and flags ARP packets that contradict it.
package arpguard

import (
	"bytes"
	"errors"
	"net"
	"time"

	"github.com/gopacket/gopacket/layers"
)

// ErrConflict means several MACs answered for the gateway, so none can be trusted.
var ErrConflict = errors.New("arpguard: multiple MACs claim the gateway")

// ErrNoReply means nobody answered the gateway probe.
var ErrNoReply = errors.New("arpguard: no reply from gateway")

// ChooseTrusted returns the gateway MAC only if exactly one distinct MAC answered the probe.
func ChooseTrusted(replies []net.HardwareAddr) (net.HardwareAddr, error) {
	if len(replies) == 0 {
		return nil, ErrNoReply
	}
	for _, mac := range replies[1:] {
		if !bytes.Equal(mac, replies[0]) {
			return nil, ErrConflict
		}
	}
	return replies[0], nil
}

// Spoof kinds.
const (
	KindGateway = "gateway" // someone claims the gateway's IP: blocked by the pin
	KindSelf    = "self"    // someone claims our IP: poisons the router against us, which the pin can't block
	KindScan    = "scan"    // one MAC asks for many IPs: how ARP attack tools find their victims
)

// A MAC asking for ScanTargets distinct IPs within ScanWindow is scanning the network.
const (
	ScanTargets = 30
	ScanWindow  = 10 * time.Second
)

// Detector flags ARP packets that claim the gateway's or our IP with the wrong MAC, and ARP scans.
type Detector struct {
	Gateway  net.IP
	Trusted  net.HardwareAddr
	Self     net.IP // nil disables the self check
	SelfMAC  net.HardwareAddr
	Cooldown time.Duration // minimum gap between user notifications per kind and attacker MAC

	lastNotify map[string]time.Time
	scans      map[string]*scan
}

type scan struct {
	start   time.Time
	targets map[string]bool
}

// Spoof describes one suspicious ARP packet. Notify is false while that attacker is in cooldown.
type Spoof struct {
	Kind     string
	Attacker net.HardwareAddr
	Notify   bool
}

// Check inspects any ARP packet (request, reply or gratuitous); all of them can poison a cache.
func (d *Detector) Check(arp *layers.ARP, now time.Time) (Spoof, bool) {
	if arp.AddrType != layers.LinkTypeEthernet || arp.Protocol != layers.EthernetTypeIPv4 {
		return Spoof{}, false
	}
	src, ip := net.HardwareAddr(arp.SourceHwAddress), net.IP(arp.SourceProtAddress)
	switch {
	case ip.Equal(d.Gateway) && !bytes.Equal(src, d.Trusted):
		return d.flag(KindGateway, src, now), true
	case d.Self != nil && ip.Equal(d.Self) && !bytes.Equal(src, d.SelfMAC):
		return d.flag(KindSelf, src, now), true
	case arp.Operation == layers.ARPRequest && !bytes.Equal(src, d.SelfMAC) && !bytes.Equal(src, d.Trusted) &&
		d.scanning(src, arp.DstProtAddress, now):
		return d.flag(KindScan, src, now), true
	}
	return Spoof{}, false
}

// scanning records a request from mac for target and reports when it completes a scan.
func (d *Detector) scanning(mac net.HardwareAddr, target []byte, now time.Time) bool {
	if d.scans == nil {
		d.scans = map[string]*scan{}
	}
	if len(d.scans) > 256 { // fake source MACs mustn't grow this forever
		for k, s := range d.scans {
			if now.Sub(s.start) > ScanWindow {
				delete(d.scans, k)
			}
		}
	}
	s := d.scans[mac.String()]
	if s == nil || now.Sub(s.start) > ScanWindow {
		s = &scan{start: now, targets: map[string]bool{}}
		d.scans[mac.String()] = s
	}
	s.targets[string(target)] = true
	if len(s.targets) < ScanTargets {
		return false
	}
	delete(d.scans, mac.String()) // start over, so a long scan is reported once per ScanTargets IPs
	return true
}

func (d *Detector) flag(kind string, mac net.HardwareAddr, now time.Time) Spoof {
	mac = bytes.Clone(mac)
	if d.lastNotify == nil {
		d.lastNotify = map[string]time.Time{}
	}
	key := kind + " " + mac.String()
	last, seen := d.lastNotify[key]
	notify := !seen || now.Sub(last) >= d.Cooldown
	if notify {
		d.lastNotify[key] = now
	}
	return Spoof{Kind: kind, Attacker: mac, Notify: notify}
}
