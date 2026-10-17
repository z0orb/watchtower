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

// Detector flags ARP packets that claim the gateway IP with a MAC other than the trusted one.
type Detector struct {
	Gateway  net.IP
	Trusted  net.HardwareAddr
	Cooldown time.Duration // minimum gap between user notifications per attacker MAC

	lastNotify map[string]time.Time
}

// Spoof describes one forged ARP packet. Notify is false while that attacker is in cooldown.
type Spoof struct {
	Attacker net.HardwareAddr
	Notify   bool
}

// Check inspects any ARP packet (request, reply or gratuitous); all of them can poison a cache.
func (d *Detector) Check(arp *layers.ARP, now time.Time) (Spoof, bool) {
	if arp.AddrType != layers.LinkTypeEthernet || arp.Protocol != layers.EthernetTypeIPv4 {
		return Spoof{}, false
	}
	if !net.IP(arp.SourceProtAddress).Equal(d.Gateway) || bytes.Equal(arp.SourceHwAddress, d.Trusted) {
		return Spoof{}, false
	}
	mac := net.HardwareAddr(bytes.Clone(arp.SourceHwAddress))
	if d.lastNotify == nil {
		d.lastNotify = map[string]time.Time{}
	}
	last, seen := d.lastNotify[mac.String()]
	notify := !seen || now.Sub(last) >= d.Cooldown
	if notify {
		d.lastNotify[mac.String()] = now
	}
	return Spoof{Attacker: mac, Notify: notify}, true
}
