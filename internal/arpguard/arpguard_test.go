package arpguard

import (
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var (
	gw       = net.IPv4(192, 168, 1, 1).To4()
	realMAC  = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01}
	evilMAC  = net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x02}
	evilMAC2 = net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x03}
)

// wireARP serializes an Ethernet+ARP frame and decodes it back, as the capture loop will.
func wireARP(t *testing.T, op uint16, mac net.HardwareAddr, ip net.IP) *layers.ARP {
	t.Helper()
	return wireARPTo(t, op, mac, ip, net.IPv4(192, 168, 1, 50).To4())
}

func wireARPTo(t *testing.T, op uint16, mac net.HardwareAddr, ip, dst net.IP) *layers.ARP {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: mac, DstMAC: layers.EthernetBroadcast, EthernetType: layers.EthernetTypeARP}
	arp := &layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
		HwAddressSize: 6, ProtAddressSize: 4, Operation: op,
		SourceHwAddress: mac, SourceProtAddress: ip,
		DstHwAddress: make([]byte, 6), DstProtAddress: dst,
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, eth, arp); err != nil {
		t.Fatal(err)
	}
	l := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default).Layer(layers.LayerTypeARP)
	if l == nil {
		t.Fatal("no ARP layer decoded")
	}
	return l.(*layers.ARP)
}

func TestChooseTrusted(t *testing.T) {
	if mac, err := ChooseTrusted([]net.HardwareAddr{realMAC, realMAC}); err != nil || mac.String() != realMAC.String() {
		t.Fatalf("single responder: got %v, %v", mac, err)
	}
	if _, err := ChooseTrusted([]net.HardwareAddr{realMAC, evilMAC}); err != ErrConflict {
		t.Fatalf("two responders: got %v, want ErrConflict", err)
	}
	if _, err := ChooseTrusted(nil); err != ErrNoReply {
		t.Fatalf("no responders: got %v, want ErrNoReply", err)
	}
}

func TestDetector(t *testing.T) {
	d := &Detector{Gateway: gw, Trusted: realMAC, Cooldown: 5 * time.Minute}
	t0 := time.Unix(1_000_000, 0)

	for _, op := range []uint16{layers.ARPReply, layers.ARPRequest} {
		if _, bad := d.Check(wireARP(t, op, realMAC, gw), t0); bad {
			t.Fatalf("op %d from real gateway flagged", op)
		}
	}
	if _, bad := d.Check(wireARP(t, layers.ARPReply, evilMAC, net.IPv4(192, 168, 1, 77).To4()), t0); bad {
		t.Fatal("other host's own ARP flagged")
	}

	s, bad := d.Check(wireARP(t, layers.ARPReply, evilMAC, gw), t0)
	if !bad || !s.Notify || s.Kind != KindGateway || s.Attacker.String() != evilMAC.String() {
		t.Fatalf("forged reply: got %+v, %v", s, bad)
	}
	if s, bad := d.Check(wireARP(t, layers.ARPRequest, evilMAC, gw), t0.Add(time.Minute)); !bad || s.Notify {
		t.Fatalf("repeat within cooldown: got %+v, %v (want flagged, no notify)", s, bad)
	}
	if s, _ := d.Check(wireARP(t, layers.ARPReply, evilMAC2, gw), t0.Add(time.Minute)); !s.Notify {
		t.Fatal("second attacker should notify independently")
	}
	if s, _ := d.Check(wireARP(t, layers.ARPReply, evilMAC, gw), t0.Add(5*time.Minute)); !s.Notify {
		t.Fatal("after cooldown should notify again")
	}
}

var (
	self    = net.IPv4(192, 168, 1, 119).To4()
	selfMAC = net.HardwareAddr{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
)

func TestDetectorSelf(t *testing.T) {
	d := &Detector{Gateway: gw, Trusted: realMAC, Self: self, SelfMAC: selfMAC, Cooldown: 5 * time.Minute}
	t0 := time.Unix(1_000_000, 0)
	if _, bad := d.Check(wireARP(t, layers.ARPReply, selfMAC, self), t0); bad {
		t.Fatal("our own ARP flagged")
	}
	s, bad := d.Check(wireARP(t, layers.ARPReply, evilMAC, self), t0)
	if !bad || s.Kind != KindSelf || !s.Notify {
		t.Fatalf("claim of our IP: got %+v, %v", s, bad)
	}
	// cooldown is per kind: the same MAC forging the gateway still notifies
	if s, _ := d.Check(wireARP(t, layers.ARPReply, evilMAC, gw), t0); s.Kind != KindGateway || !s.Notify {
		t.Fatalf("gateway forgery after self forgery: got %+v", s)
	}
	if s, _ := d.Check(wireARP(t, layers.ARPReply, evilMAC, self), t0.Add(time.Second)); s.Notify {
		t.Fatal("self repeat within cooldown notified")
	}
}

func TestDetectorScan(t *testing.T) {
	d := &Detector{Gateway: gw, Trusted: realMAC, Self: self, SelfMAC: selfMAC, Cooldown: 5 * time.Minute}
	t0 := time.Unix(1_000_000, 0)
	host := net.IPv4(192, 168, 1, 77).To4()
	sweep := func(mac net.HardwareAddr, n int, start time.Time, step time.Duration) (hits int) {
		for i := range n {
			dst := net.IPv4(192, 168, 1, byte(100+i)).To4()
			if _, bad := d.Check(wireARPTo(t, layers.ARPRequest, mac, host, dst), start.Add(time.Duration(i)*step)); bad {
				hits++
			}
		}
		return hits
	}
	if hits := sweep(evilMAC, ScanTargets-1, t0, 10*time.Millisecond); hits != 0 {
		t.Fatalf("below threshold flagged %d times", hits)
	}
	s, bad := d.Check(wireARPTo(t, layers.ARPRequest, evilMAC, host, net.IPv4(192, 168, 1, 250).To4()), t0.Add(time.Second))
	if !bad || s.Kind != KindScan || !s.Notify {
		t.Fatalf("threshold request: got %+v, %v", s, bad)
	}
	// the same target asked repeatedly is normal traffic, not a scan
	for i := range 100 {
		if _, bad := d.Check(wireARPTo(t, layers.ARPRequest, evilMAC2, host, gw), t0.Add(time.Duration(i)*time.Millisecond)); bad {
			t.Fatal("repeated request for one IP flagged as scan")
		}
	}
	// a slow sweep (one IP per second) never fills a 10 s window
	if hits := sweep(evilMAC2, 100, t0, time.Second); hits != 0 {
		t.Fatalf("slow sweep flagged %d times", hits)
	}
	// our own and the router's sweeps are ignored
	if sweep(selfMAC, 100, t0, time.Millisecond)+sweep(realMAC, 100, t0, time.Millisecond) != 0 {
		t.Fatal("own or router sweep flagged")
	}
}
