package arpguard

import (
	"bytes"
	"net"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

// NpcapAvailable reports whether Npcap's wpcap.dll can be loaded.
func NpcapAvailable() bool { return pcap.LoadWinPCAP() == nil }

// Capture reads every ARP packet on one adapter through Npcap and can probe the gateway.
type Capture struct {
	h   *pcap.Handle
	mac net.HardwareAddr
	ip  net.IP

	mu      sync.Mutex
	probeGW net.IP // non-nil while a Probe is collecting replies
	replies []net.HardwareAddr
}

func OpenCapture(adapterGUID string, mac net.HardwareAddr, ip net.IP) (*Capture, error) {
	h, err := pcap.OpenLive(`\Device\NPF_`+adapterGUID, 128, false, 200*time.Millisecond)
	if err != nil {
		return nil, err
	}
	if err := h.SetBPFFilter("arp"); err != nil {
		h.Close()
		return nil, err
	}
	return &Capture{h: h, mac: mac, ip: ip.To4()}, nil
}

func (c *Capture) Close() { c.h.Close() }

// Run passes every ARP packet to onARP until Close is called.
func (c *Capture) Run(onARP func(*layers.ARP)) {
	for pkt := range gopacket.NewPacketSource(c.h, layers.LayerTypeEthernet).Packets() {
		arp, _ := pkt.Layer(layers.LayerTypeARP).(*layers.ARP)
		if arp == nil {
			continue
		}
		c.mu.Lock()
		if c.probeGW != nil && arp.Operation == layers.ARPReply && net.IP(arp.SourceProtAddress).Equal(c.probeGW) {
			c.replies = append(c.replies, bytes.Clone(arp.SourceHwAddress))
		}
		c.mu.Unlock()
		onARP(arp)
	}
}

// Probe broadcasts an ARP request for gw and returns every MAC that claimed gw within wait,
// bypassing the Windows ARP cache (and any static pin).
func (c *Capture) Probe(gw net.IP, wait time.Duration) ([]net.HardwareAddr, error) {
	eth := &layers.Ethernet{SrcMAC: c.mac, DstMAC: layers.EthernetBroadcast, EthernetType: layers.EthernetTypeARP}
	arp := &layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
		HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest,
		SourceHwAddress: c.mac, SourceProtAddress: c.ip,
		DstHwAddress: make([]byte, 6), DstProtAddress: gw.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, eth, arp); err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.probeGW, c.replies = gw.To4(), nil
	c.mu.Unlock()
	err := c.h.WritePacketData(buf.Bytes())
	if err == nil {
		time.Sleep(wait)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	replies := c.replies
	c.probeGW, c.replies = nil, nil
	return replies, err
}
