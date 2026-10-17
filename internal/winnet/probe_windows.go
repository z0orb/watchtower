package winnet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpSendEcho    = iphlpapi.NewProc("IcmpSendEcho")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
	procSendARP         = iphlpapi.NewProc("SendARP")
	procGetIpNetTable   = iphlpapi.NewProc("GetIpNetTable")

	wlanapi                = windows.NewLazySystemDLL("wlanapi.dll")
	procWlanOpenHandle     = wlanapi.NewProc("WlanOpenHandle")
	procWlanCloseHandle    = wlanapi.NewProc("WlanCloseHandle")
	procWlanQueryInterface = wlanapi.NewProc("WlanQueryInterface")
	procWlanFreeMemory     = wlanapi.NewProc("WlanFreeMemory")
)

// Adapter is one network adapter's IPv4 configuration.
type Adapter struct {
	Index    int
	Name     string // alias, e.g. "Wi-Fi"
	GUID     string // e.g. "{...}"; the Npcap device is \Device\NPF_<GUID>
	Up       bool
	Physical bool // Ethernet or Wi-Fi, not a VPN/tunnel/loopback
	Wireless bool
	Metric   uint32
	MAC      net.HardwareAddr
	IP       net.IP
	Gateway  net.IP
	DNS      []net.IP
}

func Adapters() ([]Adapter, error) {
	size := uint32(16 << 10)
	var buf []byte
	for {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_INET,
			windows.GAA_FLAG_INCLUDE_GATEWAYS|windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST,
			0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			return nil, err
		}
	}
	var out []Adapter
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
		ad := Adapter{
			Index:    int(a.IfIndex),
			Name:     windows.UTF16PtrToString(a.FriendlyName),
			GUID:     windows.BytePtrToString(a.AdapterName),
			Up:       a.OperStatus == windows.IfOperStatusUp,
			Physical: a.IfType == windows.IF_TYPE_ETHERNET_CSMACD || a.IfType == windows.IF_TYPE_IEEE80211,
			Wireless: a.IfType == windows.IF_TYPE_IEEE80211,
			Metric:   a.Ipv4Metric,
			MAC:      bytes.Clone(a.PhysicalAddress[:a.PhysicalAddressLength]),
		}
		// SocketAddress.IP() aliases buf, so clone.
		if u := a.FirstUnicastAddress; u != nil {
			ad.IP = bytes.Clone(u.Address.IP().To4())
		}
		if g := a.FirstGatewayAddress; g != nil {
			ad.Gateway = bytes.Clone(g.Address.IP().To4())
		}
		for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
			if ip := d.Address.IP().To4(); ip != nil {
				ad.DNS = append(ad.DNS, bytes.Clone(ip))
			}
		}
		out = append(out, ad)
	}
	return out, nil
}

// ipAddr converts to the in-memory layout of a Win32 IPAddr (network byte order).
func ipAddr(ip net.IP) (uintptr, bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, false
	}
	return uintptr(binary.LittleEndian.Uint32(ip4)), true
}

// Ping sends one ICMP echo and reports whether a successful reply came back within timeout.
func Ping(ip net.IP, timeout time.Duration) bool {
	addr, ok := ipAddr(ip)
	if !ok {
		return false
	}
	h, _, _ := procIcmpCreateFile.Call()
	if windows.Handle(h) == windows.InvalidHandle {
		return false
	}
	defer procIcmpCloseHandle.Call(h)
	data := []byte("watchtower")
	reply := make([]byte, 256) // ICMP_ECHO_REPLY (40 bytes on 64-bit) + echoed data + 8
	n, _, _ := procIcmpSendEcho.Call(h, addr, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), 0,
		uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(timeout.Milliseconds()))
	return n > 0 && binary.LittleEndian.Uint32(reply[4:8]) == 0 // Status == IP_SUCCESS
}

// ResolveMAC asks Windows for ip's MAC. It answers from the ARP cache when it has an entry.
func ResolveMAC(ip net.IP) (net.HardwareAddr, error) {
	addr, ok := ipAddr(ip)
	if !ok {
		return nil, errors.New("winnet: not an IPv4 address")
	}
	var mac [8]byte
	size := uint32(len(mac))
	if r, _, _ := procSendARP.Call(addr, 0, uintptr(unsafe.Pointer(&mac[0])), uintptr(unsafe.Pointer(&size))); r != 0 {
		return nil, syscall.Errno(r)
	}
	return bytes.Clone(mac[:size]), nil
}

// PinnedMAC returns ip's ARP entry on the adapter; static is true for a pinned (permanent) entry.
// A missing entry returns a nil MAC and no error.
func PinnedMAC(ifIndex int, ip net.IP) (mac net.HardwareAddr, static bool, err error) {
	addr, ok := ipAddr(ip)
	if !ok {
		return nil, false, errors.New("winnet: not an IPv4 address")
	}
	var size uint32
	var buf []byte
	for {
		var p uintptr
		if len(buf) > 0 {
			p = uintptr(unsafe.Pointer(&buf[0]))
		}
		r, _, _ := procGetIpNetTable.Call(p, uintptr(unsafe.Pointer(&size)), 0)
		if r == 0 {
			break
		}
		if r == uintptr(windows.ERROR_NO_DATA) {
			return nil, false, nil // empty table
		}
		if r != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			return nil, false, syscall.Errno(r)
		}
		buf = make([]byte, size)
	}
	// MIB_IPNETTABLE: entry count, then 24-byte MIB_IPNETROWs: index, MAC length, MAC[8], IPv4, type.
	n := binary.LittleEndian.Uint32(buf)
	if 4+24*uint64(n) > uint64(len(buf)) {
		return nil, false, errors.New("winnet: truncated ARP table")
	}
	for i := range n {
		row := buf[4+24*i:][:24]
		macLen := min(binary.LittleEndian.Uint32(row[4:]), 8)
		if int(binary.LittleEndian.Uint32(row)) == ifIndex && uintptr(binary.LittleEndian.Uint32(row[16:])) == addr {
			return bytes.Clone(row[8 : 8+macLen]), binary.LittleEndian.Uint32(row[20:]) == 4, nil // 4 = MIB_IPNET_TYPE_STATIC
		}
	}
	return nil, false, nil
}

// SSID returns the Wi-Fi network the adapter is connected to, or "" if unknown.
func SSID(adapterGUID string) string {
	guid, err := windows.GUIDFromString(adapterGUID)
	if err != nil || procWlanOpenHandle.Find() != nil {
		return ""
	}
	var ver uint32
	var h windows.Handle
	if r, _, _ := procWlanOpenHandle.Call(2, 0, uintptr(unsafe.Pointer(&ver)), uintptr(unsafe.Pointer(&h))); r != 0 {
		return ""
	}
	defer procWlanCloseHandle.Call(uintptr(h), 0)
	const currentConnection = 7 // wlan_intf_opcode_current_connection
	var size uint32
	var data unsafe.Pointer
	if r, _, _ := procWlanQueryInterface.Call(uintptr(h), uintptr(unsafe.Pointer(&guid)), currentConnection, 0,
		uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&data)), 0); r != 0 {
		return ""
	}
	defer procWlanFreeMemory.Call(uintptr(data))
	// WLAN_CONNECTION_ATTRIBUTES: two DWORDs, WCHAR[256] profile name, then DOT11_SSID {ULONG len; UCHAR[32]}.
	const ssidOff = 8 + 512
	if size < ssidOff+4+32 {
		return ""
	}
	n := *(*uint32)(unsafe.Add(data, ssidOff))
	if n > 32 {
		return ""
	}
	return string(unsafe.Slice((*byte)(unsafe.Add(data, ssidOff+4)), n))
}
