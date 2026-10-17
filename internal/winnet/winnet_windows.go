// Package winnet runs the Windows network changes Watchtower needs. Every call needs admin/SYSTEM.
// It shells out to netsh/ipconfig because they behave the same from Win 10 LTSC 2019 to Win 11.
package winnet

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

var procFlushDNS = windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache")

// run executes cmdLine verbatim; netsh needs name="..." quoting that exec's default escaping breaks.
func run(cmdLine string) error {
	exe := strings.Fields(cmdLine)[0]
	cmd := exec.Command(exe)
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: cmdLine, HideWindow: true}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w: %s", cmdLine, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func netsh(args string) error { return run("netsh " + args) }

func idx(ifIndex int) string { return strconv.Itoa(ifIndex) }

// PinGateway sets a static ARP entry in the volatile store, so it disappears on reboot.
func PinGateway(ifIndex int, ip net.IP, mac net.HardwareAddr) error {
	m := strings.ReplaceAll(mac.String(), ":", "-")
	return netsh("interface ipv4 set neighbors interface=" + idx(ifIndex) + " address=" + ip.String() + " neighbor=" + m + " store=active")
}

func UnpinGateway(ifIndex int, ip net.IP) error {
	return netsh("interface ipv4 delete neighbors interface=" + idx(ifIndex) + " address=" + ip.String() + " store=active")
}

func FlushDNS() error {
	if r, _, err := procFlushDNS.Call(); r == 0 {
		return fmt.Errorf("DnsFlushResolverCache: %w", err)
	}
	return nil
}

func SetPublicDNS(ifIndex int) error {
	if err := netsh("interface ipv4 set dnsservers name=" + idx(ifIndex) + " source=static address=1.1.1.1 register=none validate=no"); err != nil {
		return err
	}
	return netsh("interface ipv4 add dnsservers name=" + idx(ifIndex) + " address=8.8.8.8 index=2 validate=no")
}

func RestoreDNS(ifIndex int) error {
	return netsh("interface ipv4 set dnsservers name=" + idx(ifIndex) + " source=dhcp")
}

// RenewDHCP renews without releasing first, so the IP is usually kept.
func RenewDHCP(ifName string) error { return run(`ipconfig /renew "` + ifName + `"`) }

// RestartAdapter needs the alias name: "netsh interface set interface" doesn't accept an index.
func RestartAdapter(ifName string) error {
	if err := netsh(`interface set interface name="` + ifName + `" admin=disabled`); err != nil {
		return err
	}
	return netsh(`interface set interface name="` + ifName + `" admin=enabled`)
}
