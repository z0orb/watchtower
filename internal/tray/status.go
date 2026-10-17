// Package tray is the per-user notification-area app: it shows the service's status and alerts.
package tray

import (
	"fmt"
	"slices"
	"strings"

	"github.com/z0orb/watchtower/internal/ipc"
)

// Level picks the tray icon color.
type Level int

const (
	OK   Level = iota // green: protected and online
	Warn              // amber: works, but protection or DNS is degraded
	Bad               // red: offline or unprotected
)

// Summary is the one-line status shown in the menu and tooltip; nil means the service is unreachable.
func Summary(st *ipc.Status) (string, Level) {
	var s string
	l := OK
	switch {
	case st == nil:
		return "Service not running", Bad
	case st.Network == "":
		s, l = "Not connected", Warn
	case !st.Link:
		s, l = "Adapter disconnected", Bad
	case !st.Gateway && !st.Internet:
		s, l = "Connection down, recovering", Bad
	case !st.Internet:
		s, l = "Internet down (ISP or modem)", Bad
	case !st.DNS:
		s, l = "DNS failing, recovering", Bad
	case st.Trusted == "":
		s, l = "Online, gateway NOT pinned", Warn
	default:
		s = "Protected"
	}
	if st.PublicDNS {
		s += " · public DNS"
	}
	if !st.Npcap {
		s += " · degraded: install Npcap"
	}
	if l == OK && (st.PublicDNS || !st.Npcap) {
		l = Warn
	}
	return s, l
}

// shortAlerts is the default, terse toast per alert kind; the full text stays in the log.
var shortAlerts = map[string][2]string{
	"arp_spoof":       {"Attack blocked", "A device tried to impersonate your router."},
	"arp_spoof_self":  {"IP address hijacked", "Another device is claiming your IP."},
	"arp_scan":        {"Network scan", "A device is scanning your network."},
	"pin_failed":      {"Protection off", "Couldn't keep your router pinned."},
	"trust_failed":    {"Router not pinned", "Couldn't verify your router."},
	"npcap_missing":   {"Npcap missing", "Live attack detection is off."},
	"upstream":        {"Internet down", "Your router is fine; the ISP or modem isn't."},
	"gateway_changed": {"Router changed", "Re-trust it if you replaced the router."},
	"recovery_failed": {"Still offline", "Auto-fix failed; retrying in 5 min."},
}

// alertToast is the toast for an alert; kinds without a short form show the service's full text.
func alertToast(kind, text string) (title, body string) {
	if a, ok := shortAlerts[kind]; ok {
		return a[0], a[1]
	}
	return "Watchtower alert", text
}

// heldToast merges alerts held back during a game into one toast: the distinct messages, first 3 shown.
func heldToast(alerts []string) (title, body string) {
	var uniq []string
	for _, a := range alerts {
		if !slices.Contains(uniq, a) {
			uniq = append(uniq, a)
		}
	}
	title = fmt.Sprintf("%d alerts while you were busy", len(alerts))
	if len(alerts) == 1 {
		title = "Alert while you were busy"
	}
	if len(uniq) > 3 {
		uniq = append(uniq[:3], fmt.Sprintf("…and %d more in the log", len(uniq)-3))
	}
	return title, strings.Join(uniq, "\n")
}
