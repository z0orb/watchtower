// Package tray is the per-user notification-area app: it shows the service's status and alerts.
package tray

import "github.com/z0orb/watchtower/internal/ipc"

// Summary is the one-line status shown in the menu and tooltip; nil means the service is unreachable.
func Summary(st *ipc.Status) string {
	var s string
	switch {
	case st == nil:
		return "Service not running"
	case st.Network == "":
		s = "Not connected"
	case !st.Link:
		s = "Adapter disconnected"
	case !st.Gateway && !st.Internet:
		s = "Connection down, recovering"
	case !st.Internet:
		s = "Internet down (ISP or modem)"
	case !st.DNS:
		s = "DNS failing, recovering"
	case st.Trusted == "":
		s = "Online, gateway NOT pinned"
	default:
		s = "Protected"
	}
	if st.PublicDNS {
		s += " · public DNS"
	}
	if !st.Npcap {
		s += " · degraded: install Npcap"
	}
	return s
}
