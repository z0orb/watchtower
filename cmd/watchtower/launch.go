package main

import (
	"fmt"
	"strconv"
	"strings"
)

type action int

const (
	actTray          action = iota // this is the installed copy
	actOpenInstalled               // same version installed elsewhere: show its tray
	actInstall
	actUpdate
)

// launchAction decides what a start without arguments (a double-click) does. installed is the version recorded
// by install ("" if none, e.g. before 0.2.0); exists says whether the installed exe is there.
func launchAction(running, installed string, exists, fromInstallDir bool) (action, string) {
	switch {
	case fromInstallDir:
		return actTray, ""
	case !exists:
		return actInstall, "Install Watchtower " + running + "?\n\nIt runs in the background, protecting this PC " +
			"against ARP spoofing and fixing dropped connections. Windows will ask for administrator permission."
	case installed == running:
		return actOpenInstalled, ""
	case installed == "":
		return actUpdate, "Update Watchtower to " + running + "?"
	case newer(running, installed):
		return actUpdate, fmt.Sprintf("Update Watchtower %s → %s?", installed, running)
	default:
		return actUpdate, fmt.Sprintf("Replace the installed Watchtower %s with %s?", installed, running)
	}
}

// newer reports whether version a is above b, comparing x.y.z (any -suffix ignored); false if either won't parse.
func newer(a, b string) bool {
	pa, oka := parseVersion(a)
	pb, okb := parseVersion(b)
	if !oka || !okb {
		return false
	}
	for i := range pa {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func parseVersion(v string) ([3]int, bool) {
	var p [3]int
	v, _, _ = strings.Cut(v, "-")
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return p, false
	}
	for i, s := range parts {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return p, false
		}
		p[i] = n
	}
	return p, true
}
