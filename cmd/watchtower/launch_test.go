package main

import (
	"strings"
	"testing"
)

func TestLaunchAction(t *testing.T) {
	for _, c := range []struct {
		name                string
		running, installed  string
		exists, fromInstall bool
		want                action
		prompt              string // substring
	}{
		{"installed copy", "0.1.3", "0.1.3", true, true, actTray, ""},
		{"installed copy, any version", "0.1.3", "", true, true, actTray, ""},
		{"not installed", "0.1.3", "", false, false, actInstall, "Install Watchtower 0.1.3?"},
		{"stale key, exe gone", "0.1.3", "0.1.2", false, false, actInstall, "Install"},
		{"same version", "0.1.3", "0.1.3", true, false, actOpenInstalled, ""},
		{"pre-0.2.0 install", "0.1.3", "", true, false, actUpdate, "Update Watchtower to 0.1.3?"},
		{"newer", "0.1.3", "0.1.2", true, false, actUpdate, "Update Watchtower 0.1.2 → 0.1.3?"},
		{"newer minor", "0.2.0", "0.1.9", true, false, actUpdate, "0.1.9 → 0.2.0"},
		{"older", "0.1.2", "0.1.3", true, false, actUpdate, "Replace the installed Watchtower 0.1.3 with 0.1.2?"},
		{"dev build", "dev", "0.1.3", true, false, actUpdate, "Replace"},
	} {
		got, prompt := launchAction(c.running, c.installed, c.exists, c.fromInstall)
		if got != c.want || !strings.Contains(prompt, c.prompt) {
			t.Errorf("%s: got %d %q, want %d containing %q", c.name, got, prompt, c.want, c.prompt)
		}
	}
}

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"0.1.3", "0.1.2", true},
		{"0.1.2", "0.1.3", false},
		{"0.1.10", "0.1.9", true},
		{"1.0.0", "0.9.9", true},
		{"0.1.3", "0.1.3", false},
		{"0.1.4-test", "0.1.3-test", true},
		{"dev", "0.1.3", false},
		{"0.1.3", "dev", false},
		{"0.1", "0.0.9", false},
	} {
		if got := newer(c.a, c.b); got != c.want {
			t.Errorf("newer(%q, %q) = %v", c.a, c.b, got)
		}
	}
}
