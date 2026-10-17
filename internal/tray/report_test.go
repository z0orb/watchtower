package tray

import (
	"io"
	"strings"
	"testing"
	"time"
)

func TestReport(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	older := `{"msg":"outage","start":"2026-10-12T08:00:00Z","seconds":120,"diagnosis":"upstream","fixed_by":"alert_upstream"}
{"msg":"outage","start":"2026-10-01T08:00:00Z","seconds":999,"diagnosis":"dead"}
`
	current := `{"msg":"started"}
not json
{"msg":"outage","start":"2026-10-17T11:00:00Z","seconds":31,"diagnosis":"dns_broken","fixed_by":"set_public_dns","actions":["flush_dns","set_public_dns"]}
{"msg":"outage","start":"2026-10-17T10:00:00Z","seconds":15,"diagnosis":"dns_broken"}
`
	got := Report([]io.Reader{strings.NewReader(older), strings.NewReader(current)}, now)
	for _, want := range []string{
		"Last 24 hours: 2 outages, 46s offline, longest 31s",
		"Last 7 days  : 3 outages, 2m46s offline, longest 2m0s",
		"DNS failing            2",
		"ISP or modem down      1",
		"last action: set_public_dns",
		"recovered by itself",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("report lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "Router unreachable") {
		t.Errorf("outage older than 7 days included:\n%s", got)
	}
	if i, j := strings.Index(got, "set_public_dns"), strings.Index(got, "recovered by itself"); i > j {
		t.Errorf("most recent outage should come first:\n%s", got)
	}
	if got := Report(nil, now); !strings.Contains(got, "No outages in the last 7 days.") {
		t.Errorf("empty report: %s", got)
	}
}
