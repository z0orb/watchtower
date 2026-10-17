package tray

import (
	"bufio"
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"
)

// outage is the service's one log line per finished outage.
type outage struct {
	Msg       string    `json:"msg"`
	Start     time.Time `json:"start"`
	Seconds   int       `json:"seconds"`
	Diagnosis string    `json:"diagnosis"`
	FixedBy   string    `json:"fixed_by"`
}

var causes = map[string]string{
	"link_down":       "Adapter disconnected",
	"dead":            "Router unreachable",
	"gateway_changed": "Gateway MAC changed",
	"upstream":        "ISP or modem down",
	"dns_broken":      "DNS failing",
}

// Report summarizes the outages found in the service's JSON-lines logs.
func Report(logs []io.Reader, now time.Time) string {
	var all []outage
	for _, r := range logs {
		sc := bufio.NewScanner(r)
		sc.Buffer(nil, 1<<20)
		for sc.Scan() {
			var o outage
			if json.Unmarshal(sc.Bytes(), &o) == nil && o.Msg == "outage" {
				all = append(all, o)
			}
		}
	}
	slices.SortFunc(all, func(a, b outage) int { return a.Start.Compare(b.Start) })

	var b strings.Builder
	fmt.Fprintf(&b, "Watchtower connection report, %s\n\n", now.Format("2006-01-02 15:04"))
	week := since(all, now.Add(-7*24*time.Hour))
	if len(week) == 0 {
		b.WriteString("No outages in the last 7 days.\n")
		return b.String()
	}
	for _, p := range []struct {
		name string
		os   []outage
	}{{"Last 24 hours", since(all, now.Add(-24*time.Hour))}, {"Last 7 days  ", week}} {
		total, longest := 0, 0
		for _, o := range p.os {
			total, longest = total+o.Seconds, max(longest, o.Seconds)
		}
		plural := "s"
		if len(p.os) == 1 {
			plural = ""
		}
		fmt.Fprintf(&b, "%s: %d outage%s, %s offline, longest %s\n", p.name, len(p.os), plural, dur(total), dur(longest))
	}

	b.WriteString("\nBy cause (7 days):\n")
	count := map[string]int{}
	for _, o := range week {
		count[o.Diagnosis]++
	}
	keys := slices.SortedFunc(maps.Keys(count), func(a, c string) int { return cmp.Or(count[c]-count[a], strings.Compare(a, c)) })
	for _, k := range keys {
		fmt.Fprintf(&b, "  %-22s %d\n", cmp.Or(causes[k], k), count[k])
	}

	b.WriteString("\nMost recent outages:\n")
	for _, o := range slices.Backward(week[max(0, len(week)-20):]) {
		fixed := "recovered by itself"
		if o.FixedBy != "" {
			fixed = "last action: " + o.FixedBy
		}
		fmt.Fprintf(&b, "  %s  %8s  %-22s %s\n", o.Start.Local().Format("2006-01-02 15:04:05"), dur(o.Seconds),
			cmp.Or(causes[o.Diagnosis], o.Diagnosis), fixed)
	}
	return b.String()
}

// since returns the outages (sorted by start) that began at or after t.
func since(sorted []outage, t time.Time) []outage {
	i, _ := slices.BinarySearchFunc(sorted, t, func(o outage, t time.Time) int { return o.Start.Compare(t) })
	return sorted[i:]
}

func dur(s int) string { return (time.Duration(s) * time.Second).String() }
