package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"time"
)

// dnsWorks reports whether server (or the adapter's configured DNS servers when "") answers.
// It asks for a random name so no cache can answer; an NXDOMAIN reply still proves DNS works.
func dnsWorks(server string, timeout time.Duration) bool {
	r := &net.Resolver{PreferGo: true}
	if server != "" {
		r.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, err := r.LookupHost(ctx, fmt.Sprintf("wt-%x.example.com", rand.Uint64()))
	var de *net.DNSError
	return err == nil || errors.As(err, &de) && de.IsNotFound
}
