// Package egress decides where outbound vendor requests may go.
//
// Three checks, all mandatory:
//   - CheckURL: HTTPS only, no credentials embedded in the URL.
//   - CheckSecretHost: a secret is only ever sent to the one host it is bound to.
//   - Client: checks the real IP at connect time (after DNS), so a hostname that
//     resolves to localhost, a private network or the cloud metadata service is
//     refused. Redirects are never followed.
package egress

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// ErrBlocked marks every refusal made by this package. Callers must never retry it.
var ErrBlocked = errors.New("egress blocked")

// Policy controls outbound requests. The zero value is the production policy.
type Policy struct {
	// AllowPrivate permits these ranges (e.g. a local mock vendor). DEV/TEST ONLY.
	AllowPrivate []netip.Prefix
	// AllowHTTP permits plain http. DEV/TEST ONLY.
	AllowHTTP bool
	// RootCAs overrides the system trust store. TESTS ONLY.
	RootCAs *x509.CertPool
}

// Ranges that are globally routable on paper but must never be reached.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"), // NAT64 can map to internal IPv4
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/32"), // Teredo
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"), // 6to4 can embed private IPv4
}

// CheckIP refuses any address that is not a normal public unicast address.
func (p Policy) CheckIP(ip netip.Addr) error {
	ip = ip.Unmap()
	for _, allowed := range p.AllowPrivate {
		if allowed.Contains(ip) {
			return nil
		}
	}
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("%w: address %s is not public", ErrBlocked, ip)
	}
	for _, blocked := range blockedPrefixes {
		if blocked.Contains(ip) {
			return fmt.Errorf("%w: address %s is in a reserved range", ErrBlocked, ip)
		}
	}
	return nil
}

// CheckURL enforces scheme and URL shape before any request is built.
func (p Policy) CheckURL(u *url.URL) error {
	if u == nil {
		return fmt.Errorf("%w: missing URL", ErrBlocked)
	}
	if u.Scheme != "https" && !(p.AllowHTTP && u.Scheme == "http") {
		return fmt.Errorf("%w: scheme %q not allowed, use https", ErrBlocked, u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("%w: credentials inside the URL are not allowed", ErrBlocked)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("%w: URL has no host", ErrBlocked)
	}
	return nil
}

// CheckSecretHost allows a secret to go only to its bound host (exact match,
// case-insensitive). A bound host without a port allows only the default HTTPS
// port; a bound host with a port ("localhost:8081") must match exactly.
func CheckSecretHost(boundHost string, target *url.URL) error {
	bound := strings.ToLower(strings.TrimSpace(boundHost))
	if bound == "" {
		return fmt.Errorf("%w: secret has no bound host", ErrBlocked)
	}
	if target == nil {
		return fmt.Errorf("%w: missing target URL", ErrBlocked)
	}
	if strings.Contains(bound, ":") {
		if strings.ToLower(target.Host) != bound {
			return fmt.Errorf("%w: secret is bound to %s, not %s", ErrBlocked, bound, target.Host)
		}
		return nil
	}
	host, port := strings.ToLower(target.Hostname()), target.Port()
	if host != bound || (port != "" && port != "443") {
		return fmt.Errorf("%w: secret is bound to %s, not %s", ErrBlocked, bound, target.Host)
	}
	return nil
}

// Client returns an HTTP client that enforces the policy on every connection,
// ignores proxy environment variables and refuses all redirects.
func (p Policy) Client(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		// Control runs after DNS resolution with the exact IP being dialled,
		// which defeats DNS rebinding and hostnames pointing at internal IPs.
		Control: func(_, address string, _ syscall.RawConn) error {
			addrPort, err := netip.ParseAddrPort(address)
			if err != nil {
				return fmt.Errorf("%w: cannot parse dial address", ErrBlocked)
			}
			return p.CheckIP(addrPort.Addr())
		},
	}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("%w: redirects are not followed", ErrBlocked)
		},
		Transport: &http.Transport{
			Proxy:                  nil,
			DialContext:            dialer.DialContext,
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: p.RootCAs},
			ForceAttemptHTTP2:      true,
			TLSHandshakeTimeout:    10 * time.Second,
			ResponseHeaderTimeout:  timeout,
			MaxResponseHeaderBytes: 64 << 10,
			IdleConnTimeout:        30 * time.Second,
		},
	}
}
