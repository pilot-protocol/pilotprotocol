// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/routing"
)

// Transport modes accepted by Config.TransportMode and -transport.
const (
	TransportUDP    = "udp"
	TransportCompat = "compat"
	// TransportAuto picks udp or compat at startup (SelectTransport).
	// Config.TransportMode "" behaves the same way for embedders.
	TransportAuto = "auto"
)

// NormalizeTransport lower-cases and validates a transport name. "" stays
// "" (the caller's default).
func NormalizeTransport(v string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(v))
	switch s {
	case "", TransportUDP, TransportCompat, TransportAuto:
		return s, nil
	}
	return "", fmt.Errorf("invalid transport %q: must be udp, compat or auto", v)
}

// defaultCompatCheckTimeout bounds the compat beacon check in
// SelectTransport: TCP connect (through the proxy: its CONNECT), TLS
// handshake and one HTTP exchange.
const defaultCompatCheckTimeout = 8 * time.Second

// AutoTransportProbe configures SelectTransport.
type AutoTransportProbe struct {
	// BeaconAddr is the UDP beacon ("host:port"; the first entry of a
	// comma-separated list is probed).
	BeaconAddr string
	// CompatBeaconURL is the WSS beacon compat mode would dial. Empty
	// means compat is not available and auto always picks udp.
	CompatBeaconURL string
	// Dial opens the connection for the compat beacon check, normally
	// through the proxy policy compat mode would use. nil dials directly.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// UDPTimeout bounds the UDP probe (0 = udpProbeTimeout). A reply
	// returns as soon as it arrives, so on a working UDP path the probe
	// costs one round trip.
	UDPTimeout time.Duration
	// TCPTimeout bounds the compat check (0 = 8s). It only runs when the
	// UDP probe got no answer.
	TCPTimeout time.Duration
}

// SelectTransport decides -transport=auto:
//
//   - udp when the beacon answers a UDP discover — the transport a daemon
//     would have used anyway, found in one round trip;
//   - otherwise compat, when the compat beacon itself answers through
//     p.Dial (i.e. through the egress proxy, if there is one): a TLS
//     handshake and a plain GET of the compat path return 426 Upgrade
//     Required, which only a live WebSocket endpoint sends. A bare TCP
//     connect proves nothing: the production host is an SNI-routing front
//     that accepts TCP while the beacon behind it is down, and through a
//     proxy it is only the proxy's CONNECT 200;
//   - otherwise udp, exactly as before -transport=auto existed: nothing
//     is reachable yet (no network at boot, beacon outage), and a compat
//     daemon could not start either, while a udp daemon starts degraded
//     and registers.
//
// reason is a short, log-ready explanation of the choice.
func SelectTransport(ctx context.Context, p AutoTransportProbe) (mode, reason string) {
	beacon := firstBeacon(p.BeaconAddr)
	if beacon == "" {
		return TransportUDP, "no UDP beacon configured"
	}
	udpTimeout := p.UDPTimeout
	if udpTimeout <= 0 {
		udpTimeout = udpProbeTimeout
	}
	if probeUDPReachableWithin(beacon, udpTimeout) {
		return TransportUDP, "beacon " + beacon + " answered over UDP"
	}
	if strings.TrimSpace(p.CompatBeaconURL) == "" {
		return TransportUDP, "no UDP answer from beacon " + beacon + ", and no compat beacon configured"
	}
	target, err := compatBeaconHostPort(p.CompatBeaconURL)
	if err != nil {
		return TransportUDP, "no UDP answer from beacon " + beacon + "; compat beacon unusable: " + err.Error()
	}
	tcpTimeout := p.TCPTimeout
	if tcpTimeout <= 0 {
		tcpTimeout = defaultCompatCheckTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, tcpTimeout)
	defer cancel()
	if err := checkCompatBeacon(cctx, p.Dial, p.CompatBeaconURL, target); err != nil {
		return TransportUDP, fmt.Sprintf("no UDP answer from beacon %s, and compat beacon %s did not answer (%v)", beacon, p.CompatBeaconURL, err)
	}
	return TransportCompat, fmt.Sprintf("no UDP answer from beacon %s within %s; compat beacon %s answered", beacon, udpTimeout, p.CompatBeaconURL)
}

// checkCompatBeacon proves that the WebSocket beacon at rawURL is alive:
// it opens target through dial (nil: direct), runs TLS for wss:// and
// sends a plain GET of the beacon path, which a live WebSocket endpoint
// answers with 426 Upgrade Required. Anything else — a front that accepts
// TCP but has no backend (502/503), a proxy error, a closed connection —
// is an error.
//
// The TLS session is not verified: nothing is sent but a GET of a public
// path, and the result only selects the transport. The compat connection
// itself verifies the beacon with the configured trust (and reports a
// missing CA bundle far more clearly than a failed probe could).
func checkCompatBeacon(ctx context.Context, dial func(ctx context.Context, network, addr string) (net.Conn, error), rawURL, target string) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return err
	}
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}
	conn, err := dial(ctx, "tcp", target)
	if err != nil {
		return err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	switch strings.ToLower(u.Scheme) {
	case "wss", "https":
		tc := tls.Client(conn, &tls.Config{
			ServerName: u.Hostname(),
			MinVersion: tls.VersionTLS12,
			// #nosec G402 -- liveness probe only; see the doc comment.
			InsecureSkipVerify: true, // lgtm[go/disabled-certificate-check]
		})
		if err := tc.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("tls: %w", err)
		}
		conn = tc
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	req := "GET " + path + " HTTP/1.1\r\nHost: " + u.Host + "\r\nUser-Agent: pilot-daemon/transport-auto\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUpgradeRequired {
		return fmt.Errorf("HTTP %d, want 426 from a live beacon", resp.StatusCode)
	}
	return nil
}

// probeUDPReachableWithin is probeUDPReachable with a caller-chosen bound,
// split over two discover attempts so one lost datagram does not count as
// a blocked path.
func probeUDPReachableWithin(beaconAddr string, timeout time.Duration) bool {
	if _, _, err := net.SplitHostPort(beaconAddr); err != nil {
		return false
	}
	per := timeout / 2
	if per <= 0 {
		per = timeout
	}
	for i := 0; i < 2; i++ {
		if _, err := routing.ProbeBeaconRTT(beaconAddr, 0, per); err == nil {
			return true
		}
	}
	return false
}

// compatBeaconHostPort extracts the TCP target of a ws:// or wss:// URL.
func compatBeaconHostPort(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse %q: %w", raw, err)
	}
	port := u.Port()
	switch strings.ToLower(u.Scheme) {
	case "wss", "https":
		if port == "" {
			port = "443"
		}
	case "ws", "http":
		if port == "" {
			port = "80"
		}
	default:
		return "", fmt.Errorf("unsupported scheme in %q", raw)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("no host in %q", raw)
	}
	return net.JoinHostPort(u.Hostname(), port), nil
}

// tlsTrustHint explains a certificate verification failure against the
// system trust store, which in a minimal sandbox usually means there is no
// CA bundle. "" for any other error.
func tlsTrustHint(err error, what string) string {
	if err == nil {
		return ""
	}
	var ua x509.UnknownAuthorityError
	var sr x509.SystemRootsError
	msg := err.Error()
	if !errors.As(err, &ua) && !errors.As(err, &sr) &&
		!strings.Contains(msg, "certificate signed by unknown authority") &&
		!strings.Contains(msg, "failed to load system roots") {
		return ""
	}
	switch what {
	case "registry":
		return "cannot verify the registry certificate: point SSL_CERT_FILE (or SSL_CERT_DIR) at a CA bundle, or pin it with -registry-trust=pinned -registry-fingerprint=<sha256> (config registry_trust/registry_fingerprint, or env PILOT_REGISTRY_TRUST/PILOT_REGISTRY_FINGERPRINT)"
	default:
		return "cannot verify the beacon certificate: point SSL_CERT_FILE (or SSL_CERT_DIR) at a CA bundle"
	}
}
