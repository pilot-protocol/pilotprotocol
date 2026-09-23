// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
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

// defaultCompatCheckTimeout bounds the TCP reachability check of the
// compat beacon in SelectTransport.
const defaultCompatCheckTimeout = 5 * time.Second

// AutoTransportProbe configures SelectTransport.
type AutoTransportProbe struct {
	// BeaconAddr is the UDP beacon ("host:port"; the first entry of a
	// comma-separated list is probed).
	BeaconAddr string
	// CompatBeaconURL is the WSS beacon compat mode would dial. Empty
	// means compat is not available and auto always picks udp.
	CompatBeaconURL string
	// Dial opens the compat reachability check, normally through the
	// proxy policy compat mode would use. nil dials directly.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// UDPTimeout bounds the UDP probe (0 = udpProbeTimeout). A reply
	// returns as soon as it arrives, so on a working UDP path the probe
	// costs one round trip.
	UDPTimeout time.Duration
	// TCPTimeout bounds the compat check (0 = 5s). It only runs when the
	// UDP probe got no answer.
	TCPTimeout time.Duration
}

// SelectTransport decides -transport=auto:
//
//   - udp when the beacon answers a UDP discover — the transport a daemon
//     would have used anyway, found in one round trip;
//   - otherwise compat, when the compat beacon's host:port accepts a TCP
//     connection through p.Dial (i.e. through the egress proxy, if there
//     is one): the host blocks UDP but can reach TCP 443;
//   - otherwise udp, exactly as before -transport=auto existed: nothing
//     is reachable yet (no network at boot, beacon outage), and a compat
//     daemon could not start either.
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
	dial := p.Dial
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}
	conn, err := dial(cctx, "tcp", target)
	if err != nil {
		return TransportUDP, fmt.Sprintf("no UDP answer from beacon %s, and compat beacon %s unreachable (%v)", beacon, target, err)
	}
	conn.Close()
	return TransportCompat, fmt.Sprintf("no UDP answer from beacon %s within %s; compat beacon %s reachable over TCP", beacon, udpTimeout, target)
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
