// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pilot-protocol/common/consent"
	"github.com/pilot-protocol/common/crypto"
	"github.com/pilot-protocol/common/daemonapi"
	"github.com/pilot-protocol/common/fsutil"
	"github.com/pilot-protocol/common/netproxy"
	"github.com/pilot-protocol/common/protocol"
	registry "github.com/pilot-protocol/common/registry/client"
	registrywire "github.com/pilot-protocol/common/registry/wire"
	"github.com/pilot-protocol/pilotprotocol/internal/account"
	"github.com/pilot-protocol/pilotprotocol/internal/motd"
	"github.com/pilot-protocol/pilotprotocol/internal/transport/compat"
	"github.com/pilot-protocol/pilotprotocol/internal/validate"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/routing"
	"github.com/pilot-protocol/trustedagents"
)

// isRegistryRejectingUsErr returns true when the registry's response to a
// heartbeat indicates that our identity is no longer valid for the node ID
// we hold:
//
//   - "node not found": the registry was wiped (restart with empty state) or
//     we were deregistered out-of-band.
//   - "signature verification failed": another agent has claimed our node ID
//     (e.g. after a registry restart where a peer re-registered first and
//     the registry assigned it our old node ID).
//
// In both cases the daemon should re-register on the next heartbeat cycle
// rather than waiting HeartbeatReregThresh * keepaliveInterval (~3 minutes)
// to act.  Connection-level failures ("request failed", "i/o timeout",
// "connection refused") are *not* matched — those should still use the
// normal failure-count threshold because they can be transient.
func isRegistryRejectingUsErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	if strings.Contains(msg, "node not found") {
		return true
	}
	if strings.Contains(msg, "signature verification failed") {
		return true
	}
	return false
}

const registryCallDeadline = 8 * time.Second

var errRegistryCallTimedOut = errors.New("registry: call timed out, connection likely half-open")

func withRegistryDeadline(timeout time.Duration, fn func() (map[string]interface{}, error)) (map[string]interface{}, error) {
	type registryCallResult struct {
		resp map[string]interface{}
		err  error
	}
	// Buffered so the worker can always deposit its result and exit even
	// after we have given up — otherwise it would park on the send
	// forever, retaining its stack and the decoded response map.
	resultCh := make(chan registryCallResult, 1)
	go func() {
		resp, err := fn()
		resultCh <- registryCallResult{resp: resp, err: err}
	}()

	// time.After leaks its timer until the duration elapses. On a wedged
	// registry conn this path runs repeatedly, so use an explicitly
	// stopped timer instead of pinning one 8s timer per call.
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case r := <-resultCh:
		return r.resp, r.err
	case <-timer.C:
		return nil, errRegistryCallTimedOut
	}
}

var (
	zeroTime     = func() time.Time { return time.Time{} }
	fixedTimeout = func() time.Time { return time.Now().Add(5 * time.Second) }
)

type Config struct {
	RegistryAddr        string
	BeaconAddr          string
	ListenAddr          string   // UDP listen address for tunnel traffic
	SocketPath          string   // Unix socket path for IPC
	IPCWhitelist        []string // process names (comm) trusted to bypass per-client dial quota (PILOT-346)
	Encrypt             bool     // enable tunnel-layer encryption (X25519 + AES-256-GCM)
	RegistryTLS         bool     // use TLS for registry connection
	RegistryFingerprint string   // hex SHA-256 fingerprint for TLS cert pinning
	// RegistryTrust selects which trust store verifies the registry's
	// certificate when RegistryTLS=true. "pinned" (default) requires
	// RegistryFingerprint and is what production deploys use today.
	// "system" trusts the OS x509 root store — the path for compat-mode
	// daemons pointing at registry.pilotprotocol.network:443 with its
	// Let's Encrypt certificate. Mirrors -tls-trust on the WSS side.
	RegistryTrust string
	IdentityPath  string // path to persist Ed25519 identity (empty = no persistence)
	Email         string // email address for account identification and key recovery
	Owner         string // deprecated: use Email instead

	Endpoint          string // fixed public endpoint (host:port) — skips STUN discovery (for cloud VMs)
	AdvertiseEndpoint string // override STUN-discovered endpoint for registry advertisement (host:port) — for k8s pods where STUN returns unreachable IPs
	Public            bool   // make this node's endpoint publicly discoverable
	Hostname          string // hostname for discovery (empty = none)

	// RelayOnly hides this node's real_addr from peer resolve/lookup
	// responses. Peers reach this node only via the beacon-relay path,
	// so this node's public IP is never exposed to other daemons.
	// Default false (current behavior). Task 32 — once the fleet is on a
	// new-enough binary, the operator default will flip to true.
	RelayOnly bool

	// Built-in services
	DisableEcho         bool // disable built-in echo service (port 7)
	DisableDataExchange bool // disable built-in data exchange service (port 1001)
	DisableEventStream  bool // disable built-in event stream service (port 1002)
	DisablePolicyRunner bool // skip loading expr policy runners and joining networks at startup

	// Webhook
	WebhookURL          string        // HTTP(S) endpoint for event notifications (empty = disabled)
	WebhookHTTPTimeout  time.Duration // HTTP client timeout for webhook POSTs (default 5s)
	WebhookRetryBackoff time.Duration // initial retry backoff for webhook POSTs (default 1s)

	// Trust
	TrustAutoApprove     bool // automatically approve all incoming handshake requests
	StrictDataPlaneTrust bool

	// Fleet enrollment
	AdminToken string   // admin token for network operations (empty = disabled)
	Networks   []uint16 // network IDs to auto-join at startup (empty = none)

	// Version
	Version string // binary version string (injected via LDFLAGS at build time)

	// Message of the day. The daemon polls MOTDFeedURL every MOTDInterval,
	// selects the entry dated for the current UTC day, mirrors it to
	// ~/.pilot/motd.json, and pilotctl renders it as a banner. An empty
	// MOTDFeedURL disables polling entirely (no goroutine, no network).
	MOTDFeedURL  string
	MOTDInterval time.Duration // zero = motd.DefaultInterval

	// Feature flags — ablation testing. All default false (current behavior).
	BeaconRTTProbe bool // probe beacon RTT; override hash pick when >2× slower than best

	// DisableRxWatchdog turns off the inbound-path watchdog (rxwatchdog.go).
	// The watchdog detects the long-uptime wedge where the daemon keeps
	// transmitting but the inbound UDP path has silently died (stale NAT /
	// relay mapping — 2026-07-13 incident: 43.5 MB sent vs 102 KB received
	// over 2d19h, every send-message failing with "cannot connect"). It
	// first soft-recovers (beacon + registry re-registration) and, if the
	// wedge persists on a supervised daemon, exits non-zero so
	// launchd/systemd respawns with a clean transport. Default false
	// (watchdog on) — the wedge otherwise requires a manual restart.
	DisableRxWatchdog bool

	// DisablePathWatch turns off the per-peer path watchdog
	// (pathwatch.go). The watchdog detects a SINGLE peer's NAT/relay
	// mapping dying while other peers stay healthy (so the global
	// rx-watchdog never fires), probes the peer with pong-soliciting
	// pings that every deployed daemon version answers, and on
	// sustained silence resets that one peer's path in place (same
	// sequence as `pilotctl prefer-direct`) instead of requiring a
	// full daemon restart. Default false (watchdog on).
	DisablePathWatch bool

	// Telemetry consent gate. When set to the telemetry endpoint URL,
	// the daemon initialises a telemetry client that emits signed events
	// (install, usage, view, review). When empty (default), the client
	// is a hard no-op: no dial, no buffering, no goroutines.
	TelemetryURL string

	// Compat-mode transport. Default empty ("" or "udp") = today's
	// behavior: bind a UDP socket via udpio.Listen. Set "compat" to
	// dial WSS to BeaconURL instead (for daemons in UDP-blocked
	// environments — Docker on Render/Railway/Vercel/Lambda).
	// See docs/SPEC-compat-mode.md.
	TransportMode string // "" | "udp" | "compat"
	// CompatBeaconURL is the wss:// URL of the beacon when
	// TransportMode=compat. Ignored otherwise.
	CompatBeaconURL string
	// CompatTLSTrust selects the TLS trust store for compat mode:
	// "pinned" (default; only the Pilot root CA embedded in the
	// binary) or "system" (OS trust store; escape hatch for daemons
	// behind TLS-intercepting corp proxies).
	CompatTLSTrust string

	// Proxy is the outbound proxy policy, normally built by ResolveProxy
	// from -proxy and the transport mode. When non-nil it governs every
	// TCP/HTTP connection the daemon opens itself: the registry (primary,
	// pool and every reconnect), the compat-mode WSS beacon and the MOTD
	// fetch. Targets stay host names end to end — the proxy is asked to
	// CONNECT by name and TLS runs through the tunnel to the real server.
	// nil keeps the historical behaviour: registry and beacon are dialed
	// directly and HTTP fetches follow net/http's proxy environment.
	Proxy *netproxy.Resolver

	// ProxyPolicy, when non-nil, replaces Proxy with a policy that can
	// change while the daemon runs — NewCommandProxyPolicy re-reads the
	// proxy URL from a command, for egress proxies that rotate their
	// credentials. Start keeps it refreshed every ProxyRefreshInterval
	// (0 = 60s) until Stop.
	ProxyPolicy          *ProxyPolicy
	ProxyRefreshInterval time.Duration

	// systemRoots replaces the OS trust store behind the "system" trust
	// settings (RegistryTrust, CompatTLSTrust). Test seam only: it is
	// always nil outside this package's tests.
	systemRoots *x509.CertPool

	// Tuning (zero = use defaults)
	KeepaliveInterval     time.Duration // default 60s
	IdleTimeout           time.Duration // default 120s
	SYNRateLimit          int           // default 100
	MaxConnectionsPerPort int           // default 1024
	MaxTotalConnections   int           // default 65536 (DefaultMaxTotalConnections)
	TimeWaitDuration      time.Duration // default 10s
}

// Default tuning constants (used when Config fields are zero).
const (
	DefaultKeepaliveInterval = 60 * time.Second
	DefaultIdleTimeout       = 120 * time.Second
	DefaultIdleSweepInterval = 15 * time.Second
	// hostnameReannounceInterval is how often the daemon re-sets its
	// hostname with the registry. This heals hostname resolution after
	// a registry restart/roll wipes the in-memory hostname store.
	hostnameReannounceInterval   = 60 * time.Second
	DefaultSYNRateLimit          = 100
	DefaultMaxConnectionsPerPort = 1024
	// DefaultMaxTotalConnections caps the daemon's total overlay
	// connection table. It is intentionally large (65536) to support
	// high-fan-out daemons (registry-scale hosts run tens of thousands of
	// identities/conns). This is NOT the first line of DoS defence: a
	// single local client cannot reach it because MaxConnsPerIPCClient
	// (4096) and MaxIPCClients (1024) gate per-client and per-socket
	// growth, and MaxConnectionsPerPort (1024) bounds inbound fan-in per
	// listening port. DoS sizing: each table slot can carry a retxLoop
	// goroutine plus send/recv buffers, so 65536 is the documented upper
	// bound on that memory; lower MaxTotalConnections in Config to tighten
	// it on memory-constrained hosts.
	DefaultMaxTotalConnections = 65536
	DefaultTimeWaitDuration    = 10 * time.Second
)

// Dial and retransmission constants.
const (
	DialDirectRetries    = 3                      // direct connection attempts before relay
	DialMaxRetries       = 7                      // total attempts (direct + relay). 3 direct + 4 relay. With DialInitialRTO=250ms exponential-backoff capped at DialMaxRTO=8s, the relay phase is ~7.75s — covers cold-start handshake (key_exchange + flushPending + SYN/SYN-ACK round trip) for typical peers while keeping bad dials from blocking longer than the user's --timeout. The probe-and-adapt machinery (see srttHistory below) will let us shorten this for peers we've successfully dialed before.
	DialInitialRTO       = 250 * time.Millisecond // initial SYN retransmission timeout. Lowered from 1s — modern relay RTT is <200ms; waiting a full second before assuming loss makes cold dials feel like a stall. Three direct retries with exponential backoff (250→500→1000) still cover up to 1.75s of jitter before flipping to relay; that's plenty for an unhealthy direct path while letting the common case (peer is reachable, single retry needed) feel snappy.
	DialMaxRTO           = 8 * time.Second        // max backoff for SYN retransmission
	DialCheckInterval    = 10 * time.Millisecond  // poll interval for state changes during dial
	RetxCheckInterval    = 100 * time.Millisecond // retransmission check ticker
	MaxRetxAttempts      = 8                      // abandon connection after this many retransmissions
	HeartbeatReregThresh = 3                      // heartbeat failures before re-registration
	SYNBucketAge         = 10 * time.Second       // stale per-source SYN bucket reap threshold
)

// Zero-window probe constants.
const (
	ZeroWinProbeInitial = 500 * time.Millisecond // initial zero-window probe interval
	ZeroWinProbeMax     = 30 * time.Second       // max zero-window probe backoff
	// P1-004: stop probing after this many attempts so a peer stuck at
	// window=0 (crashed, deadlocked, or adversarial) doesn't leak a
	// goroutine + timer + probe packets indefinitely. ~30 probes at the
	// 30s cap is ~15 minutes of trying, which matches the idle sweep.
	MaxZeroWindowProbes = 30
)

// RelayProbeInterval is how often we attempt to upgrade relay-flagged peers
// to a direct path via coordinated hole-punching. Was 5m (far too slow — a
// peer stuck on relay stayed there for minutes); tightened to 15s so a peer
// that becomes direct-capable (or one that briefly flipped to relay under
// load) is re-punched promptly. The punch + probe is cheap and only runs for
// peers still flagged relay, so it self-limits once a peer is promoted.
const RelayProbeInterval = 15 * time.Second

// EndpointCacheTTL is how long a cached endpoint is considered fresh.
// After this, the entry is stale but still usable as a fallback.
const EndpointCacheTTL = 5 * time.Minute

// ResolveCacheTTL is how long a registry resolve response is cached.
// During cron bursts, agents resolve the same peers repeatedly — this
// avoids hitting the registry for the same node within the TTL window.
const ResolveCacheTTL = 60 * time.Second

// DefaultNetworkSyncInterval is how often the daemon refreshes network
// memberships, port policies, and member tags from the registry.
const DefaultNetworkSyncInterval = 5 * time.Minute

// networkSnapshot is the JSON format persisted to {identityDir}/networks.json.
type networkSnapshot struct {
	Networks   []uint16            `json:"networks"`
	Policies   map[uint16][]uint16 `json:"policies,omitempty"`
	MemberTags map[uint16][]string `json:"member_tags,omitempty"`
	SyncedAt   string              `json:"synced_at"`
}

// endpointEntry caches a resolved endpoint for a peer node.
type endpointEntry struct {
	addr     string    // "host:port"
	cachedAt time.Time // when the entry was stored
}

// resolveEntry caches a full registry resolve response for a peer node.
type resolveEntry struct {
	resp     map[string]interface{}
	cachedAt time.Time
}

// hostnameCacheEntry caches a resolve_hostname response so repeated
// send-message calls to the same peer don't pound the registry.
type hostnameCacheEntry struct {
	resp     map[string]interface{}
	cachedAt time.Time
}

// hostnameCacheTTL is how long a cached hostname resolution stays
// valid. Short enough that legitimate hostname rotations propagate
// within a minute; long enough to absorb rapid-fire CLI invocations.
const hostnameCacheTTL = 60 * time.Second

type Daemon struct {
	config         Config
	addrMu         sync.RWMutex // protects nodeID, addr, publicEndpoint (H6 fix)
	nodeID         uint32
	addr           protocol.Addr
	publicEndpoint string       // host:port reported to the registry at registration
	identityMu     sync.RWMutex // protects identity after hot rotate-key
	identity       *crypto.Identity
	// rotateKeyMu serializes RotateKey calls. Without it, two concurrent
	// rotations capture the same `current = d.identity` snapshot under
	// identityMu.RLock(), then race: one finishes first, swaps, and zeros
	// the OLD PrivateKey buffer while the other is still inside
	// current.Sign(challenge) reading from the same bytes. Serializing
	// rotation eliminates the shared-buffer hazard without changing the
	// existing RLock/RUnlock pattern for non-rotating Sign callers.
	rotateKeyMu sync.Mutex
	regConn     atomic.Pointer[registry.Client]
	tunnels     *TunnelManager
	ports       *PortManager
	ipc         *IPCServer
	handshakes  HandshakeService

	// handshakeInFlight tracks peers with an outbound trust-handshake
	// currently in progress on this daemon. Per-peer keyed
	// (nodeID → struct{}). Inserted on entry to HandshakeSendRequest,
	// removed on return. Concurrent callers for the same peer observe
	// the existing entry and short-circuit with ErrHandshakeInFlight so
	// they do not race a second DialConnection on port 444 — which under
	// a burst (e.g. parallel `pilotctl handshake` commands) was capable
	// of saturating the ephemeral-port bitmap for a few seconds before
	// the SYN_SENT reaper recovered the pool. Per-peer dedup keeps
	// concurrent intent to the same target collapsed to one in-flight
	// dial regardless of caller count.
	handshakeInFlight sync.Map

	// autoHandshakeLastAttempt records the last time DialConnection's
	// inline trusted-agents auto-handshake (daemon.go ~3139) fired for
	// a peer (nodeID → time.Time). Used by shouldAutoHandshake to
	// throttle the dial-driven fanout: handshakeInFlight only collapses
	// CONCURRENT callers, not SEQUENTIAL ones — when SendRequest
	// returns fast (e.g. sendMessage hits ErrEphemeralExhausted in
	// microseconds, or the registry-relay fallback completes), the
	// in-flight slot is released immediately and the next DialConnection
	// caller re-fires the goroutine, re-enters SendRequest, and emits
	// another "direct handshake failed" log line. Without a cooldown,
	// this produced a 4k-log-line-per-second storm against
	// blockchain-ticker (node 19418) on 2026-06-06 — daemon log grew
	// to 1 GB in under four hours while every outbound dial to that
	// peer (and any concurrent tenant of the port pool) failed with
	// "ephemeral ports exhausted".
	//
	// Distinct from handshakeInFlight (concurrent-burst dedup): this is
	// a separate time-keyed gate that runs only on the DialConnection
	// auto-spawn path, so explicit user-initiated `pilotctl handshake`
	// IPC calls are NOT throttled.
	autoHandshakeLastAttempt sync.Map

	// network.* bus subscriber for daemon-internal reactions (managed
	// engines + member-tag cache). Wired by subscribeNetworkInternalToBus
	// during Start; torn down before tunnels in doStop. (T4.3.)
	netSubMu   sync.Mutex
	netSubStop func()

	// lastRegistryOKNano is the unix-nano time of the last successful
	// registry interaction (initial registration, heartbeat, or
	// re-registration). The rx watchdog uses it to distinguish "data
	// plane wedged, control plane fine" (restart helps — the incident
	// signature) from "whole network unreachable" (restart just loops).
	lastRegistryOKNano atomic.Int64

	// lastDialOKNano / consecutiveDialTimeouts feed the rx watchdog's
	// PARTIAL-wedge detector. A daemon can be "up" with rx trickling —
	// a couple of keepalive packets from existing peers keep PktsRecv
	// advancing, so the rx-silence check stays quiet — yet be unable to
	// open a single new outbound data-exchange connection: every
	// DialConnection returns ErrDialTimeout. Observed 2026-07-15, the
	// overlay went dark (pilot-director + list-agents both unreachable)
	// and the watchdog did NOT fire because the keepalive trickle reset
	// its silence timer every tick; only a manual daemon restart cleared
	// it. consecutiveDialTimeouts counts back-to-back dial timeouts
	// (reset to 0 on any successful dial); a run of them to distinct
	// peers means our outbound path is wedged, not that one peer is dead.
	lastDialOKNano          atomic.Int64
	consecutiveDialTimeouts atomic.Uint64

	startTime       time.Time
	stopCh          chan struct{}         // closed on Stop() to signal goroutines
	beaconSelection *beaconSelectionState // multi-beacon discovery state
	stopOnce        sync.Once             // ensures stopCh is closed exactly once
	bgWG            sync.WaitGroup        // tracks daemon-scoped background goroutines

	// In-process event bus. Core layers Publish; the webhook plugin
	// (and any other observability plugin) Subscribe. Replaces inline
	// webhook.Emit calls (T4.1).
	bus *inProcessBus

	// Webhook plugin handle, set via RegisterWebhookManager. Daemon-
	// local interface (no plugin import). Routes IPC's `set-webhook`
	// to the plugin and exposes plugin counters for DaemonInfo.
	webhookManager WebhookManager

	// Trust checker registered by the trustedagents plugin via
	// RegisterTrustChecker. Daemon-local interface (primitive
	// signatures) so daemon doesn't import pkg/coreapi (T7.1).
	trustChecker TrustChecker

	// Policy plugin handle, set via RegisterPolicyManager. Daemon-
	// local interface (primitive signatures only).
	policyManager PolicyManager

	// Daemon-shutdown context that sidecar plugins respect for
	// graceful shutdown. Canceled when stopCh closes.
	ctx       context.Context
	cancelCtx context.CancelFunc

	lanAddrs []string // LAN addresses for same-network peer detection

	// Endpoint cache: nodeID -> last-known endpoint (peer resilience)
	epCacheMu sync.RWMutex
	epCache   map[uint32]*endpointEntry

	// Resolve cache: nodeID -> cached registry response (60s TTL)
	resolveCacheMu sync.RWMutex
	resolveCache   map[uint32]*resolveEntry

	// Hostname cache: hostname string -> cached resolve_hostname response.
	// Avoids hitting the registry for every send-message to the same peer
	// when the regConn is contended (policy fetchMembers loops, etc.).
	// 60s TTL — hostnames do change (rotation, reassignment) but rarely
	// fast enough for sub-minute staleness to matter.
	hostnameCacheMu sync.RWMutex
	hostnameCache   map[string]*hostnameCacheEntry

	// nodeNetworks cache: short TTL snapshot of `regConn.Lookup(self).networks`.
	// Issue #93: Daemon.Info() and handleHealth call nodeNetworks() on every
	// invocation. Under §4.8 stress (250 heartbeat goroutines × ~10 ops/s,
	// half of which are Info/Health) that meant ~1250 registry round-trips
	// per second per daemon, all serialised through the IPC read loop.
	// Caching for one second turns the steady-state cost from O(calls) to
	// O(unique seconds) without observable staleness for callers (network
	// memberships rarely change inside a second; admins who care invalidate
	// via JoinNetwork/LeaveNetwork which clear the cache).
	nodeNetworksCacheMu sync.Mutex
	nodeNetworksCache   []uint16
	nodeNetworksCacheAt time.Time

	// Message of the day: the text active for the current UTC day, set by
	// motdPollLoop from the remote feed and mirrored to ~/.pilot/motd.json
	// for the CLI banner. Empty means no banner. The daemon is the only
	// component that fetches the feed; pilotctl reads the mirror.
	motdMu sync.RWMutex
	motd   string

	// SYN rate limiter (token bucket)
	synMu       sync.Mutex
	synTokens   int
	synLastFill time.Time

	// Per-source SYN rate limiter
	perSrcSYNMu sync.Mutex
	perSrcSYN   map[uint32]*srcSYNBucket // source nodeID -> bucket
	// PILOT-343: trusted source nodes that bypass BOTH the global SYN
	// rate limit and the per-source SYN limit. Empty by default. Read
	// under atomic.Pointer on the hot path to avoid locking. Populated
	// at startup via SetSYNWhitelist.
	synWhitelist atomic.Pointer[map[uint32]struct{}]
	// PILOT-343 wildcard: when true, every source bypasses both SYN
	// gates regardless of the synWhitelist contents. Set by passing
	// "*" via env / -syn-whitelist, or directly via
	// SetSYNWhitelistMatchAll(true). Used on service-agent boxes
	// where the SYN-flood protection blocks legitimate high-volume
	// query traffic.
	synWhitelistAll atomic.Bool

	// Network port policies: netID -> allowed ports (nil/empty = all allowed)
	netPolicyMu sync.RWMutex
	netPolicies map[uint16][]uint16

	// gaveUpResetMu guards lastGaveUpReset, the per-peer cooldown for
	// rekey-gave-up-triggered path resets (onRekeyGaveUp).
	gaveUpResetMu   sync.Mutex
	lastGaveUpReset map[uint32]time.Time

	// Managed network engines: netID -> engine (older "managed network"
	// feature — doesn't reference pkg/policy, stays in pkg/daemon).
	managedMu sync.Mutex
	managed   map[uint16]*ManagedEngine

	// policyRunners moved to plugins/policy as part of T2.3. Daemon
	// now consults policyManager (above).

	// Cached member tags: netID -> local node's admin-assigned tags
	memberTagsMu sync.RWMutex
	memberTags   map[uint16][]string

	// AcceptQueueDrops counts SYNs that hit a full Listener.AcceptCh.
	// Each drop sends a RST back to the dialer (so the peer learns
	// immediately) and bumps this counter for operator visibility.
	// Without this, accept-queue overflows are silent slow-downs that
	// only surface as application-level connection failures.
	AcceptQueueDrops uint64
}

const perSourceSYNLimit = 10     // max SYNs per source per second
const maxPerSrcSYNEntries = 4096 // max tracked source entries (M9 fix)

type srcSYNBucket struct {
	tokens   int
	lastFill time.Time
}

func (c *Config) keepaliveInterval() time.Duration {
	if c.KeepaliveInterval > 0 {
		return c.KeepaliveInterval
	}
	return DefaultKeepaliveInterval
}

func (c *Config) idleTimeout() time.Duration {
	if c.IdleTimeout > 0 {
		return c.IdleTimeout
	}
	return DefaultIdleTimeout
}

func (c *Config) synRateLimit() int {
	if c.SYNRateLimit > 0 {
		return c.SYNRateLimit
	}
	return DefaultSYNRateLimit
}

func (c *Config) maxConnectionsPerPort() int {
	if c.MaxConnectionsPerPort > 0 {
		return c.MaxConnectionsPerPort
	}
	return DefaultMaxConnectionsPerPort
}

func (c *Config) maxTotalConnections() int {
	if c.MaxTotalConnections > 0 {
		return c.MaxTotalConnections
	}
	return DefaultMaxTotalConnections
}

func (c *Config) timeWaitDuration() time.Duration {
	if c.TimeWaitDuration > 0 {
		return c.TimeWaitDuration
	}
	return DefaultTimeWaitDuration
}

func New(cfg Config) *Daemon {
	d := &Daemon{
		config:          cfg,
		tunnels:         NewTunnelManager(),
		ports:           NewPortManager(),
		stopCh:          make(chan struct{}),
		synTokens:       cfg.synRateLimit(),
		synLastFill:     time.Now(),
		perSrcSYN:       make(map[uint32]*srcSYNBucket),
		epCache:         make(map[uint32]*endpointEntry),
		resolveCache:    make(map[uint32]*resolveEntry),
		hostnameCache:   make(map[string]*hostnameCacheEntry),
		netPolicies:     make(map[uint16][]uint16),
		lastGaveUpReset: make(map[uint32]time.Time),
		managed:         make(map[uint16]*ManagedEngine),
		memberTags:      make(map[uint16][]string),
	}
	d.ctx, d.cancelCtx = context.WithCancel(context.Background())
	d.bus = newInProcessBus(d.NodeID)
	// Event-driven T2 recovery: reset a peer's path the moment the rekey
	// machinery gives up on it (see onRekeyGaveUp / pathwatch.go).
	d.tunnels.SetRekeyGaveUpHook(d.onRekeyGaveUp)
	d.tunnels.SetTrustGate(d.admitDataPlanePeer)
	d.tunnels.SetPeerTrustFn(d.isTrustedPeer)
	d.ipc = NewIPCServer(cfg.SocketPath, d)
	// HandshakeService is wired post-construction by the composition
	// root via RegisterHandshakeService (T3.3 — handshake plugin moved
	// to plugins/handshake). Tests that don't register the plugin will
	// see d.handshakes == nil; the trust-gate / IPC paths guard against
	// that.
	return d
}

// allowSYN returns true if a SYN should be accepted under the rate limit.
// Uses a simple token bucket: refills at SYNRateLimit tokens/second.
func (d *Daemon) allowSYN() bool {
	d.synMu.Lock()
	defer d.synMu.Unlock()

	limit := d.config.synRateLimit()
	now := time.Now()
	elapsed := now.Sub(d.synLastFill)
	if elapsed > 0 {
		refill := int(elapsed.Seconds() * float64(limit))
		if refill > 0 {
			d.synTokens += refill
			if d.synTokens > limit {
				d.synTokens = limit
			}
			d.synLastFill = now
		}
	}

	if d.synTokens > 0 {
		d.synTokens--
		return true
	}
	return false
}

// allowSYNFromSource checks per-source SYN rate limit (10 SYNs/source/second).
func (d *Daemon) allowSYNFromSource(srcNode uint32) bool {
	d.perSrcSYNMu.Lock()
	defer d.perSrcSYNMu.Unlock()

	b, ok := d.perSrcSYN[srcNode]
	now := time.Now()
	if !ok {
		// Cap the map size to prevent unbounded growth (M9 fix)
		if len(d.perSrcSYN) >= maxPerSrcSYNEntries {
			return false // reject when map is full
		}
		d.perSrcSYN[srcNode] = &srcSYNBucket{tokens: perSourceSYNLimit - 1, lastFill: now}
		return true
	}

	elapsed := now.Sub(b.lastFill)
	if elapsed > 0 {
		refill := int(elapsed.Seconds() * float64(perSourceSYNLimit))
		if refill > 0 {
			b.tokens += refill
			if b.tokens > perSourceSYNLimit {
				b.tokens = perSourceSYNLimit
			}
			b.lastFill = now
		}
	}

	if b.tokens > 0 {
		b.tokens--
		return true
	}
	return false
}

// reapPerSrcSYN removes stale per-source SYN buckets.
func (d *Daemon) reapPerSrcSYN() {
	d.perSrcSYNMu.Lock()
	defer d.perSrcSYNMu.Unlock()
	threshold := time.Now().Add(-SYNBucketAge)
	for id, b := range d.perSrcSYN {
		if b.lastFill.Before(threshold) {
			delete(d.perSrcSYN, id)
		}
	}
}

// SetSYNWhitelist replaces the trusted-source whitelist for SYN rate
// limits (PILOT-343). Nodes in the set bypass BOTH allowSYN() and
// allowSYNFromSource(). Empty slice clears the whitelist. Safe to
// call at any time — the underlying field is an atomic.Pointer.
func (d *Daemon) SetSYNWhitelist(nodeIDs []uint32) {
	m := make(map[uint32]struct{}, len(nodeIDs))
	for _, id := range nodeIDs {
		if id == 0 {
			continue
		}
		m[id] = struct{}{}
	}
	d.synWhitelist.Store(&m)
}

// SetSYNWhitelistMatchAll toggles SYN wildcard mode (PILOT-343). When
// true, every source bypasses both SYN gates regardless of the
// SetSYNWhitelist contents. Use on service-agent boxes that should
// accept all callers without SYN-rate limiting.
func (d *Daemon) SetSYNWhitelistMatchAll(on bool) {
	d.synWhitelistAll.Store(on)
}

// SetReplyWhitelistMatchAll proxies to the embedded keyexchange.Manager
// (PILOT-344 wildcard).
func (d *Daemon) SetReplyWhitelistMatchAll(on bool) {
	if d.tunnels != nil {
		d.tunnels.SetReplyWhitelistMatchAll(on)
	}
}

// SetRekeyWhitelistMatchAll proxies to the TunnelManager (PILOT-345
// wildcard).
func (d *Daemon) SetRekeyWhitelistMatchAll(on bool) {
	if d.tunnels != nil {
		d.tunnels.SetRekeyWhitelistMatchAll(on)
	}
}

// SetReplyWhitelist proxies to the embedded keyexchange.Manager (PILOT-344).
// Trusted peers bypass the 1-second asymmetric-recovery reply gate.
func (d *Daemon) SetReplyWhitelist(nodeIDs []uint32) {
	if d.tunnels != nil {
		d.tunnels.SetReplyWhitelist(nodeIDs)
	}
}

// SetRekeyWhitelist proxies to the TunnelManager (PILOT-345). Trusted
// peers bypass the 3-second rekey-request interval and the 4096
// requester-map cap.
func (d *Daemon) SetRekeyWhitelist(nodeIDs []uint32) {
	if d.tunnels != nil {
		d.tunnels.SetRekeyWhitelist(nodeIDs)
	}
}

func (d *Daemon) Start() error {
	// Stamp startTime before any background goroutine launches — the rx
	// watchdog reads it from its own goroutine for the min-uptime guard,
	// and the historical assignment at the bottom of Start left a window
	// where a loop could read the zero value.
	d.startTime = time.Now()

	// Warm the hostname cache from disk before the IPC server comes up,
	// so the first send-message after restart hits the cache instead of
	// pounding regConn for a fresh resolve_hostname.
	d.loadHostnameCache()

	// 0. Resolve identity first (needed if we have to synthesise an email
	// from the public-key fingerprint when no email is provided).
	if d.config.IdentityPath != "" {
		id, err := crypto.LoadIdentity(d.config.IdentityPath)
		if err != nil {
			return fmt.Errorf("load identity: %w", err)
		}
		if id != nil {
			d.identity = id
			slog.Info("loaded identity", "path", d.config.IdentityPath)
		}
	}
	if d.identity == nil {
		id, err := crypto.GenerateIdentity()
		if err != nil {
			return fmt.Errorf("generate identity: %w", err)
		}
		d.identity = id
		if d.config.IdentityPath != "" {
			if err := crypto.SaveIdentity(d.config.IdentityPath, d.identity); err != nil {
				slog.Warn("failed to save identity", "error", err)
			} else {
				slog.Info("saved identity", "path", d.config.IdentityPath)
			}
		}
	}

	// 0b. Resolve email: flag > owner (deprecated) > account file > synthesise
	// from the public-key fingerprint. Email is required as a stable identifier
	// the registry can use; if the user didn't provide one, default to a
	// synthetic <fingerprint>@nodes.pilotprotocol.network. The synthetic email
	// is unambiguously not a real person — the registry treats it as a local
	// node with no public contact, and the user can later override it via
	// `pilotctl set-email <addr>` to opt into Network 9 / public directory.
	email := d.config.Email
	if email == "" && d.config.Owner != "" {
		email = d.config.Owner
	}
	if email == "" && d.config.IdentityPath != "" {
		acctPath := account.PathFromIdentity(d.config.IdentityPath)
		if acct, err := account.Load(acctPath); err == nil && acct != nil {
			email = acct.Email
			slog.Info("loaded email from account file", "path", acctPath)
		}
	}
	synthesised := false
	if email == "" {
		// Derive 12 hex chars from the first 6 bytes of the Ed25519 public key.
		// Stable per-identity, locally derivable, no PII.
		fp := hex.EncodeToString(d.identity.PublicKey[:6])
		email = fp + "@nodes.pilotprotocol.network"
		synthesised = true
		slog.Info("no email provided; using synthetic identity-derived email",
			"email", email,
			"hint", "set a real email later via `pilotctl set-email <addr>` to opt into Network 9 / public directory")
	}
	if err := validate.Email(email); err != nil {
		return fmt.Errorf("invalid email: %w", err)
	}
	d.config.Email = email
	d.config.Owner = email // keep Owner in sync for registry and DaemonInfo

	// Persist email to account file (if identity path is set). For synthetic
	// emails we still persist so subsequent daemon starts produce a stable
	// identity rather than a fresh fingerprint each boot.
	if d.config.IdentityPath != "" {
		acctPath := account.PathFromIdentity(d.config.IdentityPath)
		if err := account.Save(acctPath, &account.Account{Email: email}); err != nil {
			slog.Warn("failed to save account file", "error", err)
		}
	}
	_ = synthesised // reserved for future log/metric tagging

	// 0b. Auto-detect transport mode. PILOT_TRANSPORT env var lets the
	// operator force a mode at install time. When nothing is set (or
	// TransportMode is "auto"), probe UDP reachability to the beacon; on
	// UDP-blocked hosts that can reach the compat beacon over TCP the
	// daemon auto-falls back to compat (WSS/443) so it can reach peers
	// without a manual restart. cmd/daemon resolves -transport=auto itself
	// (it also switches the registry for compat); this path serves
	// embedders that leave TransportMode empty.
	if envTransport := os.Getenv("PILOT_TRANSPORT"); envTransport != "" && d.config.TransportMode == "" {
		switch envTransport {
		case TransportUDP, TransportCompat:
			d.config.TransportMode = envTransport
			slog.Info("transport set from PILOT_TRANSPORT env", "mode", envTransport)
		case TransportAuto:
		default:
			slog.Warn("ignoring unknown PILOT_TRANSPORT value", "value", envTransport, "valid", "udp, compat, auto")
		}
	}
	if d.config.TransportMode == TransportAuto {
		d.config.TransportMode = ""
	}
	if d.config.TransportMode == "" {
		stunBeacon := firstBeacon(d.config.BeaconAddr)
		switch {
		case stunBeacon == "":
			// No beacon to probe — leave transport on the UDP default.
		case d.config.CompatBeaconURL == "":
			if !probeUDPReachable(stunBeacon) {
				// UDP looks blocked but we have no compat beacon to fall
				// back to. Switching to compat would strand the daemon, so
				// stay on UDP and warn the operator to configure compat.
				slog.Warn("UDP probe to beacon failed but no compat beacon configured — staying on UDP",
					"beacon", stunBeacon,
					"hint", "set -compat-beacon and PILOT_TRANSPORT=compat to use WSS/443")
			}
		default:
			// Compat would use the environment's proxy (-proxy=auto)
			// unless the embedder set a policy; check reachability the
			// same way.
			policy := d.proxyPolicy()
			if policy == nil {
				if p, err := ResolveProxy(proxyAutoSpec, TransportCompat); err == nil {
					policy = StaticProxyPolicy(p)
				} else {
					slog.Warn("proxy environment unusable; compat check dials directly", "error", err)
				}
			}
			mode, reason := SelectTransport(context.Background(), AutoTransportProbe{
				BeaconAddr:      stunBeacon,
				CompatBeaconURL: d.config.CompatBeaconURL,
				Dial:            d.dialerFor(policy),
			})
			if mode == TransportCompat {
				d.config.TransportMode = TransportCompat
				if d.config.ProxyPolicy == nil && d.config.Proxy == nil {
					d.config.ProxyPolicy = policy
				}
				slog.Warn("UDP probe to beacon failed — auto-falling back to compat mode (WSS/443)",
					"beacon", stunBeacon,
					"compat_beacon", d.config.CompatBeaconURL,
					"reason", reason,
					"hint", "set PILOT_TRANSPORT=udp to force UDP")
			} else {
				slog.Info("transport auto-selected", "transport", TransportUDP, "reason", reason)
			}
		}
	}

	// 1. Discover our public endpoint via beacon using a temporary UDP socket.
	// If -endpoint is set, skip STUN and use the fixed address (for cloud VMs).
	// In compat mode (TransportMode=compat) we skip STUN entirely — the
	// daemon doesn't bind a public UDP socket, so endpoint discovery is
	// meaningless. The daemon registers with a placeholder addr and
	// relay_only=true; peers reach it through the beacon's WSS bridge.
	// Reject unknown -transport values up front rather than silently
	// falling through to UDP. Empty string is allowed (means "udp",
	// preserving zero-Config callers).
	switch d.config.TransportMode {
	case "", "udp", "compat":
		// ok
	default:
		return fmt.Errorf("invalid -transport %q: must be 'udp' or 'compat'", d.config.TransportMode)
	}

	// A command-backed proxy policy (rotating proxy credentials) stays
	// current for the daemon's lifetime: registry redials, WSS reconnects
	// and HTTP fetches always see the latest proxy URL.
	d.startProxyRefresh()

	var registrationAddr string
	if d.config.TransportMode == "compat" {
		registrationAddr = "0.0.0.0:0" // placeholder — relay_only daemons hide this from peers
		d.config.RelayOnly = true
		slog.Info("compat mode enabled — skipping STUN; will dial WSS beacon after register",
			"compat_beacon", d.config.CompatBeaconURL,
			"tls_trust", d.config.CompatTLSTrust)
		if d.config.BeaconRTTProbe {
			slog.Info("compat mode: -beacon-rtt-probe disabled (its raw UDP probes cannot leave a UDP-blocked host)")
		}
	} else if d.config.Endpoint != "" {
		registrationAddr = d.config.Endpoint
		slog.Info("using fixed endpoint", "endpoint", registrationAddr)
	} else {
		registrationAddr = resolveLocalAddr(d.config.ListenAddr)
		// Identity isn't loaded yet; STUN reflection is identical regardless
		// of which beacon we hit, so use the first entry of the parsed list.
		// Once identity is loaded later, the post-registration beacon set
		// uses hash-of-pubkey for sticky load distribution across the mesh.
		stunBeacon := firstBeacon(d.config.BeaconAddr)
		if stunBeacon != "" {
			pubAddr, err := discoverWithTempSocket(stunBeacon, d.config.ListenAddr)
			if err != nil {
				slog.Warn("beacon discover failed, using local addr", "error", err)
			} else if isPrivateAddr(pubAddr) {
				slog.Warn("STUN returned private/unusable IP, discarding", "stun_addr", pubAddr)
			} else {
				registrationAddr = pubAddr
				slog.Debug("discovered public endpoint", "endpoint", pubAddr)
			}
		}
	}

	// 1b. Override discovered endpoint for environments where STUN
	// returns an unreachable address (e.g. k8s pods behind CNI — STUN
	// returns the worker node's external IP, which is unreachable
	// from other pods in the same cluster). -advertise-endpoint lets
	// the deployment YAML set the pod's cluster-IP:hostPort so peers
	// route through the correct intra-cluster address.
	if d.config.AdvertiseEndpoint != "" {
		registrationAddr = d.config.AdvertiseEndpoint
		slog.Info("overriding STUN-discovered endpoint with -advertise-endpoint",
			"advertised", registrationAddr)
	}

	// 2. Enable tunnel encryption if configured
	if d.config.Encrypt {
		if err := d.tunnels.EnableEncryption(); err != nil {
			return fmt.Errorf("tunnel encryption: %w", err)
		}
	} else {
		slog.Warn("tunnel encryption is disabled — all connections will send plaintext")
	}

	// 2b. Wire the event bus into the tunnel layer BEFORE starting the
	// UDP listener. The readLoop spawned by Listen() reads tm.bus from
	// every recoverLayer call site; if SetEventBus runs after Listen,
	// the bus pointer write races with those reads (issue #99 surfaced
	// the race under §4.8 stress with -race). d.bus is constructed in
	// New() so it's safe to publish here.
	d.tunnels.SetEventBus(d.bus)

	// 3. Start UDP listener for tunnel traffic. Compat-mode daemons
	// skip this — the WSS transport is dialed after register, once we
	// know our node ID for the auth challenge.
	var actualAddr string
	if d.config.TransportMode == "compat" {
		actualAddr = "0.0.0.0:0" // synthetic; no real local socket bound
		d.lanAddrs = nil         // no LAN advertisement for compat daemons
	} else {
		if err := d.tunnels.Listen(d.config.ListenAddr); err != nil {
			return fmt.Errorf("tunnel listen: %w", err)
		}
		actualAddr = d.tunnels.LocalAddr().String()
		slog.Info("tunnel listening", "addr", actualAddr)

		// Warn when the tunnel bound to a wildcard address — reachable
		// from any network interface that can route to this host.
		// Pass -listen 127.0.0.1:0 to restrict to localhost only.
		if host, _, hostErr := net.SplitHostPort(actualAddr); hostErr == nil && (host == "0.0.0.0" || host == "::") {
			slog.Warn("tunnel bound to wildcard address",
				"addr", actualAddr,
				"hint", "pass -listen 127.0.0.1:0 to restrict to localhost; see -endpoint for fixed public IP")
		}

		// Collect LAN addresses using the actual tunnel port (not config port which may be 0)
		_, actualPort, _ := net.SplitHostPort(actualAddr)
		if actualPort == "" || actualPort == "0" {
			actualPort = "4000"
		}
		d.lanAddrs = collectLANAddrs(actualPort)
	}

	// If STUN discovered a public endpoint, keep it. The temp socket and
	// tunnel socket bind the same local port, so endpoint-independent NAT
	// (like Cloud NAT) maps them to the same external IP:port.
	// Only fall back to the local address if STUN didn't run or failed.
	// In compat mode the placeholder registrationAddr ("0.0.0.0:0") is
	// intentional — we never reveal a UDP endpoint — so skip this fix-up.
	if d.config.TransportMode != "compat" {
		stunHost, _, splitErr := net.SplitHostPort(registrationAddr)
		isLocalAddr := splitErr != nil || stunHost == "" || stunHost == "127.0.0.1" || stunHost == "::1" || stunHost == "0.0.0.0" || stunHost == "::"
		if isLocalAddr {
			registrationAddr = resolveLocalAddr(actualAddr)
		}
	}

	// 3. Identity is already loaded/generated at the top of Start (step 0)
	//    so the synthetic email could be derived from the public key. Nothing
	//    to do here.

	// 4. Register with the registry (always with client-generated key).
	rc, err := d.dialRegistryClient()
	if err != nil {
		return err
	}
	d.regConn.Store(rc)

	pubKeyB64 := crypto.EncodePublicKey(d.identity.PublicKey)
	resp, err := rc.RegisterWithKeyOpts(registry.RegisterOpts{
		ListenAddr: registrationAddr,
		PublicKey:  pubKeyB64,
		Owner:      d.config.Owner,
		LANAddrs:   d.lanAddrs,
		Version:    d.config.Version,
		RelayOnly:  d.config.RelayOnly, // task 32 — hide real_addr from peers
	})
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}

	// Use registry-observed IP as fallback when STUN returned garbage
	if observed, ok := resp["observed_addr"].(string); ok && observed != "" {
		obsHost, _, _ := net.SplitHostPort(observed)
		obsIP := net.ParseIP(obsHost)
		if obsIP != nil && !obsIP.IsPrivate() && !obsIP.IsLoopback() && !obsIP.IsLinkLocalUnicast() {
			regHost, _, _ := net.SplitHostPort(registrationAddr)
			regIP := net.ParseIP(regHost)
			if regIP == nil || regIP.IsPrivate() || regIP.IsLoopback() || regIP.IsLinkLocalUnicast() {
				_, stunPort, _ := net.SplitHostPort(registrationAddr)
				registrationAddr = net.JoinHostPort(obsHost, stunPort)
				slog.Info("using registry-observed IP", "observed", obsHost)
			}
		}
	}

	nodeIDVal, ok := resp["node_id"].(float64)
	if !ok {
		return fmt.Errorf("register: missing node_id in response")
	}
	d.nodeID = uint32(nodeIDVal)
	addrStr, ok := resp["address"].(string)
	if !ok {
		return fmt.Errorf("register: missing address in response")
	}
	parsedAddr, err := protocol.ParseAddr(addrStr)
	if err != nil {
		return fmt.Errorf("register: invalid address %q: %w", addrStr, err)
	}
	d.addr = parsedAddr
	d.tunnels.SetNodeID(d.nodeID)

	// Set identity on tunnel manager for authenticated key exchange
	if d.identity != nil {
		d.tunnels.SetIdentity(d.identity)
		d.tunnels.SetPeerVerifyFunc(d.lookupPeerPubKey)
	}

	// Compat mode: now that we have the node ID, dial the beacon over
	// WSS and install that as the tunnel transport. The readLoop and
	// keepalive loop start inside ConnectCompat, mirroring what
	// Listen() does for UDP. See docs/SPEC-compat-mode.md.
	if d.config.TransportMode == "compat" {
		tlsCfg, terr := buildCompatTLSConfig(d.config.CompatTLSTrust)
		if terr != nil {
			return fmt.Errorf("compat tls config: %w", terr)
		}
		if tlsCfg.RootCAs == nil {
			tlsCfg.RootCAs = d.config.systemRoots // "system" trust; nil = OS store
		}
		ccCtx, ccCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer ccCancel()
		if cerr := d.tunnels.ConnectCompat(ccCtx, ConnectCompatConfig{
			BeaconURL:   d.config.CompatBeaconURL,
			TLSConfig:   tlsCfg,
			DialContext: d.proxyDialer(),
			Identity:    d.identity,
			NodeID:      d.nodeID,
		}); cerr != nil {
			if hint := tlsTrustHint(cerr, "beacon"); hint != "" && d.config.CompatTLSTrust == "system" {
				return fmt.Errorf("compat connect: %w; %s", cerr, hint)
			}
			return fmt.Errorf("compat connect: %w", cerr)
		}
		slog.Info("compat mode tunnel up",
			"node_id", d.nodeID,
			"beacon", d.config.CompatBeaconURL)
	}

	// Stash the registration endpoint for Info() readers — used by tests
	// and operators to confirm beacon discover round-trip succeeded.
	d.addrMu.Lock()
	d.publicEndpoint = registrationAddr
	d.addrMu.Unlock()

	slog.Info("daemon registered", "node_id", d.nodeID, "addr", d.addr, "endpoint", registrationAddr)
	d.lastRegistryOKNano.Store(time.Now().UnixNano())

	// T4.1: webhook is now a bus subscriber owned by plugins/webhook.
	// cmd/daemon (composition root) constructs the plugin and starts
	// it via plugins/runtime.StartPlugins AFTER Daemon.Start returns.
	// All d.webhook.Emit sites have been migrated to d.publishEvent.
	// (SetEventBus moved earlier — see step 2b above. Issue #99: read/write
	// race against the tunnel readLoop with `-race` under §4.8.)
	// T4.3: daemon-internal reaction to network.* events (managed
	// engines + member-tag cache). Must wire BEFORE the first
	// reconcileMembership tick so the inaugural delta is observed.
	d.subscribeNetworkInternalToBus()
	d.publishEvent("node.registered", map[string]interface{}{
		"address":  d.addr.String(),
		"endpoint": registrationAddr,
	})
	d.publishEvent("agent.registered", map[string]interface{}{
		"address":  d.addr.String(),
		"endpoint": registrationAddr,
		"node_id":  d.nodeID,
	})

	// Register with beacon using real nodeID for NAT traversal (punch/relay).
	//
	// Multi-beacon support (back-compat): -beacon may be a single addr
	// (current behavior) OR a comma-separated list. With a list, hash the
	// daemon's identity public key to pick ONE beacon stably. The relay
	// path uses a single beaconAddr; the beacon-mesh Tier 2 forwarding
	// transparently routes to whichever beacon owns the destination node.
	if d.config.BeaconAddr != "" {
		beaconList := parseBeaconList(d.config.BeaconAddr)
		// Initialize the beaconSelection state so the refresh loop has
		// something to merge against from tick #0.
		d.beaconSelection = newBeaconSelectionState(beaconList)
		var picked string
		if d.identity != nil {
			picked = pickBeacon(beaconList, d.identity.PublicKey)
		} else if len(beaconList) > 0 {
			// Defensive: if identity is somehow nil here, fall through to
			// the first beacon. Should never happen in normal startup.
			picked = beaconList[0]
		}
		if picked != "" {
			if err := d.tunnels.SetBeaconAddr(picked); err != nil {
				slog.Warn("failed to set beacon addr", "error", err, "picked", picked)
			} else {
				if len(beaconList) > 1 {
					slog.Info("beacon selected from multi-beacon list",
						"picked", picked,
						"available", len(beaconList))
				}
				// Record the initial pick into selection state so the
				// refresh loop's swap-detection sees the right baseline.
				d.beaconSelection.ApplyRefreshDecision(refreshDecision{
					NewList:    beaconList,
					NewPick:    picked,
					ShouldSwap: true,
				})
				d.tunnels.RegisterWithBeacon()
			}
		}
	}

	// Set node visibility
	if d.config.Public {
		if _, err := d.reg().SetVisibility(d.nodeID, true); err != nil {
			slog.Warn("failed to set public visibility", "error", err)
		} else {
			slog.Info("node visibility set", "visibility", "public")
		}
	}

	// Set hostname if configured
	if d.config.Hostname != "" {
		if _, err := d.reg().SetHostname(d.nodeID, d.config.Hostname); err != nil {
			slog.Warn("failed to set hostname", "hostname", d.config.Hostname, "error", err)
		} else {
			slog.Info("hostname set", "hostname", d.config.Hostname)
		}
	}

	// Auto-join configured networks
	d.autoJoinNetworks()

	// Load cached network snapshot (bootstraps port policies / member tags from disk)
	d.loadNetworkSnapshot()

	// Cache network port policies for SYN enforcement (overwrites snapshot with live data)
	d.loadNetworkPolicies()

	// Load expr-based policy runners for joined networks
	if !d.config.DisablePolicyRunner {
		d.loadPolicyRunners()
	}

	// Detect managed networks and start engines
	d.startManaged()

	// 4. Start IPC server
	if err := d.ipc.Start(); err != nil {
		return fmt.Errorf("ipc start: %w", err)
	}

	// 5. Handshake service (port 444) is started by the handshake plugin
	// via plugins/runtime.StartPlugins after Daemon.Start completes.
	// See cmd/daemon/main.go for the registration glue.

	// 6. Start built-in services (echo, dataexchange, eventstream)
	d.startBuiltinServices()

	// 7. Start packet router
	d.bgWG.Add(1)
	go func() { defer d.bgWG.Done(); d.routeLoop() }()

	// 8. Start heartbeat — split per layer (T4.3, P9/P10):
	//    - trustRepublishLoop          (L5/L8): registry heartbeat + reregister
	//    - tunnelKeepaliveLoop         (L4):    beacon NAT-mapping refresh
	//    - handshakePollLoop           (L11):   relayed-handshake polling
	//    - observabilityHeartbeatLoop  (L11):   agent.heartbeat bus publish
	d.bgWG.Add(1)
	go func() { defer d.bgWG.Done(); d.trustRepublishLoop() }()
	d.bgWG.Add(1)
	go func() { defer d.bgWG.Done(); d.tunnelKeepaliveLoop() }()
	d.bgWG.Add(1)
	go func() { defer d.bgWG.Done(); d.handshakePollLoop() }()
	d.bgWG.Add(1)
	go func() { defer d.bgWG.Done(); d.observabilityHeartbeatLoop() }()

	// 8b. Start inbound-path watchdog (L4). Detects the "transmitting into
	// a dead NAT mapping" wedge and recovers — see rxwatchdog.go.
	d.bgWG.Add(1)
	go func() { defer d.bgWG.Done(); d.rxWatchdogLoop() }()

	// 8c. Start per-peer path watchdog (L4). Detects a single peer's
	// NAT/relay mapping dying while others stay healthy and resets that
	// peer's path in place — see pathwatch.go.
	d.bgWG.Add(1)
	go func() { defer d.bgWG.Done(); d.pathWatchLoop() }()

	// 9. Start idle connection sweeper
	d.bgWG.Add(1)
	go func() { defer d.bgWG.Done(); d.idleSweepLoop() }()

	// 10. Start relay→direct fallback probe (checks every 5 min)
	d.bgWG.Add(1)
	go func() { defer d.bgWG.Done(); d.relayProbeLoop() }()

	// 11. Start network sync (refreshes memberships/policies every 5 min)
	d.bgWG.Add(1)
	go func() { defer d.bgWG.Done(); d.networkSyncLoop() }()

	// 12. Start beacon discovery refresh loop. Refreshes the beacon list
	// from the registry every 60s ± jitter so MIG autoscale events
	// (instances added/removed) propagate to the daemon's pick within a
	// minute. Bootstrap-only daemons (-beacon HOST:PORT, no comma) still
	// benefit: if the registry knows about additional beacons, this
	// daemon will discover them and may migrate to a different one if
	// hash-pick lands on a fresher beacon.
	d.bgWG.Add(1)
	go func() { defer d.bgWG.Done(); d.beaconRefreshLoop() }()

	// 13. Start periodic hostname re-announcement. Pilot rendezvous
	// servers (including the canary registry) keep the hostname store
	// purely in-memory; a server restart/roll wipes it. Without
	// periodic re-announce, daemons that set their hostname once at
	// startup become unresolvable by hostname until they restart.
	// Re-announcing every ~60 s (the same cadence as beacon refresh)
	// ensures self-healing within one interval after a registry roll.
	d.bgWG.Add(1)
	go func() { defer d.bgWG.Done(); d.hostnameReannounceLoop() }()

	// 14. Start message-of-the-day poll loop. Fetches the MOTD feed on an
	// interval and mirrors today's (UTC) entry to ~/.pilot/motd.json so
	// pilotctl can render the banner without any network or IPC call. The
	// loop returns immediately (cheap no-op goroutine) when no feed URL is
	// configured. This is the ONLY component that fetches the MOTD feed.
	d.bgWG.Add(1)
	go func() { defer d.bgWG.Done(); d.motdPollLoop() }()

	// 12b. Earlier rc2-dev iterations pre-warmed trusted peers at
	// startup. Two variants were tried and both made things worse:
	//
	//   (1) sendKeyExchangeToNode for each peer → rekey storm. Every
	//       call marked pendingRekey; the retransmit loop pounded all
	//       peers simultaneously; each peer's reply was interpreted as
	//       a fresh key-exchange request that rotated session keys
	//       mid-flight. Pings worked for a few seconds then dial
	//       timed out for minutes.
	//
	//   (2) ensureTunnel only (no key exchange) → NAT-punch wave.
	//       ensureTunnel still issues a punch via beacon for non-
	//       relay-only peers, and the dial path that owns the punch
	//       takes 7-15s per peer to time out and flip to relay. With
	//       7 peers in a 1.4s burst, the daemon was busy doing
	//       dial-fail-over for ~70s after start. User pings during
	//       that window collided with the prewarm activity.
	//
	// Neither variant survives contact with a fleet that has many
	// trusted peers. Lazy-on-first-use is the right behavior: pay the
	// 600ms cold cost on the first send-message and let warm cache
	// handle everything after.
	//
	// Latency wins kept (independent of prewarm):
	//   - DialInitialRTO 1s → 250ms
	//   - hostname cache (in-memory + disk-persisted)
	//   - fetchMembers exponential backoff
	//   - resolve cache pre-warm via the resolve_hostname IPC handler
	//     (warms ONLY the peer the user just asked about, not the
	//     entire trust list)

	// 13/14. L11 plugin lifecycle (trustedagents, skillinject,
	// dataexchange, eventstream, tasks, policy) is owned by
	// plugins/runtime — cmd/daemon (composition root) calls
	// runtime.StartPlugins(ctx) AFTER this Start returns. This
	// inversion is T7.1: pkg/daemon no longer imports pkg/coreapi.

	slog.Info("daemon running", "node_id", d.nodeID, "addr", d.addr)
	return nil
}

// udpProbeTimeout bounds how long probeUDPReachable waits for evidence
// that UDP works end-to-end. It must cover at least one beacon round trip
// on a healthy-but-slow link; 1.5s comfortably exceeds typical relay RTT
// (<200ms) plus jitter while keeping cold-start fast.
const udpProbeTimeout = 1500 * time.Millisecond

// probeUDPReachable reports whether UDP works end-to-end to the beacon.
//
// It sends a real BeaconMsgDiscover and requires a valid BeaconMsgDiscover-
// Reply within udpProbeTimeout. Reachability is asserted ONLY on positive
// evidence (a reply). Absence of any reply within the window — the signature
// of a silently-dropped/blackholed UDP path, the most common UDP-blocked
// corporate case, which sends no ICMP reject — is treated as NOT reachable
// so the caller can auto-switch to compat (WSS/443).
//
// This avoids false-positives on quiet-but-working links: the beacon always
// answers a discover on a functioning UDP path (it is the same cold-start
// STUN exchange the daemon already depends on to learn its public endpoint),
// so a healthy link produces a reply well inside the window. A merely idle
// link is irrelevant here — we actively solicit a reply rather than waiting
// for unsolicited traffic. Any error (socket creation refused, hard ICMP
// reject, or timeout with no reply) yields false.
func probeUDPReachable(beaconAddr string) bool {
	if _, _, err := net.SplitHostPort(beaconAddr); err != nil {
		return false
	}
	// nodeID 0 is fine — the beacon's reply depends only on our UDP
	// source address, not the payload nodeID.
	_, err := routing.ProbeBeaconRTT(beaconAddr, 0, udpProbeTimeout)
	return err == nil
}

// discoverWithTempSocket does STUN discovery on a temporary UDP socket
// bound to the same port, then closes it so the tunnel can bind.
func discoverWithTempSocket(beaconAddr, listenAddr string) (string, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return "", err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return "", fmt.Errorf("temp listen: %w", err)
	}
	defer conn.Close()

	pub, err := DiscoverEndpoint(beaconAddr, 0, conn)
	if err != nil {
		return "", err
	}
	return pub.String(), nil
}

// isPrivateAddr returns true if the host part of addr is a private, loopback,
// or link-local IP — i.e., not routable on the public internet.
func isPrivateAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast())
}

// collectLANAddrs returns all non-loopback private IPv4 addresses with the
// given port appended (e.g., ["192.168.4.76:4000", "10.0.1.5:4000"]).
func collectLANAddrs(listenPort string) []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var addrs []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		ifAddrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range ifAddrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.To4() == nil {
				continue // skip IPv6 and nil
			}
			if ip.IsLoopback() {
				continue
			}
			if ip.IsPrivate() || ip.IsLinkLocalUnicast() {
				addrs = append(addrs, net.JoinHostPort(ip.String(), listenPort))
			}
		}
	}
	return addrs
}

// matchLANSubnet checks if any of our LAN IPs share a /24 subnet with any peer LAN IP.
// Returns the matching peer LAN address, or empty string if no match.
func matchLANSubnet(ours []string, theirs []interface{}) string {
	for _, theirRaw := range theirs {
		theirAddr, ok := theirRaw.(string)
		if !ok {
			continue
		}
		theirHost, _, err := net.SplitHostPort(theirAddr)
		if err != nil {
			continue
		}
		theirIP := net.ParseIP(theirHost)
		if theirIP == nil || theirIP.To4() == nil {
			continue
		}

		for _, ourAddr := range ours {
			ourHost, _, err := net.SplitHostPort(ourAddr)
			if err != nil {
				continue
			}
			ourIP := net.ParseIP(ourHost)
			if ourIP == nil || ourIP.To4() == nil {
				continue
			}

			// Same /24 subnet
			ourNet := ourIP.To4().Mask(net.CIDRMask(24, 32))
			theirNet := theirIP.To4().Mask(net.CIDRMask(24, 32))
			if ourNet.Equal(theirNet) {
				return theirAddr
			}
		}
	}
	return ""
}

// addrFamilyMismatch returns true if addr is a different IP family than the tunnel socket.
// For example, returns true if the tunnel is bound to IPv6 but addr is IPv4 (or vice versa).
func (d *Daemon) addrFamilyMismatch(addr string) bool {
	local := d.tunnels.LocalAddr()
	if local == nil {
		return false
	}
	localHost, _, err := net.SplitHostPort(local.String())
	if err != nil {
		return false
	}
	remoteHost, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	localIP := net.ParseIP(localHost)
	remoteIP := net.ParseIP(remoteHost)
	if localIP == nil || remoteIP == nil {
		return false
	}
	// Wildcard addresses (:: or 0.0.0.0) are dual-stack — they accept both families.
	if localIP.IsUnspecified() {
		return false
	}
	localIs4 := localIP.To4() != nil
	remoteIs4 := remoteIP.To4() != nil
	return localIs4 != remoteIs4
}

// autoJoinNetworks joins the networks listed in Config.Networks at startup.
// Requires AdminToken. Errors are logged but do not prevent daemon startup.
func (d *Daemon) autoJoinNetworks() {
	if d.config.AdminToken == "" || len(d.config.Networks) == 0 {
		return
	}
	for _, netID := range d.config.Networks {
		_, err := d.reg().JoinNetwork(d.nodeID, netID, "", 0, d.config.AdminToken)
		if err != nil {
			slog.Warn("auto-join failed", "network_id", netID, "error", err)
			continue
		}
		slog.Info("auto-joined network", "network_id", netID)
		d.publishEvent("network.auto_joined", map[string]interface{}{"network_id": netID})
	}
}

// stopping returns true if Stop() has been called.
func (d *Daemon) stopping() bool {
	select {
	case <-d.stopCh:
		return true
	default:
		return false
	}
}

func (d *Daemon) Stop() error {
	// Idempotent: only the first caller runs shutdown; others wait and return nil.
	d.stopOnce.Do(func() {
		close(d.stopCh)
		if d.cancelCtx != nil {
			d.cancelCtx()
		}
		d.doStop()
	})
	return nil
}

func (d *Daemon) doStop() {
	// Wait for all daemon-scoped background goroutines to notice
	// stopCh and exit before tearing down shared infrastructure.
	// Use a 5-second timeout to prevent a hung goroutine (e.g.
	// blocked on registry I/O during an outage) from blocking
	// shutdown forever. Leaked goroutines are the lesser evil.
	done := make(chan struct{})
	go func() {
		d.bgWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		slog.Warn("timed out waiting for background goroutines to exit", "leaked", true)
	}

	// v1.9.1: emit a shutdown signal BEFORE any teardown so operators
	// can distinguish planned drain from crash. Auto-scalers and
	// webhook-driven dashboards rely on this transition event;
	// otherwise the only visible signal is "events stop arriving,"
	// which is indistinguishable from a kernel panic. Payload carries
	// state snapshot for correlation with pre-shutdown metrics.
	conns := d.ports.AllConnections()
	openConns := 0
	for _, c := range conns {
		c.Mu.Lock()
		if c.State == StateEstablished {
			openConns++
		}
		c.Mu.Unlock()
	}
	d.publishEvent("daemon.shutting_down", map[string]interface{}{
		"open_connections": openConns,
		"known_peers":      d.tunnels.PeerCount(),
		"uptime_seconds":   int(time.Since(d.startTime).Seconds()),
	})

	// Graceful close: send FIN to all active connections, then force remove
	for _, conn := range conns {
		conn.Mu.Lock()
		st := conn.State
		seq := conn.SendSeq
		conn.Mu.Unlock()
		if st == StateEstablished {
			// Send FIN
			fin := &protocol.Packet{
				Version:  protocol.Version,
				Flags:    protocol.FlagFIN,
				Protocol: protocol.ProtoStream,
				Src:      conn.LocalAddr,
				Dst:      conn.RemoteAddr,
				SrcPort:  conn.LocalPort,
				DstPort:  conn.RemotePort,
				Seq:      seq,
			}
			d.tunnels.Send(conn.RemoteAddr.Node, fin)
		}
		// On shutdown, skip TIME_WAIT and remove immediately
		conn.Mu.Lock()
		conn.State = StateClosed
		conn.Mu.Unlock()
		conn.CloseRecvBuf()
		d.ports.RemoveConnection(conn.ID)
	}
	if len(conns) > 0 {
		slog.Info("closed active connections", "count", len(conns))
	}

	// Wait for background handshake RPCs to drain
	if d.handshakes != nil {
		d.handshakes.Stop()
	}

	// Intentionally NOT calling Deregister on shutdown: deregister removes the
	// node from every network.Members list, so a restarted daemon comes back
	// with no network memberships — losing per-network policy state
	// (including persisted deny/grudge lists). The 5-minute heartbeat TTL
	// reaps truly-dead nodes; users who explicitly want to leave call
	// `pilotctl deregister` via IPC (CmdDeregister) which is unaffected.
	if d.reg() != nil {
		d.reg().Close()
	}

	d.stopPolicyRunners()
	d.stopManaged()

	// L11 plugin lifecycle is owned by plugins/runtime — cmd/daemon
	// (composition root) calls runtime.StopPlugins(ctx) BEFORE
	// invoking Daemon.Stop. By the time we get here, plugins are
	// already stopped. (T7.1.)

	d.ipc.Close()
	d.tunnels.Close()

	// T4.3: drain the network.* internal subscriber so no in-flight
	// reconcileMembership tick lingers after Stop returns.
	d.netSubMu.Lock()
	netStop := d.netSubStop
	d.netSubStop = nil
	d.netSubMu.Unlock()
	if netStop != nil {
		netStop()
	}

	// T4.1: webhook lifecycle (bus subscribe + HTTP client) is owned
	// by plugins/webhook. cmd/daemon stops plugins after Daemon.Stop
	// so the daemon.shutting_down event published above flows through
	// the bus to the still-subscribed plugin, which drains its
	// internal queue on Stop().

	// Defense-in-depth: flush identity to disk on shutdown.
	// Today all identity mutations persist eagerly (GenerateIdentity
	// in startNetworked and RotateKey save synchronously), but a
	// future code path that mutates d.identity in-memory without a
	// write would lose the change on next start. Writing here ensures
	// identity on disk always reflects the shutdown state.
	//
	// d.identity can be nil here — many short-lived test daemons
	// (and any daemon that stops before startNetworked has loaded /
	// generated an identity) reach doStop without ever populating it.
	// SaveIdentity dereferences the second arg unconditionally, so
	// passing nil panics with SIGSEGV (see TestL7RetxLoopPanicSurvival).
	// Read under identityMu so a concurrent RotateKey on the shutdown
	// path can't tear the pointer load either.
	if d.config.IdentityPath != "" {
		d.identityMu.RLock()
		id := d.identity
		d.identityMu.RUnlock()
		if id != nil {
			if err := crypto.SaveIdentity(d.config.IdentityPath, id); err != nil {
				slog.Warn("identity flush on shutdown failed", "error", err)
			}
		}
	}
}

// startManaged detects managed networks this node belongs to and starts engines.
func (d *Daemon) startManaged() {
	resp, err := d.reg().ListNetworks()
	if err != nil {
		slog.Debug("managed: cannot list networks", "err", err)
		return
	}
	networks, _ := resp["networks"].([]interface{})
	for _, raw := range networks {
		n, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		rulesRaw, hasRules := n["rules"]
		if !hasRules || rulesRaw == nil {
			continue
		}
		netID, ok := networkIDFromJSON(n["id"])
		if !ok {
			slog.Warn("rules: skipping network with invalid id", "id", n["id"])
			continue
		}

		// Check if this node is a member
		isMember := false
		for _, nid := range d.nodeNetworks() {
			if nid == netID {
				isMember = true
				break
			}
		}
		if !isMember {
			continue
		}

		// Parse rules from map
		rb, _ := json.Marshal(rulesRaw)
		rules, err := registrywire.ParseRules(string(rb))
		if err != nil {
			slog.Warn("managed: invalid rules on network", "network_id", netID, "err", err)
			continue
		}

		me := NewManagedEngine(netID, rules, d)
		me.Start()
		d.managedMu.Lock()
		d.managed[netID] = me
		d.managedMu.Unlock()
		slog.Info("managed: engine started for network", "network_id", netID)
	}
}

// stopManaged stops all managed engines.
func (d *Daemon) stopManaged() {
	d.managedMu.Lock()
	engines := make(map[uint16]*ManagedEngine, len(d.managed))
	for k, v := range d.managed {
		engines[k] = v
	}
	d.managedMu.Unlock()

	for _, me := range engines {
		me.Stop()
	}
}

// StartManagedEngine starts a managed engine for a newly joined network.
func (d *Daemon) StartManagedEngine(netID uint16, rules *registrywire.NetworkRules) {
	d.managedMu.Lock()
	defer d.managedMu.Unlock()

	if _, exists := d.managed[netID]; exists {
		return // already running
	}

	me := NewManagedEngine(netID, rules, d)
	me.Start()
	d.managed[netID] = me
}

// StopManagedEngine stops a managed engine (e.g., on network leave).
func (d *Daemon) StopManagedEngine(netID uint16) {
	d.managedMu.Lock()
	me, ok := d.managed[netID]
	if ok {
		delete(d.managed, netID)
	}
	d.managedMu.Unlock()

	if ok {
		me.Stop()
	}
}

// GetManagedEngine returns the managed engine for a network, or nil.
func (d *Daemon) GetManagedEngine(netID uint16) *ManagedEngine {
	d.managedMu.Lock()
	defer d.managedMu.Unlock()
	return d.managed[netID]
}

// nodeNetworks returns this node's network memberships by querying the registry.
// nodeNetworksTTL bounds how long a cached nodeNetworks() snapshot may serve
// readers. Issue #93: bumped from "no cache" to 1 s to absorb §4.8-style
// concurrent Info/Health bursts without each one round-tripping the registry.
const nodeNetworksTTL = 1 * time.Second

// nodeNetworks returns the cached network membership list, refreshing on
// miss. Use nodeNetworksFresh to bypass the cache (e.g. when membership
// is known to have changed but the cache TTL hasn't expired).
func (d *Daemon) nodeNetworks() []uint16 {
	d.nodeNetworksCacheMu.Lock()
	if !d.nodeNetworksCacheAt.IsZero() && time.Since(d.nodeNetworksCacheAt) < nodeNetworksTTL {
		// Return a copy so callers can mutate freely without poisoning
		// the cache.
		out := make([]uint16, len(d.nodeNetworksCache))
		copy(out, d.nodeNetworksCache)
		d.nodeNetworksCacheMu.Unlock()
		return out
	}
	d.nodeNetworksCacheMu.Unlock()
	return d.nodeNetworksFresh()
}

// nodeNetworksFresh always fetches from the registry, ignoring the cache.
// Stores the result in the cache for subsequent nodeNetworks() callers.
// Used by reconcileMembership where stale cache hides genuine join/leave
// deltas, and by paths that must observe an up-to-the-millisecond list.
func (d *Daemon) nodeNetworksFresh() []uint16 {
	rc := d.reg()
	resp, err := withRegistryDeadline(registryCallDeadline, func() (map[string]interface{}, error) {
		return rc.Lookup(d.NodeID())
	})
	if err != nil {
		return nil
	}
	networksRaw, _ := resp["networks"].([]interface{})
	var nets []uint16
	for _, v := range networksRaw {
		if id, ok := networkIDFromJSON(v); ok {
			nets = append(nets, id)
		}
	}

	d.nodeNetworksCacheMu.Lock()
	d.nodeNetworksCache = nets
	d.nodeNetworksCacheAt = time.Now()
	d.nodeNetworksCacheMu.Unlock()

	out := make([]uint16, len(nets))
	copy(out, nets)
	return out
}

// invalidateNodeNetworksCache clears the cached membership list. Called from
// network-mutating IPC paths (JoinNetwork / LeaveNetwork) so callers see
// fresh state immediately, not after the TTL expires.
func (d *Daemon) invalidateNodeNetworksCache() {
	d.nodeNetworksCacheMu.Lock()
	d.nodeNetworksCache = nil
	d.nodeNetworksCacheAt = time.Time{}
	d.nodeNetworksCacheMu.Unlock()
}

func (d *Daemon) NodeID() uint32 {
	d.addrMu.RLock()
	defer d.addrMu.RUnlock()
	return d.nodeID
}

// loadNetworkPolicies fetches AllowedPorts for every joined network and caches
// them for SYN-handler enforcement. Called at startup and after IPC joins.
func (d *Daemon) loadNetworkPolicies() {
	nets := d.nodeNetworks()

	// Snapshot the current cache so a transient GetNetworkPolicy error
	// carries the last-known policy FORWARD instead of dropping it.
	// Dropping an entry makes isPortAllowed fall through to allow-all
	// (empty list == no restriction), so a restricted network would go
	// silently unrestricted on any registry hiccup — a fail-OPEN hole.
	// A restriction is relaxed only by an explicit successful response
	// that no longer lists it, never by a failed lookup.
	d.netPolicyMu.RLock()
	prior := make(map[uint16][]uint16, len(d.netPolicies))
	for k, v := range d.netPolicies {
		prior[k] = v
	}
	d.netPolicyMu.RUnlock()

	results := make([]netPolicyResult, 0, len(nets))
	for _, netID := range nets {
		var resp map[string]interface{}
		var err error
		// Bounded retry so a transient blip on the very first load (when
		// there is no prior to fall back to) still self-heals quickly.
		for attempt := 0; attempt < 3; attempt++ {
			if resp, err = d.reg().GetNetworkPolicy(netID); err == nil {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		if err != nil {
			_, hadPrior := prior[netID]
			slog.Warn("network policy load failed — retaining last-known policy, not failing open",
				"net_id", netID, "had_prior", hadPrior, "err", err)
			d.publishEvent("network.policy_load_failed", map[string]any{
				"net_id":    netID,
				"had_prior": hadPrior,
			})
			results = append(results, netPolicyResult{netID: netID, err: err})
			continue
		}
		portsRaw, _ := resp["allowed_ports"].([]interface{})
		var ports []uint16
		for _, p := range portsRaw {
			if f, ok := p.(float64); ok {
				ports = append(ports, uint16(f))
			}
		}
		results = append(results, netPolicyResult{netID: netID, ports: ports})
	}

	newPolicies := mergeNetworkPolicies(prior, results)
	d.netPolicyMu.Lock()
	d.netPolicies = newPolicies
	d.netPolicyMu.Unlock()
}

// netPolicyResult is one network's port-policy fetch outcome, fed to
// mergeNetworkPolicies.
type netPolicyResult struct {
	netID uint16
	ports []uint16
	err   error
}

// mergeNetworkPolicies computes the new port-policy cache from the fetch
// results and the prior cache. A FAILED fetch retains the prior policy
// (fail-CLOSED — a transient registry error must not drop a restriction
// and silently relax the network to allow-all); a SUCCESSFUL fetch is
// stored verbatim, including an empty list, which explicitly means "no
// restriction" and is the only thing that relaxes an existing policy.
// Pure function so the fail-closed invariant is unit-testable without a
// live registry.
func mergeNetworkPolicies(prior map[uint16][]uint16, results []netPolicyResult) map[uint16][]uint16 {
	policies := make(map[uint16][]uint16, len(results))
	for _, r := range results {
		if r.err != nil {
			if p, ok := prior[r.netID]; ok {
				policies[r.netID] = p
			}
			continue
		}
		policies[r.netID] = r.ports
	}
	return policies
}

// isPortAllowed checks whether dstPort is permitted by the network's AllowedPorts
// policy. Returns true if no restriction is set (empty list = all ports allowed).
func (d *Daemon) isPortAllowed(netID uint16, port uint16) bool {
	d.netPolicyMu.RLock()
	ports := d.netPolicies[netID]
	d.netPolicyMu.RUnlock()
	if len(ports) == 0 {
		return true
	}
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

// evaluatePortPolicy checks whether a protocol event is allowed by the policy
// engine. The packet's destination network is the primary runner consulted;
// in addition, any other runner this daemon owns that lists `peerNodeID` as
// a member is also evaluated, so a policy loaded on overlay network N still
// fires for traffic that arrives on the default network 0 — the test suite
// frequently loads a policy on a managed network and then sends a
// connect/datagram on the default tunnel between two members of that
// network. Without the cross-network evaluation, the policy's score/tag
// directives never apply.
//
// Combination rule: deny wins. If any consulted runner explicitly denies,
// the event is rejected; otherwise allow. Side effects (score, tag, log,
// webhook) execute on every matching runner so each network's view of the
// peer reflects the activity.
func (d *Daemon) evaluatePortPolicy(eventType PolicyEventType, netID uint16, port uint16, peerNodeID uint32, payloadSize int, direction string) bool {
	pm := d.policyManager
	if pm == nil {
		return d.isPortAllowed(netID, port)
	}

	primary := pm.Get(netID)
	var others []PolicyRunner
	for _, pr := range pm.All() {
		if pr.NetworkID() == netID {
			continue
		}
		if pr.HasMember(peerNodeID) {
			others = append(others, pr)
		}
	}

	nodeInfoTags := d.nodeInfoTagsFor(peerNodeID)

	allow := true
	consulted := 0

	if primary != nil {
		consulted++
		d.memberTagsMu.RLock()
		localTags := append([]string(nil), d.memberTags[netID]...)
		d.memberTagsMu.RUnlock()
		if !primary.EvaluatePortGate(eventType, port, peerNodeID, payloadSize, direction, localTags, nodeInfoTags) {
			allow = false
		}
	}
	for _, pr := range others {
		consulted++
		// Each cross-network runner must use localTags from its own network,
		// not the packet's network. The member tags for network N are stored
		// under d.memberTags[N]; using d.memberTags[packetNetID] would always
		// return empty for cross-network evaluation (packet comes in on net 0
		// but the policy runner lives on a managed network).
		d.memberTagsMu.RLock()
		localTags := append([]string(nil), d.memberTags[pr.NetworkID()]...)
		d.memberTagsMu.RUnlock()
		if !pr.EvaluatePortGate(eventType, port, peerNodeID, payloadSize, direction, localTags, nodeInfoTags) {
			allow = false
		}
	}

	if consulted == 0 {
		return d.isPortAllowed(netID, port)
	}
	return allow
}

// nodeInfoTagsFor returns the registry-level tags assigned to a peer
// (`pilotctl set-tags`). The plugin merges these with policy-local
// tags inside EvaluatePortGate (T2.3). Replaces the daemon-side
// peerTagsFor merge that previously lived alongside runPolicyGate.
func (d *Daemon) nodeInfoTagsFor(peerNodeID uint32) []string {
	var tags []string
	d.resolveCacheMu.RLock()
	if e, ok := d.resolveCache[peerNodeID]; ok {
		if raw, ok := e.resp["tags"].([]interface{}); ok {
			for _, t := range raw {
				if s, ok := t.(string); ok {
					tags = append(tags, s)
				}
			}
		}
	}
	d.resolveCacheMu.RUnlock()
	return tags
}

// GetPolicyRunner returns the policy runner for a network, or nil.
// Delegates to the registered policy manager.
func (d *Daemon) GetPolicyRunner(netID uint16) PolicyRunner {
	if d.policyManager == nil {
		return nil
	}
	return d.policyManager.Get(netID)
}

// StartPolicyRunner compiles a policy JSON and registers a runner via
// the policy manager. Errors when no manager is registered.
func (d *Daemon) StartPolicyRunner(netID uint16, policyJSON json.RawMessage) error {
	if d.policyManager == nil {
		return fmt.Errorf("policy plugin not registered")
	}
	if _, err := d.policyManager.Start(netID, policyJSON); err != nil {
		return err
	}
	return nil
}

// StopPolicyRunner stops the policy runner for a network. No-op if no
// manager is registered or no runner exists for netID.
func (d *Daemon) StopPolicyRunner(netID uint16) {
	if d.policyManager == nil {
		return
	}
	d.policyManager.Stop(netID)
}

// RegisterPolicyManager wires the L11 policy plugin into the daemon.
// cmd/daemon (composition root) constructs the plugin and calls this.
// Takes the daemon-local PolicyManager interface (primitive
// signatures only); the plugin's manager satisfies it via structural
// typing without daemon importing pkg/coreapi (T7.1).
func (d *Daemon) RegisterPolicyManager(pm PolicyManager) {
	d.policyManager = pm
}

// GetTrustChecker exposes the registered trust checker (or nil) so
// plugins/runtime can include it in the coreapi.Deps it constructs.
func (d *Daemon) GetTrustChecker() TrustChecker { return d.trustChecker }

// RegisterTrustChecker installs the daemon-wide TrustChecker used by
// the handshake handler to gate auto-accept. Replaces any previously-
// registered checker. Takes the daemon-local interface (primitive
// signatures) — plugin types satisfy it via structural typing.
func (d *Daemon) RegisterTrustChecker(tc TrustChecker) {
	d.trustChecker = tc
}

// NewConnReadWriter wraps a Connection with the daemon's net.Conn
// adapter. plugins/runtime uses this to expose the conn as a
// coreapi.Stream without needing access to the unexported connAdapter.
func (d *Daemon) NewConnReadWriter(conn *Connection) ConnReadWriter {
	return newConnAdapter(d, conn)
}

// ConnReadWriter is the public interface plugins/runtime sees for the
// io-side of a Connection. Matches the unexported connAdapter shape.
type ConnReadWriter interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
}

// --- Public accessors used by the policy plugin's Runtime adapter (T2.3) ---

func (d *Daemon) PublishEvent(topic string, payload map[string]any) {
	d.publishEvent(topic, payload)
}

func (d *Daemon) AdminToken() string { return d.config.AdminToken }

func (d *Daemon) RegConnListNodes(netID uint16, token string) (map[string]any, error) {
	if d.reg() == nil {
		return nil, fmt.Errorf("registry connection not initialized")
	}
	return d.reg().ListNodes(netID, token)
}

// TrustedPeers returns the trust records held by the registered
// handshake service. Returns nil when no handshake plugin is wired
// (e.g. unit tests that bypass plugins/runtime).
func (d *Daemon) TrustedPeers() []HandshakeTrustRecord {
	if d.handshakes == nil {
		return nil
	}
	return d.handshakes.TrustedPeers()
}

func (d *Daemon) HandshakeRevokeTrust(nodeID uint32) error {
	if d.handshakes == nil {
		return fmt.Errorf("handshake service not registered")
	}
	return d.handshakes.RevokeTrust(nodeID)
}

// ErrHandshakeInFlight is returned by HandshakeSendRequest when another
// outbound handshake to the same peer is currently in progress on this
// daemon. Callers can treat this as a soft success: the existing in-flight
// call will produce a trust outcome shortly. Surfaced through the IPC
// SubHandshakeSend handler as a distinct "in_flight" reply status so
// pilotctl users get a clean signal rather than a generic error.
var ErrHandshakeInFlight = errors.New("handshake already in flight to this peer")

// autoHandshakeCooldown is the per-peer minimum gap between
// DialConnection-driven auto-handshake spawns. Sized to match the dial
// budget (~25-78s of direct-retry + relay) so a peer that's unreachable
// can't drive log/dial fanout faster than the dial itself takes. The
// next caller still gets an auto-handshake — just not 4000 of them per
// second from the same hot dial path.
const autoHandshakeCooldown = 30 * time.Second

// shouldAutoHandshake reports whether DialConnection's inline
// trusted-agents auto-handshake should fire for peer. Returns true the
// first time it sees the peer and after autoHandshakeCooldown has
// elapsed since the last spawn. Records the spawn time atomically so
// concurrent racers see one winner; subsequent callers within the
// cooldown window observe a recent timestamp and return false without
// spawning a goroutine.
//
// Gates only the dial-driven auto-spawn path: explicit
// `pilotctl handshake <peer>` IPC calls hit HandshakeSendRequest
// directly and are unaffected (so a user explicitly retrying is never
// silently dropped).
func (d *Daemon) shouldAutoHandshake(peer uint32) bool {
	now := time.Now()
	prev, loaded := d.autoHandshakeLastAttempt.LoadOrStore(peer, now)
	if !loaded {
		return true
	}
	prevTime, ok := prev.(time.Time)
	if !ok {
		// Defensive — value type mismatch should be impossible, but if
		// it happens, overwrite and proceed rather than wedge.
		d.autoHandshakeLastAttempt.Store(peer, now)
		return true
	}
	if now.Sub(prevTime) < autoHandshakeCooldown {
		return false
	}
	// Cooldown expired — race to claim the slot. CompareAndSwap means at
	// most one of N concurrent racers wins; the rest skip this round and
	// will try again on the next dial after cooldown.
	return d.autoHandshakeLastAttempt.CompareAndSwap(peer, prev, now)
}

// HandshakeSendRequest issues an outbound trust handshake to peerNodeID
// via the registered handshake plugin, deduped per-peer.
//
// Concurrent callers for the same peer (e.g. a burst of `pilotctl
// handshake <agent>` commands) coalesce: the first call records its
// intent in d.handshakeInFlight and proceeds; any subsequent caller that
// observes the entry returns immediately with ErrHandshakeInFlight
// without firing a second DialConnection. The first call's deferred
// delete frees the slot when the underlying SendRequest returns.
//
// This collapses the dial-side fanout: N callers → 1 DialConnection → 1
// ephemeral port held during the dial budget, rather than N callers → N
// dials → N ports. Eliminates the port-pool saturation footprint that
// otherwise appeared in the daemon log under parallel handshake bursts.
func (d *Daemon) HandshakeSendRequest(nodeID uint32, reason string) error {
	if d.handshakes == nil {
		return fmt.Errorf("handshake service not registered")
	}
	if _, loaded := d.handshakeInFlight.LoadOrStore(nodeID, struct{}{}); loaded {
		return ErrHandshakeInFlight
	}
	defer d.handshakeInFlight.Delete(nodeID)
	return d.handshakes.SendRequest(nodeID, reason)
}

// RegisterHandshakeService installs the daemon-wide HandshakeService
// implementation provided by the handshake plugin (T3.3). Called from
// the composition root after constructing the plugin's Service.
// Replaces any previously-registered service.
func (d *Daemon) RegisterHandshakeService(svc HandshakeService) {
	d.handshakes = svc
}

// HandshakeService returns the registered HandshakeService (or nil if
// no handshake plugin has been registered). Mostly used by daemon
// internals; external callers prefer the typed wrappers above.
func (d *Daemon) HandshakeService() HandshakeService { return d.handshakes }

// handshakePendingCount returns the pending-handshake count for the
// status report, with a nil-safe guard for daemons that don't have a
// handshake plugin registered.
func handshakePendingCount(svc HandshakeService) int {
	if svc == nil {
		return 0
	}
	return svc.PendingCount()
}

// IdentityPath returns the configured identity file path, or "" if the
// daemon runs without persistent identity. Exposed so the handshake
// plugin can derive its trust.json store path from the same directory.
func (d *Daemon) IdentityPath() string { return d.config.IdentityPath }

// TrustAutoApprove reports whether the daemon was started with the
// trust-auto-approve flag set. Exposed for the handshake plugin's
// auto-accept gate.
func (d *Daemon) TrustAutoApprove() bool { return d.config.TrustAutoApprove }

// RegistryClient returns the underlying L8 registry-side-channel
// client (or nil if no registry is configured). Exposed so the
// handshake plugin can issue Lookup/ReportTrust/RevokeTrust /
// RequestHandshake / RespondHandshake / PollHandshakes against the
// same client the daemon uses elsewhere — there is no separate
// connection or auth context.
func (d *Daemon) RegistryClient() *registry.Client { return d.reg() }

func (d *Daemon) reg() *registry.Client {
	return d.regConn.Load()
}

func (d *Daemon) dialRegistryClient() (*registry.Client, error) {
	var rc *registry.Client
	var err error
	const maxRegistryDialAttempts = 10
	const regConnPoolSize = 4
	registryDialBackoff := 500 * time.Millisecond
	dialOpts := d.registryDialOptions()
	for attempt := 1; attempt <= maxRegistryDialAttempts; attempt++ {
		if d.config.RegistryTLS {
			trust := d.config.RegistryTrust
			if trust == "" {
				trust = "pinned"
			}
			switch trust {
			case "pinned":
				if d.config.RegistryFingerprint == "" {
					return nil, fmt.Errorf("registry TLS with -registry-trust=pinned requires RegistryFingerprint")
				}
				rc, err = registry.DialTLSPinned(d.config.RegistryAddr, d.config.RegistryFingerprint, dialOpts...)
			case "system":
				rc, err = registry.DialTLSPool(d.config.RegistryAddr, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: d.config.systemRoots}, regConnPoolSize, dialOpts...)
			default:
				return nil, fmt.Errorf("invalid -registry-trust %q: must be 'pinned' or 'system'", trust)
			}
		} else {
			rc, err = registry.DialPool(d.config.RegistryAddr, regConnPoolSize, dialOpts...)
		}
		if err == nil {
			break
		}
		if attempt == maxRegistryDialAttempts {
			if hint := tlsTrustHint(err, "registry"); hint != "" {
				return nil, fmt.Errorf("registry dial (after %d attempts): %w; %s", attempt, err, hint)
			}
			return nil, fmt.Errorf("registry dial (after %d attempts): %w", attempt, err)
		}
		slog.Warn("registry dial failed, retrying",
			"attempt", attempt, "max", maxRegistryDialAttempts,
			"backoff", registryDialBackoff, "error", err)
		time.Sleep(registryDialBackoff)
		if registryDialBackoff < 5*time.Second {
			registryDialBackoff *= 2
		}
	}

	if d.identity != nil {
		rc.SetSigner(func(challenge string) string {
			d.identityMu.RLock()
			defer d.identityMu.RUnlock()
			cur := d.identity
			if cur == nil {
				return ""
			}
			return base64.StdEncoding.EncodeToString(cur.Sign([]byte(challenge)))
		})
	}
	return rc, nil
}

func (d *Daemon) forceReconnectRegistry() error {
	newConn, err := d.dialRegistryClient()
	if err != nil {
		return err
	}
	old := d.regConn.Swap(newConn)
	if old != nil {
		go old.Close()
	}
	slog.Warn("registry connection force-reconnected after half-open detection", "addr", d.config.RegistryAddr)
	return nil
}

// peerTagsFor returns the merged tag set for a peer as seen by the policy
// evaluator: policy-runner local tags (assigned via the `tag` action) unioned
// with the peer's global NodeInfo tags (assigned via `pilotctl set-tags`,
// read from the registry resolve cache). De-duplicated, stable order:
// NodeInfo first, then policy-local tags not already present.
//
// This is the canonical tag store for `has_tag(peer_tags, ...)` policies.
// Without the NodeInfo merge, admin-assigned tags are invisible to the
// policy engine even though they are the primary way operators classify
// peers.
func (d *Daemon) peerTagsFor(peerNodeID uint32, localTags []string) []string {
	var nodeInfoTags []string
	d.resolveCacheMu.RLock()
	if e, ok := d.resolveCache[peerNodeID]; ok {
		if raw, ok := e.resp["tags"].([]interface{}); ok {
			for _, t := range raw {
				if s, ok := t.(string); ok {
					nodeInfoTags = append(nodeInfoTags, s)
				}
			}
		}
	}
	d.resolveCacheMu.RUnlock()

	if len(nodeInfoTags) == 0 && len(localTags) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(nodeInfoTags)+len(localTags))
	merged := make([]string, 0, len(nodeInfoTags)+len(localTags))
	for _, t := range nodeInfoTags {
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		merged = append(merged, t)
	}
	for _, t := range localTags {
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		merged = append(merged, t)
	}
	return merged
}

// SetMemberTags updates the cached member tags for the local node in a network.
func (d *Daemon) SetMemberTags(netID uint16, tags []string) {
	d.memberTagsMu.Lock()
	d.memberTags[netID] = tags
	d.memberTagsMu.Unlock()
}

// GetMemberTags returns the cached member tags for the local node in a network.
func (d *Daemon) GetMemberTags(netID uint16) []string {
	d.memberTagsMu.RLock()
	tags := d.memberTags[netID]
	d.memberTagsMu.RUnlock()
	return tags
}

// loadPolicyRunners loads expr policies for all joined networks at startup.
func (d *Daemon) loadPolicyRunners() {
	resp, err := d.reg().ListNetworks()
	if err != nil {
		slog.Debug("policy: cannot list networks", "err", err)
		return
	}
	networks, _ := resp["networks"].([]interface{})
	for _, raw := range networks {
		n, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		// Only load if has_expr_policy is true
		hasPolicy, _ := n["has_expr_policy"].(bool)
		if !hasPolicy {
			continue
		}
		netID, ok := networkIDFromJSON(n["id"])
		if !ok {
			slog.Warn("policy: skipping network with invalid id", "id", n["id"])
			continue
		}

		// Check membership
		isMember := false
		for _, nid := range d.nodeNetworks() {
			if nid == netID {
				isMember = true
				break
			}
		}
		if !isMember {
			continue
		}

		// Fetch the full policy
		resp, err := d.reg().GetExprPolicy(netID)
		if err != nil {
			slog.Warn("policy: cannot fetch expr_policy", "network_id", netID, "err", err)
			continue
		}

		var policyJSON json.RawMessage
		switch v := resp["expr_policy"].(type) {
		case string:
			policyJSON = json.RawMessage(v)
		case map[string]interface{}:
			b, _ := json.Marshal(v)
			policyJSON = b
		default:
			continue
		}

		if err := d.StartPolicyRunner(netID, policyJSON); err != nil {
			slog.Warn("policy: failed to start runner", "network_id", netID, "err", err)
			continue
		}
		slog.Info("policy: runner started for network", "network_id", netID)
	}
}

// stopPolicyRunners delegates to the policy manager. No-op when no
// manager is registered (test daemons that don't load the plugin).
func (d *Daemon) stopPolicyRunners() {
	if d.policyManager == nil {
		return
	}
	d.policyManager.StopAll()
}

// SetWebhookURL hot-swaps the webhook URL by delegating to the
// registered WebhookManager (the plugins/webhook plugin). Called from
// IPC's set-webhook handler. No-op if no manager is registered (e.g.
// unit-test daemons that bypass cmd/daemon's plugin wiring).
func (d *Daemon) SetWebhookURL(url string) {
	if d.webhookManager == nil {
		return
	}
	d.webhookManager.SetURL(url)
}

// RegisterWebhookManager wires the L11 webhook plugin into the daemon
// (T4.1). cmd/daemon (composition root) constructs the plugin and
// calls this with an adapter satisfying the daemon-local interface.
func (d *Daemon) RegisterWebhookManager(wm WebhookManager) {
	d.webhookManager = wm
}

// Identity returns the daemon's Ed25519 identity (may be nil if unset).
func (d *Daemon) Identity() *crypto.Identity {
	d.identityMu.RLock()
	defer d.identityMu.RUnlock()
	return d.identity
}

// Sign signs msg with the daemon's Ed25519 private key. Returns nil
// when no identity is loaded (in-memory tests, pre-bootstrap).
//
// Required by daemonapi.Daemon (common@v0.4.3). The adapter at
// zz_daemonapi_conformance.go forwards to this directly.
func (d *Daemon) Sign(msg []byte) []byte {
	d.identityMu.RLock()
	id := d.identity
	d.identityMu.RUnlock()
	if id == nil {
		return nil
	}
	return id.Sign(msg)
}

// RotateKey generates a new Ed25519 keypair, proves ownership of the current
// key to the registry via a `rotate:<node_id>` signature, atomically swaps the
// in-memory identity on success, and persists it to disk. Returns the
// registry response on success.
func (d *Daemon) RotateKey() (map[string]interface{}, error) {
	// Serialize rotations: see comment on rotateKeyMu. Two concurrent
	// RotateKey calls would otherwise race on the OLD PrivateKey buffer
	// (one zeros it while the other is still signing with it).
	d.rotateKeyMu.Lock()
	defer d.rotateKeyMu.Unlock()

	d.identityMu.RLock()
	current := d.identity
	d.identityMu.RUnlock()
	if current == nil {
		return nil, fmt.Errorf("rotate_key: daemon has no identity")
	}
	if d.reg() == nil {
		return nil, fmt.Errorf("rotate_key: registry connection unavailable")
	}

	newID, err := crypto.GenerateIdentity()
	if err != nil {
		return nil, fmt.Errorf("rotate_key: generate keypair: %w", err)
	}

	nodeID := d.NodeID()
	newPubB64 := crypto.EncodePublicKey(newID.PublicKey)
	// Bind new_public_key into the challenge so an on-the-wire attacker
	// cannot substitute their own pubkey while reusing the signature.
	challenge := fmt.Sprintf("rotate:%d:%s", nodeID, newPubB64)
	sig := current.Sign([]byte(challenge))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	resp, err := d.reg().RotateKey(nodeID, sigB64, newPubB64)
	if err != nil {
		return nil, fmt.Errorf("rotate_key: registry: %w", err)
	}

	// Swap the identity AND zero the old private key under the SAME write
	// Lock. Signer closures read the private key under identityMu.RLock()
	// for the full duration of Sign(); RLock and Lock are mutually
	// exclusive, so zeroing here can never overlap an in-flight Sign() of
	// the old key. Doing the zero outside the Lock (the old behavior) raced
	// with a signer that had captured the old identity before the swap.
	//
	// We zero the old key so it doesn't linger on the heap until GC — a
	// long-lived daemon can keep it alive for hours. ed25519.PrivateKey is
	// a []byte (seed || public).
	d.identityMu.Lock()
	d.identity = newID
	for i := range current.PrivateKey {
		current.PrivateKey[i] = 0
	}
	d.identityMu.Unlock()

	d.tunnels.SetIdentity(newID)
	// The signer installed in Start() reads d.identity under d.identityMu
	// on every call, so this SetSigner re-bind is no longer load-bearing —
	// kept for symmetry with the original RotateKey contract. The closure
	// here holds the RLock across Sign() (same invariant as Start's signer)
	// so it is safe against a future rotation's in-place key zeroing.
	d.reg().SetSigner(func(c string) string {
		d.identityMu.RLock()
		defer d.identityMu.RUnlock()
		cur := d.identity
		if cur == nil {
			return ""
		}
		return base64.StdEncoding.EncodeToString(cur.Sign([]byte(c)))
	})

	if d.config.IdentityPath != "" {
		if err := crypto.SaveIdentity(d.config.IdentityPath, newID); err != nil {
			slog.Warn("rotate_key: persist identity failed", "error", err)
		}
	}

	d.publishEvent("key.rotated", map[string]interface{}{
		"node_id":    nodeID,
		"public_key": newPubB64,
	})

	slog.Info("rotated identity key", "node_id", nodeID)
	return resp, nil
}

// AddTunnelPeer registers a peer's address in the tunnel manager (for testing/manual setup).
func (d *Daemon) AddTunnelPeer(nodeID uint32, addr *net.UDPAddr) {
	d.tunnels.AddPeer(nodeID, addr)
}

// TunnelAddr returns the local UDP address of the tunnel listener.
func (d *Daemon) TunnelAddr() net.Addr { return d.tunnels.LocalAddr() }

func (d *Daemon) Addr() protocol.Addr {
	d.addrMu.RLock()
	defer d.addrMu.RUnlock()
	return d.addr
}

// --- Accessors for the plugin-runtime package (T7.1) ---
//
// These let plugins/runtime construct coreapi-typed adapters
// (daemonStreams, daemonEventBus, daemonPolo) without pkg/daemon
// importing pkg/coreapi.

// Ports returns the daemon's port manager. Plugins/runtime uses this
// to bind a coreapi.Listener for plugin services.
func (d *Daemon) Ports() *PortManager { return d.ports }

// Bus returns the daemon's in-process pub/sub bus. Plugins/runtime
// uses it to construct a coreapi.EventBus adapter.
func (d *Daemon) Bus() daemonapi.EventBus { return d.bus }

// Tunnels returns the daemon's tunnel manager. Mostly for in-tree
// plugins that want direct access (tests + unusual integrations).
func (d *Daemon) Tunnels() *TunnelManager { return d.tunnels }

// publishEvent is the daemon-internal helper for publishing to the bus.
// All event-bus subscribers (including the L11 webhook plugin via its
// "*" subscription) receive the event. Nil-safe.
func (d *Daemon) publishEvent(topic string, payload map[string]any) {
	if d == nil || d.bus == nil {
		return
	}
	d.bus.Publish(topic, payload)
}

// publishEventInternal is the entry point used by daemonEventBus.
// Same dispatch as publishEvent — both go through the bus, which
// fans out to all subscribers.
func (d *Daemon) publishEventInternal(topic string, payload map[string]any) {
	d.publishEvent(topic, payload)
}

// webhookStats fetches counters from the registered WebhookManager.
// Returns the zero-value WebhookStats if no manager is registered —
// keeps Info() nil-safe in unit tests that bypass plugins/runtime.
func (d *Daemon) webhookStats() WebhookStats {
	if d.webhookManager == nil {
		return WebhookStats{}
	}
	return d.webhookManager.Stats()
}

// subscribeNetworkInternalToBus wires the daemon-internal reactor for
// network.* bus events. Today it owns:
//   - network.joined      → start a managed engine if the payload
//     carries non-empty rules and no engine is
//     running for the network
//   - network.left        → stop the managed engine if one is running
//   - network.tags_changed → already updated in the cache by
//     refreshMemberTagsAndDiff before publish;
//     event is observed for symmetry/logging
//
// When managed-engine moves to its own plugin, its half here will
// move with it; the member-tag refresh side will stay daemon-internal
// because the cache is consumed by L7 packet handlers (isPortAllowed,
// peerTagsFor merge inside evaluatePortPolicy).
//
// Idempotent — replaces a prior subscription if already active.
func (d *Daemon) subscribeNetworkInternalToBus() {
	d.netSubMu.Lock()
	defer d.netSubMu.Unlock()
	if d.netSubStop != nil {
		d.netSubStop()
		d.netSubStop = nil
	}
	if d.bus == nil {
		return
	}
	ch, cancel := d.bus.Subscribe("network.*")
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ev := range ch {
			switch ev.Topic {
			case TopicNetworkJoined:
				d.handleNetworkJoinedInternal(ev.Payload)
			case TopicNetworkLeft:
				d.handleNetworkLeftInternal(ev.Payload)
			case TopicNetworkTagsChanged:
				// Cache already updated by the publisher; nothing to
				// do here. Subscriber kept for symmetry/logging.
			}
		}
	}()
	var once sync.Once
	d.netSubStop = func() {
		once.Do(func() {
			cancel()
			<-done
		})
	}
}

// handleNetworkJoinedInternal starts a managed engine when the
// network.joined payload carries non-empty rules. Mirrors the old
// syncManagedEngines logic (skip-if-running + ParseRules) so the
// observable behavior of join → managed-engine.Start is unchanged.
func (d *Daemon) handleNetworkJoinedInternal(payload map[string]any) {
	netID, ok := networkIDFromBusPayload(payload)
	if !ok {
		return
	}
	rulesRaw, hasRules := payload["rules"]
	if !hasRules || rulesRaw == nil {
		return
	}

	d.managedMu.Lock()
	_, running := d.managed[netID]
	d.managedMu.Unlock()
	if running {
		return
	}

	rb, err := json.Marshal(rulesRaw)
	if err != nil {
		slog.Debug("network-sync: cannot marshal rules from event",
			"network_id", netID, "err", err)
		return
	}
	rules, err := registrywire.ParseRules(string(rb))
	if err != nil {
		slog.Debug("network-sync: invalid rules in network.joined event",
			"network_id", netID, "err", err)
		return
	}
	d.StartManagedEngine(netID, rules)
	slog.Info("network-sync: started managed engine from event", "network_id", netID)
}

// handleNetworkLeftInternal stops a managed engine when the
// network.left event arrives.
func (d *Daemon) handleNetworkLeftInternal(payload map[string]any) {
	netID, ok := networkIDFromBusPayload(payload)
	if !ok {
		return
	}
	d.StopManagedEngine(netID)
}

// networkIDInRange reports whether a JSON-decoded numeric network id
// (always float64 from encoding/json) is a valid 16-bit network id. Network
// ids occupy the high 16 bits of a 48-bit pilot address, so the valid range
// is [0, 65535]. We reject NaN, negatives, fractional values, and anything
// out of range BEFORE the uint16 cast: a silent wrap (e.g. 65537 -> 1) would
// let a malformed or hostile registry payload remap policy/rules onto a
// different network's identity.
func networkIDInRange(f float64) bool {
	return f == math.Trunc(f) && f >= 0 && f <= math.MaxUint16
}

// networkIDFromJSON validates and converts a JSON-decoded network id field.
// ok is false when the field is absent, not numeric, or out of range.
func networkIDFromJSON(v any) (uint16, bool) {
	f, isFloat := v.(float64)
	if !isFloat || !networkIDInRange(f) {
		return 0, false
	}
	return uint16(f), true
}

// networkIDFromBusPayload extracts a network_id from a bus-event
// payload, accepting both the typed uint16 form (publisher uses it
// directly) and JSON-decoded numeric forms (after the event has
// round-tripped through any external transport). Out-of-range numeric
// forms are rejected rather than silently wrapped.
func networkIDFromBusPayload(p map[string]any) (uint16, bool) {
	if p == nil {
		return 0, false
	}
	switch v := p["network_id"].(type) {
	case uint16:
		return v, true
	case int:
		if v < 0 || v > math.MaxUint16 {
			return 0, false
		}
		return uint16(v), true
	case int64:
		if v < 0 || v > math.MaxUint16 {
			return 0, false
		}
		return uint16(v), true
	case float64:
		return networkIDFromJSON(v)
	default:
		return 0, false
	}
}

// DaemonInfo holds status information about the running daemon.
type NetworkMembership struct {
	NetworkID uint16 `json:"network_id"`
	Address   string `json:"address"`
}

type DaemonInfo struct {
	NodeID                uint32
	Address               string
	Endpoint              string // host:port registered with the rendezvous (proves beacon discover succeeded)
	Hostname              string
	Uptime                time.Duration
	Connections           int
	Ports                 int
	Peers                 int
	EncryptedPeers        int
	AuthenticatedPeers    int
	Encrypt               bool
	Identity              bool   // true if identity is persisted
	PublicKey             string // base64 Ed25519 public key (empty if no identity)
	Email                 string // email address for account identification and key recovery
	BytesSent             uint64
	BytesRecv             uint64
	PktsSent              uint64
	PktsRecv              uint64
	EncryptOK             uint64
	EncryptFail           uint64
	HandshakePendingCount int
	Version               string
	Networks              []NetworkMembership
	PeerList              []PeerInfo
	ConnList              []ConnectionInfo

	// v1.9.1: health metrics surfaced for operators / dashboards.
	// These counters live elsewhere (Daemon.AcceptQueueDrops, the
	// WebhookClient internals) but had no path to reach `pilotctl info`
	// until now. Each is monotonic; operators compute rate by diffing
	// two snapshots over time.
	AcceptQueueDrops    uint64
	WebhookQueueDropped uint64
	WebhookCircuitSkips uint64

	RelayPeerCount int    // peers currently on relay path (symmetric NAT)
	BeaconAddr     string // active beacon address

	MOTD string // message-of-the-day active for the current UTC day ("" = none)

	// Transport is the tunnel transport the daemon runs: "udp" or "compat"
	// (after -transport=auto was resolved).
	Transport string
}

// transportName is the resolved tunnel transport, "udp" or "compat". Only
// meaningful after Start has resolved it.
func (d *Daemon) transportName() string {
	if d.config.TransportMode == TransportCompat {
		return TransportCompat
	}
	return TransportUDP
}

// Info returns current daemon status.
func (d *Daemon) Info() *DaemonInfo {
	d.ports.mu.RLock()
	numConns := 0
	for _, c := range d.ports.connections {
		c.Mu.Lock()
		st := c.State
		c.Mu.Unlock()
		if st == StateEstablished || st == StateSynSent || st == StateSynReceived {
			numConns++
		}
	}
	numPorts := len(d.ports.listeners)
	d.ports.mu.RUnlock()

	peerList := d.tunnels.PeerList()
	encryptedPeers := 0
	authenticatedPeers := 0
	for _, p := range peerList {
		if p.Encrypted {
			encryptedPeers++
		}
		if p.Authenticated {
			authenticatedPeers++
		}
	}

	hasIdentity := d.config.IdentityPath != ""
	pubKeyStr := ""
	// Issue #93: take identityMu for the read — RotateKey writes d.identity
	// under that mutex. Without it concurrent Info() / RotateKey races trip
	// the race detector.
	d.identityMu.RLock()
	if d.identity != nil {
		pubKeyStr = crypto.EncodePublicKey(d.identity.PublicKey)
	}
	d.identityMu.RUnlock()

	d.addrMu.RLock()
	nid := d.nodeID
	addrStr := d.addr.String()
	hostname := d.config.Hostname
	endpoint := d.publicEndpoint
	d.addrMu.RUnlock()

	// Collect network memberships from registry
	var networks []NetworkMembership
	for _, netID := range d.nodeNetworks() {
		if netID == 0 {
			continue // backbone is already shown as primary address
		}
		addr := protocol.Addr{Network: netID, Node: nid}
		networks = append(networks, NetworkMembership{
			NetworkID: netID,
			Address:   addr.String(),
		})
	}

	return &DaemonInfo{
		NodeID:                nid,
		Address:               addrStr,
		Endpoint:              endpoint,
		Hostname:              hostname,
		Uptime:                time.Since(d.startTime).Round(time.Second),
		Connections:           numConns,
		Ports:                 numPorts,
		Peers:                 d.tunnels.PeerCount(),
		EncryptedPeers:        encryptedPeers,
		AuthenticatedPeers:    authenticatedPeers,
		Encrypt:               d.config.Encrypt,
		Identity:              hasIdentity,
		PublicKey:             pubKeyStr,
		Email:                 d.config.Email,
		BytesSent:             atomic.LoadUint64(&d.tunnels.BytesSent),
		BytesRecv:             atomic.LoadUint64(&d.tunnels.BytesRecv),
		PktsSent:              atomic.LoadUint64(&d.tunnels.PktsSent),
		PktsRecv:              atomic.LoadUint64(&d.tunnels.PktsRecv),
		EncryptOK:             atomic.LoadUint64(&d.tunnels.EncryptOK),
		EncryptFail:           atomic.LoadUint64(&d.tunnels.EncryptFail),
		HandshakePendingCount: handshakePendingCount(d.handshakes),
		Version:               d.config.Version,
		Networks:              networks,
		PeerList:              peerList,
		ConnList:              d.ports.ConnectionList(),
		AcceptQueueDrops:      atomic.LoadUint64(&d.AcceptQueueDrops),
		WebhookQueueDropped:   d.webhookStats().Dropped,
		WebhookCircuitSkips:   d.webhookStats().CircuitSkips,
		RelayPeerCount:        len(d.tunnels.RelayPeerIDs()),
		BeaconAddr:            d.config.BeaconAddr,
		MOTD:                  d.currentMOTD(),
		Transport:             d.transportName(),
	}
}

// HealthSnapshot holds the purely-local liveness fields exposed by the
// daemon health check. Unlike Info(), gathering it NEVER touches the
// registry, so registry latency or an unreachable registry cannot degrade
// or stall a local health probe (the probe an operator relies on to detect
// a stuck daemon). Every field below is read from in-memory daemon state.
type HealthSnapshot struct {
	Uptime                time.Duration
	Connections           int
	Peers                 int
	BytesSent             uint64
	BytesRecv             uint64
	EncryptedPeers        int
	AuthenticatedPeers    int
	HandshakePendingCount int
	RelayPeerCount        int
	AcceptQueueDrops      uint64
	WebhookQueueDropped   uint64
	WebhookCircuitSkips   uint64
	BeaconAddr            string
}

// HealthSnapshot returns a purely-local liveness view. It deliberately does
// NOT call nodeNetworks()/the registry (the source of the latency coupling
// that used to let a slow registry stall health) — it reads only in-memory
// counters and tunnel/port state.
func (d *Daemon) HealthSnapshot() HealthSnapshot {
	d.ports.mu.RLock()
	numConns := 0
	for _, c := range d.ports.connections {
		c.Mu.Lock()
		st := c.State
		c.Mu.Unlock()
		if st == StateEstablished || st == StateSynSent || st == StateSynReceived {
			numConns++
		}
	}
	d.ports.mu.RUnlock()

	encryptedPeers := 0
	authenticatedPeers := 0
	for _, p := range d.tunnels.PeerList() {
		if p.Encrypted {
			encryptedPeers++
		}
		if p.Authenticated {
			authenticatedPeers++
		}
	}

	webhookStats := d.webhookStats()

	return HealthSnapshot{
		Uptime:                time.Since(d.startTime).Round(time.Second),
		Connections:           numConns,
		Peers:                 d.tunnels.PeerCount(),
		BytesSent:             atomic.LoadUint64(&d.tunnels.BytesSent),
		BytesRecv:             atomic.LoadUint64(&d.tunnels.BytesRecv),
		EncryptedPeers:        encryptedPeers,
		AuthenticatedPeers:    authenticatedPeers,
		HandshakePendingCount: handshakePendingCount(d.handshakes),
		RelayPeerCount:        len(d.tunnels.RelayPeerIDs()),
		AcceptQueueDrops:      atomic.LoadUint64(&d.AcceptQueueDrops),
		WebhookQueueDropped:   webhookStats.Dropped,
		WebhookCircuitSkips:   webhookStats.CircuitSkips,
		BeaconAddr:            d.config.BeaconAddr,
	}
}

// currentMOTD returns the message-of-the-day text active for the current
// UTC day, or "" if none. Safe for concurrent callers.
func (d *Daemon) currentMOTD() string {
	d.motdMu.RLock()
	defer d.motdMu.RUnlock()
	return d.motd
}

func (d *Daemon) routeLoop() {
	for {
		select {
		case <-d.stopCh:
			return
		case incoming, ok := <-d.tunnels.RecvCh():
			if !ok {
				return
			}
			d.routePacketWithRecover(incoming.Packet, incoming.From)
		}
	}
}

// routePacketWithRecover wraps handlePacket in an L7 panic boundary.
// A panic inside any segment handler (handleStreamPacket,
// handleDatagramPacket, handleControlPacket) drops THIS packet only;
// other in-flight conns and the routeLoop itself stay alive. Per-conn
// teardown still happens inside retxLoop's own boundary if a panic
// flows back via async work.
//
// L7 panic boundary (architecture-notes/03-INVARIANTS.md §8).
func (d *Daemon) routePacketWithRecover(pkt *protocol.Packet, from *net.UDPAddr) {
	defer recoverLayer("L7", "routeLoop", d.bus, nil)
	d.handlePacket(pkt, from)
}

func redactID(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

// keyBoundHandshakeService is the optional half of HandshakeService for
// trust stores that record which peer key each grant was made against.
// Implementations that predate it (test fakes, older plugin builds) are
// answered by node ID alone via handshakeTrusts.
type keyBoundHandshakeService interface {
	IsTrustedWithKey(nodeID uint32, pubKeyB64 string) bool
}

// cachedPeerKeyB64 returns the peer's Ed25519 key as base64, matching
// crypto.EncodePublicKey, or "" when none is cached. Cache-only — no
// registry lookup — so it is safe to call per packet.
func (d *Daemon) cachedPeerKeyB64(nodeID uint32) string {
	if d.tunnels == nil {
		return ""
	}
	pk, ok := d.tunnels.peerPubKeyCached(nodeID)
	if !ok || len(pk) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(pk)
}

// handshakeTrusts consults the handshake trust store for srcNode,
// passing along the peer's currently-known key so the store can check
// it against the key the grant was bound to. A node ID whose key has
// changed since trust was granted does not inherit that trust.
func (d *Daemon) handshakeTrusts(srcNode uint32) bool {
	if d.handshakes == nil {
		return false
	}
	kb, ok := d.handshakes.(keyBoundHandshakeService)
	if !ok {
		return d.handshakes.IsTrusted(srcNode)
	}
	return kb.IsTrustedWithKey(srcNode, d.cachedPeerKeyB64(srcNode))
}

func (d *Daemon) isTrustedPeer(srcNode uint32) bool {
	trusted := d.handshakeTrusts(srcNode)
	if !trusted && d.reg() != nil {
		var err error
		trusted, err = d.reg().CheckTrust(d.NodeID(), srcNode)
		if err != nil {
			slog.Warn("registry trust check failed (data-plane)", "src_node", srcNode, "err", err)
		}
	}
	return trusted
}

func (d *Daemon) admitDataPlanePeer(srcNode uint32) bool {
	if !d.config.StrictDataPlaneTrust || d.config.Public {
		return true
	}
	return d.isTrustedPeer(srcNode)
}

func (d *Daemon) handlePacket(pkt *protocol.Packet, from *net.UDPAddr) {
	// D14 mitigation: when encryption is enabled, only auto-add peers that have an
	// established crypto context (proving prior key exchange). This prevents peer table
	// poisoning from spoofed packets. In plaintext mode, auto-add is safe since
	// there's no authentication to bypass.
	if !d.tunnels.HasPeer(pkt.Src.Node) {
		if !d.config.Encrypt || d.tunnels.HasCrypto(pkt.Src.Node) {
			d.tunnels.AddPeer(pkt.Src.Node, from)
			d.publishEvent("tunnel.peer_added", map[string]interface{}{
				"peer_node_id": pkt.Src.Node,
			})
		}
	}

	switch pkt.Protocol {
	case protocol.ProtoStream:
		d.handleStreamPacket(pkt)
	case protocol.ProtoDatagram:
		d.handleDatagramPacket(pkt)
	case protocol.ProtoControl:
		d.handleControlPacket(pkt)
	}
}

func (d *Daemon) handleStreamPacket(pkt *protocol.Packet) {
	// SYN — incoming connection request
	if pkt.HasFlag(protocol.FlagSYN) && !pkt.HasFlag(protocol.FlagACK) {
		ln := d.ports.GetListener(pkt.DstPort)
		if ln == nil {
			// Nothing listening — send RST
			d.sendRST(pkt)
			return
		}

		// Check for retransmitted SYN (connection already exists for this 4-tuple).
		// Only replay SYN-ACK for active connections (SynReceived or Established).
		// TIME_WAIT and CLOSED connections are ineligible: the peer's source port
		// was reused for a new connection, not a retransmit of the old one. Treating
		// them as retransmits resends a stale SYN-ACK seq that the new client rejects,
		// blocking the new connection for up to TimeWaitDuration + IdleSweepInterval.
		if existing := d.ports.FindConnection(pkt.DstPort, pkt.Src, pkt.SrcPort); existing != nil {
			existing.Mu.Lock()
			st := existing.State
			eAck := existing.RecvAck
			// P1-001: prefer the recorded SYN-ACK sequence over `SendSeq-1`.
			// Once data has been sent on this connection, SendSeq has drifted
			// forward and `SendSeq-1` is no longer the original SYN-ACK seq.
			var eSeq uint32
			if existing.SynAckSeqSet {
				eSeq = existing.SynAckSeq
			} else {
				eSeq = existing.SendSeq - 1 // pre-existing connections from older builds
			}
			existing.Mu.Unlock()
			if st == StateSynReceived || st == StateEstablished {
				// Active connection — resend SYN-ACK (genuine retransmit dedup).
				synack := &protocol.Packet{
					Version:  protocol.Version,
					Flags:    protocol.FlagSYN | protocol.FlagACK,
					Protocol: protocol.ProtoStream,
					Src:      pkt.Dst,
					Dst:      pkt.Src,
					SrcPort:  pkt.DstPort,
					DstPort:  pkt.SrcPort,
					Seq:      eSeq,
					Ack:      eAck,
					Window:   existing.RecvWindow(),
				}
				d.tunnels.Send(pkt.Src.Node, synack)
				return
			}
			// TIME_WAIT or CLOSED — source port reuse: fall through to create new connection.
		}

		// Trust gate: private nodes only accept SYN from trusted or same-network peers.
		// Runs before rate limiting so untrusted sources cannot waste rate-limit tokens.
		if !d.config.Public {
			srcNode := pkt.Src.Node
			trusted := d.handshakeTrusts(srcNode)
			if !trusted && d.reg() != nil {
				// Fall back to registry trust check (covers admin-set trust pairs + shared networks)
				var err error
				trusted, err = d.reg().CheckTrust(d.NodeID(), srcNode)
				if err != nil {
					slog.Warn("registry trust check failed (SYN)", "src_node", srcNode, "err", err)
				}
			}
			if !trusted {
				slog.Warn("SYN rejected: untrusted source", "src_node", srcNode, "src_addr", pkt.Src, "dst_port", pkt.DstPort)
				d.publishEvent("syn.rejected", map[string]interface{}{
					"dst_port": pkt.DstPort,
				})
				return // silent drop — no RST to avoid leaking node existence
			}
		}

		// Network policy: reject SYN if port/peer is not allowed
		if !d.evaluatePortPolicy(PolicyEventConnect, pkt.Dst.Network, pkt.DstPort, pkt.Src.Node, 0, "") {
			slog.Warn("SYN rejected: not allowed by network policy",
				"src_node", pkt.Src.Node, "dst_port", pkt.DstPort, "network", pkt.Dst.Network)
			d.publishEvent("syn.port_rejected", map[string]interface{}{
				"src_node_id": pkt.Src.Node,
				"dst_port":    pkt.DstPort,
				"network":     pkt.Dst.Network,
			})
			return // silent drop — don't reveal policy to attacker
		}

		// PILOT-343: whitelisted source nodes bypass both SYN rate gates.
		// Used for trusted operator peers (paired daemons, test rigs)
		// where the SYN-flood protection would otherwise interfere with
		// legitimate high-rate connection bursts.
		synWhitelisted := false
		if d.synWhitelistAll.Load() {
			synWhitelisted = true
		} else if wl := d.synWhitelist.Load(); wl != nil {
			if _, ok := (*wl)[pkt.Src.Node]; ok {
				synWhitelisted = true
			}
		}

		// SYN rate limiting
		if !synWhitelisted && !d.allowSYN() {
			slog.Warn("SYN rate limit exceeded", "src_addr", pkt.Src, "src_port", pkt.SrcPort)
			d.publishEvent("security.syn_rate_limited", map[string]interface{}{
				"src_addr_hash": redactID(pkt.Src.String()), "src_port": pkt.SrcPort,
			})
			return // silently drop — don't even RST (avoid amplification)
		}
		if !synWhitelisted && !d.allowSYNFromSource(pkt.Src.Node) {
			slog.Warn("per-source SYN rate limit exceeded", "src_node", pkt.Src.Node, "src_port", pkt.SrcPort)
			return
		}

		// Check per-port connection limit
		if d.ports.ConnectionCountForPort(pkt.DstPort) >= d.config.maxConnectionsPerPort() {
			slog.Warn("max connections per port reached, rejecting SYN", "port", pkt.DstPort, "src_addr", pkt.Src, "src_port", pkt.SrcPort)
			d.sendRST(pkt)
			return
		}

		// Check global connection limit
		if d.ports.TotalActiveConnections() >= d.config.maxTotalConnections() {
			slog.Warn("max total connections reached, rejecting SYN", "src_addr", pkt.Src, "src_port", pkt.SrcPort)
			d.sendRST(pkt)
			return
		}

		conn := d.ports.NewConnection(pkt.DstPort, pkt.Src, pkt.SrcPort)
		conn.Mu.Lock()
		// Use the destination address from the SYN as our local address.
		// This ensures the correct network-specific address is used for
		// multi-network connections (e.g. 1:0001.0000.0003 instead of
		// the primary 0:0000.0000.0003).
		conn.LocalAddr = pkt.Dst
		conn.State = StateSynReceived
		conn.RecvAck = pkt.Seq + 1
		conn.ExpectedSeq = pkt.Seq + 1 // first data segment after SYN
		conn.Mu.Unlock()
		d.publishEvent("conn.syn_received", map[string]interface{}{
			"src_addr": pkt.Src.String(), "src_port": pkt.SrcPort,
			"dst_port": pkt.DstPort, "conn_id": conn.ID,
		})

		// Process peer's receive window from SYN (H9 fix: always update, including Window==0)
		conn.RetxMu.Lock()
		prevWin := conn.PeerRecvWin
		conn.PeerRecvWin = int(pkt.Window) * MaxSegmentSize
		// prevWin==-1 is the sentinel (no advertisement yet); don't signal
		// window-opened on the first transition (unknown→zero would fire).
		winOpened := prevWin != -1 && conn.PeerRecvWin > prevWin && conn.WindowAvailable()
		conn.RetxMu.Unlock()
		if winOpened && conn.WindowCh != nil {
			select {
			case conn.WindowCh <- struct{}{}:
			default:
			}
		}

		// Send SYN-ACK with our receive window
		conn.Mu.Lock()
		synack := &protocol.Packet{
			Version:  protocol.Version,
			Flags:    protocol.FlagSYN | protocol.FlagACK,
			Protocol: protocol.ProtoStream,
			Src:      pkt.Dst,
			Dst:      pkt.Src,
			SrcPort:  pkt.DstPort,
			DstPort:  pkt.SrcPort,
			Seq:      conn.SendSeq,
			Ack:      conn.RecvAck,
			Window:   conn.RecvWindow(),
		}
		d.tunnels.Send(pkt.Src.Node, synack)
		conn.SynAckSeq = conn.SendSeq
		conn.SynAckSeqSet = true
		conn.SendSeq++
		conn.State = StateEstablished
		conn.Mu.Unlock()
		d.publishEvent("conn.established", map[string]interface{}{
			"src_addr": pkt.Src.String(), "src_port": pkt.SrcPort,
			"dst_port": pkt.DstPort, "conn_id": conn.ID,
		})

		d.startRetxLoop(conn)
		// Non-blocking push to accept queue — if full, clean up and RST.
		// v1.9.1: surface the drop via AcceptQueueDrops counter and a
		// dedicated webhook event so operators can detect overflow.
		// Without this signal, slow-Accept applications silently lose
		// inbound connections.
		// v1.9.1: TrySend is safe after Unbind — returns false instead of
		// panicking on a closed AcceptCh (bare send would crash routeLoop).
		if !ln.TrySend(conn) {
			drops := atomic.AddUint64(&d.AcceptQueueDrops, 1)
			slog.Warn("accept queue full after SYN-ACK, closing connection",
				"port", pkt.DstPort, "src_addr", pkt.Src, "drops_total", drops)
			conn.Mu.Lock()
			conn.State = StateClosed
			conn.Mu.Unlock()
			d.ports.RemoveConnection(conn.ID)
			d.sendRST(pkt)
			d.publishEvent("conn.accept_queue_full", map[string]interface{}{
				"port":        pkt.DstPort,
				"src_addr":    pkt.Src.String(),
				"src_port":    pkt.SrcPort,
				"drops_total": drops,
			})
		}
		return
	}

	// SYN-ACK — response to our dial
	if pkt.HasFlag(protocol.FlagSYN) && pkt.HasFlag(protocol.FlagACK) {
		conn := d.ports.FindConnection(pkt.DstPort, pkt.Src, pkt.SrcPort)
		if conn == nil {
			return
		}
		conn.Mu.Lock()
		if conn.State != StateSynSent {
			conn.Mu.Unlock()
			return
		}
		conn.RecvAck = pkt.Seq + 1
		conn.State = StateEstablished
		sendSeq := conn.SendSeq
		recvAck := conn.RecvAck
		conn.Mu.Unlock()

		conn.RecvMu.Lock()
		conn.ExpectedSeq = pkt.Seq + 1 // first data segment after SYN-ACK
		conn.RecvMu.Unlock()

		// Process peer's receive window from SYN-ACK (H9 fix: always update)
		conn.RetxMu.Lock()
		prevWin := conn.PeerRecvWin
		conn.PeerRecvWin = int(pkt.Window) * MaxSegmentSize
		winOpened := prevWin != -1 && conn.PeerRecvWin > prevWin && conn.WindowAvailable()
		conn.RetxMu.Unlock()
		if winOpened && conn.WindowCh != nil {
			select {
			case conn.WindowCh <- struct{}{}:
			default:
			}
		}

		// Send ACK with our receive window
		ack := &protocol.Packet{
			Version:  protocol.Version,
			Flags:    protocol.FlagACK,
			Protocol: protocol.ProtoStream,
			Src:      conn.LocalAddr,
			Dst:      pkt.Src,
			SrcPort:  pkt.DstPort,
			DstPort:  pkt.SrcPort,
			Seq:      sendSeq,
			Ack:      recvAck,
			Window:   conn.RecvWindow(),
		}
		d.tunnels.Send(pkt.Src.Node, ack)
		return
	}

	// FIN — remote close (or FIN-ACK acknowledging our FIN)
	if pkt.HasFlag(protocol.FlagFIN) {
		conn := d.ports.FindConnection(pkt.DstPort, pkt.Src, pkt.SrcPort)
		if conn != nil {
			conn.CloseRecvBuf()
			conn.Mu.Lock()
			wasFinWait := conn.State == StateFinWait
			wasTimeWait := conn.State == StateTimeWait
			conn.State = StateTimeWait
			// Only refresh LastActivity on the FIRST FIN. A peer's FIN-ACK
			// reply has FlagFIN set too; if we refresh on every FIN we keep
			// idleSweepLoop from reaping this conn, which combined with the
			// guarded send below would have created a packet-amplification
			// loop (storm) at line rate.
			if !wasTimeWait {
				conn.LastActivity = time.Now()
			}
			conn.KeepaliveUnacked = 0
			sendSeq := conn.SendSeq
			conn.Mu.Unlock()
			// If we were in FIN_WAIT, this is a FIN-ACK — clear retx buffer
			if wasFinWait {
				conn.RetxMu.Lock()
				conn.Unacked = nil
				conn.RetxMu.Unlock()
			}
			if !wasTimeWait {
				d.publishEvent("conn.fin", map[string]interface{}{
					"remote_addr": pkt.Src.String(), "remote_port": pkt.SrcPort,
					"local_port": pkt.DstPort, "conn_id": conn.ID,
				})
			}
			// Connection will be reaped by idleSweepLoop after TimeWaitDuration

			// Send FIN-ACK once, only on the FIRST FIN. Subsequent FINs are
			// our peer's FIN-ACK reply (or duplicates); echoing them back
			// triggers a storm because FIN-ACK has FlagFIN set.
			if !wasTimeWait {
				finack := &protocol.Packet{
					Version:  protocol.Version,
					Flags:    protocol.FlagFIN | protocol.FlagACK,
					Protocol: protocol.ProtoStream,
					Src:      conn.LocalAddr,
					Dst:      pkt.Src,
					SrcPort:  pkt.DstPort,
					DstPort:  pkt.SrcPort,
					Seq:      sendSeq,
					Ack:      pkt.Seq + 1,
				}
				d.tunnels.Send(pkt.Src.Node, finack)
			}
		}
		return
	}

	// RST
	if pkt.HasFlag(protocol.FlagRST) {
		conn := d.ports.FindConnection(pkt.DstPort, pkt.Src, pkt.SrcPort)
		if conn != nil {
			conn.Mu.Lock()
			conn.State = StateClosed
			conn.Mu.Unlock()
			conn.CloseRecvBuf()
			d.ports.RemoveConnection(conn.ID)
			d.publishEvent("conn.rst", map[string]interface{}{
				"remote_addr": pkt.Src.String(), "remote_port": pkt.SrcPort,
				"local_port": pkt.DstPort, "conn_id": conn.ID,
			})
		}
		return
	}

	// ACK — pure ACK or data packet
	if pkt.HasFlag(protocol.FlagACK) {
		conn := d.ports.FindConnection(pkt.DstPort, pkt.Src, pkt.SrcPort)
		if conn == nil {
			return
		}

		conn.Mu.Lock()
		conn.LastActivity = time.Now()
		conn.KeepaliveUnacked = 0
		conn.Mu.Unlock()

		// Update peer's receive window (H9 fix: always update, honor Window==0)
		conn.RetxMu.Lock()
		prevPeerWin := conn.PeerRecvWin
		conn.PeerRecvWin = int(pkt.Window) * MaxSegmentSize
		peerWinOpened := prevPeerWin != -1 && conn.PeerRecvWin > prevPeerWin && conn.WindowAvailable()
		conn.RetxMu.Unlock()
		if peerWinOpened && conn.WindowCh != nil {
			select {
			case conn.WindowCh <- struct{}{}:
			default:
			}
		}

		// Process ACK for retransmission tracking.
		// v1.9.1: removed the 'pkt.Ack > 0' guard — Ack=0 is the legitimate
		// cumulative ACK value after a 4 GiB uint32 sequence-space wraparound.
		// Decode SACK payload first so we can set isPureACK correctly: a packet
		// whose payload is only SACK blocks carries no user data and is a pure
		// ACK for dup-ACK detection purposes. Computing isPureACK as
		// len(pkt.Payload)==0 alone wrongly marks SACK-carrying ACKs as
		// non-pure, suppressing DupAckCount and blocking fast retransmit.
		sackBlocks, isSACK := DecodeSACK(pkt.Payload)
		{
			isPureACK := len(pkt.Payload) == 0 || isSACK
			// RFC 5681 §3.1 condition (e): a packet is only a duplicate ACK
			// when "the advertised window equals the advertised window in the
			// last incoming acknowledgment."  If the peer's receive window
			// changed (window update), condition (e) is violated and we must
			// not count this as a dup-ACK — set isPureACK=false so ProcessAck's
			// early-return suppresses DupAckCount.  SACKs always count as dup-
			// ACKs regardless of window changes (they report OOO data).
			if !isSACK && conn.PeerRecvWin != prevPeerWin {
				isPureACK = false
			}
			conn.ProcessAck(pkt.Ack, isPureACK)
		}

		// Check if payload is SACK info (not user data)
		if isSACK {
			conn.ProcessSACK(sackBlocks)
		} else if len(pkt.Payload) > 0 {
			conn.Mu.Lock()
			established := conn.State == StateEstablished
			if established {
				conn.LastActivity = time.Now()
				conn.Stats.BytesRecv += uint64(len(pkt.Payload))
				conn.Stats.SegsRecv++
			}
			conn.Mu.Unlock()
			if !established {
				return
			}
			// Deliver data using receive window (handles reordering)
			cumAck := conn.DeliverInOrder(pkt.Seq, pkt.Payload)
			conn.Mu.Lock()
			conn.RecvAck = cumAck
			conn.Mu.Unlock()

			// Check if we have out-of-order data — ACK immediately with SACK
			conn.RecvMu.Lock()
			hasOOO := len(conn.OOOBuf) > 0
			conn.RecvMu.Unlock()

			conn.AckMu.Lock()
			if hasOOO {
				// Immediate ACK with SACK blocks (trigger fast retransmit)
				conn.AckMu.Unlock()
				d.sendDelayedACK(conn)
			} else {
				// Delayed ACK: batch up to 2 segments or 40ms
				conn.PendingACKs++
				if conn.PendingACKs >= DelayedACKThreshold {
					conn.AckMu.Unlock()
					d.sendDelayedACK(conn)
				} else if conn.ACKTimer == nil {
					conn.ACKTimer = time.AfterFunc(DelayedACKTimeout, func() {
						d.sendDelayedACK(conn)
					})
					conn.AckMu.Unlock()
				} else {
					conn.AckMu.Unlock()
				}
			}
		}
	}
}

// sendDelayedACK sends a cumulative ACK for a connection, including SACK blocks if needed.
func (d *Daemon) sendDelayedACK(conn *Connection) {
	// Reset delayed ACK state
	conn.AckMu.Lock()
	if conn.ACKTimer != nil {
		conn.ACKTimer.Stop()
		conn.ACKTimer = nil
	}
	conn.PendingACKs = 0
	conn.AckMu.Unlock()

	conn.Mu.Lock()
	sendSeq := conn.SendSeq
	recvAck := conn.RecvAck
	conn.Mu.Unlock()

	ack := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagACK,
		Protocol: protocol.ProtoStream,
		Src:      conn.LocalAddr,
		Dst:      conn.RemoteAddr,
		SrcPort:  conn.LocalPort,
		DstPort:  conn.RemotePort,
		Seq:      sendSeq,
		Ack:      recvAck,
		Window:   conn.RecvWindow(),
	}

	// Include SACK blocks if we have out-of-order segments
	conn.RecvMu.Lock()
	sackBlocks := conn.SACKBlocks()
	conn.RecvMu.Unlock()
	if len(sackBlocks) > 0 {
		ack.Payload = EncodeSACK(sackBlocks)
		conn.Mu.Lock()
		conn.Stats.SACKSent += uint64(len(sackBlocks))
		conn.Mu.Unlock()
	}

	d.tunnels.Send(conn.RemoteAddr.Node, ack)
}

func (d *Daemon) handleDatagramPacket(pkt *protocol.Packet) {
	if len(pkt.Payload) == 0 {
		return
	}

	// Trust gate: private nodes only accept datagrams from trusted or same-network peers
	if !d.config.Public {
		srcNode := pkt.Src.Node
		trusted := d.handshakeTrusts(srcNode)
		if !trusted && d.reg() != nil {
			var err error
			trusted, err = d.reg().CheckTrust(d.NodeID(), srcNode)
			if err != nil {
				slog.Warn("registry trust check failed (datagram)", "src_node", srcNode, "err", err)
			}
		}
		if !trusted {
			slog.Warn("datagram rejected: untrusted source", "src_node", srcNode, "src_addr", pkt.Src, "dst_port", pkt.DstPort)
			d.publishEvent("datagram.rejected", map[string]interface{}{
				"dst_port": pkt.DstPort,
			})
			return
		}
	}

	// Network policy: reject datagram if not allowed
	if !d.evaluatePortPolicy(PolicyEventDatagram, pkt.Dst.Network, pkt.DstPort, pkt.Src.Node, len(pkt.Payload), "in") {
		slog.Warn("datagram rejected: not allowed by network policy",
			"src_node", pkt.Src.Node, "dst_port", pkt.DstPort, "network", pkt.Dst.Network)
		d.publishEvent("datagram.port_rejected", map[string]interface{}{
			"src_node_id": pkt.Src.Node,
			"dst_port":    pkt.DstPort,
			"network":     pkt.Dst.Network,
		})
		return
	}

	d.publishEvent("data.datagram", map[string]interface{}{
		"src_addr": pkt.Src.String(), "src_port": pkt.SrcPort,
		"dst_port": pkt.DstPort, "size": len(pkt.Payload),
	})
	d.ipc.DeliverDatagram(pkt.Src, pkt.SrcPort, pkt.DstPort, pkt.Payload)
}

func (d *Daemon) handleControlPacket(pkt *protocol.Packet) {
	if pkt.DstPort == protocol.PortPing {
		// Don't reply to a peer's pong: that would be a packet-amplification
		// loop. The pong's SrcPort is PortPing too (so DstPort==PortPing on
		// the receiver), so we have to differentiate by the FlagACK bit:
		// a request (echo) has Ack==0 + no FlagACK; a reply has FlagACK set.
		// relayProbeLoop emits probes with FlagACK already set + Seq=1 to
		// the same effect — a probe is its own pong, no further reply is
		// expected. See pkg/daemon/daemon.go:3175-3194 (relayProbeLoop).
		if pkt.HasFlag(protocol.FlagACK) {
			return
		}
		if !d.admitDataPlanePeer(pkt.Src.Node) {
			return
		}
		// Ping request — send pong back
		src := pkt.Dst
		if src.Node == 0 {
			// Path probes from v1.13.0–v1.13.9 leave Dst unset. The ping was
			// delivered to us, so we are its destination: name ourselves.
			// Echoing the zero Dst makes the pong claim node 0, the prober's
			// identity binding drops it as spoofed, and its path watchdog
			// resets this healthy path. A Dst that names a node is echoed
			// unchanged, as before.
			src.Node = d.tunnels.loadNodeID()
		}
		pong := &protocol.Packet{
			Version:  protocol.Version,
			Flags:    protocol.FlagACK,
			Protocol: protocol.ProtoControl,
			Src:      src,
			Dst:      pkt.Src,
			SrcPort:  protocol.PortPing,
			DstPort:  pkt.SrcPort,
			Seq:      pkt.Seq,
			Ack:      pkt.Seq + 1,
			Payload:  pkt.Payload,
		}
		d.tunnels.Send(pkt.Src.Node, pong)
	}
}

func (d *Daemon) sendRST(orig *protocol.Packet) {
	rst := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagRST,
		Protocol: protocol.ProtoStream,
		Src:      orig.Dst,
		Dst:      orig.Src,
		SrcPort:  orig.DstPort,
		DstPort:  orig.SrcPort,
	}
	d.tunnels.Send(orig.Src.Node, rst)
}

// DialConnection initiates a connection to a remote address:port.
// Wraps DialConnectionContext with context.Background() for callers
// that don't have cancellation semantics (handshake bootstrap,
// internal probes, tests). New code should prefer DialConnectionContext.
func (d *Daemon) DialConnection(dstAddr protocol.Addr, dstPort uint16) (*Connection, error) {
	return d.DialConnectionContext(context.Background(), dstAddr, dstPort)
}

// DialConnectionContext is the cancellable variant of DialConnection.
// Used by the IPC handler so a dial started on behalf of a pilotctl
// command is aborted (and its SYN_SENT entry removed) the moment the
// IPC client disconnects — no more orphan SYN_SENTs from Ctrl+C'd
// commands grinding through the full retry budget.
//
// Each call returns a fresh, independent *Connection (its own ephemeral
// port + SYN handshake). This matches BSD-socket semantics where
// concurrent connect() to the same (peer, port) yield independent
// streams. Issue #105: the previous (v1.9.1) per-(peer,port) dedup
// returned the SAME *Connection to every concurrent caller; under
// fan-in workloads (e.g. 10 task submissions racing) all callers
// shared one underlying conn-ID, the IPC driver's recvCh map keyed
// on conn-ID was overwritten by each subsequent registerRecvCh, and
// frames from multiple callers got muxed into a single byte stream
// — producing JSON-decode errors on the receiver and indefinite
// hangs on the senders waiting for a response that never came back
// to their (orphaned) Conn. The shared resource that genuinely
// benefits from per-peer dedup is the tunnel/x25519 handshake; that
// is already idempotent inside TunnelManager.AddPeer/HasPeer.
func (d *Daemon) DialConnectionContext(ctx context.Context, dstAddr protocol.Addr, dstPort uint16) (*Connection, error) {
	return d.dialConnectionLocked(ctx, dstAddr, dstPort)
}

// dialConnectionLocked is the leader's dial body. Followers in the
// dialFlight map wait on the leader's done channel and never reach
// this function. The ctx here is the leader's caller's context;
// cancellation tears down the in-flight SYN_SENT and returns
// ctx.Err() to followers via flight.err.
func (d *Daemon) dialConnectionLocked(ctx context.Context, dstAddr protocol.Addr, dstPort uint16) (*Connection, error) {
	// v1.9.1: bail before any side-effecting work if ctx is already
	// cancelled. iter 2 made the SYN-retry loop cancellable, but
	// ensureTunnel + port alloc + initial SYN send all happen BEFORE
	// the loop. Without this check, a pre-cancelled ctx still results
	// in a wire-side SYN going to the peer, who replies with SYN-ACK
	// for a connection the dialer already abandoned.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Enforce outbound port policy: prevent dialing ports blocked by the network
	if !d.evaluatePortPolicy(PolicyEventDial, dstAddr.Network, dstPort, dstAddr.Node, 0, "") {
		return nil, fmt.Errorf("port %d not allowed by network %d policy", dstPort, dstAddr.Network)
	}

	// Ensure we have a tunnel to the destination
	if err := d.ensureTunnel(dstAddr.Node); err != nil {
		return nil, err
	}

	// Compat mode: the daemon has no public UDP socket, so any direct
	// SYN we send out can't reach the peer. Pre-flip the routing
	// state to relay BEFORE the first SYN so it goes out via the
	// beacon WSS bridge on the first try, not after a 25-78s direct
	// retry budget burns. Same reasoning as the directRetries=0
	// branch in the retransmit loop below — we just need it earlier
	// so the initial SYN is correctly routed.
	if d.config.TransportMode == "compat" && !d.tunnels.IsRelayPeer(dstAddr.Node) {
		d.tunnels.SetRelayPeer(dstAddr.Node, true)
	}

	// Auto-initiate handshake toward known trusted agents when we have no
	// local trust entry yet. Scoped to the trusted-agents list so we don't
	// spray handshakes at arbitrary peers. Fires non-blocking so the
	// SYN-retry loop succeeds once the peer approves.
	//
	// d.handshakes is wired post-construction (see RegisterHandshakeService);
	// integration tests that build a Daemon directly without the plugin set
	// see it as nil — guard so this code path is a no-op there rather than
	// a nil-deref. The on-wire SYN still goes out below; we just skip the
	// proactive handshake when the plugin isn't loaded.
	if d.handshakes != nil && !d.handshakes.IsTrusted(dstAddr.Node) {
		// TODO(security/H4): IsTrusted keys on node_id only (no pubkey
		// binding). This gate is outbound — we proactively initiate toward
		// dstAddr — so the peer's authenticated pubkey is not in scope and
		// node_id match is all we can check here. Pubkey pinning belongs in
		// the upstream github.com/pilot-protocol/trustedagents module at its
		// inbound auto-accept path, where the presented key is available.
		if _, ok := trustedagents.IsTrusted(dstAddr.Node); ok {
			// Route through HandshakeSendRequest (not the plugin's raw
			// SendRequest) so the per-peer in-flight dedup catches the
			// recursive case: this proactive auto-handshake fires from
			// within DialConnection, and SendRequest itself eventually
			// calls back into DialConnection on port 444, which re-checks
			// this same gate. Without dedup that's a self-driving fanout
			// — verified locally 2026-05-31: ~12k "direct handshake
			// failed" entries within 800 ms for a single trusted-agents
			// peer, all from the recursive go-fired chain. The wrapper's
			// LoadOrStore caps it at one in-flight call per peer.
			//
			// The in-flight dedup catches CONCURRENT racers. It does NOT
			// catch the SEQUENTIAL retry storm that emerges when the
			// underlying SendRequest returns fast (e.g. sendMessage hits
			// ErrEphemeralExhausted): the slot is released within
			// microseconds and the next DialConnection re-fires the
			// goroutine immediately, producing 4k+ "direct handshake
			// failed" log lines per second (1 GB of daemon log in <4 h
			// observed against blockchain-ticker, node 19418, on
			// 2026-06-06). shouldAutoHandshake adds a per-peer time
			// cooldown so the auto-spawn fires at most once per
			// autoHandshakeCooldown, regardless of caller volume.
			// Explicit `pilotctl handshake` IPC calls still bypass this
			// gate.
			//
			// Returns are intentionally discarded — the goroutine is best
			// effort, just like before. ErrHandshakeInFlight short-circuit
			// is the dedup hit, which is the success case.
			if d.shouldAutoHandshake(dstAddr.Node) {
				go func() { _ = d.HandshakeSendRequest(dstAddr.Node, "") }()
			}
		}
	}

	localPort := d.ports.AllocEphemeralPort()
	if localPort == 0 {
		return nil, ErrEphemeralExhausted
	}
	conn := d.ports.NewConnection(localPort, dstAddr, dstPort)
	// Guard the initial state-mutation under conn.Mu — observers (test
	// helpers, idleSweepLoop, the IPC handler walking the conn table)
	// take conn.Mu before reading State; without the lock here, the
	// race detector flags the write/read pair. Pre-existing race that
	// was hidden until the v1.9.1 dedup test started observing
	// SYN_SENT entries from another goroutine.
	conn.Mu.Lock()
	conn.LocalAddr = protocol.Addr{Network: dstAddr.Network, Node: d.NodeID()}
	conn.State = StateSynSent
	conn.Mu.Unlock()

	// Send SYN with our receive window
	syn := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagSYN,
		Protocol: protocol.ProtoStream,
		Src:      conn.LocalAddr,
		Dst:      dstAddr,
		SrcPort:  localPort,
		DstPort:  dstPort,
		Seq:      conn.SendSeq,
		Window:   conn.RecvWindow(),
	}

	if err := d.tunnels.Send(dstAddr.Node, syn); err != nil {
		// ErrPendingDropped means the SYN itself IS queued; only an older
		// packet was dropped to make room. The tunnel is mid-handshake.
		// Don't abort the dial — the SYN will go out as soon as the key
		// exchange completes, and if not, the retry loop below will
		// retransmit. Aborting here turns a transient handshake-startup
		// condition into a hard "dial failed" for the user.
		if !errors.Is(err, ErrPendingDropped) {
			d.ports.RemoveConnection(conn.ID)
			return nil, fmt.Errorf("send SYN: %w", err)
		}
		slog.Debug("dial: SYN queued during tunnel handshake (will retransmit)",
			"peer_node_id", dstAddr.Node, "dst_port", dstPort)
	}
	conn.Mu.Lock()
	conn.SendSeq++
	conn.Mu.Unlock()

	// Wait for ESTABLISHED with SYN retransmission.
	// Phase 1: Direct connection (DialDirectRetries attempts).
	// Phase 2: Relay through beacon if direct fails (remaining attempts).
	retries := 0
	directRetries := DialDirectRetries
	maxRetries := DialMaxRetries
	// relayActive is set when this peer is currently flagged for relay.
	// We distinguish between PINNED flags (authoritative: registry
	// relay_only=true, beacon-admitted symmetric-NAT, ICMP-unreachable
	// threshold) and UNPINNED flags (set by a previous dial's failed
	// direct phase). Pinned: skip the direct retry budget entirely.
	// Unpinned: still try direct first — a previous dial's loss-induced
	// flip should not trap subsequent dials in relay-only mode when
	// the relay path is itself unhealthy (the 2026-05-26 worktree
	// diagnostic showed 80% wedge rate at 20% drop because the dial's
	// SetRelayPeer was sticky across dials).
	relayActive := d.tunnels.IsRelayPeer(dstAddr.Node)
	relayPinned := d.tunnels.IsRelayPinned(dstAddr.Node)
	// relayActivatedHere tracks whether THIS dial was the one that
	// flipped the peer to relay. On failure we clear our own (unpinned)
	// flip so the next dial isn't trapped in relay-only mode.
	relayActivatedHere := false
	if relayActive && relayPinned {
		directRetries = 0
	}
	rto := DialInitialRTO
	timer := time.NewTimer(rto)
	defer timer.Stop()

	check := time.NewTicker(DialCheckInterval)
	defer check.Stop()

	for {
		select {
		case <-ctx.Done():
			// Caller (typically the IPC client) gave up. Tear down the
			// half-open connection so it doesn't sit in SYN_SENT for the
			// rest of the retry budget. Counter-symptom: the
			// "ID 13/14/15 SYN_SENT" orphan rows in `pilotctl info`
			// after Ctrl+C — gone within ~1 ms of the cancel.
			d.ports.RemoveConnection(conn.ID)
			// Same cleanup as the maxRetries-exhausted path: if THIS
			// dial flipped the peer to advisory relay, drop the flag so
			// the next dial isn't trapped probing a (possibly broken)
			// relay path. Pinned flags are untouched.
			if relayActivatedHere && !d.tunnels.IsRelayPinned(dstAddr.Node) {
				d.tunnels.SetRelayPeer(dstAddr.Node, false)
			}
			return nil, ctx.Err()
		case <-check.C:
			conn.Mu.Lock()
			st := conn.State
			conn.Mu.Unlock()
			if st == StateEstablished || st == StateFinWait || st == StateTimeWait {
				// StateFinWait/StateTimeWait: the three-way handshake completed but
				// the remote closed before we observed ESTABLISHED. The connection
				// was successfully established — return it so the caller can handle
				// the closed state normally.
				if st == StateEstablished {
					d.startRetxLoop(conn)
				}
				// A completed handshake proves the outbound path is alive —
				// clears the rx-watchdog's partial-wedge signal.
				d.lastDialOKNano.Store(time.Now().UnixNano())
				d.consecutiveDialTimeouts.Store(0)
				return conn, nil
			}
			if st == StateClosed {
				// Symmetric with the ctx.Done and retries>maxRetries arms:
				// the connection is finished from this dial's perspective,
				// so release the slot immediately. StaleConnections does
				// catch StateClosed entries on its next tick, but until
				// then the conn occupies an ephemeral port AND counts toward
				// MaxTotalConnections — making the next dial fail under
				// burst even though nothing real holds the slot.
				d.ports.RemoveConnection(conn.ID)
				return nil, protocol.ErrConnRefused
			}
		case <-timer.C:
			retries++

			// Switch to relay mode after direct retries exhaust. Use
			// SetRelayPeer (not Pinned) so ClearRelayOnDirect can recover
			// the direct path if it becomes reachable again. The pinned
			// setter is reserved for registry relay_only=true signals and
			// beacon-admitted symmetric-NAT peers.
			if retries == directRetries && d.config.BeaconAddr != "" && !relayActive {
				slog.Info("direct dial timed out, switching to relay", "node_id", dstAddr.Node)
				d.tunnels.SetRelayPeer(dstAddr.Node, true)
				relayActive = true
				relayActivatedHere = true
				rto = DialInitialRTO // reset backoff for relay phase
			}

			if retries > maxRetries {
				d.ports.RemoveConnection(conn.ID)
				// v1.9.1: a peer that didn't respond to the full retry
				// budget (direct + relay) is reachably dead. Invalidate
				// the resolve / endpoint caches so the application's
				// next dial fetches fresh registry data instead of
				// re-dialing the same dead address for ResolveCacheTTL.
				d.forgetPeerResolution(dstAddr.Node)
				// Clear our advisory relay flip so the NEXT dial gets a
				// fresh shot at direct. Without this, one failed dial
				// pins the peer to a (possibly broken) relay path for
				// every subsequent dial — the 80%-wedge pattern from
				// the lossy diagnostic. Pinned peers (authoritative
				// signals) are untouched.
				if relayActivatedHere && !d.tunnels.IsRelayPinned(dstAddr.Node) {
					d.tunnels.SetRelayPeer(dstAddr.Node, false)
				}
				// Full direct+relay retry budget exhausted with no SYN-ACK.
				// Feeds the rx-watchdog's partial-wedge detector: a run of
				// these to distinct peers means our outbound is wedged.
				d.consecutiveDialTimeouts.Add(1)
				return nil, protocol.ErrDialTimeout
			}
			// Resend SYN (uses relay if relayActive)
			conn.Mu.Lock()
			syn.Seq = conn.SendSeq - 1
			conn.Mu.Unlock()
			d.tunnels.Send(dstAddr.Node, syn)
			rto = rto * 2 // exponential backoff
			if rto > DialMaxRTO {
				rto = DialMaxRTO
			}
			timer.Reset(rto)
		}
	}
}

// NagleTimeout is the maximum time to buffer small writes before flushing.
const NagleTimeout = 40 * time.Millisecond

// DelayedACKTimeout is the max time to delay an ACK (RFC 1122 suggests 500ms max, we use 40ms).
const DelayedACKTimeout = 40 * time.Millisecond

// DelayedACKThreshold is the number of segments to receive before sending an ACK immediately.
const DelayedACKThreshold = 2

// SendData sends data over an established connection.
// Implements Nagle's algorithm: small writes are coalesced into MSS-sized
// segments unless NoDelay is set. Large writes (>= MSS) are sent immediately.
// ErrSendBufFull is returned by SendData when the per-connection
// NagleBuf would exceed MaxNagleBuf if the caller's write were
// appended. Callers must back off and retry — typically by waiting
// for a webhook or polling the connection's send-buffer state.
//
// This error replaces the silent unbounded-growth behavior that
// could OOM the daemon when an application wrote faster than the
// network drained. Pinned by TestSendDataNagleBufGrowsUnbounded.
var ErrSendBufFull = errors.New("send buffer full")

func (d *Daemon) SendData(conn *Connection, data []byte) error {
	conn.Mu.Lock()
	st := conn.State
	conn.Mu.Unlock()
	if st != StateEstablished {
		return fmt.Errorf("connection not established")
	}

	// If Nagle is disabled (NoDelay), send everything immediately in segments
	if conn.NoDelay {
		return d.sendDataImmediate(conn, data)
	}

	conn.NagleMu.Lock()
	// v1.9.1: cap NagleBuf at MaxNagleBuf. Without this, slow peers /
	// full cwnd / packet loss caused the buffer to grow without bound,
	// linearly with offered-but-undeliverable load. ErrSendBufFull is
	// the application's signal to stop pushing — retry once buffer
	// drains. Caller-side: dataexchange.WriteFrame propagates this up.
	if len(conn.NagleBuf)+len(data) > MaxNagleBuf {
		conn.NagleMu.Unlock()
		return ErrSendBufFull
	}
	conn.NagleBuf = append(conn.NagleBuf, data...)
	conn.NagleMu.Unlock()

	return d.nagleFlush(conn)
}

// nagleFlush sends buffered data according to Nagle's algorithm:
// - Full MSS segments are always sent
// - Sub-MSS data is sent only if no unacknowledged data exists or timeout
func (d *Daemon) nagleFlush(conn *Connection) error {
	for {
		conn.NagleMu.Lock()
		if len(conn.NagleBuf) == 0 {
			conn.NagleMu.Unlock()
			return nil
		}

		// If we have at least MSS bytes, send a full segment
		if len(conn.NagleBuf) >= MaxSegmentSize {
			segment := make([]byte, MaxSegmentSize)
			copy(segment, conn.NagleBuf[:MaxSegmentSize])
			conn.NagleBuf = conn.NagleBuf[MaxSegmentSize:]
			conn.NagleMu.Unlock()

			if err := d.sendSegment(conn, segment); err != nil {
				return err
			}
			continue
		}

		// Sub-MSS data: check if we can send now (check under NagleMu).
		// Use BytesInFlight() rather than len(Unacked): SACKed entries
		// stay in Unacked until cumulative ACK removes them, but they
		// are already at the peer and should not delay a flush.
		conn.RetxMu.Lock()
		hasUnacked := conn.BytesInFlight() > 0
		conn.RetxMu.Unlock()

		if !hasUnacked {
			// No data in flight — send immediately (Nagle allows this)
			segment := make([]byte, len(conn.NagleBuf))
			copy(segment, conn.NagleBuf)
			conn.NagleBuf = conn.NagleBuf[:0]
			conn.NagleMu.Unlock()

			return d.sendSegment(conn, segment)
		}
		conn.NagleMu.Unlock()

		// Data in flight — wait for ACK or timeout
		nagleTimer := time.NewTimer(NagleTimeout)
		select {
		case <-conn.NagleCh:
			nagleTimer.Stop()
			// All data ACKed — flush now
		case <-nagleTimer.C:
			// Timeout — flush regardless
		case <-conn.RetxStop:
			nagleTimer.Stop()
			return protocol.ErrConnClosed
		}

		// Re-check under lock after waking
		conn.NagleMu.Lock()
		if len(conn.NagleBuf) == 0 {
			conn.NagleMu.Unlock()
			return nil
		}

		// Send whatever we have (might have reached MSS now)
		if len(conn.NagleBuf) >= MaxSegmentSize {
			conn.NagleMu.Unlock()
			continue // loop back to send full segments
		}

		segment := make([]byte, len(conn.NagleBuf))
		copy(segment, conn.NagleBuf)
		conn.NagleBuf = conn.NagleBuf[:0]
		conn.NagleMu.Unlock()

		return d.sendSegment(conn, segment)
	}
}

// sendDataImmediate sends data in MSS-sized segments without Nagle coalescing.
func (d *Daemon) sendDataImmediate(conn *Connection, data []byte) error {
	for offset := 0; offset < len(data); {
		end := offset + MaxSegmentSize
		if end > len(data) {
			end = len(data)
		}
		segment := data[offset:end]

		if err := d.sendSegment(conn, segment); err != nil {
			return err
		}
		offset = end
	}
	return nil
}

// sendSegment sends a single segment, waiting for the congestion window.
// Implements zero-window probing when the peer's receive window is 0.
func (d *Daemon) sendSegment(conn *Connection, data []byte) error {
	probeInterval := ZeroWinProbeInitial
	probeCount := 0

	// Wait for effective window to have space
	probeTimer := time.NewTimer(probeInterval)
	defer probeTimer.Stop()
	for {
		conn.RetxMu.Lock()
		avail := conn.WindowAvailable()
		conn.RetxMu.Unlock()
		if avail {
			break
		}

		// Window full — wait for ACK to open it, with zero-window probing
		select {
		case <-conn.WindowCh:
			probeInterval = ZeroWinProbeInitial
			probeCount = 0
			if !probeTimer.Stop() {
				select {
				case <-probeTimer.C:
				default:
				}
			}
			probeTimer.Reset(probeInterval)
		case <-conn.RetxStop:
			return protocol.ErrConnClosed
		case <-probeTimer.C:
			// Send zero-window probe (empty ACK) to trigger window update
			conn.Mu.Lock()
			probeSeq := conn.SendSeq
			probeAck := conn.RecvAck
			conn.Mu.Unlock()
			probe := &protocol.Packet{
				Version:  protocol.Version,
				Flags:    protocol.FlagACK,
				Protocol: protocol.ProtoStream,
				Src:      conn.LocalAddr,
				Dst:      conn.RemoteAddr,
				SrcPort:  conn.LocalPort,
				DstPort:  conn.RemotePort,
				Seq:      probeSeq,
				Ack:      probeAck,
				Window:   conn.RecvWindow(),
			}
			d.tunnels.Send(conn.RemoteAddr.Node, probe)
			probeCount++
			// P1-004: give up after MaxZeroWindowProbes rather than
			// probing a dead peer forever. RST the connection so the
			// sender sees an error instead of an opaque hang.
			if probeCount >= MaxZeroWindowProbes {
				slog.Warn("zero-window probe limit reached, aborting connection",
					"conn_id", conn.ID,
					"peer_node_id", conn.RemoteAddr.Node,
					"probes", probeCount)
				rst := &protocol.Packet{
					Version:  protocol.Version,
					Flags:    protocol.FlagRST,
					Protocol: protocol.ProtoStream,
					Src:      conn.LocalAddr,
					Dst:      conn.RemoteAddr,
					SrcPort:  conn.LocalPort,
					DstPort:  conn.RemotePort,
				}
				d.tunnels.Send(conn.RemoteAddr.Node, rst)
				conn.Mu.Lock()
				conn.State = StateClosed
				conn.Mu.Unlock()
				return protocol.ErrConnClosed
			}
			// Exponential backoff up to 30s
			probeInterval = probeInterval * 2
			if probeInterval > ZeroWinProbeMax {
				probeInterval = ZeroWinProbeMax
			}
			probeTimer.Reset(probeInterval)
		}
	}

	// v1.9.1: reserve seq atomically with the read — pre-incrementing SendSeq
	// inside the same Mu critical section prevents two concurrent sendSegment
	// callers from reading the same SendSeq and emitting packets with identical
	// sequence numbers (which causes the peer to discard one as a duplicate,
	// silently losing the data and corrupting the connection's seq state).
	conn.Mu.Lock()
	seq := conn.SendSeq
	conn.SendSeq += uint32(len(data))
	ack := conn.RecvAck
	conn.Mu.Unlock()
	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagACK,
		Protocol: protocol.ProtoStream,
		Src:      conn.LocalAddr,
		Dst:      conn.RemoteAddr,
		SrcPort:  conn.LocalPort,
		DstPort:  conn.RemotePort,
		Seq:      seq,
		Ack:      ack,
		Window:   conn.RecvWindow(),
		Payload:  data,
	}

	// v1.9.1: track before send so a tunnel failure doesn't consume the seq
	// slot without a retx entry — retxLoop can retry if Send returns an error.
	conn.TrackSend(seq, data)
	if err := d.tunnels.Send(conn.RemoteAddr.Node, pkt); err != nil {
		return err
	}
	conn.Mu.Lock()
	conn.LastActivity = time.Now()
	conn.Stats.BytesSent += uint64(len(data))
	conn.Stats.SegsSent++
	conn.Mu.Unlock()

	// Cancel delayed ACK — this data packet piggybacks the ACK
	conn.AckMu.Lock()
	if conn.ACKTimer != nil {
		conn.ACKTimer.Stop()
		conn.ACKTimer = nil
	}
	conn.PendingACKs = 0
	conn.AckMu.Unlock()

	return nil
}

// startRetxLoop starts the retransmission goroutine for a connection.
// RetxStop is initialized in PortManager.NewConnection so it is non-nil
// (and safe to read from RemoveConnection / idleSweepLoop) from the
// moment the connection is registered, regardless of whether the retx
// loop has been wired up yet.
func (d *Daemon) startRetxLoop(conn *Connection) {
	conn.RTO = InitialRTO
	conn.RetxSend = func(pkt *protocol.Packet) {
		d.tunnels.Send(conn.RemoteAddr.Node, pkt)
	}
	go d.retxLoop(conn)
}

func (d *Daemon) retxLoop(conn *Connection) {
	ticker := time.NewTicker(RetxCheckInterval)
	defer ticker.Stop()
	// L7 panic boundary (architecture-notes/03-INVARIANTS.md §8 +
	// P1-002): a panic inside retransmitUnacked would silently kill the
	// retransmit goroutine, stranding the connection with unacked
	// segments. Tear down THIS connection only — other connections in
	// the daemon must continue. recoverLayer publishes the bus event so
	// observability sees the per-conn teardown.
	defer recoverLayer("L7", "retxLoop", d.bus, func(_ any) {
		slog.Error("L7 retxLoop tearing down connection after panic",
			"conn_id", conn.ID,
			"remote_node_id", conn.RemoteAddr.Node)
		conn.CloseRecvBuf()
		d.ports.RemoveConnection(conn.ID)
	})

	for {
		select {
		case <-conn.RetxStop:
			return
		case <-ticker.C:
			conn.Mu.Lock()
			st := conn.State
			conn.Mu.Unlock()
			if st == StateEstablished {
				d.retransmitUnacked(conn)
			} else if st == StateFinWait {
				// retxLoop's job is to keep DATA delivery alive. Once we
				// move to FinWait, the local side has already sent its FIN
				// (it sits in Unacked as an isFIN sentinel). If there are
				// still real DATA segments in Unacked, keep retransmitting
				// them. Otherwise — only the FIN remains — exit and let
				// idleSweepLoop clean up. Without this exit, a connection
				// stuck waiting for FIN-ACK keeps a retxLoop goroutine
				// alive for ~MaxRetxAttempts × RTO ≈ 53 s, which under the
				// §4.8 stress workload accumulates ~20 lingering loops
				// per rep (busts the goroutine-delta gate).
				if !d.unackedHasData(conn) {
					return
				}
				d.retransmitUnacked(conn)
			} else if st == StateClosed {
				// Connection abandoned (max retransmit) — clean up immediately
				conn.CloseRecvBuf()
				d.ports.RemoveConnection(conn.ID)
				return
			} else {
				// TIME_WAIT or other non-active state — stop retransmitting
				// Cleanup is handled by idleSweepLoop
				return
			}
		}
	}
}

// unackedHasData returns true if conn.Unacked contains any non-FIN,
// non-SACKed entry. Used by retxLoop to decide whether the FinWait
// state still has work to do (real DATA still in flight) or just
// the FIN sentinel (no useful retx left).
func (d *Daemon) unackedHasData(conn *Connection) bool {
	conn.RetxMu.Lock()
	defer conn.RetxMu.Unlock()
	for _, e := range conn.Unacked {
		if e.isFIN || e.sacked {
			continue
		}
		return true
	}
	return false
}

func (d *Daemon) retransmitUnacked(conn *Connection) {
	conn.RetxMu.Lock()
	defer conn.RetxMu.Unlock()

	if len(conn.Unacked) == 0 {
		return
	}

	now := time.Now()

	// Only retransmit one segment per RTO period (like real TCP).
	if !conn.LastRetxTime.IsZero() && now.Sub(conn.LastRetxTime) < conn.RTO {
		return
	}

	// Find the first non-SACKed unacked segment that has timed out
	for _, e := range conn.Unacked {
		if e.sacked {
			continue
		}
		if now.Sub(e.sentAt) > conn.RTO {
			if e.attempts >= MaxRetxAttempts {
				// Too many retransmissions — abandon connection
				slog.Error("max retransmits exceeded, sending RST", "conn_id", conn.ID)
				// Send RST to notify the remote peer
				rst := &protocol.Packet{
					Version:  protocol.Version,
					Flags:    protocol.FlagRST,
					Protocol: protocol.ProtoStream,
					Src:      conn.LocalAddr,
					Dst:      conn.RemoteAddr,
					SrcPort:  conn.LocalPort,
					DstPort:  conn.RemotePort,
				}
				if conn.RetxSend != nil {
					conn.RetxSend(rst)
				}
				conn.Mu.Lock()
				conn.State = StateClosed
				conn.Mu.Unlock()
				return
			}

			conn.Mu.Lock()
			sendSeq := conn.SendSeq
			conn.Mu.Unlock()

			// RFC 5681 §3.1 eq. 4: ssthresh = max(FlightSize/2, 2*SMSS) on every
			// timeout expiry — unconditional, no exception for connections already
			// in fast recovery.  FlightSize = sum of ALL Unacked entries.
			var flightSize int
			for _, e := range conn.Unacked {
				flightSize += len(e.data)
			}
			conn.SSThresh = flightSize / 2
			if conn.SSThresh < 2*MaxSegmentSize {
				conn.SSThresh = 2 * MaxSegmentSize
			}
			conn.InRecovery = true
			conn.RecoveryPoint = sendSeq
			// Timeout resets to slow start per RFC 5681 §3.1 (LW = 1 SMSS).
			// InitialCongWin (RFC 6928, 10*SMSS) applies only at connection
			// startup; post-timeout cwnd must be 1 SMSS so the connection
			// re-enters slow start rather than jumping directly to CA.
			conn.CongWin = MaxSegmentSize

			// RFC 6298 §5.5–5.6: double RTO on every timeout expiry, not only
			// the first one.  Window reduction above is once-per-loss-event, but
			// the backoff applies each time the timer fires without an ACK.
			conn.RTO = conn.RTO * 2
			if conn.RTO > 10*time.Second {
				conn.RTO = 10 * time.Second
			}
			// P2-009: add 0-25% random jitter so many connections that
			// started at the same time don't retransmit in lockstep
			// under shared congestion. Cap still applies after jitter.
			jitter := time.Duration(rand.Int63n(int64(conn.RTO / 4)))
			conn.RTO += jitter
			if conn.RTO > 10*time.Second {
				conn.RTO = 10 * time.Second
			}

			e.attempts++
			e.sentAt = now
			conn.Mu.Lock()
			conn.Stats.Retransmits++
			conn.Mu.Unlock()
			// Timeout supersedes fast-recovery dup-ACK state: reset DupAckCount and
			// FastRecovery so the next new ACK does not execute the fast-recovery-exit
			// path (CongWin = SSThresh), which would override the timeout's
			// CongWin = MaxSegmentSize reduction.
			conn.DupAckCount = 0
			conn.FastRecovery = false
			conn.LastRetxTime = now

			conn.Mu.Lock()
			recvAck := conn.RecvAck
			conn.Mu.Unlock()

			// FIN retransmit: use e.isFIN (set by CloseConnection) rather than
			// state==FinWait. A data entry can time out before the FIN entry
			// reaches its RTO; using state would misidentify the data entry as
			// the FIN and send FlagFIN with the wrong sequence number.
			if e.isFIN {
				pkt := &protocol.Packet{
					Version:  protocol.Version,
					Flags:    protocol.FlagFIN,
					Protocol: protocol.ProtoStream,
					Src:      conn.LocalAddr,
					Dst:      conn.RemoteAddr,
					SrcPort:  conn.LocalPort,
					DstPort:  conn.RemotePort,
					Seq:      e.seq,
				}
				if conn.RetxSend != nil {
					conn.RetxSend(pkt)
				}
				return
			}

			pkt := &protocol.Packet{
				Version:  protocol.Version,
				Flags:    protocol.FlagACK,
				Protocol: protocol.ProtoStream,
				Src:      conn.LocalAddr,
				Dst:      conn.RemoteAddr,
				SrcPort:  conn.LocalPort,
				DstPort:  conn.RemotePort,
				Seq:      e.seq,
				Ack:      recvAck,
				Window:   conn.RecvWindow(),
				Payload:  e.data,
			}
			if conn.RetxSend != nil {
				conn.RetxSend(pkt)
			}
			return // only retransmit ONE segment per RTO
		}
		// Not timed out yet — continue checking remaining entries.
		// sentAt ordering is not guaranteed: a prior retransmit updates sentAt
		// for the retransmitted entry while later entries retain their original
		// (older) sentAt, so an entry after a recent-retransmit may be timed out.
	}
}

// CloseConnection sends FIN and enters FIN_WAIT. The FIN is tracked in the
// retransmission buffer so it will be retried if lost — the existing retxLoop
// handles it. When FIN-ACK is received the connection moves to TIME_WAIT and
// is eventually reaped by idleSweepLoop.
func (d *Daemon) CloseConnection(conn *Connection) {
	// Capture every conn field this function reads under Mu; reading them
	// post-unlock would race with concurrent state mutations from
	// handleStreamPacket / sendDelayedACK / sendSegment paths.
	// v1.9.1: pre-increment SendSeq inside this critical section so that a
	// concurrent sendSegment cannot read the same value and produce a data
	// segment with the same seq as the FIN sentinel (iter 24 fix, same
	// pattern as the sendSegment pre-increment fix in iter 23).
	conn.Mu.Lock()
	st := conn.State
	sendSeq := conn.SendSeq
	if st == StateEstablished {
		conn.SendSeq++ // reserve FIN seq atomically with the read
	}
	localAddr := conn.LocalAddr
	localPort := conn.LocalPort
	remoteAddr := conn.RemoteAddr
	remotePort := conn.RemotePort
	connID := conn.ID
	conn.Mu.Unlock()
	if st == StateEstablished && remotePort == protocol.PortDataExchange {
		d.publishEvent("file.delivered", map[string]interface{}{
			"remote_addr": remoteAddr.String(),
			"remote_port": remotePort,
			"conn_id":     connID,
		})
	}
	if st == StateEstablished {
		finData := []byte{0} // 1-byte sentinel so retxEntry has non-zero length
		fin := &protocol.Packet{
			Version:  protocol.Version,
			Flags:    protocol.FlagFIN,
			Protocol: protocol.ProtoStream,
			Src:      localAddr,
			Dst:      remoteAddr,
			SrcPort:  localPort,
			DstPort:  remotePort,
			Seq:      sendSeq,
		}
		d.tunnels.Send(remoteAddr.Node, fin)
		// Track FIN in retransmission buffer so the retxLoop retries it.
		// Use isFIN=true so retransmitUnacked can distinguish the FIN entry
		// from regular data entries (which must be retransmitted as data even
		// when the connection is in StateFinWait).
		conn.RetxMu.Lock()
		now := time.Now()
		conn.Unacked = append(conn.Unacked, &retxEntry{
			data:       finData,
			seq:        sendSeq,
			sentAt:     now,
			origSentAt: now,
			attempts:   1,
			isFIN:      true,
		})
		conn.RetxMu.Unlock()
	}
	conn.CloseRecvBuf()
	// P1-003: stop a pending delayed-ACK timer so it doesn't fire after
	// the connection is gone and queue an ACK for a dead peer. ACKTimer
	// is guarded by AckMu (see Connection field comment), NOT Mu — taking
	// Mu here would have raced with handleStreamPacket's delayed-ACK
	// scheduler (data race flagged by go test -race).
	conn.AckMu.Lock()
	if conn.ACKTimer != nil {
		conn.ACKTimer.Stop()
		conn.ACKTimer = nil
	}
	conn.AckMu.Unlock()
	conn.Mu.Lock()
	conn.State = StateFinWait
	conn.LastActivity = time.Now()
	conn.Mu.Unlock()
}

// SendDatagram sends an unreliable unicast packet. Broadcast addresses
// (Node=0xFFFFFFFF) are rejected — use BroadcastDatagram, which requires
// an admin token.
func (d *Daemon) SendDatagram(dstAddr protocol.Addr, dstPort uint16, data []byte) error {
	if dstAddr.IsBroadcast() {
		return fmt.Errorf("broadcast address requires admin token: use BroadcastDatagram")
	}
	// Enforce outbound port policy
	if !d.evaluatePortPolicy(PolicyEventDatagram, dstAddr.Network, dstPort, dstAddr.Node, len(data), "out") {
		slog.Warn("datagram rejected: not allowed by network policy",
			"direction", "out", "dst_node", dstAddr.Node, "dst_port", dstPort, "network", dstAddr.Network)
		d.publishEvent("datagram.port_rejected", map[string]interface{}{
			"direction":   "out",
			"dst_node_id": dstAddr.Node,
			"dst_port":    dstPort,
			"network":     dstAddr.Network,
		})
		return fmt.Errorf("port %d not allowed by network %d policy", dstPort, dstAddr.Network)
	}

	srcPort := d.ports.AllocEphemeralPort()
	if srcPort == 0 {
		return ErrEphemeralExhausted
	}

	if err := d.ensureTunnel(dstAddr.Node); err != nil {
		return err
	}

	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoDatagram,
		Src:      protocol.Addr{Network: dstAddr.Network, Node: d.NodeID()},
		Dst:      dstAddr,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Payload:  data,
	}

	return d.tunnels.Send(dstAddr.Node, pkt)
}

// BroadcastDatagram is the admin-gated entry point for sending a datagram
// to every member of a network. The admin token must be non-empty and equal
// to the daemon's configured Config.AdminToken (constant-time compare). With
// a valid token, broadcast is permitted on every network including the
// backbone (network 0); membership of the sender is NOT required — admin
// tokens are root-level. Per-recipient outbound port policy still applies.
func (d *Daemon) BroadcastDatagram(netID uint16, dstPort uint16, data []byte, adminToken string) error {
	home, _ := os.UserHomeDir()
	if !consent.GetConsent(home, "broadcasts") {
		slog.Debug("broadcast dropped: broadcasts consent is off")
		return nil
	}
	if d.config.AdminToken == "" {
		return fmt.Errorf("broadcast denied: daemon has no admin token configured")
	}
	if subtle.ConstantTimeCompare([]byte(adminToken), []byte(d.config.AdminToken)) != 1 {
		return fmt.Errorf("broadcast denied: invalid admin token")
	}
	srcPort := d.ports.AllocEphemeralPort()
	if srcPort == 0 {
		return ErrEphemeralExhausted
	}
	return d.broadcastDatagram(netID, srcPort, dstPort, data, adminToken)
}

// broadcastDatagram performs the per-peer fanout. Authentication is the
// caller's responsibility — exported callers must go through
// BroadcastDatagram, which enforces the admin-token check. Network 0 is
// permitted; sender membership is not checked. Per-recipient outbound port
// policy is still evaluated. The admin token (when non-empty) is forwarded
// to the registry so backbone enumeration (network 0) is unlocked.
func (d *Daemon) broadcastDatagram(netID uint16, srcPort, dstPort uint16, data []byte, adminToken string) error {
	if netID == 0 {
		return fmt.Errorf("broadcast not permitted on backbone network")
	}
	var resp map[string]interface{}
	var err error
	if adminToken != "" {
		resp, err = d.reg().ListNodes(netID, adminToken)
	} else {
		resp, err = d.reg().ListNodes(netID)
	}
	if err != nil {
		return fmt.Errorf("list nodes for broadcast: %w", err)
	}

	nodesRaw, ok := resp["nodes"].([]interface{})
	if !ok {
		return nil // no nodes
	}

	// Verify this daemon is a member of the network before broadcasting.
	selfID := d.NodeID()
	isMember := false
	for _, n := range nodesRaw {
		nm, ok := n.(map[string]interface{})
		if !ok {
			continue
		}
		if nid, ok := nm["node_id"].(float64); ok && uint32(nid) == selfID {
			isMember = true
			break
		}
	}
	if !isMember {
		return fmt.Errorf("broadcast denied: node %d is not a member of network %d", selfID, netID)
	}

	for _, n := range nodesRaw {
		nodeMap, ok := n.(map[string]interface{})
		if !ok {
			continue
		}
		nidVal, ok := nodeMap["node_id"].(float64)
		if !ok {
			continue
		}
		nodeID := uint32(nidVal)
		if nodeID == d.NodeID() {
			continue // skip self
		}

		// Evaluate outbound datagram policy per recipient
		if !d.evaluatePortPolicy(PolicyEventDatagram, netID, dstPort, nodeID, len(data), "out") {
			slog.Debug("broadcast: policy denied", "network_id", netID, "peer", nodeID)
			continue
		}

		if err := d.ensureTunnel(nodeID); err != nil {
			slog.Warn("broadcast: skip node", "node_id", nodeID, "error", err)
			continue
		}

		pkt := &protocol.Packet{
			Version:  protocol.Version,
			Protocol: protocol.ProtoDatagram,
			Src:      protocol.Addr{Network: netID, Node: d.NodeID()},
			Dst:      protocol.Addr{Network: netID, Node: nodeID},
			SrcPort:  srcPort,
			DstPort:  dstPort,
			Payload:  data,
		}
		d.tunnels.Send(nodeID, pkt)
	}
	return nil
}

// reapCaches evicts expired entries from the three peer-resolution caches.
// Called every DefaultIdleSweepInterval (15 s) from idleSweepLoop.
// Without this, caches grow monotonically as the node talks to new peers:
//   - epCache     — no read-time eviction; entries used as fallback even when stale.
//   - resolveCache — read-time TTL check returns nil but never deletes the entry.
//   - hostnameCache — same pattern as resolveCache.
func (d *Daemon) reapCaches() {
	now := time.Now()
	epEvictAfter := 12 * EndpointCacheTTL // keep fallback for up to 1 h
	rvEvictAfter := 2 * ResolveCacheTTL   // stale after TTL; keep 1 extra window
	hnEvictAfter := 2 * hostnameCacheTTL

	d.epCacheMu.Lock()
	for nodeID, e := range d.epCache {
		if now.Sub(e.cachedAt) > epEvictAfter {
			delete(d.epCache, nodeID)
		}
	}
	d.epCacheMu.Unlock()

	d.resolveCacheMu.Lock()
	for nodeID, e := range d.resolveCache {
		if now.Sub(e.cachedAt) > rvEvictAfter {
			delete(d.resolveCache, nodeID)
		}
	}
	d.resolveCacheMu.Unlock()

	d.hostnameCacheMu.Lock()
	for hostname, e := range d.hostnameCache {
		if now.Sub(e.cachedAt) > hnEvictAfter {
			delete(d.hostnameCache, hostname)
		}
	}
	d.hostnameCacheMu.Unlock()
}

// cacheEndpoint stores a resolved endpoint in the cache.
func (d *Daemon) cacheEndpoint(nodeID uint32, addr string) {
	d.epCacheMu.Lock()
	d.epCache[nodeID] = &endpointEntry{addr: addr, cachedAt: time.Now()}
	d.epCacheMu.Unlock()
}

// cachedEndpoint returns a previously cached endpoint, or empty string if none.
// The second return value is true if the entry exists (even if stale).
func (d *Daemon) cachedEndpoint(nodeID uint32) (string, bool) {
	d.epCacheMu.RLock()
	e, ok := d.epCache[nodeID]
	d.epCacheMu.RUnlock()
	if !ok {
		return "", false
	}
	return e.addr, true
}

// isEndpointStale returns true if the cached entry is older than EndpointCacheTTL.
// Stale entries are still usable as fallback, but a fresh resolve is preferred.
func (d *Daemon) isEndpointStale(nodeID uint32) bool {
	d.epCacheMu.RLock()
	e, ok := d.epCache[nodeID]
	d.epCacheMu.RUnlock()
	if !ok {
		return true
	}
	return time.Since(e.cachedAt) > EndpointCacheTTL
}

// CachedEndpoint returns a previously cached endpoint for a peer (exported for testing).
func (d *Daemon) CachedEndpoint(nodeID uint32) (string, bool) {
	return d.cachedEndpoint(nodeID)
}

// cachedResolve returns a cached registry resolve response if it exists and is fresh.
func (d *Daemon) cachedResolve(nodeID uint32) (map[string]interface{}, bool) {
	d.resolveCacheMu.RLock()
	e, ok := d.resolveCache[nodeID]
	d.resolveCacheMu.RUnlock()
	if !ok || time.Since(e.cachedAt) > ResolveCacheTTL {
		return nil, false
	}
	return e.resp, true
}

// cacheResolve stores a registry resolve response in the cache.
func (d *Daemon) cacheResolve(nodeID uint32, resp map[string]interface{}) {
	d.resolveCacheMu.Lock()
	d.resolveCache[nodeID] = &resolveEntry{resp: resp, cachedAt: time.Now()}
	d.resolveCacheMu.Unlock()
}

// prewarmTrustedResolves iterates trusted peers and warms the registry
// resolve cache for each. After this, ensureTunnel() on the dial path
// hits the in-memory cache instead of paying a registry round-trip.
//
// Does NOT fire ECDH key exchanges. An earlier version did, and the
// ~7-trusted-peer fleet observed here triggered a feedback storm:
// every sendKeyExchangeToNode marked the peer pendingRekey, the
// retransmit loop fired against ~7 peers simultaneously, and each
// peer's reply was interpreted by our handler as a fresh key-exchange
// request that rotated session keys mid-flight. Resulting symptom:
// pings worked for 5-10 seconds after restart, then dial timed out
// for minutes as session keys rotated faster than encrypted packets
// could decrypt. The encryption layer is intentionally left for the
// first real dial; we just want the resolve cache warm.
func (d *Daemon) prewarmTrustedResolves() {
	if d.handshakes == nil {
		return
	}
	// Brief delay so registration + beacon-refresh have settled before
	// we hit the registry.
	select {
	case <-time.After(2 * time.Second):
	case <-d.stopCh:
		return
	}
	peers := d.handshakes.TrustedPeers()
	if len(peers) == 0 {
		return
	}
	slog.Info("prewarming resolve cache for trusted peers", "count", len(peers))
	warmed := 0
	for _, rec := range peers {
		if d.stopping() {
			return
		}
		// ensureTunnel fetches the peer's UDP endpoint (real_addr / relay)
		// and registers it with the tunnel manager. Populates resolveCache
		// and epCache as a side effect. NO key exchange.
		if err := d.ensureTunnel(rec.NodeID); err != nil {
			slog.Debug("prewarm: ensureTunnel failed", "peer", rec.NodeID, "err", err)
			continue
		}
		warmed++
		// 200ms gap so a 50-peer fleet doesn't pile up at the registry.
		paceTimer := time.NewTimer(200 * time.Millisecond)
		select {
		case <-paceTimer.C:
		case <-d.stopCh:
			paceTimer.Stop()
			return
		}
	}
	slog.Info("prewarm complete", "peers_warmed", warmed)
}

// motdMirrorPath returns the on-disk location of the message-of-the-day
// mirror that pilotctl reads. It sits next to the persisted identity
// (normally ~/.pilot/), falling back to $HOME/.pilot when the daemon runs
// without identity persistence so the CLI — which always looks in
// ~/.pilot — still finds it. Empty only if the home directory can't be
// determined.
func (d *Daemon) motdMirrorPath() string {
	if d.config.IdentityPath != "" {
		return filepath.Join(filepath.Dir(d.config.IdentityPath), "motd.json")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".pilot", "motd.json")
}

// motdPollLoop periodically fetches the MOTD feed, selects the entry active
// for the current UTC day, stores it in d.motd, and mirrors it to disk for
// the CLI. A cleared/empty feed (or a removed entry) propagates within one
// interval as a cleared mirror, so the banner disappears on its own. The
// loop is a cheap no-op when no feed URL is configured.
func (d *Daemon) motdPollLoop() {
	url := d.config.MOTDFeedURL
	if url == "" {
		return
	}
	interval := d.config.MOTDInterval
	if interval <= 0 {
		interval = motd.DefaultInterval
	}
	client := d.newHTTPClient(10 * time.Second)

	// Fire once on startup so the banner is warm shortly after boot,
	// then settle into the interval.
	d.refreshMOTD(client, url)

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case <-t.C:
			d.refreshMOTD(client, url)
		}
	}
}

// refreshMOTD performs one fetch+select+mirror cycle. On a fetch error it
// keeps the last good mirror in place (offline tolerance) — a stale mirror
// can't show an out-of-date message because the CLI re-validates the UTC
// day on read.
func (d *Daemon) refreshMOTD(client *http.Client, url string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	feed, err := motd.Fetch(ctx, client, url)
	if err != nil {
		slog.Debug("motd fetch failed; keeping last mirror", "err", err)
		return
	}

	now := time.Now()
	msg, active := motd.SelectForToday(feed, now)

	d.motdMu.Lock()
	if active {
		d.motd = msg.Text
	} else {
		d.motd = ""
	}
	d.motdMu.Unlock()

	if path := d.motdMirrorPath(); path != "" {
		if err := motd.WriteMirror(path, msg, now); err != nil {
			slog.Debug("motd mirror write failed", "err", err, "path", path)
		}
	}
}

// hostnameCachePath returns the on-disk location of the persisted
// hostname cache, derived from the identity path. Empty if the daemon
// is in-memory only (no identity persistence configured).
func (d *Daemon) hostnameCachePath() string {
	if d.config.IdentityPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(d.config.IdentityPath), "hostname_cache.json")
}

// hostnameCacheDisk is the on-disk format for the hostname cache.
type hostnameCacheDisk struct {
	SavedAt   time.Time                         `json:"saved_at"`
	Hostnames map[string]hostnameCacheDiskEntry `json:"hostnames"`
}

type hostnameCacheDiskEntry struct {
	Resp     map[string]interface{} `json:"resp"`
	CachedAt time.Time              `json:"cached_at"`
}

// persistHostnameCache writes the in-memory hostname cache to disk so
// a daemon restart starts warm. Best-effort — errors are logged at
// debug level; a missing/corrupt file just means a slower first call.
// Held lock is read-only and brief; the JSON marshal happens after
// release.
func (d *Daemon) persistHostnameCache() {
	path := d.hostnameCachePath()
	if path == "" {
		return
	}
	d.hostnameCacheMu.RLock()
	snap := hostnameCacheDisk{
		SavedAt:   time.Now(),
		Hostnames: make(map[string]hostnameCacheDiskEntry, len(d.hostnameCache)),
	}
	for k, v := range d.hostnameCache {
		snap.Hostnames[k] = hostnameCacheDiskEntry{Resp: v.resp, CachedAt: v.cachedAt}
	}
	d.hostnameCacheMu.RUnlock()
	data, err := json.Marshal(snap)
	if err != nil {
		slog.Debug("persist hostname cache marshal failed", "err", err)
		return
	}
	if err := fsutil.AtomicWrite(path, data); err != nil {
		slog.Debug("persist hostname cache write failed", "err", err)
	}
}

// loadHostnameCache reads the persisted hostname cache from disk into
// memory at daemon startup. Stale entries (older than hostnameCacheTTL)
// are dropped — they'd be filtered by the read path anyway, but
// dropping them on load keeps memory tight.
func (d *Daemon) loadHostnameCache() {
	path := d.hostnameCachePath()
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		// First-run / missing file is normal — do not log.
		if !os.IsNotExist(err) {
			slog.Debug("hostname cache read failed", "err", err)
		}
		return
	}
	var snap hostnameCacheDisk
	if err := json.Unmarshal(data, &snap); err != nil {
		slog.Debug("hostname cache parse failed", "err", err)
		return
	}
	now := time.Now()
	loaded := 0
	d.hostnameCacheMu.Lock()
	for k, v := range snap.Hostnames {
		if now.Sub(v.CachedAt) >= hostnameCacheTTL {
			continue
		}
		d.hostnameCache[k] = &hostnameCacheEntry{resp: v.Resp, cachedAt: v.CachedAt}
		loaded++
	}
	d.hostnameCacheMu.Unlock()
	if loaded > 0 {
		slog.Info("hostname cache loaded from disk", "entries", loaded)
	}
}

// forgetPeerResolution invalidates the registry resolve cache and the
// fallback endpoint cache for a peer. Called when there is strong
// evidence the cached endpoint is wrong (dial timeout reached, ICMP
// unreachable threshold flipped to relay, peer explicitly removed).
// Without this, ensureTunnel keeps reusing a stale entry for up to
// ResolveCacheTTL (60 s) — silent dial failures against a dead address.
func (d *Daemon) forgetPeerResolution(nodeID uint32) {
	d.resolveCacheMu.Lock()
	delete(d.resolveCache, nodeID)
	d.resolveCacheMu.Unlock()

	d.epCacheMu.Lock()
	delete(d.epCache, nodeID)
	d.epCacheMu.Unlock()
}

// ensureTunnel makes sure we have a route to the given node.
// Requests beacon hole-punching for NAT traversal when beacon is configured.
// Uses a resolve cache (60s TTL) to avoid repeated registry calls during
// cron bursts, and an endpoint cache as fallback when the registry is unreachable.
func (d *Daemon) ensureTunnel(nodeID uint32) error {
	if d.tunnels.HasPeer(nodeID) {
		return nil
	}

	// Check resolve cache first (60s TTL) to avoid registry round-trip
	resp, cached := d.cachedResolve(nodeID)
	if !cached {
		// Cache miss — resolve from registry
		var err error
		rc := d.reg()
		resp, err = withRegistryDeadline(registryCallDeadline, func() (map[string]interface{}, error) {
			return rc.Resolve(nodeID, d.NodeID())
		})
		if err != nil {
			// Registry unreachable — fall back to cached endpoint
			if ep, ok := d.cachedEndpoint(nodeID); ok {
				stale := d.isEndpointStale(nodeID)
				slog.Warn("registry resolve failed, using cached endpoint",
					"node_id", nodeID, "cached_addr", ep, "stale", stale, "error", err)
				udpAddr, udpErr := net.ResolveUDPAddr("udp", ep)
				if udpErr != nil {
					return fmt.Errorf("resolve cached %s: %w", ep, udpErr)
				}
				d.tunnels.AddPeer(nodeID, udpAddr)
				return nil
			}
			return fmt.Errorf("resolve node %d: %w", nodeID, err)
		}
		// Store in resolve cache for subsequent calls within TTL
		d.cacheResolve(nodeID, resp)
	}

	realAddr, ok := resp["real_addr"].(string)
	if !ok || realAddr == "" {
		return fmt.Errorf("node %d has no real address", nodeID)
	}

	// Same-LAN detection: if peer has LAN addresses matching our subnet, use LAN directly.
	// Skip if the registered address is already loopback (tests, same-host) or if our
	// tunnel is bound to a different address family (e.g. IPv6 tunnel vs IPv4 LAN).
	targetAddr := realAddr
	realHost, _, _ := net.SplitHostPort(realAddr)
	realIP := net.ParseIP(realHost)
	isLoopback := realIP != nil && realIP.IsLoopback()
	if !isLoopback {
		if lanAddrs, ok := resp["lan_addrs"].([]interface{}); ok && len(lanAddrs) > 0 {
			if lanAddr := matchLANSubnet(d.lanAddrs, lanAddrs); lanAddr != "" {
				if !d.addrFamilyMismatch(lanAddr) {
					targetAddr = lanAddr
					slog.Info("same-LAN peer detected, using LAN address", "node_id", nodeID, "lan_addr", lanAddr)
				} else {
					slog.Debug("same-LAN peer skipped: address family mismatch with tunnel", "lan_addr", lanAddr)
				}
			}
		}
	}

	// Cache the resolved endpoint for fallback
	d.cacheEndpoint(nodeID, targetAddr)

	udpAddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", targetAddr, err)
	}

	// Task 32 — relay-by-default hint: if the registry indicates the
	// target is RelayOnly, skip the NAT punch request (which would make
	// the beacon reveal the peer's real IP via PunchCommand back to us)
	// and flip the peer's relay flag immediately. This closes the
	// punch-coordination leak: A learns nothing about B's IP, and packets
	// flow A → beacon → B as MsgRelay frames.
	relayOnly, _ := resp["relay_only"].(bool)
	if relayOnly {
		// Pin the relay flag — the registry's relay_only=true is an
		// authoritative signal. clearRelayOnDirectLocked must not
		// auto-flip pinned peers back to direct based on observed
		// non-beacon source addresses (NAT-port-rewrite, beacon mesh
		// forward from a different IP, etc).
		d.tunnels.SetRelayPeerPinned(nodeID, true)
		d.tunnels.AddPeer(nodeID, udpAddr) // udpAddr is already the beacon (substituted by registry)
		slog.Debug("peer is RelayOnly, skipping hole punch", "node_id", nodeID)
		return nil
	}

	// Only request hole-punching if NOT using LAN address
	if targetAddr == realAddr && d.config.BeaconAddr != "" {
		d.tunnels.RequestHolePunch(nodeID)
	}

	d.tunnels.AddPeer(nodeID, udpAddr)
	return nil
}

// T4.3 (P9/P10): The legacy heartbeatLoop spanned L4 + L5/L8 + L11 — registry
// trust republish, beacon NAT-mapping refresh, relayed-handshake polling, and
// observability heartbeat publish were chained off a single ticker, with the
// downstream concerns gated on a successful registry heartbeat. That violated
// P9 ("Layer-spanning loops forbidden") and P10 ("State ownership documented
// per block").
//
// The loop is now split into four goroutines, one per layer of state owned:
//
//   - trustRepublishLoop (L5/L8): regConn.Heartbeat + reRegister. Owns
//     registry-side identity republish state (consecutiveFailures, backoff).
//     Touches no tunnel state.
//   - tunnelKeepaliveLoop (L4): tunnels.RegisterWithBeacon. Owns the L4 NAT
//     mapping refresh against the selected beacon. Briefly RLocks tm.mu via
//     RegisterWithBeacon — the only loop that touches tm.mu per tick.
//   - handshakePollLoop (L11): pollRelayedHandshakes. Drives the plugin-tier
//     handshake manager (L11) by polling registry for relayed handshake
//     traffic. Touches no tunnel state.
//   - observabilityHeartbeatLoop (L11): publishes agent.heartbeat to the bus
//     so subscribers (webhook bridge, dashboards, plugins) can observe a
//     live daemon. Owns no transport, no registry state.
//
// Note on the per-tunnel transport keepalive (L4/L7 MsgKeepalive): the
// keepalive that pokes peers below the consumer-NAT 30 s idle window lives at
// TunnelManager.keepaliveLoop (tunnel.go), spawned by TunnelManager.Listen
// and tied to TunnelKeepaliveInterval — distinct from this daemon-level
// tunnelKeepaliveLoop, which handles the beacon-side NAT mapping refresh.
//
// Each loop stops on d.stopCh and uses an independent ticker derived from
// d.config.keepaliveInterval(). A 0-5 s jitter is applied to the initial tick
// of each loop independently to avoid thundering-herd at startup.

// trustRepublishLoop (L5/L8) sends the periodic identity heartbeat to the
// registry and re-registers on persistent failure. Owns no tunnel state.
func (d *Daemon) trustRepublishLoop() {
	// 0-5 s startup jitter to avoid thundering herd after a registry restart.
	time.Sleep(time.Duration(rand.Int63n(int64(5 * time.Second))))

	ticker := time.NewTicker(d.config.keepaliveInterval())
	defer ticker.Stop()
	consecutiveFailures := 0
	reregBackoff := 100 * time.Millisecond
	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			rc := d.reg()
			if rc == nil {
				continue
			}
			_, err := withRegistryDeadline(registryCallDeadline, func() (map[string]interface{}, error) {
				return rc.Heartbeat(d.NodeID())
			})
			if err != nil {
				consecutiveFailures++
				if errors.Is(err, errRegistryCallTimedOut) {
					slog.Warn("heartbeat timed out — registry connection likely half-open, forcing reconnect",
						"consecutive_failures", consecutiveFailures, "deadline", registryCallDeadline)
					if rcErr := d.forceReconnectRegistry(); rcErr != nil {
						slog.Warn("registry force-reconnect failed", "error", rcErr)
					} else {
						consecutiveFailures = HeartbeatReregThresh
					}
				}
				// If the registry rejects our identity (node not found, or a
				// signature-verification failure because someone else claimed
				// our node ID) re-register on this cycle instead of waiting
				// for the full failure threshold to elapse.
				if isRegistryRejectingUsErr(err) && consecutiveFailures < HeartbeatReregThresh {
					consecutiveFailures = HeartbeatReregThresh
				}
				slog.Warn("heartbeat failed", "consecutive_failures", consecutiveFailures, "error", err)

				if consecutiveFailures >= HeartbeatReregThresh {
					// Backoff with jitter before attempting re-registration.
					jitter := time.Duration(rand.Int63n(int64(reregBackoff) / 2))
					time.Sleep(reregBackoff + jitter)

					slog.Info("attempting re-registration", "backoff", reregBackoff)
					d.reRegister()
					consecutiveFailures = 0

					// Exponential backoff: 100ms → 200ms → 400ms → ... → 30s max.
					reregBackoff *= 2
					if reregBackoff > 30*time.Second {
						reregBackoff = 30 * time.Second
					}
				}
			} else {
				if consecutiveFailures > 0 {
					slog.Info("heartbeat recovered", "previous_failures", consecutiveFailures)
				}
				consecutiveFailures = 0
				reregBackoff = 100 * time.Millisecond
				d.lastRegistryOKNano.Store(time.Now().UnixNano())
			}
		}
	}
}

// tunnelKeepaliveLoop (L4) refreshes the daemon's beacon registration so the
// beacon retains a fresh endpoint for hole-punching and the upstream NAT
// keeps the source mapping alive. Owns L4 beacon state only; briefly RLocks
// tm.mu inside RegisterWithBeacon.
func (d *Daemon) tunnelKeepaliveLoop() {
	// Independent jitter so this loop does not align with trustRepublishLoop.
	time.Sleep(time.Duration(rand.Int63n(int64(5 * time.Second))))

	ticker := time.NewTicker(d.config.keepaliveInterval())
	defer ticker.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			if d.config.BeaconAddr == "" {
				continue
			}
			d.tunnels.RegisterWithBeacon()
		}
	}
}

// handshakePollLoop (L11) polls the registry for relayed handshake requests
// and responses and dispatches them into the plugin-tier handshake manager.
// Owns no transport state. Independent of trustRepublishLoop's failure
// tracking — handshake polling is best-effort and survives transient
// registry hiccups on its own.
func (d *Daemon) handshakePollLoop() {
	// Independent jitter so this loop does not align with the others.
	time.Sleep(time.Duration(rand.Int63n(int64(5 * time.Second))))

	ticker := time.NewTicker(d.config.keepaliveInterval())
	defer ticker.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			if d.reg() == nil {
				continue
			}
			d.pollRelayedHandshakes()
		}
	}
}

// observabilityHeartbeatLoop (L11) publishes an "agent.heartbeat" event to
// the in-process bus on every tick. Subscribers (webhook bridge, dashboards,
// plugins) use it as a liveness signal: a daemon that stops heartbeating
// within ~2 × keepaliveInterval is considered down. This loop owns no
// transport state, no registry state, and never blocks on either — it is
// strictly an observability emitter, independent of trustRepublishLoop's
// success or failure.
func (d *Daemon) observabilityHeartbeatLoop() {
	// Independent jitter so this loop does not align with the others.
	time.Sleep(time.Duration(rand.Int63n(int64(5 * time.Second))))

	ticker := time.NewTicker(d.config.keepaliveInterval())
	defer ticker.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.publishHeartbeatEvent()
		}
	}
}

// publishHeartbeatEvent publishes a single "agent.heartbeat" event with the
// daemon's stable identity (node_id + address). Factored out so tests can
// drive it deterministically without waiting on the loop's ticker. The bus
// itself stamps NodeID and Time on the Event envelope; the payload carries
// only what subscribers cannot infer from the envelope.
func (d *Daemon) publishHeartbeatEvent() {
	d.publishEvent("agent.heartbeat", map[string]any{
		"address": d.Addr().String(),
		"node_id": d.NodeID(),
	})
}

// reRegister re-registers with the registry after a connection loss or registry restart.
// Checks d.stopCh between regConn calls to avoid racing with Stop().
func (d *Daemon) reRegister() {
	if d.stopping() {
		return
	}

	var registrationAddr string
	if d.config.Endpoint != "" {
		registrationAddr = d.config.Endpoint
	} else {
		registrationAddr = resolveLocalAddr(d.config.ListenAddr)
		if d.tunnels.LocalAddr() != nil {
			registrationAddr = resolveLocalAddr(d.tunnels.LocalAddr().String())
		}
	}

	// Always re-register with client-generated key.
	// Hold identityMu.RLock for the snapshot so RotateKey (which
	// takes Lock to swap d.identity) can't tear the read here.
	// Surfaced by §4.8 stress under -race when pilotctl key rotate
	// fires while trustRepublishLoop is mid-tick.
	d.identityMu.RLock()
	pubKeyB64 := crypto.EncodePublicKey(d.identity.PublicKey)
	d.identityMu.RUnlock()
	resp, err := d.reg().RegisterWithKeyOpts(registry.RegisterOpts{
		ListenAddr: registrationAddr,
		PublicKey:  pubKeyB64,
		Owner:      d.config.Owner,
		LANAddrs:   d.lanAddrs,
		Version:    d.config.Version,
		RelayOnly:  d.config.RelayOnly, // task 32
	})
	if err != nil {
		slog.Error("re-registration failed", "error", err)
		return
	}

	nodeIDVal, ok := resp["node_id"].(float64)
	if !ok {
		slog.Error("re-registration: missing node_id in response")
		return
	}
	newNodeID := uint32(nodeIDVal)
	addrStr, ok := resp["address"].(string)
	if !ok {
		slog.Error("re-registration: missing address in response")
		return
	}
	newAddr, err := protocol.ParseAddr(addrStr)
	if err != nil {
		slog.Error("re-registration: invalid address", "address", addrStr, "error", err)
		return
	}

	d.addrMu.Lock()
	if newNodeID != d.nodeID {
		slog.Warn("re-registered with new node ID", "new_node_id", newNodeID, "old_node_id", d.nodeID)
		d.nodeID = newNodeID
		d.addr = newAddr
		d.tunnels.SetNodeID(d.nodeID)
	}
	nodeID := d.nodeID
	slog.Info("re-registered", "node_id", nodeID, "addr", d.addr)
	d.addrMu.Unlock()
	d.lastRegistryOKNano.Store(time.Now().UnixNano())
	d.publishEvent("node.reregistered", map[string]interface{}{
		"address": d.addr.String(),
	})
	d.publishEvent("agent.registered", map[string]interface{}{
		"address":      d.addr.String(),
		"node_id":      nodeID,
		"reregistered": true,
	})

	if d.stopping() {
		return
	}

	// Restore visibility and hostname after re-registration
	if d.config.Public {
		if _, err := d.reg().SetVisibility(nodeID, true); err != nil {
			slog.Warn("re-registration: failed to restore visibility", "error", err)
		}
	}
	if d.config.Hostname != "" {
		if _, err := d.reg().SetHostname(nodeID, d.config.Hostname); err != nil {
			slog.Warn("re-registration: failed to restore hostname", "error", err)
		}
	}

	if d.stopping() {
		return
	}

	// Re-sync local trust pairs to registry (trust survives disconnection locally
	// but the registry may have lost and re-loaded state)
	if d.handshakes != nil {
		peers := d.handshakes.TrustedPeers()
		for _, rec := range peers {
			if d.stopping() {
				return
			}
			if _, err := d.reg().ReportTrust(nodeID, rec.NodeID); err != nil {
				slog.Debug("re-registration: failed to re-sync trust pair", "peer", rec.NodeID, "error", err)
			}
		}
		if len(peers) > 0 {
			slog.Info("re-synced trust pairs", "count", len(peers))
		}
	}

	// Re-register with beacon for NAT traversal
	if d.config.BeaconAddr != "" {
		d.tunnels.RegisterWithBeacon()
	}
}

// reapStalePeers removes tunnel peers that have no active connections
// and haven't been contacted for peerReapIdleTimeout. Called periodically
// from idleSweepLoop to prevent unbounded growth of per-peer maps
// (tm.peers, routing relay/blackhole/send-err maps, keyexchange
// pubkey/rekey state) in long-running daemons with peer churn.
func (d *Daemon) reapStalePeers() {
	const peerReapIdleTimeout = 5 * time.Minute

	active := d.ports.ActiveNodeIDs()
	now := time.Now()
	peers := d.tunnels.PeerList()

	for _, p := range peers {
		if active[p.NodeID] {
			continue // has active connection — keep
		}

		lastDirect := d.tunnels.LastDirectRecv(p.NodeID)
		lastOutbound, ok := d.tunnels.LastOutboundSend(p.NodeID)

		// Find the latest known contact.
		latest := lastDirect
		if ok && lastOutbound.After(latest) {
			latest = lastOutbound
		}

		if latest.IsZero() {
			// Never contacted — fresh peer entry, don't reap yet.
			continue
		}

		if now.Sub(latest) > peerReapIdleTimeout {
			slog.Debug("reaping stale peer", "node_id", p.NodeID,
				"last_contact", latest.Round(time.Second),
				"has_encryption", p.Encrypted)
			d.tunnels.RemovePeer(p.NodeID)
		}
	}
}

// hostnameReannounceLoop periodically re-sets the daemon's hostname
// with the registry, so hostname resolution self-heals after a registry
// restart/roll that wipes the in-memory hostname store.
func (d *Daemon) hostnameReannounceLoop() {
	ticker := time.NewTicker(hostnameReannounceInterval)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			if d.config.Hostname == "" || d.reg() == nil {
				continue
			}
			if _, err := d.reg().SetHostname(d.NodeID(), d.config.Hostname); err != nil {
				slog.Debug("hostname reannounce failed", "hostname", d.config.Hostname, "error", err)
			}
		}
	}
}

// idleSweepLoop periodically sends keepalive probes and closes dead connections.
func (d *Daemon) idleSweepLoop() {
	ticker := time.NewTicker(DefaultIdleSweepInterval)
	defer ticker.Stop()
	idleTimeout := d.config.idleTimeout()
	keepaliveInterval := d.config.keepaliveInterval()
	timeWaitDur := d.config.timeWaitDuration()
	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			// Clean up stale non-established connections (CLOSED, FIN_WAIT, etc.)
			stale := d.ports.StaleConnections(timeWaitDur)
			for _, conn := range stale {
				conn.CloseRecvBuf()
				d.ports.RemoveConnection(conn.ID)
			}

			// Close connections idle beyond timeout
			dead := d.ports.IdleConnections(idleTimeout)
			for _, conn := range dead {
				slog.Debug("closing dead connection", "conn_id", conn.ID, "idle_timeout", idleTimeout, "remote_addr", conn.RemoteAddr, "remote_port", conn.RemotePort)
				d.publishEvent("conn.idle_timeout", map[string]interface{}{
					"remote_addr": conn.RemoteAddr.String(), "remote_port": conn.RemotePort,
					"local_port": conn.LocalPort, "conn_id": conn.ID,
				})
				d.CloseConnection(conn)
			}

			// Reap stale per-source SYN rate limit buckets
			d.reapPerSrcSYN()

			// Reap stale "queue full" log-throttle entries so
			// lastPendDropLog doesn't accumulate one slot per
			// unique-peer-ever-throttled.
			d.tunnels.reapPendDropLog()

			// Evict expired entries from the three peer-resolution caches.
			// epCache: stale-but-usable after EndpointCacheTTL; evict after 1 hour.
			// resolveCache and hostnameCache: strictly TTL-gated on read; evict after 2× TTL.
			d.reapCaches()

			// Reap stale tunnel peers that have no active connections and
			// haven't been contacted recently. Prevents unbounded growth of
			// per-peer maps in long-running daemons with peer churn.
			d.reapStalePeers()

			// Keepalive probes + dead-peer detection. See keepaliveSweep
			// for details. Extracted into its own method so tests can
			// drive a single tick without standing up the full ticker.
			d.keepaliveSweep(keepaliveInterval)
		}
	}
}

// keepaliveSweep runs one iteration of the keepalive-probe / dead-peer
// detection loop. For each connection idle beyond `keepaliveInterval`:
//
//   - If it's in StateEstablished and 3 prior probes already went
//     unanswered, close it politely via CloseConnection (sends FIN
//     with retx tracking, transitions to StateFinWait). This is
//     intentionally NOT a RST: an idle StateEstablished connection
//     is the expected steady-state after a successful request/reply
//     cycle (pilot's pseudo-TCP has no half-close API), so RST'ing
//     it poisons the peer's session table for that conn_id and
//     cascades into "dial: connection refused" on the peer's next
//     outbound to us. Observed fleet-wide on 2026-05-11 as bursts
//     of N successful sends followed by total loss of reachability
//     for a peer; root cause was the prior inline-RST keepalive
//     reaper. CloseConnection's FIN lets the peer cleanly transition
//     FIN-ACK → StateTimeWait → reap with no poisoning.
//
//   - Otherwise, increment KeepaliveUnacked and send a probe packet
//     (FlagACK only). The probe doubles as a NAT-keepalive: it bumps
//     the consumer-NAT idle timer for our external mapping every
//     keepaliveInterval, holding the inbound path open between
//     application-driven sends.
//
// Exposed (unexported, same-package) so the white-box tests in
// zz_keepalive_fin_not_rst_test.go can drive a single tick without
// the ticker-loop overhead.
func (d *Daemon) keepaliveSweep(keepaliveInterval time.Duration) {
	idle := d.ports.IdleConnections(keepaliveInterval)
	for _, conn := range idle {
		conn.Mu.Lock()
		st := conn.State
		sendSeq := conn.SendSeq
		recvAck := conn.RecvAck
		kaUnacked := conn.KeepaliveUnacked
		conn.Mu.Unlock()
		if st != StateEstablished {
			continue
		}
		if kaUnacked >= 3 {
			slog.Info("idle peer reaped (3 keepalives unanswered, sending FIN)",
				"conn_id", conn.ID, "remote_addr", conn.RemoteAddr, "remote_port", conn.RemotePort)
			d.publishEvent("conn.dead_peer", map[string]interface{}{
				"remote_addr": conn.RemoteAddr.String(), "remote_port": conn.RemotePort,
				"local_port": conn.LocalPort, "conn_id": conn.ID,
			})
			d.CloseConnection(conn)
			continue
		}
		conn.Mu.Lock()
		conn.KeepaliveUnacked++
		conn.Mu.Unlock()
		probe := &protocol.Packet{
			Version:  protocol.Version,
			Flags:    protocol.FlagACK,
			Protocol: protocol.ProtoStream,
			Src:      conn.LocalAddr,
			Dst:      conn.RemoteAddr,
			SrcPort:  conn.LocalPort,
			DstPort:  conn.RemotePort,
			Seq:      sendSeq,
			Ack:      recvAck,
			Window:   conn.RecvWindow(),
		}
		d.tunnels.Send(conn.RemoteAddr.Node, probe)
	}
}

// relayProbeLoop periodically sends direct probes to relay-flagged peers.
// If the peer responds directly, relay mode is cleared for that peer.
func (d *Daemon) relayProbeLoop() {
	ticker := time.NewTicker(RelayProbeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			for _, nodeID := range d.tunnels.RelayPeerIDs() {
				go d.tryDirectUpgrade(nodeID)
			}
		}
	}
}

// tryDirectUpgrade attempts to promote a relay-flagged peer to a direct path
// via coordinated NAT hole-punching, then verifies on the rig that the path
// actually carries traffic.
//
// Why this exists: the old relayProbeLoop sent a single one-way SendDirectProbe
// and assumed the direct path "had recovered". Through a stateful firewall/NAT
// a one-way probe is dropped — there is no conntrack pinhole until BOTH peers
// send. So a relay tunnel never upgraded unless the peer was already publicly
// reachable. Here we (1) coordinate a simultaneous punch via the beacon to
// open the pinhole on both NATs, then (2) push several encrypted probes at the
// peer's REAL address (not the beacon placeholder) so the peer's
// ClearRelayOnDirect promotes the path (DirectClearsRequired=3 direct decrypts).
func (d *Daemon) tryDirectUpgrade(nodeID uint32) {
	// Only act on peers we have authoritative resolve info for. Punching a
	// relay-only peer would leak its real IP via the beacon PunchCommand
	// (see establishConnection), so require resolve info that says the peer
	// is NOT relay-only before we punch or probe.
	resp, ok := d.cachedResolve(nodeID)
	if !ok {
		// A relay tunnel established via beacon discovery never populated
		// the resolve cache. Resolve fresh so we can target the peer's real
		// address; without this the upgrade can never start.
		rc := d.reg()
		if rc == nil {
			return
		}
		r, err := withRegistryDeadline(registryCallDeadline, func() (map[string]interface{}, error) {
			return rc.Resolve(nodeID, d.NodeID())
		})
		if err != nil {
			return
		}
		d.cacheResolve(nodeID, r)
		resp = r
	}
	if relayOnly, _ := resp["relay_only"].(bool); relayOnly {
		return
	}
	realAddrStr, _ := resp["real_addr"].(string)
	if realAddrStr == "" {
		return
	}
	realAddr, err := net.ResolveUDPAddr("udp", realAddrStr)
	if err != nil {
		return
	}

	// A prior blackhole flip may have PINNED the peer to relay; ClearRelayOnDirect
	// will not promote a pinned peer. Unpin it — we've confirmed above it is not
	// registry relay-only, so direct is allowed to win on its merits.
	if d.tunnels.IsRelayPinned(nodeID) {
		d.tunnels.SetRelayPeerPinned(nodeID, false)
	}

	// Coordinate the punch (opens the conntrack pinhole on both NATs).
	d.tunnels.RequestHolePunch(nodeID)

	probe := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagACK,
		Protocol: protocol.ProtoControl,
		Src:      d.Addr(),
		Dst:      protocol.Addr{Network: 0, Node: nodeID},
		SrcPort:  protocol.PortPing,
		DstPort:  protocol.PortPing,
		Seq:      1,
	}
	// Give the punch a moment to land, then probe the real address a few
	// times so at least DirectClearsRequired (=3) direct decrypts arrive
	// while the pinhole is open.
	for i := 0; i < 5; i++ {
		time.Sleep(200 * time.Millisecond)
		if err := d.tunnels.SendDirectProbeTo(nodeID, realAddr, probe); err != nil {
			slog.Debug("direct upgrade probe skipped", "node_id", nodeID, "error", err)
			return
		}
	}
}

// ---------------------------------------------------------------------------
// Network membership reconciliation: periodic delta detection vs the
// registry's authoritative membership list. The reconciler is L7-only:
// it fetches from the L8 registry client, computes joined / left /
// tags-changed deltas, refreshes the daemon-local port-policy cache,
// publishes bus events for each delta, and persists a snapshot.
//
// The lifecycle reactions that used to live inline (StartPolicyRunner,
// StartManagedEngine, etc.) are now handled by bus subscribers — see
// pkg/daemon/network_events.go for the topic catalog and
// subscribeNetworkInternalToBus below for the daemon-internal half
// (managed engines + member-tag cache). Plugin-side reactions (policy
// runners) live in plugins/policy/service.go and subscribe via
// coreapi.Deps.Events. (T4.3.)
// ---------------------------------------------------------------------------

// networkSyncLoop periodically reconciles local membership with the registry.
// Runs every DefaultNetworkSyncInterval. Each tick publishes
// network.joined / network.left / network.tags_changed events for any
// observed delta; subscribers (plugins + daemon-internal handler) drive
// the actual lifecycle work.
func (d *Daemon) networkSyncLoop() {
	// Random jitter (0-30s) to spread load across fleet restarts.
	jitter := time.Duration(rand.Int63n(int64(30 * time.Second)))
	select {
	case <-d.stopCh:
		return
	case <-time.After(jitter):
	}

	ticker := time.NewTicker(DefaultNetworkSyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.reconcileMembership()
		}
	}
}

// reconcileMembership runs one membership-delta tick. It fetches the
// authoritative network list from the registry, computes joins / leaves /
// tag changes vs. local state, refreshes the L7-internal port-policy
// cache, publishes network.* bus events for each delta, and persists
// a snapshot. It does NOT start or stop policy runners or managed
// engines directly — those are bus subscribers' responsibility (T4.3).
func (d *Daemon) reconcileMembership() {
	if d.reg() == nil {
		return
	}

	// 1. Fetch current network memberships from the registry (L8).
	// Use the cache-bypassing variant: this tick is the authoritative
	// source for join/leave deltas and a stale cached entry would cause
	// us to miss a genuine membership change. Issue #93 added the cache
	// for the §4.8 Info/Health hot path; reconcile must NOT see it.
	newNets := d.nodeNetworksFresh()
	if newNets == nil {
		slog.Debug("network-sync: registry unreachable, skipping")
		return
	}

	newSet := make(map[uint16]bool, len(newNets))
	for _, n := range newNets {
		newSet[n] = true
	}

	// 2. Snapshot prior known set BEFORE any state mutation so the
	// delta detection sees a stable picture.
	oldSet := d.knownNetworkSet()

	// 3. Refresh the daemon-internal port-policy cache (L7-internal,
	// fed from L8). Done BEFORE event publication so subscribers
	// reading isPortAllowed observe coherent state.
	d.loadNetworkPolicies()

	// 4. Fetch the rich network list once for join-event payloads
	// (rules + has_expr_policy hint). Empty if registry hiccups —
	// joined-event payloads will then carry network_id only and
	// subscribers can fall back to lazy fetch.
	var networkList []interface{}
	if listResp, err := d.reg().ListNetworks(); err == nil {
		networkList, _ = listResp["networks"].([]interface{})
	}
	listByID := make(map[uint16]map[string]interface{}, len(networkList))
	for _, raw := range networkList {
		n, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		id, ok := networkIDFromJSON(n["id"])
		if !ok {
			continue
		}
		listByID[id] = n
	}

	// 5. Refresh authoritative member tags from the registry for every
	// current network. Compute change set vs cached values so the
	// network.tags_changed event fires only on actual deltas.
	tagChanges := d.refreshMemberTagsAndDiff(newNets)

	// 6. Detect newly joined networks. Build rich payloads (rules +
	// expr_policy + member_tags) and publish network.joined.
	for netID := range newSet {
		if netID == 0 {
			continue
		}
		if oldSet[netID] {
			continue
		}
		slog.Info("network-sync: new network detected", "network_id", netID)
		payload := d.buildJoinPayload(netID, listByID[netID])
		d.publishEvent(TopicNetworkJoined, payload)
	}

	// 7. Detect removed networks. Snapshot the locally-cached state
	// BEFORE clearing it so subscribers observing the event still see
	// the network as present in their own view. Then clear the
	// daemon-internal cache (port policies + tag cache) and publish
	// network.left so subscribers can stop their per-network state.
	for netID := range oldSet {
		if newSet[netID] {
			continue
		}
		slog.Info("network-sync: network removed", "network_id", netID)
		d.clearNetworkState(netID)
		d.publishEvent(TopicNetworkLeft, map[string]any{
			"network_id": netID,
		})
	}

	// 8. Publish per-network tag deltas.
	for netID, tags := range tagChanges {
		d.publishEvent(TopicNetworkTagsChanged, map[string]any{
			"network_id": netID,
			"tags":       append([]string(nil), tags...),
		})
	}

	// 9. Persist snapshot.
	d.saveNetworkSnapshot(newNets)

	slog.Debug("network-sync: complete", "networks", len(newNets))
}

// buildJoinPayload assembles the network.joined payload for a single
// network. Pulls expr_policy and rules from the cached ListNetworks()
// response when available, plus the freshly-refreshed member_tags
// cache. Falls back to a minimal payload (network_id only) if the
// registry's network entry is missing.
func (d *Daemon) buildJoinPayload(netID uint16, n map[string]interface{}) map[string]any {
	payload := map[string]any{
		"network_id": netID,
	}
	if n != nil {
		if rulesRaw, ok := n["rules"]; ok && rulesRaw != nil {
			payload["rules"] = rulesRaw
		}
		if hasPolicy, _ := n["has_expr_policy"].(bool); hasPolicy {
			// Fetch the compiled expr policy so subscribers don't have
			// to re-issue the L8 RPC. Same lazy-fetch the old
			// syncPolicyRunners did, but moved up into the publisher
			// so the policy-plugin subscriber stays L8-free.
			if pResp, err := d.reg().GetExprPolicy(netID); err == nil {
				if v, ok := pResp["expr_policy"]; ok && v != nil {
					payload["expr_policy"] = v
				}
			}
		}
	}
	d.memberTagsMu.RLock()
	tags := append([]string(nil), d.memberTags[netID]...)
	d.memberTagsMu.RUnlock()
	payload["member_tags"] = tags
	return payload
}

// refreshMemberTagsAndDiff fetches authoritative member tags from the
// registry for every joined network, updates the local cache, and
// returns the set of networks whose tags changed (i.e. need a
// network.tags_changed event). Networks not present in the response
// are left untouched. Network 0 (default/backbone) is skipped.
func (d *Daemon) refreshMemberTagsAndDiff(nets []uint16) map[uint16][]string {
	nodeID := d.NodeID()
	changes := make(map[uint16][]string)
	for _, netID := range nets {
		if netID == 0 {
			continue
		}
		resp, err := d.reg().GetMemberTags(netID, nodeID)
		if err != nil {
			continue
		}
		tagsRaw, _ := resp["tags"].([]interface{})
		var tags []string
		for _, t := range tagsRaw {
			if s, ok := t.(string); ok {
				tags = append(tags, s)
			}
		}
		d.memberTagsMu.Lock()
		prev := d.memberTags[netID]
		if !stringSliceEqual(prev, tags) {
			changes[netID] = append([]string(nil), tags...)
		}
		d.memberTags[netID] = tags
		d.memberTagsMu.Unlock()
	}
	return changes
}

// stringSliceEqual returns true if two string slices contain the same
// elements in the same order. Used by tag-diff to suppress redundant
// network.tags_changed events on every reconciliation tick.
func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// knownNetworkSet returns the set of non-backbone network IDs the daemon
// currently has state for (policies, runners, managed engines, or member tags).
func (d *Daemon) knownNetworkSet() map[uint16]bool {
	set := make(map[uint16]bool)

	d.netPolicyMu.RLock()
	for netID := range d.netPolicies {
		if netID != 0 {
			set[netID] = true
		}
	}
	d.netPolicyMu.RUnlock()

	if d.policyManager != nil {
		for _, pr := range d.policyManager.All() {
			set[pr.NetworkID()] = true
		}
	}

	d.managedMu.Lock()
	for netID := range d.managed {
		set[netID] = true
	}
	d.managedMu.Unlock()

	d.memberTagsMu.RLock()
	for netID := range d.memberTags {
		set[netID] = true
	}
	d.memberTagsMu.RUnlock()

	return set
}

// clearNetworkState removes cached port policies and member tags for a network.
func (d *Daemon) clearNetworkState(netID uint16) {
	d.netPolicyMu.Lock()
	delete(d.netPolicies, netID)
	d.netPolicyMu.Unlock()

	d.memberTagsMu.Lock()
	delete(d.memberTags, netID)
	d.memberTagsMu.Unlock()
}

// saveNetworkSnapshot persists the current network state to {identityDir}/networks.json.
func (d *Daemon) saveNetworkSnapshot(nets []uint16) {
	if d.config.IdentityPath == "" {
		return
	}

	d.netPolicyMu.RLock()
	policies := make(map[uint16][]uint16, len(d.netPolicies))
	for k, v := range d.netPolicies {
		policies[k] = v
	}
	d.netPolicyMu.RUnlock()

	d.memberTagsMu.RLock()
	tags := make(map[uint16][]string, len(d.memberTags))
	for k, v := range d.memberTags {
		tags[k] = v
	}
	d.memberTagsMu.RUnlock()

	snap := networkSnapshot{
		Networks:   nets,
		Policies:   policies,
		MemberTags: tags,
		SyncedAt:   time.Now().Format(time.RFC3339),
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		slog.Error("save network snapshot", "err", err)
		return
	}

	dir := filepath.Dir(d.config.IdentityPath)
	path := filepath.Join(dir, "networks.json")
	if err := os.MkdirAll(dir, 0700); err != nil {
		slog.Error("create network snapshot directory", "dir", dir, "err", err)
		return
	}
	if err := fsutil.AtomicWrite(path, data); err != nil {
		slog.Error("write network snapshot", "err", err)
		return
	}
	slog.Debug("network snapshot saved", "networks", len(nets))
}

// loadNetworkSnapshot loads cached network state from {identityDir}/networks.json.
// Used at startup to bootstrap port policies and member tags when the registry
// is temporarily unavailable. Only fills gaps — does not overwrite live data.
func (d *Daemon) loadNetworkSnapshot() {
	if d.config.IdentityPath == "" {
		return
	}

	dir := filepath.Dir(d.config.IdentityPath)
	path := filepath.Join(dir, "networks.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return // no file yet
	}

	var snap networkSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		slog.Warn("load network snapshot", "err", err)
		return
	}

	if len(snap.Policies) > 0 {
		d.netPolicyMu.Lock()
		for netID, ports := range snap.Policies {
			if _, exists := d.netPolicies[netID]; !exists {
				d.netPolicies[netID] = ports
			}
		}
		d.netPolicyMu.Unlock()
	}

	if len(snap.MemberTags) > 0 {
		d.memberTagsMu.Lock()
		for netID, t := range snap.MemberTags {
			if _, exists := d.memberTags[netID]; !exists {
				d.memberTags[netID] = t
			}
		}
		d.memberTagsMu.Unlock()
	}

	slog.Info("loaded network snapshot", "networks", len(snap.Networks), "synced_at", snap.SyncedAt)
}

// lookupPeerPubKey fetches a peer's Ed25519 public key from the registry.
func (d *Daemon) lookupPeerPubKey(nodeID uint32) (ed25519.PublicKey, error) {
	resp, err := d.reg().Lookup(nodeID)
	if err != nil {
		return nil, fmt.Errorf("lookup node %d: %w", nodeID, err)
	}

	pubKeyB64, ok := resp["public_key"].(string)
	if !ok || pubKeyB64 == "" {
		return nil, fmt.Errorf("node %d has no public key", nodeID)
	}

	return crypto.DecodePublicKey(pubKeyB64)
}

// pollRelayedHandshakes checks the registry for handshake requests and
// responses relayed to this node and processes them.
func (d *Daemon) pollRelayedHandshakes() {
	resp, err := d.reg().PollHandshakes(d.NodeID())
	if err != nil {
		slog.Debug("poll handshakes failed", "error", err)
		return
	}

	// Process incoming handshake requests
	requests, _ := resp["requests"].([]interface{})
	for _, r := range requests {
		req, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		fromIDVal, ok := req["from_node_id"].(float64)
		if !ok {
			continue
		}
		fromNodeID := uint32(fromIDVal)
		justification, _ := req["justification"].(string)

		slog.Info("relayed handshake request received", "from_node_id", fromNodeID, "justification", justification)

		// Process through the handshake service as if it were a direct request
		if d.handshakes != nil {
			d.handshakes.ProcessRelayedRequest(fromNodeID, justification)
		}
	}

	// Process handshake responses (approvals/rejections relayed back to us)
	responses, _ := resp["responses"].([]interface{})
	for _, r := range responses {
		respMsg, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		fromIDVal, ok := respMsg["from_node_id"].(float64)
		if !ok {
			continue
		}
		fromNodeID := uint32(fromIDVal)
		accept, _ := respMsg["accept"].(bool)

		if accept {
			slog.Info("relayed handshake approval received", "from_node_id", fromNodeID)
			if d.handshakes != nil {
				d.handshakes.ProcessRelayedApproval(fromNodeID)
			}
		} else {
			slog.Info("relayed handshake rejection received", "from_node_id", fromNodeID)
			if d.handshakes != nil {
				d.handshakes.ProcessRelayedRejection(fromNodeID)
			}
		}
	}
}

// resolveLocalAddr replaces wildcard addresses with the appropriate loopback.
func resolveLocalAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "" || host == "0.0.0.0" {
		return "127.0.0.1:" + port
	}
	if host == "::" {
		return "[::1]:" + port
	}
	return addr
}

// buildCompatTLSConfig returns the tls.Config used to verify the
// beacon's certificate in compat mode. trust=="pinned" (default)
// returns a config trusting only the Pilot root(s) embedded in the
// daemon binary. trust=="system" falls back to the OS trust store —
// the escape hatch for daemons behind TLS-intercepting corp proxies.
// Any other value is rejected.
func buildCompatTLSConfig(trust string) (*tls.Config, error) {
	switch trust {
	case "", "pinned":
		pool, err := compat.PinnedRoots()
		if err != nil {
			return nil, fmt.Errorf("load pinned roots: %w", err)
		}
		return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
	case "system":
		slog.Warn("compat mode: TLS trust relaxed to OS store — TLS-intercepting proxies on the path can read/alter relay traffic; end-to-end Ed25519 still protects payload identity")
		return &tls.Config{MinVersion: tls.VersionTLS12}, nil
	default:
		return nil, fmt.Errorf("invalid -tls-trust %q: must be 'pinned' or 'system'", trust)
	}
}
