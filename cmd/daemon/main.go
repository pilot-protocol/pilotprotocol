// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pilot-protocol/common/config"
	"github.com/pilot-protocol/common/driver"
	"github.com/pilot-protocol/common/logging"
	"github.com/pilot-protocol/common/netproxy"
	"github.com/pilot-protocol/pilotprotocol/internal/enterprisecontrol"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/authority"
	"github.com/pilot-protocol/pilotprotocol/internal/motd"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon"

	// L11 plugin imports — cmd/daemon (L12) is the only place these
	// are allowed. The daemon proper imports only pkg/coreapi
	// interfaces.
	"github.com/pilot-protocol/app-store/plugin/appstore"
	"github.com/pilot-protocol/dataexchange"
	"github.com/pilot-protocol/eventstream"
	"github.com/pilot-protocol/handshake"
	"github.com/pilot-protocol/policy"
	"github.com/pilot-protocol/runtime"
	"github.com/pilot-protocol/skillinject"
	"github.com/pilot-protocol/trustedagents"
	"github.com/pilot-protocol/webhook"

	"github.com/pilot-protocol/pilotprotocol/internal/catalogtrust"
	"github.com/pilot-protocol/pilotprotocol/internal/catalogue"
	"github.com/pilot-protocol/pilotprotocol/pkg/telemetry"
)

var version = "dev"

var remoteLifecycleRequests = make(chan string, 1)

func main() {
	configPath := flag.String("config", "", "path to config file (JSON)")
	securityProfile := flag.String("security-profile", envString("PILOT_SECURITY_PROFILE", securityProfileCompatible), "locked security profile: compatible or enterprise")
	registryDefault := defaultRegistryAddr
	registryFromEnv := false
	if v := os.Getenv("PILOT_REGISTRY"); v != "" {
		registryDefault = v
		registryFromEnv = true
	}
	beaconDefault := defaultBeaconAddr
	beaconFromEnv := false
	if v := os.Getenv("PILOT_BEACON"); v != "" {
		beaconDefault = v
		beaconFromEnv = true
	}
	registryAddr := flag.String("registry", registryDefault, "registry server address (or $PILOT_REGISTRY)")
	beaconAddr := flag.String("beacon", beaconDefault, "beacon server address (or $PILOT_BEACON)")
	listenAddr := flag.String("listen", ":0", "UDP listen address for tunnel traffic")
	socketPath := flag.String("socket", driver.DefaultSocketPath(), "Unix socket path for IPC")
	endpoint := flag.String("endpoint", "", "fixed public endpoint (host:port) — skips STUN (for cloud VMs with known IPs)")
	advertiseEndpoint := flag.String("advertise-endpoint", "", "override STUN-discovered endpoint for registry advertisement (host:port) — for k8s pods where STUN returns unreachable IPs. When set, STUN still runs but the advertised address uses this value")
	encrypt := flag.Bool("encrypt", true, "enable tunnel-layer encryption (X25519 + AES-256-GCM)")
	registryTLS := flag.Bool("registry-tls", false, "use TLS for registry connection")
	registryFingerprint := flag.String("registry-fingerprint", "", "hex SHA-256 fingerprint of registry TLS certificate (required when -registry-trust=pinned)")
	registryTrust := flag.String("registry-trust", "pinned", "trust store for -registry-tls: 'pinned' (verify cert against -registry-fingerprint) or 'system' (OS x509 root store — used for compat-mode registry on registry.pilotprotocol.network:443 with Let's Encrypt)")
	identityPath := flag.String("identity", "", "path to persist Ed25519 identity (enables stable identity across restarts)")
	email := flag.String("email", "", "email address for account identification and key recovery")
	owner := flag.String("owner", "", "(deprecated: use -email) owner identifier for key rotation recovery")
	keepalive := flag.Duration("keepalive", 0, "keepalive probe interval (default 60s)")
	idleTimeout := flag.Duration("idle-timeout", 0, "idle connection timeout (default 120s)")
	synRate := flag.Int("syn-rate-limit", 0, "max SYN packets per second (default 100)")
	maxConnsPerPort := flag.Int("max-conns-per-port", 0, "max connections per port (default 1024)")
	maxConnsTotal := flag.Int("max-conns-total", 0, "max total connections (default 65536)")
	// PILOT-343/344/345 rate-limit whitelists. Comma-separated trusted-peer
	// node IDs (decimal uint32). Env fallbacks let deployments configure
	// without editing flag strings. Empty default preserves backwards
	// compatibility — fleets that don't set them behave exactly as before.
	synWhitelist := flag.String("syn-whitelist", "", "PILOT-343: comma-separated trusted source node IDs that bypass the SYN rate limit. Env: PILOT_SYN_WHITELIST.")
	replyWhitelist := flag.String("reply-whitelist", "", "PILOT-344: comma-separated trusted peer node IDs that bypass the keyexchange reply interval gate. Env: PILOT_REPLY_WHITELIST.")
	rekeyWhitelist := flag.String("rekey-whitelist", "", "PILOT-345: comma-separated trusted peer node IDs that bypass the tunnel-rekey interval and 4096 cap. Env: PILOT_REKEY_WHITELIST.")
	timeWait := flag.Duration("time-wait", 0, "TIME_WAIT duration (default 10s)")
	public := flag.Bool("public", false, "make this node's endpoint publicly visible (default: private)")
	strictDataplaneTrust := flag.Bool("strict-dataplane-trust", false, "WS1: refuse key-exchange/control-plane interaction with untrusted peers on a private node. Default false (not enforcing, wire-compatible with old agents). Env: PILOT_STRICT_DATAPLANE_TRUST=1.")
	relayOnly := flag.Bool("relay-only", false, "hide real_addr from peers; reach this node only via beacon-relay path. Privacy stance: peers cannot enumerate this daemon's public IP. Trade-off: relay adds one beacon hop. Default false (current direct-first behavior).")
	hostname := flag.String("hostname", "", "hostname for discovery (lowercase alphanumeric + hyphens, max 63 chars)")
	noEcho := flag.Bool("no-echo", false, "disable built-in echo service (port 7)")
	noDataExchange := flag.Bool("no-dataexchange", false, "disable built-in data exchange service (port 1001)")
	dataExchangeB64 := flag.Bool("dataexchange-b64", false, "write inbox message payloads as a raw base64 `data_b64` field in place of the UTF-8 `data` field — needed only for binary payloads (e.g. zlib-compressed envelopes)")
	noEventStream := flag.Bool("no-eventstream", false, "disable built-in event stream service (port 1002)")
	enterpriseControlPath := flag.String("enterprise-control", "", "path to signed enterprise control attachment (root pin, trust bundle, policy bundle, and governed transport rules)")
	noSkillinject := flag.Bool("no-skillinject", false, "disable built-in skill-injection service (agent context injection). Env: PILOT_NO_SKILLINJECT=1.")
	webhookURL := flag.String("webhook", "", "HTTP(S) endpoint for event notifications (empty = disabled)")
	webhookSecret := flag.String("webhook-secret", "", "HMAC-SHA256 pre-shared secret for webhook payload signing (empty = no signature). Env: PILOT_WEBHOOK_SECRET.")
	adminToken := flag.String("admin-token", "", "admin token for network operations")
	networks := flag.String("networks", "", "comma-separated network IDs to auto-join at startup")
	trustAutoApprove := flag.Bool("trust-auto-approve", false, "automatically approve all incoming trust handshakes")
	beaconRTTProbe := flag.Bool("beacon-rtt-probe", false, "probe beacon RTT before selection; override hash pick when >2× slower than best (ablation test, default off)")
	noRxWatchdog := flag.Bool("no-rx-watchdog", false, "disable the inbound-path watchdog that soft-recovers (beacon+registry re-registration) and, on a persistent wedge, exits non-zero for supervisor respawn")
	noPathWatch := flag.Bool("no-path-watch", false, "disable the per-peer path watchdog that probes inbound-silent peers and resets a dead peer path in place (prefer-direct sequence) without a daemon restart")
	transportMode := flag.String("transport", transportDefault(), "tunnel transport: 'udp' (default) or 'compat' (WSS to beacon, opt-in, for UDP-blocked environments). Env: PILOT_TRANSPORT.")
	proxySpec := flag.String("proxy", envString("PILOT_PROXY", netproxy.ModeAuto), "outbound proxy for registry, beacon and HTTP connections: 'auto' (with -transport=compat, HTTPS_PROXY/ALL_PROXY from the environment, honoring NO_PROXY; nothing with -transport=udp), 'off', or a proxy URL 'http://[user:pass@]host:port' used for every connection. Env: PILOT_PROXY.")
	compatBeacon := flag.String("compat-beacon", "wss://beacon.pilotprotocol.network/v1/compat", "beacon WSS URL for -transport=compat")
	tlsTrust := flag.String("tls-trust", "system", "TLS trust store for -transport=compat: 'system' (OS trust store; current default while compat mode uses Let's Encrypt certs on beacon.pilotprotocol.network) or 'pinned' (Pilot CA root embedded in the daemon binary; will become the default in a future release once production root ships)")
	showVersion := flag.Bool("version", false, "print version and exit")
	logLevel := flag.String("log-level", "info", "log level (debug, info, warn, error)")
	logFormat := flag.String("log-format", "text", "log format (text, json)")
	sandbox := flag.Bool("sandbox", false, "restrict all file I/O to the sandbox directory (see -sandbox-dir)")
	sandboxDir := flag.String("sandbox-dir", "", "confinement root when -sandbox is set (default: ~/.pilot)")
	motdFeedURL := flag.String("motd-feed-url", motd.DefaultFeedURL, "message-of-the-day feed URL (empty to disable); overridden by $PILOT_MOTD_URL")
	motdInterval := flag.Duration("motd-interval", 0, "message-of-the-day poll interval (default 15m)")
	telemetryURLDefault := os.Getenv("PILOT_TELEMETRY_URL")
	if telemetryURLDefault == "" {
		telemetryURLDefault = telemetry.DefaultEndpoint
	}
	telemetryURL := flag.String("telemetry-url", telemetryURLDefault,
		"telemetry endpoint URL (empty = consent off, hard no-op). "+
			"Env: PILOT_TELEMETRY_URL. Default: "+telemetry.DefaultEndpoint+".")
	flag.Parse()
	if *adminToken == "" {
		if v := os.Getenv("PILOT_ADMIN_TOKEN"); v != "" {
			*adminToken = v
		}
	}
	if v := os.Getenv("PILOT_MOTD_URL"); v != "" {
		*motdFeedURL = v
	}

	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	// Auto-load ~/.pilot/config.json when -config isn't passed. Without
	// this, launching the daemon directly (vs. via `pilotctl daemon
	// start`) gives an empty IdentityPath, which silently disables
	// identity persistence AND trust-state persistence (Manager.loadTrust
	// only runs when IdentityPath != ""). Result: every restart loses
	// trust.json contents from the runtime even though the file is on
	// disk. Mirroring `pilotctl daemon start`'s implicit config path
	// here closes that gap.
	if *configPath == "" {
		if home, err := os.UserHomeDir(); err == nil {
			defaultConfig := home + "/.pilot/config.json"
			if _, err := os.Stat(defaultConfig); err == nil {
				configPath = &defaultConfig
			}
		}
	}
	if *configPath != "" {
		cfg, err := config.Load(*configPath)
		if err != nil {
			log.Fatalf("load config: %v", err)
		}
		config.ApplyToFlags(cfg)
	}
	if *enterpriseControlPath == "" {
		if discovered, ok := discoverManagedEnterpriseControl(); ok {
			*enterpriseControlPath = discovered
		}
	}

	// Compat-mode 443-only defaults. When -transport=compat is selected
	// and the operator hasn't explicitly overridden -registry/-registry-tls/
	// -registry-trust, route the registry to its TLS hostname (TCP/443
	// via nginx SNI routing on the production rendezvous box) so the
	// daemon really does use a single port. The TCP/9000 fallback is
	// still available to anyone who passes a non-default -registry
	// explicitly; the compiled-in default counts as not explicit (see
	// compatKeepsRegistry). -beacon needs no such rule: in compat mode the
	// UDP beacon address is only the relay-wrap destination on the WSS
	// pipe and is never dialed.
	if *transportMode == "compat" {
		explicit := map[string]bool{}
		flag.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
		if !compatKeepsRegistry(*registryAddr, explicit["registry"], os.Getenv("PILOT_REGISTRY") != "") {
			v := compatRegistryAddr
			registryAddr = &v
			registryFromEnv = false
		}
		if !explicit["registry-tls"] {
			v := true
			registryTLS = &v
		}
		if !explicit["registry-trust"] {
			v := "system"
			registryTrust = &v
			slog.Warn("compat-mode registry-trust defaulted to 'system' (Let's Encrypt validation). Override with -registry-trust=pinned if using pinned certificates (supply -registry-fingerprint).")
		}
	}

	profileOptions := daemonSecurityOptions{
		RegistryAddr:                    *registryAddr,
		RegistryTLS:                     *registryTLS,
		RegistryFingerprint:             *registryFingerprint,
		RegistryTrust:                   *registryTrust,
		Encrypt:                         *encrypt,
		StrictDataPlaneTrust:            *strictDataplaneTrust || os.Getenv("PILOT_STRICT_DATAPLANE_TRUST") == "1",
		IdentityPath:                    *identityPath,
		TrustAutoApprove:                *trustAutoApprove,
		DisableSkillinject:              *noSkillinject || os.Getenv("PILOT_NO_SKILLINJECT") == "1",
		SkillinjectVerificationKeyFound: os.Getenv("PILOT_SKILLINJECT_MANIFEST_PUBKEY") != "" || os.Getenv("PILOT_SKILLINJECT_PUBKEY") != "",
		MOTDFeedURL:                     *motdFeedURL,
		WebhookURL:                      *webhookURL,
		EnterpriseControlPath:           *enterpriseControlPath,
		DisableDataExchange:             *noDataExchange,
		DisableEventStream:              *noEventStream,
	}
	if err := applyDaemonSecurityProfile(*securityProfile, &profileOptions); err != nil {
		log.Fatalf("security profile: %v", err)
	}
	*registryTLS = profileOptions.RegistryTLS
	*encrypt = profileOptions.Encrypt
	*strictDataplaneTrust = profileOptions.StrictDataPlaneTrust
	*noSkillinject = profileOptions.DisableSkillinject
	*motdFeedURL = profileOptions.MOTDFeedURL

	logging.Setup(*logLevel, *logFormat)

	// Outbound proxy: resolved once, after -transport is final, and shared
	// by everything that dials out — the registry client, the compat WSS
	// beacon, pkg/daemon's own HTTP fetches (via daemon.Config.Proxy) and
	// every plugin HTTP client (via http.DefaultTransport).
	proxyPolicy, err := resolveProxyPolicy(*proxySpec, *transportMode)
	if err != nil {
		log.Fatalf("-proxy: %v", err)
	}
	installDefaultTransportProxy(proxyPolicy)
	slog.Info("outbound network", "transport", *transportMode, "proxy", describeProxy(*proxySpec, *transportMode, proxyPolicy))

	// Sandbox: validate all configured file paths are under the confinement
	// root before the daemon touches the filesystem. Network paths are unaffected.
	if *sandbox {
		sbDir := *sandboxDir
		if sbDir == "" {
			if home, err := os.UserHomeDir(); err == nil {
				sbDir = filepath.Join(home, ".pilot")
			}
		}
		abs, err := filepath.Abs(sbDir)
		if err != nil {
			log.Fatalf("sandbox: resolve sandbox-dir %q: %v", sbDir, err)
		}
		sbDir = abs
		slog.Info("sandbox mode active", "dir", sbDir)
		checkSandbox := func(label, path string) {
			if path == "" {
				return
			}
			abs, err := filepath.Abs(path)
			if err != nil {
				log.Fatalf("sandbox: resolve %s path %q: %v", label, path, err)
			}
			rel, err := filepath.Rel(sbDir, abs)
			if err != nil || strings.HasPrefix(rel, "..") {
				log.Fatalf("sandbox violation: %s path %q escapes sandbox dir %q", label, path, sbDir)
			}
		}
		checkSandbox("config", *configPath)
		checkSandbox("identity", *identityPath)
		checkSandbox("socket", *socketPath)
		checkSandbox("enterprise-control", *enterpriseControlPath)
	}

	var enterpriseControls *enterprisecontrol.Runtime
	if *enterpriseControlPath != "" {
		var err error
		enterpriseControls, err = enterprisecontrol.Load(*enterpriseControlPath)
		if err != nil {
			log.Fatalf("enterprise control: %v", err)
		}
	}
	if strings.EqualFold(strings.TrimSpace(*securityProfile), securityProfileEnterprise) {
		if err := enterpriseControls.RequireEnabledServiceGates(!*noDataExchange, !*noEventStream); err != nil {
			log.Fatalf("enterprise control: %v", err)
		}
	}

	if registryFromEnv {
		slog.Warn("PILOT_REGISTRY env var overrides compiled default — registry address redirected to " + *registryAddr + ". If this is unexpected, check the daemon's environment for tampering.")
	}
	if beaconFromEnv {
		slog.Warn("PILOT_BEACON env var overrides compiled default — beacon address redirected to " + *beaconAddr + ". If this is unexpected, check the daemon's environment for tampering.")
	}

	d := daemon.New(daemon.Config{
		RegistryAddr:          *registryAddr,
		BeaconAddr:            *beaconAddr,
		ListenAddr:            *listenAddr,
		SocketPath:            *socketPath,
		Endpoint:              *endpoint,
		AdvertiseEndpoint:     *advertiseEndpoint,
		Encrypt:               *encrypt,
		RegistryTLS:           *registryTLS,
		RegistryFingerprint:   *registryFingerprint,
		RegistryTrust:         *registryTrust,
		IdentityPath:          *identityPath,
		Email:                 *email,
		Owner:                 *owner,
		KeepaliveInterval:     *keepalive,
		IdleTimeout:           *idleTimeout,
		SYNRateLimit:          *synRate,
		MaxConnectionsPerPort: *maxConnsPerPort,
		MaxTotalConnections:   *maxConnsTotal,
		TimeWaitDuration:      *timeWait,
		Public:                *public,
		StrictDataPlaneTrust:  *strictDataplaneTrust || os.Getenv("PILOT_STRICT_DATAPLANE_TRUST") == "1",
		RelayOnly:             *relayOnly,
		Hostname:              *hostname,
		DisableEcho:           *noEcho,
		DisableDataExchange:   *noDataExchange,
		DisableEventStream:    *noEventStream,
		WebhookURL:            *webhookURL,
		AdminToken:            *adminToken,
		Networks:              parseNetworkIDs(*networks),
		Version:               version,
		TrustAutoApprove:      *trustAutoApprove,
		BeaconRTTProbe:        *beaconRTTProbe,
		DisableRxWatchdog:     *noRxWatchdog,
		DisablePathWatch:      *noPathWatch,
		TransportMode:         *transportMode,
		CompatBeaconURL:       *compatBeacon,
		CompatTLSTrust:        *tlsTrust,
		Proxy:                 proxyPolicy,
		MOTDFeedURL:           *motdFeedURL,
		MOTDInterval:          *motdInterval,
		TelemetryURL:          *telemetryURL,
	})

	// L11 plugin lifecycle (T7.1): composition root owns the
	// ServiceRegistry via plugins/runtime. Daemon never imports
	// pkg/coreapi.
	//
	// runtime + the per-plugin Runtime constructors take a
	// daemonapi.Daemon. *Daemon doesn't satisfy that interface
	// directly (engine-typed Connection/PortAllocator/etc.); the
	// adapter at pkg/daemon/zz_daemonapi_conformance.go does. We
	// resolve it once via d.DaemonAPI() and thread the shared value
	// everywhere — keeps the type assertion in one place.
	dapi := d.DaemonAPI()
	rt := runtime.New(dapi)

	ta := trustedagents.NewService()
	if err := rt.Register(ta); err != nil {
		log.Fatalf("register trustedagents: %v", err)
	}
	d.RegisterTrustChecker(ta)

	// skillinject is the context-injection plugin: it keeps the core
	// SKILL.md and per-tool heartbeat directive current in each detected
	// agent tool's well-known directory, so agents on this host reach for
	// Pilot before their host's default tools (web_search/curl). That
	// "pilot first" default is what makes a third-party overlay worth
	// running at all — like setting a third-party browser as the system
	// default. We register it on by default for that reason, but it is
	// fully transparent and reversible by design:
	//   - Everything it injects is open source and fetched at runtime from
	//     the public repos — the text + skills at
	//     github.com/TeoSlayer/pilot-skills, the injector itself at
	//     github.com/pilot-protocol/skillinject (AGPL-3.0). Nothing is
	//     embedded or hidden.
	//   - It only rewrites its own marker block, never operator content.
	//   - Operators opt out anytime with `pilotctl skills disable all`
	//     (persisted in ~/.pilot/config.json); see cmd/pilotctl/skills.go.
	if !*noSkillinject && os.Getenv("PILOT_NO_SKILLINJECT") != "1" {
		skillinjectCfg := skillinject.Config{}
		if pk := os.Getenv("PILOT_SKILLINJECT_MANIFEST_PUBKEY"); pk != "" {
			raw, err := base64.StdEncoding.DecodeString(pk)
			if err != nil {
				log.Fatalf("PILOT_SKILLINJECT_MANIFEST_PUBKEY: invalid base64 encoding")
			}
			if len(raw) != ed25519.PublicKeySize {
				log.Fatalf("PILOT_SKILLINJECT_MANIFEST_PUBKEY: must be a %d-byte ed25519 key", ed25519.PublicKeySize)
			}
			skillinjectCfg.ManifestPublicKey = ed25519.PublicKey(raw)
		}
		if err := rt.Register(skillinject.NewService(skillinjectCfg)); err != nil {
			log.Fatalf("register skillinject: %v", err)
		}
	}

	if !*noDataExchange {
		dataExchangeConfig := dataexchange.ServiceConfig{
			IncludeBase64: *dataExchangeB64,
		}
		if err := enterpriseControls.ApplyDataExchange(&dataExchangeConfig); err != nil {
			log.Fatalf("configure dataexchange enterprise control: %v", err)
		}
		if err := rt.Register(dataexchange.NewService(dataExchangeConfig)); err != nil {
			log.Fatalf("register dataexchange: %v", err)
		}
	}

	if !*noEventStream {
		eventStreamService := eventstream.NewService()
		if err := enterpriseControls.ApplyEventStream(eventStreamService); err != nil {
			log.Fatalf("configure eventstream enterprise control: %v", err)
		}
		if err := rt.Register(eventStreamService); err != nil {
			log.Fatalf("register eventstream: %v", err)
		}
	}

	policySvc := policy.NewService(runtime.NewPolicyRuntime(dapi))
	if err := rt.Register(policySvc); err != nil {
		log.Fatalf("register policy: %v", err)
	}
	d.RegisterPolicyManager(runtime.AsDaemonPolicyManager(policySvc.Manager()))

	// Manual trust-handshake (port 444) — extracted from pkg/daemon in T3.3.
	hsSvc := handshake.NewService(runtime.NewHandshakeRuntime(dapi))
	if actionHook := enterpriseControls.ActionHook(); actionHook != nil {
		hsSvc.Manager().SetActionHook(actionHook)
	}
	if err := rt.Register(hsSvc); err != nil {
		log.Fatalf("register handshake: %v", err)
	}
	d.RegisterHandshakeService(runtime.NewHandshakeServiceAdapter(hsSvc))

	// Webhook (T4.1): the daemon publishes events to the in-process
	// bus, the plugin subscribes and POSTs to the configured URL. URL
	// hot-swap (IPC's `set-webhook`) routes through SetURL on the
	// plugin via the daemon's WebhookManager interface.
	webhookSvc := webhook.NewService(*webhookURL, webhook.WithSecret(*webhookSecret))
	if err := rt.Register(webhookSvc); err != nil {
		log.Fatalf("register webhook: %v", err)
	}
	d.RegisterWebhookManager(webhookManagerAdapter{svc: webhookSvc})

	// App store — ALWAYS on. The supervisor scans <home>/.pilot/apps
	// every 2s, verifies each installed bundle's manifest signature
	// against its embedded publisher, and spawns the app's binary under
	// a child supervisor with an IPC socket the daemon brokers to. No
	// flag gates this: apps are installed individually (via
	// `pilotctl appstore install`), but the supervisor is part of every
	// daemon process from now on.
	//
	// Default-on rationale: pilotctl appstore install/list/call all
	// assume the supervisor is running. Gating it behind a flag would
	// silently break those commands on hosts that forgot to enable it.
	appstoreInstallRoot := ""
	if home, herr := os.UserHomeDir(); herr == nil {
		appstoreInstallRoot = filepath.Join(home, ".pilot", "apps")
	}
	if r := os.Getenv("PILOT_APPSTORE_ROOT"); r != "" {
		appstoreInstallRoot = r
	}
	// Catalogue trust anchor: load the per-app publisher pins from the
	// release-signed catalogue and feed them to the supervisor. A non-sideloaded
	// app is spawned only if its manifest publisher matches the key the catalogue
	// pins for its id (see appstore.Config.CataloguePublisher). The pins are
	// cached on disk so a transient catalogue outage on restart doesn't fail-close
	// every app; with neither a live catalogue nor a cache, apps fail closed.
	cataloguePins := catalogue.NewProvider(
		catalogue.URL(),
		filepath.Join(filepath.Dir(appstoreInstallRoot), "catalogue-pins.json"),
	)
	if err := cataloguePins.Refresh(); err != nil {
		if cataloguePins.LoadCache() {
			log.Printf("appstore: catalogue refresh failed (%v); using %d cached publisher pin(s)", err, cataloguePins.Count())
		} else {
			log.Printf("appstore: catalogue refresh failed (%v) and no cache; catalogue apps fail closed until the next refresh succeeds", err)
		}
	} else {
		log.Printf("appstore: loaded %d catalogue publisher pin(s)", cataloguePins.Count())
	}
	// Refresh the pins periodically so newly-catalogued apps become spawnable
	// without a daemon restart. Daemon-lifetime loop; the process exit stops it.
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for range t.C {
			if err := cataloguePins.Refresh(); err != nil {
				log.Printf("appstore: catalogue pin refresh failed: %v (keeping previous pins)", err)
			}
		}
	}()
	// The app-usage telemetry emitter shares the daemon's identity file
	// and telemetry URL. When consent is off (empty URL) the client is
	// a permanent no-op — no goroutines, no dials, no buffering.
	idPath := *identityPath
	if idPath == "" {
		if home, herr := os.UserHomeDir(); herr == nil {
			defaultID := filepath.Join(home, ".pilot", "identity.json")
			if _, serr := os.Stat(defaultID); serr == nil {
				idPath = defaultID
			}
		}
	}
	if err := rt.Register(&appstoreAdapter{
		svc: appstore.NewService(appstore.Config{
			InstallRoot:    appstoreInstallRoot,
			RescanInterval: 2 * time.Second,
			// Real catalogue trust anchor (replaces the all-zeros
			// placeholder default): the embedded ed25519 catalogue key.
			CatalogPubkey: []byte(catalogtrust.PublicKey()),
			// Per-app publisher pins from the release-signed catalogue: the
			// supervisor confirms each non-sideloaded app's manifest publisher
			// against this before spawning. nil/unpinned => fail closed.
			CataloguePublisher: cataloguePins.Publisher,
		}),
	}); err != nil {
		log.Fatalf("register appstore: %v", err)
	}

	// T4.1: subscribe plugins to the bus BEFORE Daemon.Start so the
	// webhook plugin captures the node.registered / agent.registered
	// events published from registerWithRegistry inside d.Start.
	// Plugin Start methods don't depend on d.Start having run; ports
	// and tunnels are constructed in daemon.New.
	if err := rt.StartPlugins(context.Background()); err != nil {
		log.Fatalf("plugin startup: %v", err)
	}

	// PILOT-343/344/345: apply rate-limit whitelists BEFORE Start so the
	// first inbound SYN/PILA/encrypted-frame already sees them. Each
	// helper tolerates empty/garbage input — bad tokens log a warning
	// and are dropped so a typo in env doesn't fail-fast the daemon.
	applyNodeIDWhitelist("syn", *synWhitelist, "PILOT_SYN_WHITELIST", d.SetSYNWhitelist, d.SetSYNWhitelistMatchAll)
	applyNodeIDWhitelist("reply", *replyWhitelist, "PILOT_REPLY_WHITELIST", d.SetReplyWhitelist, d.SetReplyWhitelistMatchAll)
	applyNodeIDWhitelist("rekey", *rekeyWhitelist, "PILOT_REKEY_WHITELIST", d.SetRekeyWhitelist, d.SetRekeyWhitelistMatchAll)

	if err := d.Start(); err != nil {
		log.Fatalf("daemon start: %v", err)
	}

	rolloutRefreshCtx, rolloutRefreshCancel := context.WithCancel(context.Background())
	if enterpriseControls.HasRollout() {
		if err := enterpriseControls.RefreshRollout(rolloutRefreshCtx); err != nil {
			slog.Warn("enterprise rollout refresh failed; retaining current local policy", "err", err)
		}
		go func() {
			ticker := time.NewTicker(enterpriseControls.RolloutInterval())
			defer ticker.Stop()
			for {
				select {
				case <-rolloutRefreshCtx.Done():
					return
				case <-ticker.C:
					if err := enterpriseControls.RefreshRollout(rolloutRefreshCtx); err != nil {
						slog.Warn("enterprise rollout refresh failed; retaining current local policy", "err", err)
					}
				}
			}
		}()
	}

	fleetControlCtx, fleetControlCancel := context.WithCancel(context.Background())
	if enterpriseControls.HasFleetControl() {
		synchronizeFleetControl(fleetControlCtx, enterpriseControls, d)
		go func() {
			ticker := time.NewTicker(enterpriseControls.FleetReportInterval())
			defer ticker.Stop()
			for {
				select {
				case <-fleetControlCtx.Done():
					return
				case <-ticker.C:
					synchronizeFleetControl(fleetControlCtx, enterpriseControls, d)
				}
			}
		}()
	}
	if enterpriseControls.HasFleetStateSync() {
		synchronizeFleetState(fleetControlCtx, enterpriseControls)
		go func() {
			ticker := time.NewTicker(enterpriseControls.FleetStateSyncInterval())
			defer ticker.Stop()
			for {
				select {
				case <-fleetControlCtx.Done():
					return
				case <-ticker.C:
					synchronizeFleetState(fleetControlCtx, enterpriseControls)
				}
			}
		}()
	}

	if enterpriseControls.HasAppReconcile() {
		appInstaller := enterprisecontrol.PilotctlInstaller{BinaryPath: pilotctlBinaryPath()}
		reconcileApps(fleetControlCtx, enterpriseControls, appInstaller)
		go func() {
			ticker := time.NewTicker(enterpriseControls.AppReconcileInterval())
			defer ticker.Stop()
			for {
				select {
				case <-fleetControlCtx.Done():
					return
				case <-ticker.C:
					reconcileApps(fleetControlCtx, enterpriseControls, appInstaller)
				}
			}
		}()
	}

	receiptExportCtx, receiptExportCancel := context.WithCancel(context.Background())
	if enterpriseControls.HasReceiptExport() {
		if err := enterpriseControls.ExportReceiptsOnce(receiptExportCtx); err != nil {
			slog.Warn("enterprise receipt export failed; local evidence remains durable", "err", err)
		}
		go func() {
			ticker := time.NewTicker(enterpriseControls.ReceiptExportInterval())
			defer ticker.Stop()
			for {
				select {
				case <-receiptExportCtx.Done():
					return
				case <-ticker.C:
					if err := enterpriseControls.ExportReceiptsOnce(receiptExportCtx); err != nil {
						slog.Warn("enterprise receipt export failed; local evidence remains durable", "err", err)
					}
				}
			}
		}()
	}

	// SIGHUP advances only the already-pinned signed authority state. It does
	// not reload daemon flags, root pins, or resource mappings, which remain a
	// deliberate restart-time administrative change.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	restartRequested := false
shutdownLoop:
	for {
		select {
		case received := <-sig:
			if received == syscall.SIGHUP {
				if enterpriseControls == nil {
					slog.Warn("enterprise control reload ignored: no attachment is configured")
				} else if err := enterpriseControls.Reload(); err != nil {
					slog.Error("enterprise control reload rejected; keeping current signed state", "err", err)
				} else {
					slog.Info("enterprise control reloaded")
				}
				continue
			}
			break shutdownLoop
		case lifecycle := <-remoteLifecycleRequests:
			restartRequested = lifecycle == "restart"
			break shutdownLoop
		}
	}
	signal.Stop(sig)
	rolloutRefreshCancel()
	receiptExportCancel()
	fleetControlCancel()

	// Order matters: Daemon.Stop publishes daemon.shutting_down to the
	// bus before tearing down ports/IPC/tunnels. Plugins (notably
	// webhook) are still subscribed at that point, so the event flows
	// through. StopPlugins then drains each plugin's queue. Reversing
	// this order would lose the shutdown event because the webhook's
	// bus subscription would be cancelled before doStop publishes.
	slog.Info("shutting down")
	d.Stop()

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := rt.StopPlugins(stopCtx); err != nil {
		slog.Warn("plugin shutdown error", "err", err)
	}
	stopCancel()
	if restartRequested {
		executable, err := os.Executable()
		if err != nil {
			slog.Error("resolve daemon executable for remote restart", "err", err)
			return
		}
		slog.Info("restarting daemon after graceful shutdown")
		// #nosec G204,G702 -- restart re-execs the current OS-resolved daemon directly; signed fleet commands cannot supply a path or arguments.
		if err := syscall.Exec(executable, os.Args, os.Environ()); err != nil {
			slog.Error("remote daemon restart failed", "err", err)
		}
	}
}

func discoverManagedEnterpriseControl() (string, bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", false
	}
	path := filepath.Join(home, ".pilot", "managed", "enterprise-control.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return "", false
	}
	return path, true
}

// synchronizeFleetControl reports bounded local health and runs only the
// fixed, authority-signed maintenance commands. It intentionally has no
// generic process execution, file access, shell, or network-dial capability.
func synchronizeFleetControl(ctx context.Context, controls *enterprisecontrol.Runtime, daemonInstance *daemon.Daemon) {
	health := daemonInstance.HealthSnapshot()
	info := daemonInstance.Info()
	reconciliation, reconciliationErr := controls.ReconcileFleetControl(ctx, info.Version)
	if reconciliationErr != nil {
		slog.Warn("fleet desired-state reconciliation failed", "err", reconciliationErr)
	} else if reconciliation.Found && reconciliation.Status != "applied" {
		slog.Warn("fleet desired state requires attention", "revision", reconciliation.Control.Revision, "detail", reconciliation.DetailCode)
	}
	if reconciliation.Found {
		if err := controls.ReportFleetControlAcknowledgement(ctx, reconciliation, info.Version); err != nil {
			slog.Warn("fleet desired-state acknowledgement failed", "revision", reconciliation.Control.Revision, "err", err)
		}
	}
	status := enterprisecontrol.FleetNodeStatus{
		NodeID:        info.NodeID,
		AgentVersion:  info.Version,
		UptimeSeconds: uint64(health.Uptime.Seconds()),
		// #nosec G115 -- daemon counters are non-negative in-memory collection sizes and cannot exceed the process address space.
		Connections: uint32(health.Connections),
		// #nosec G115 -- daemon counters are non-negative in-memory collection sizes and cannot exceed the process address space.
		Peers: uint32(health.Peers),
		// #nosec G115 -- daemon counters are non-negative in-memory collection sizes and cannot exceed the process address space.
		EncryptedPeers: uint32(health.EncryptedPeers),
		BytesSent:      health.BytesSent,
		BytesReceived:  health.BytesRecv,
		PolicyRevision: controls.CurrentPolicyRevision(ctx),
	}
	if err := controls.ReportFleetStatus(ctx, status); err != nil {
		slog.Warn("fleet status report failed", "err", err)
	}
	commands, err := controls.FleetCommands(ctx)
	if err != nil {
		slog.Warn("fleet command poll failed", "err", err)
		return
	}
	for _, command := range commands {
		outcome, detail := "succeeded", ""
		lifecycle := ""
		switch command.Kind {
		case authority.FleetCommandRefreshPolicy:
			if err := controls.RefreshRollout(ctx); err != nil {
				outcome, detail = "failed", "rollout_refresh_failed"
			}
		case authority.FleetCommandExportReceipts:
			if !controls.HasReceiptExport() {
				outcome, detail = "rejected", "receipt_export_unconfigured"
			} else if err := controls.ExportReceiptsOnce(ctx); err != nil {
				outcome, detail = "failed", "receipt_export_failed"
			}
		case authority.FleetCommandReloadControl:
			if err := controls.Reload(); err != nil {
				outcome, detail = "failed", "control_reload_failed"
			}
		case authority.FleetCommandSyncState:
			if !controls.HasFleetStateSync() {
				outcome, detail = "rejected", "state_sync_unconfigured"
			} else if _, err := controls.SyncFleetState(ctx); err != nil {
				outcome, detail = "failed", "state_sync_failed"
			}
		case authority.FleetCommandDiagnostics:
			// The signed health report above is the bounded diagnostic
			// payload. Include the .pilot mirror when that optional channel
			// is enabled, without returning logs or environment values.
			if controls.HasFleetStateSync() {
				if _, err := controls.SyncFleetState(ctx); err != nil {
					outcome, detail = "failed", "diagnostics_sync_failed"
				}
			}
		case authority.FleetCommandRestartRuntime:
			if controls.LifecycleCommandAlreadyApplied(command) {
				outcome, detail = "rejected", "already_applied"
			} else {
				lifecycle = "restart"
			}
		case authority.FleetCommandShutdownRuntime:
			if controls.LifecycleCommandAlreadyApplied(command) {
				outcome, detail = "rejected", "already_applied"
			} else {
				lifecycle = "shutdown"
			}
		default:
			outcome, detail = "rejected", "command_not_allowlisted"
		}
		if err := controls.ReportFleetCommandResult(ctx, command.ID, outcome, detail); err != nil {
			slog.Warn("fleet command result report failed", "command_id", command.ID, "err", err)
			continue
		}
		if outcome == "succeeded" && lifecycle != "" {
			// Persist the idempotency record BEFORE acting, and fail closed if
			// it can't be written — otherwise a replayed signed command could
			// loop across every poll and across the restart it triggers.
			if err := controls.MarkLifecycleCommandApplied(command); err != nil {
				slog.Error("persist lifecycle idempotency record failed; refusing to act to avoid a replay loop", "command_id", command.ID, "err", err)
				continue
			}
			select {
			case remoteLifecycleRequests <- lifecycle:
			default:
				slog.Warn("fleet lifecycle request already pending", "command_id", command.ID)
			}
		}
	}
}

// pilotctlBinaryPath resolves the pilotctl that ships beside this daemon.
// Preferring the sibling binary over $PATH keeps the verified install path
// pinned to the same release as the daemon rather than to whatever a user
// happens to have earlier in their environment.
func pilotctlBinaryPath() string {
	if executable, err := os.Executable(); err == nil {
		sibling := filepath.Join(filepath.Dir(executable), "pilotctl")
		if info, statErr := os.Stat(sibling); statErr == nil && !info.IsDir() {
			return sibling
		}
	}
	if resolved, err := exec.LookPath("pilotctl"); err == nil {
		return resolved
	}
	return "pilotctl"
}

// reconcileApps converges installed apps toward the authority's desired set.
// A failure here must never disturb policy enforcement or the state mirror, so
// it is logged and retried on the next tick rather than propagated.
func reconcileApps(ctx context.Context, controls *enterprisecontrol.Runtime, installer enterprisecontrol.AppInstaller) {
	result, err := controls.ReconcileApps(ctx, installer)
	if err != nil {
		slog.Warn("managed app reconcile failed", "err", err)
		return
	}
	if result.Installed+result.Staged+result.Removed+result.Failed > 0 {
		slog.Info("managed apps reconciled",
			"desired", result.Desired, "installed", result.Installed,
			"awaiting_grants", result.Staged, "removed", result.Removed, "failed", result.Failed)
	}
}

func synchronizeFleetState(ctx context.Context, controls *enterprisecontrol.Runtime) {
	result, err := controls.SyncFleetState(ctx)
	if err != nil {
		slog.Warn("fleet .pilot state synchronization failed", "err", err)
		return
	}
	if result.AppliedMutations > 0 || result.RejectedMutations > 0 {
		slog.Info("fleet .pilot state synchronized", "revision", result.Revision, "entries", result.Entries, "applied_mutations", result.AppliedMutations, "rejected_mutations", result.RejectedMutations)
	}
}

func envString(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

// webhookManagerAdapter bridges *webhook.Service to the daemon's
// WebhookManager interface. Defined here (composition root) rather
// than in the plugin to keep the plugin free of pkg/daemon imports.
type webhookManagerAdapter struct{ svc *webhook.Service }

func (a webhookManagerAdapter) SetURL(url string) { a.svc.SetURL(url) }
func (a webhookManagerAdapter) Stats() daemon.WebhookStats {
	s := a.svc.Stats()
	return daemon.WebhookStats{Dropped: s.Dropped, CircuitSkips: s.CircuitSkips}
}

// parseNetworkIDs parses a comma-separated string of network IDs into a uint16 slice.
func parseNetworkIDs(s string) []uint16 {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var ids []uint16
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			log.Printf("warning: invalid network ID %q: %v", p, err)
			continue
		}
		ids = append(ids, uint16(n))
	}
	return ids
}

// parseNodeIDs parses a comma-separated string of uint32 node IDs.
// Garbage tokens are logged and skipped — a typo in env shouldn't
// fail-fast the daemon.
func parseNodeIDs(s string) []uint32 {
	if s == "" {
		return nil
	}
	var ids []uint32
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			log.Printf("warning: invalid node ID %q: %v", p, err)
			continue
		}
		ids = append(ids, uint32(n))
	}
	return ids
}

// applyNodeIDWhitelist resolves flag, falls back to env, parses the
// comma-separated list, and applies via the provided setter. Logs one
// line on success showing the count so deployments can sanity-check
// what landed.
//
// PILOT-343/344/345 wildcard: the literal tokens "*" and "all" mean
// "every source bypasses this rate limit." Used on service-agent boxes
// where the rate limit interferes with legitimate high-volume query
// traffic. Wildcard takes effect via the matchAll setter; the per-ID
// list is still applied (so a mixed list like "*,12345" works the
// same as "*" alone — the bool just short-circuits the map lookup).
func applyNodeIDWhitelist(name, flagVal, envName string, set func([]uint32), setAll func(bool)) {
	raw := flagVal
	if raw == "" {
		raw = os.Getenv(envName)
	}
	if raw == "" {
		return
	}
	all := false
	for _, t := range strings.Split(raw, ",") {
		t = strings.TrimSpace(t)
		if t == "*" || t == "all" {
			all = true
			break
		}
	}
	if all {
		setAll(true)
		log.Printf("%s-rate-limit whitelist: wildcard '*' — every source bypasses", name)
		return
	}
	ids := parseNodeIDs(raw)
	set(ids)
	log.Printf("%s-rate-limit whitelist configured: %d node(s)", name, len(ids))
}
