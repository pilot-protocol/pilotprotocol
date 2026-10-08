# Changelog

All notable changes to Pilot Protocol are recorded here. This file follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions. The
project uses [Semantic Versioning](https://semver.org/).

Detailed per-release notes are on the
[GitHub Releases page](https://github.com/TeoSlayer/pilotprotocol/releases).

## [Unreleased]

### Added
- **`pilotctl send-message` can take its payload from stdin or a file**:
  `--data -` and `--data-file <path>`. A payload passed as an argument is
  capped by the OS — a 1 MB `--data` failed with "Argument list too long",
  and on Linux a single argument stops at 128 KiB — which is why senders of
  large bodies needed a separate stdin helper.
  `--data -` now means stdin, so a message that is just `-` has to come from
  `--data-file`. One message can carry up to the 64 MiB data-exchange frame
  limit; a larger payload is refused before anything is sent.
- **A client can ask the daemon whether a datagram was actually sent.** The
  IPC `SendTo` command is fire-and-forget: when the daemon could not send a
  datagram (no route to the node, port policy, ephemeral ports exhausted) it
  only logged `IPC datagram send failed`, and `pilotctl dgram` and the
  driver's `SendTo` still reported success. A new command pair,
  `CmdSendToConfirm` (0x39) / `CmdSendToOK` (0x3A), sends the same datagram
  and replies OK once it is handed to the tunnel, or with the error. The
  daemon lists `dgram_confirm` in the `info` reply's `features`. The
  existing `SendTo` command is unchanged and still never replies, so
  current clients and SDKs are unaffected. The driver's `SendToConfirmed`
  (common v0.6.1) uses it, and so does `pilotctl dgram`: a datagram the
  daemon refuses fails the command with the reason, an answer that does not
  come in time says the outcome is unknown, and against an older daemon it
  sends the old way and reports `"confirmed": false`.
- **`pilotctl send-message --wait` can match the reply by message ID.** The
  wait takes the oldest new message from the peer, so two concurrent
  requests to one peer, or anything else the peer sends in the window, can
  hand a caller another request's answer. Every message is now sent with a
  new message ID (`message_id` in the `--json` result, and in the receiver's
  inbox record). A reply whose `reply_to` is that ID is matched exactly, and
  a message whose `reply_to` names another request is never taken. Exact
  matching needs the responder to echo the request's `message_id` as
  `reply_to`, which no service responder does yet. An untagged reply still
  works: it is matched by sender and arrival time and taken as soon as it
  arrives, as before, so for such responders concurrent waits can still be
  crossed. From a peer known to echo IDs (one of its newest messages in the
  inbox carries a `reply_to`) an untagged message is held back until 0.75 s
  after it arrived, in case the reply naming the request follows; the inbox
  is searched for that history beside the send, not before it. Once the
  peer has been seen naming another request in `reply_to` during the wait,
  only a reply naming ours is taken. New flag `--reply-to <message_id>`
  sends a message as the answer to a received one (an inbox file id is
  looked up; a bare flag is refused).
  `pilotctl inbox` now shows each message's `message_id` and `reply_to`, in
  the listing and with `--json` (new fields; `id` is still the file name).
  A first-contact re-send uses an ID of its own (the receiver would drop a
  repeat of the same ID as a duplicate) and a reply to either is accepted.
  When the ack is lost, the message is sent once more on a new connection
  with the same ID (`"retried": true`; `--no-resend` opts out). A receiver
  from v1.13.10 on recognises the repeat and keeps one copy; one through
  v1.13.9 can store the message twice when the ack of its untagged copy is
  the one lost. A `--trace` message is never sent again: receivers do not
  suppress repeated trace frames. Receivers that predate message IDs
  (v1.13.9 and older) still get the message, in the old format
  (`"tagged": false` in the result). They store nothing for the message
  carrying the ID, so it is sent to them a second time on the same
  connection, without the ID: the whole payload, up to 64 MiB, crosses the
  network twice, and twice more when its ack is lost and it is sent again.
  No dependency change: the dataexchange release already required carries
  the IDs.
- **The daemon caps its own log file.** launchd never rotates the daemon's
  `StandardOutPath`/`StandardErrorPath` (`~/.pilot/daemon.log`), which grew
  without bound — 22 MB on one laptop. When stderr is a regular file the
  daemon now checks it every minute and, past `-log-max-size` MB (default 50;
  `0` disables), copy-truncates it into gzipped generations
  `daemon.log.pilot.1.gz` … `daemon.log.pilot.N.gz` (`-log-max-backups`,
  default 3). Truncation is safe for every writer — the file is opened
  append-only and shared by child processes. Both flags can also be set in
  `~/.pilot/config.json` (`log_max_size`, `log_max_backups`). No-op when the
  output goes to journald, a pipe or a terminal.
  - By default only a log Pilot set up is rotated: one inside `~/.pilot`,
    where install.sh's launchd job and `pilotctl daemon start` put it (also
    `$PILOT_HOME/.pilot`), and the Homebrew service's
    `$(brew --prefix)/var/log/pilot-daemon.log` when the daemon is the one
    `brew install pilotprotocol` installed (`brew services`, launchd or
    systemd). If you send the daemon's output somewhere else, rotation stays
    off unless you set `-log-max-size` explicitly, on the command line or in
    `config.json`, so your own rotation (logrotate, newsyslog) keeps working
    as before.
  - A rotation interrupted by a crash or kill is finished by the next
    rotation of that log. In `~/.pilot` this includes a rotation left under
    the `pilot-<pid>.log` name of a daemon that `pilotctl daemon start`
    launched earlier. Only those names are finished this way, so another
    program's `<name>.pilot.1` is never taken for one. A rotation holds its
    uncompressed copy (`<log>.pilot.1`) locked with `flock` until it is
    compressed, so a copy that another running daemon is still working on
    is left alone.
  - If the log cannot be truncated (an append-only file, or a filesystem
    that refuses it), no backup is lost. The round's copy is removed, the
    generations are put back, and the next attempt waits twice as long as
    the last, up to about an hour.
  - It never touches files it did not create. The `.pilot` infix keeps its
    backups apart from logrotate's and newsyslog's names (`daemon.log.1`,
    `daemon.log.2.gz`, …). It skips a symlink or another user's file at one
    of its own names, and creates its files with `O_EXCL|O_NOFOLLOW`. If
    other users can create files in the log's directory, it only truncates
    and keeps no backups. That is the case when the directory is writable
    by others, is owned by another user, or is writable by a group other
    than the user's own private group. A `~/.pilot` that is group-writable
    only because of the umask 002 on Ubuntu, Debian or Fedora (the group
    is the user's own, with no other members) keeps its backups.
- **Opt out of automatic app-store updates with `PILOT_APP_UPDATE_OPT_OUT`.** The
  `pilot-updater` keeps installed apps current by periodically running
  `pilotctl appstore upgrade --all`. Set `PILOT_APP_UPDATE_OPT_OUT=true` in the
  updater's environment and it stops checking for and installing app updates —
  installed apps stay at the version you installed. Unset it or set it to
  `false` (the default) to switch app auto-updates back on. Pilot daemon/CLI
  binary updates are never affected. Honors the existing
  `PILOT_UPDATER_NO_APP_UPGRADE` as a back-compat alias.
- **Works behind an HTTPS proxy with UDP blocked (Meta Muse and other hosted
  agent sandboxes) — no flags needed.** pilot-daemon gets `-proxy
  <auto|off|URL>` (`$PILOT_PROXY`, config.json `proxy`): with compat mode the
  registry, the WSS beacon and every plugin HTTP client go through
  `$HTTPS_PROXY` / `$ALL_PROXY` (honoring `$NO_PROXY`), CONNECTing by host
  name so poisoned local DNS does not matter, with TLS end to end; an
  explicit `http(s)://[user:pass@]host:port` proxies every connection except
  loopback. `off` also accepts `none`, `no`, `false`, `direct`; any other bare
  word is an error instead of a proxy host name. Proxy credentials never
  appear in logs, errors or `-help`.
- **Rotating proxy credentials: `-proxy-cmd` / `$PILOT_PROXY_CMD` /
  config.json `proxy_cmd`** (`pilotctl daemon start --proxy-cmd`, passed as
  `$PILOT_PROXY_CMD`, never on argv). A command whose output is the current
  proxy URL (e.g. `bash -c 'printf %s "$https_proxy"'`), run with `sh -c`
  in the environment the daemon was launched with. It drives common
  v0.5.15's netproxy refresh: the command runs at startup, again once 60s
  have passed, and whenever the proxy rejects the credentials — a 407, or a
  CONNECT answer so garbled it cannot be parsed, which is how Meta Muse's
  proxy answers them ("malformed HTTP status code") — after which that
  connection is retried once with the new credentials (`netproxy.Dialer` for
  the registry — primary, pool and every redial — and the compat WSS beacon
  and its reconnects; `netproxy.RefreshingTransport` for the daemon's own
  HTTP clients). Tunnels already open are never touched. The command's
  output is never logged, and a failing command keeps the last good proxy
  URL (at first, the launch environment's).
  - **Apps follow the rotation too.** App-store apps are processes the
    daemon starts, and they inherit its environment — with the launch-time
    credentials, which the proxy stops accepting within minutes: every app
    that opened a new connection failed (also after a respawn) while the
    node stayed online ("node online, all apps broken"). A daemon that
    proxies now runs a CONNECT relay on loopback (random port, its own
    random credentials, CONNECT only, never sees inside the TLS tunnels),
    which opens each tunnel upstream with the current credentials, refreshes
    and retries once on a rejection, and answers a tunnel it cannot open
    with a 502/403/504 whose reason says why without proxy text or
    credentials. With a refresh command, the apps the daemon starts get
    `HTTPS_PROXY` / `https_proxy` (and `$PILOT_PROXY` if it holds a URL)
    pointing at the relay, so they never hold the proxy's credentials;
    `HTTP_PROXY` is left alone (the relay only tunnels). The daemon's own
    refresh command still runs in the launch environment, a refresh that
    would name the relay is refused, and a remote restart re-execs with the
    launch environment. Without a refresh command the apps' environment is
    left as it is.
  - **Plugin HTTP clients** (`http.DefaultTransport`: catalogue pins,
    skillinject, trustedagents, webhook, telemetry) send their https
    requests through the same relay, so a rejected CONNECT — including
    Muse's garbled form, which net/http never hands to a hook and quotes
    in its error — is refreshed and retried instead of failing until the
    next timed refresh.
  - In a Linux container/VM without systemd whose `HTTPS_PROXY` or
    `https_proxy` carries credentials, `pilotctl daemon start` hands the
    daemon `PILOT_PROXY_CMD=bash -c 'case $https_proxy in *@*) printf %s
    "$https_proxy";; *) printf %s "${HTTPS_PROXY:-$https_proxy}";; esac'`
    itself when no `proxy_cmd` is configured (so a node set up by any
    installer gets it), and the installer saves the same command: the
    variable that carries credentials wins (`$https_proxy`, which Meta
    Muse's guidance reads from a fresh shell, when both do), so the command
    never swaps a credentialed proxy URL for one without credentials.
    pilotctl's own registry commands use the same command.
- **`-transport=auto`.** UDP when the beacon answers a UDP discover (one round
  trip), otherwise compat when the compat beacon itself answers over TCP 443
  (through the proxy, if any: a TLS GET of the beacon path must return `426
  Upgrade Required` — a front that accepts TCP while the beacon is down does
  not count), otherwise compat too when a proxy is configured and it refuses
  the check (407 wrong or stale credentials, 403, a garbled answer, or the
  proxy cannot be reached) — udp would dial the registry directly, past the
  proxy, which proxy-only sandboxes kill; compat keeps every connection on
  the proxy, refreshes the credentials on a 407 and fails naming the proxy's
  answer — otherwise udp as before; the decision is logged once
  (`transport auto-selected`, at WARN with a hint when the proxy refused). It never moves a node with a private registry
  or beacon onto the public compat beacon. pilot-daemon's own default stays
  `udp` (or `$PILOT_TRANSPORT_DEFAULT`, which applies only when nothing else
  chooses); `pilotctl daemon start` asks for `auto` whenever no transport is
  configured and the daemon supports it, and the systemd/launchd units the
  installer writes set `PILOT_TRANSPORT_DEFAULT=auto`. `auto` is never saved
  in config.json, where a daemon that predates it would refuse to start.
- **`$PILOT_TRANSPORT` and config.json `transport` are honored by pilot-daemon
  itself** (both used to be masked by the `-transport` default). Precedence for
  `-transport`, `-proxy`, `-registry-trust` and `-registry-fingerprint`: flag,
  then `$PILOT_TRANSPORT` / `$PILOT_PROXY` / `$PILOT_REGISTRY_TRUST` /
  `$PILOT_REGISTRY_FINGERPRINT`, then config.json, then the default — so a
  credential-bearing proxy handed over in the environment beats a saved
  `"proxy": "auto"`.
- **Pinned registry trust from config/env for sandboxes without a CA bundle.**
  `registry_trust` / `registry_fingerprint` in config.json (or the env vars
  above) now survive compat mode, and a fingerprint alone selects pinned
  trust there. Certificate errors name the fix: `SSL_CERT_FILE` /
  `SSL_CERT_DIR` (forwarded by pilotctl) or the registry fingerprint.
- **`pilotctl daemon start --transport <udp|compat|auto> --proxy <auto|off|URL>`**,
  also from `$PILOT_TRANSPORT` / `$PILOT_PROXY` and config.json. The daemon
  binary is probed once (`-help`): flags or values it predates are dropped
  (auto becomes udp) with a warning, so a new pilotctl still starts an older
  daemon, and an old pilotctl (v1.13.9) starts the new daemon unchanged. A
  proxy URL with credentials (any `@`) travels as `$PILOT_PROXY`, never on the
  daemon's argv, and is shown redacted. The ready summary reports the
  transport the daemon actually chose.
- **pilotctl's own registry connections follow the daemon's network.**
  `lookup`, `register`, `rotate-key`, the auto-handshake visibility check and
  `recovery recover` dial through an explicit `$PILOT_PROXY` / config `proxy`
  URL, and through `$HTTPS_PROXY` / `$ALL_PROXY` only when the daemon runs
  compat (asked over IPC; the info reply now carries `transport`), else
  `$PILOT_TRANSPORT` / config.json — on a udp host that merely exports a proxy
  they dial directly, as the daemon does, so a private raw-TCP registry keeps
  working. Proxied or compat dials use `registry.pilotprotocol.network:443`
  over TLS; a direct raw-TCP attempt falls back to it. With the transport
  unknown (no daemon answering, nothing configured) the production registry
  is tried through the environment's proxy first and directly second, and a
  direct connection whose peer talks or hangs up before the first request (a
  sandbox's network guard) is not used, so the proxy's error is reported
  instead of a broken pipe. `proxy=off` restores direct dials.
- **`pilotctl daemon start` says why a start failed.** It notices a daemon
  that exits during startup at once instead of polling its socket until the
  deadline, and both then and on a timeout it prints the daemon's last error
  and its last proxy error from the log (for example `last proxy error: proxy
  CONNECT registry.pilotprotocol.network:443: 407 Proxy Authentication
  Required`), with a hint for it (wrong or rotated credentials → `proxy_cmd`),
  instead of only "did not become ready". pilot-daemon logs its fatal
  startup errors at ERROR (they came out at INFO), and a registry or compat
  beacon dial the proxy refused ends with a hint naming the fix. A CONNECT
  answer that cannot be parsed (`read CONNECT response: malformed HTTP
  status code (response text withheld)`, Meta Muse's answer to wrong or
  expired credentials) gets the credentials/`proxy_cmd` hint, and no hint
  suggests `-transport=udp` except for a proxy that cannot be reached, and
  then only for a host that can reach the internet without it.
- **`daemon start` forwards the proxy/TLS environment** (`HTTPS_PROXY`,
  `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY` in both cases, `PILOT_PROXY`,
  `PILOT_TRANSPORT`, `PILOT_REGISTRY_TRUST`, `PILOT_REGISTRY_FINGERPRINT`,
  `SSL_CERT_FILE`, `SSL_CERT_DIR`) on both the fork and `--foreground` paths,
  and passes through `--compat-beacon`, `--registry-trust`,
  `--registry-fingerprint` and `--tls-trust`.
- **`install.sh --transport <auto|udp|compat>`** (or `PILOT_TRANSPORT`).
  install.sh here is a copy of `pilot-protocol/release:install.sh`, the script
  https://pilotprotocol.network/install.sh serves; these installer changes
  reach users through pilot-protocol/release#49, which also keeps the
  managed-node mode (`--managed-url`).
  `udp` and `compat` are saved; `auto` (the default) is not — `--transport
  auto` removes a saved transport. `compat` skips the UDP probe. No `proxy`
  key is written (the daemon default already uses the environment's proxy).
  Service units take the transport from config.json, so `pilotctl config
  --set transport=` applies to them too. Every installer download goes through
  `$HTTPS_PROXY`; service setup without root/systemd/launchd degrades to a
  printed `pilotctl daemon start` hint; download failures name the proxy
  (redacted) and the hosts it must allow. In a Linux container/VM without
  systemd the installer runs as root without `PILOT_ALLOW_ROOT` (hosted
  sandboxes run the agent as root); regular hosts still refuse root.
- **The daemon warns when it is PID 1.** As the entrypoint of a container
  started without an init, the daemon is handed every orphaned process, and
  the servers its apps start (redis, postgres) stay as zombies after they
  are stopped. The daemon does not reap them — that would also take the exit
  status of the apps it supervises — and now logs one warning at startup, on
  Linux, saying to run it under an init (`docker run --init`, tini as the
  entrypoint, Kubernetes `shareProcessNamespace`, ECS `initProcessEnabled`).
  README: Install.

### Removed
- **Hosted control plane client.** The hosted control plane has been retired,
  and everything in this repository that existed only to talk to it is gone:
  - `pilotctl enterprise` (`adopt`, `status`, `dashboard-url`, `trust`,
    `policy`, `mandate`, `receipt`, `workflow`, `hook`).
  - The `--enterprise-control` and `--governed-resource` flags of
    `pilotctl send-message` and `pilotctl send-file`. Both commands now
    refuse those flags instead of sending ungoverned.
  - The daemon's `-enterprise-control` flag, the `enterprise_control` config
    key, automatic discovery of `~/.pilot/managed/enterprise-control.json`,
    signed fleet reporting, fleet commands (including remote restart and
    shutdown), policy rollout refresh, `.pilot` state sync, managed app
    reconcile and receipt export. A leftover attachment file or config key is
    ignored.
  - The `control-agent` binary.
  - `install.sh --managed-url` / `PILOT_MANAGEMENT_URL` / `--no-start`, and
    the `managed-runtime-v*` release tag stream.
- `-security-profile enterprise` no longer requires `-enterprise-control`
  while data exchange or event stream is enabled; its other locked settings
  are unchanged.
- SIGHUP no longer reloads control state. It is still caught and ignored.
- **Governed envelopes in the plugins.** dataexchange v0.3.0, eventstream
  v0.3.0 and handshake v0.3.0 no longer contain the governed-send,
  governed-publication and action-hook code the hosted control plane used.
  A node that receives a data-exchange frame of type 8 or 9 (the retired
  governed types) now answers `ERR ... unsupported frame type`, as for any
  unknown type; before it answered that no verifier was configured.

### Changed
- **`pilotctl send-message` asks the daemon for its `info` reply once, not
  twice.** The auto-handshake read the daemon's `features` from a second
  `info` request, although the command had fetched one a moment earlier for
  its first-contact check. The reply lists every peer and connection: on a
  node with 5,400 peers it is several hundred KB, and parsing it costs the
  CLI 7.5 ms of CPU and 2.9 MB of allocations, more than the rest of a send.
  The second request happened on every send to an agent in the trusted list
  (`list-agents`, `pilot-mom`) and to any public peer not yet trusted.
- **The daemon uses far less CPU under bursts of sends.** Measured on two
  local daemons, the sending side's CPU per message fell from 4.5 ms to
  1.6 ms at 32 concurrent sends and from 24 ms to 3.5 ms at 256. Two
  changes:
  - A dial no longer polls its connection every 10 ms. SYN-ACK, RST and
    shutdown wake the dialer directly; the poll is a 250 ms backstop. With
    hundreds of dials in flight the poll alone kept the Go scheduler busy.
  - Concurrent `info` requests share one reply for 200 ms. Every
    `pilotctl send-message` asks for `info`, and the reply lists every
    connection, so a burst of N sends built N replies over a table that grew
    with N: 73% of everything the daemon allocated during a 256-way burst.

  Hosts with many cores can cut scheduler overhead further by setting
  `GOMAXPROCS` (for example 4) in the daemon's environment.
- **`pilotctl dgram` exits with a code that says whether to retry.** Every
  datagram the daemon refused was `connection_failed`, which the error-code
  list calls retryable, though a port the network's policy forbids or a
  datagram too large to send fails the same way every time. The `code` in
  the error (and in `--json`) now follows the reason, so scripts that
  matched `connection_failed` for these see a different code:
  - a port the network's policy does not allow: `permission_denied` (now in
    the `pilotctl context` error-code list);
  - a payload too large for a packet, the tunnel socket or the IPC frame,
    or a broadcast address: `invalid_argument`;
  - a node the registry does not know: `not_found`;
  - a datagram that waited too long for its turn and was not sent:
    `timeout`, as one whose answer did not come in time already was;
  - anything else (no route or tunnel yet, a key exchange in progress, the
    registry unreachable, ephemeral ports exhausted): `connection_failed`,
    as before.

  A `--data` over 65535 bytes is now refused before the daemon is
  contacted.
- **The tunnel socket asks the kernel for 4 MB buffers** in each direction
  instead of the default (about 200 KB on Linux). Every tunnel shares the one
  socket, and several streams sending at once overflowed it. The kernel caps
  the request at `net.core.rmem_max` / `wmem_max`; raise those to get the full
  size.
- **The daemon's `info` reply is cheaper to build.** `pilotctl send-message`
  asks for it on every send, and with a few hundred connections in the table
  it was three quarters of the daemon's CPU under send load. The JSON is
  unchanged.
- **Dependencies: skillinject v0.2.4, dataexchange v0.2.3, updater v0.2.5**
  (plus common v0.5.14, and the sigstore-go v1.3.0 / go-openapi versions
  updater v0.2.5 requires).
  - skillinject: heartbeats are rendered literally, so a `$5` in a heartbeat is
    no longer read as a regex group and dropped. A heartbeat-only edit now
    reaches hosts. Retired surfaces from older manifests (the OpenClaw
    `workspace/HEARTBEAT.md` block, the PicoClaw `workspace/AGENT.md` block, the
    `pilotprotocol-prompt-injector` plugin and `~/.pilot/bin/pilot-ask`) are
    removed on every tick, including on hosts that already ran
    `pilotctl skills disable all`. The disclosure line in each block now says
    `pilotctl skills disable all`. Existing blocks are rewritten in place once.
  - dataexchange: the default inbox byte cap no longer deletes the whole inbox.
    It evicts the oldest messages instead. Frames can carry optional request
    and reply IDs, and a re-delivered frame with the same ID is stored only
    once.
  - updater: downloads resume after a stall instead of failing after 30 s. The
    releases API call sends `GITHUB_TOKEN`/`GH_TOKEN` when set. On Linux, a
    daemon under a systemd unit with `Restart=always` is now restarted onto the
    new binary. In every other case the daemon keeps running and
    `restart_error` says how to restart it. Every check is recorded in
    `~/.pilot/update-state.json`.
- **`pilotctl appstore install` says whether the app started.** Install only
  writes files and the daemon starts the app a moment later, so it reported
  success for an app that then exited at every start (seen with
  `io.pilot.sqlite` on an image without `tar`) and was suspended half a minute
  later. With a daemon running, install now waits up to 20s (`--wait <dur>`
  changes that) for the first start and reports one of three outcomes:
  started; failed — the supervisor suspended the app, it exited at least
  twice without opening its socket, or the supervisor refused it as older
  than the version it runs — in which case install **exits non-zero**
  (`app_start_failed`) with the last supervisor log line and where to look
  next; or still starting, which is not an error, so an app that needs longer
  than the wait is not a failed install. On an upgrade, what the replaced
  instance logs before the daemon swaps it out (the end of its crash loop, or
  its exit when it is stopped) is not counted against the new version. The
  `--json` report gains `start_state`, `start_exits`, `start_detail` and
  `start_waited_ms`; nothing existing changed. No wait with `--no-wait`, when
  no daemon is running, or for a reinstall the supervisor does not act on
  (same version and binary, or an older version, ordered as the supervisor
  orders them, so `1.0.0-beta.1` is older than `1.0.0`); for an older
  version install says the daemon starts it only when the daemon restarts.
  `appstore upgrade` does not wait.

### Fixed
- **A write followed at once by a close no longer loses its end under
  loss.** A FIN that overtook a lost segment was acted on at once: the
  receiver closed the stream with the segment missing, and its FIN-ACK made
  the sender drop the segment it was about to resend. Every version did
  this. In the lab, 4 of 30 pub/sub events at 5% loss never reached the
  broker while `pilotctl publish` reported success; one-shot sends and any
  client that closes right after writing were exposed the same way. A
  receiver now handles the FIN only once the data before it has arrived,
  and asks for what is missing meanwhile. If the sender stops resending it
  (a daemon stopped or restarted with a segment lost), the receiver closes
  the stream without it 15 s after it last heard from the sender, rather
  than waiting about two minutes for keepalive. A closing sender also holds
  its FIN until its data is acknowledged (5 s at most, without blocking the
  caller), so the end of a write survives loss on receivers that have not
  upgraded too.
- **A send error no longer strands the end of a stream write.** When the
  tunnel refused a segment of a write's last piece (or of any write up to
  56 segments), the daemon returned the error and left the rest of the write
  in the send buffer, where nothing sent it: `send-message` then waited for
  the receiver's two-minute idle timeout. The refused segment is not lost —
  it is retransmitted — so the write now carries on past it, as the earlier
  pieces of a large write already did. Closing a connection likewise sends
  everything left in the send buffer ahead of the FIN after a send error,
  instead of dropping the rest.
- **The retransmission timeout no longer jumps after a recovery.** The ACK
  for a resent segment also covers the segments behind it, which were sent
  once, possibly seconds earlier, and the round-trip time was sampled from
  the oldest of them. After a parked segment was resent the timeout went from
  437 ms to 4.5 s. Following Karn's algorithm as Linux applies it, an ACK that
  newly acknowledges any resent segment gives no round-trip sample.
- **Address-change recovery follow-ups:** registry retries no longer delay
  the next address move (it waited up to 80 s, now 10 s); stopping the
  daemon no longer waits up to 47 s for a recovery redialling a registry
  that refuses connections; and the heartbeat no longer repeats the registry
  reconnect and full re-registration a recovery has just done. A recovery
  whose re-registration failed, or that restored the node's visibility,
  hostname or trust pairs only in part, does not count as done.
- **`pilotctl send-message --count N --reuse-conn` carries on after a lost
  ack.** A lost ack means the shared connection is gone, but the messages
  after it were still written into it. The driver only notices a connection
  it closed itself, so those writes appeared to succeed and were dropped. Each
  later message then lost its ack too and was sent again on a new connection:
  every message showed `"retried": true`, and with `--no-resend` every
  message after the lost one failed. The messages after it now go on the
  retry's connection, or on a new one when there was no retry. `reused` is
  true only when the connection had carried an earlier message. A later
  message whose new connection cannot be dialled is reported as failed, and
  the run goes on.
- **A failed `pilotctl send-message` says which message failed.** When a
  single message could not be sent, was not acknowledged or was refused by
  the receiver, the `--json` error did not include its `message_id`, so the
  caller could not look for it in the receiver's inbox or for a reply naming
  it. The error now carries the message's result in `results`, as a
  `--count` run's error already did. A refused message's error also gets a
  `hint`.
- **`pilotctl bench` fails when the echo does not all come back.** A run
  whose echo stopped short printed `"status":"ok"` and exited 0: with the
  echo cut off after 2 KiB, `bench <peer> 0.01 --timeout 300ms` reported
  4096 of 10485 bytes received as a success. Such a run now **exits 1**,
  with code `timeout` when `--timeout` ended the wait for the echo, or
  `connection_failed` when the echo stream ended early, and the error's
  `results` carry the partial figures. A complete run adds
  `"complete": true` to its result. `total_mbps` is now computed from the
  bytes that came back rather than the bytes sent, and the received count is
  no longer read while the reader may still be writing it (a data race).
- **A bulk transfer no longer hangs when the receiver's application falls
  behind.** When a receiver's application stops reading for a second, the
  receiver parks the next in-order segment in its reorder buffer and keeps
  SACKing it, delivering it only when that segment arrives again (v1.15.0 and
  later receivers). Senders never resent a SACKed segment, so the parked one
  was never resent and nothing moved until the application timed out: about
  one bulk transfer in ten from a v1.16.0 node into a v1.15.0 node over the
  relay stalled for the full 120 s of `pilotctl bench`. Following RFC 2018
  §5.1 (and Linux's SACK-reneging check), a sender now treats a SACKed
  oldest segment that has gone a retransmission timeout as not received:
  it forgets its SACK marks and resends from the cumulative ACK. Nodes that
  have not upgraded still stall this way when they are the sender.
  The receiver also drops reorder-buffer entries the stream has moved past.
  After such a recovery the parked copy used to stay for the life of the
  connection: every segment was then ACKed at once with a stale SACK block,
  one of the 128 reorder slots stayed taken, and once the sequence space
  wrapped (after 4 GiB on one connection) its stale bytes could be delivered
  in place of real data. A connection closing with only SACKed
  data left keeps retransmitting it too, instead of giving up on it.
- **A daemon stopping mid-poll no longer loses relayed handshakes.** The
  registry empties a node's handshake inbox as it answers a poll, and
  shutdown closed the registry client without waiting for a poll in flight,
  so a restart during one dropped the requests and approvals it carried.
  Shutdown now waits for it before stopping the handshake manager, so what it
  brings back is still acted on and saved, and starts no new poll once it
  has begun. The wait shares the 5s that shutdown already allows its
  background goroutines.
- **A full table of handshake windows lets go of one settled peer, not all
  of them.** With 64 peers tracked, a new request evicted every peer whose
  fast-poll window had closed, and those peers lost the hold-off that stops
  an automatic handshake from reopening their window early. Now only the
  one whose hold-off ends soonest makes room.
- **Bytes after a known beacon notify kind are ignored** instead of the
  whole notify being dropped, so a later beacon can extend the message.
- **`info` and the trusted-peers list work on nodes with very many peers.**
  One IPC message holds at most 1 MB. Past about 10,000 peers the `info`
  reply no longer fit, nor did the trusted list past about 8,000 records;
  the daemon could not send it and closed the client's connection. Every
  command that asked for it failed with `daemon disconnected`: `pilotctl
  info`, `peers`, `connections` and `trust`, and `send-message`, whose
  later requests went over the closed connection. Seen on service agents
  with 10,909 peers and over 20,000 trust records. The daemon now sends as
  many rows as fit, peers with an open connection and the newest trust
  records first, and marks the list with `peer_list_truncated` or
  `trusted_truncated`; the counts still give the totals. `pilotctl peers`
  and `trust` say when a list was cut.
- **Stream segments fit one packet.** A full stream segment was 4096 bytes,
  about 4.2 KB on the wire and three IP fragments on a 1500-byte path. NATs,
  firewalls and some virtual networks drop fragments, so on those paths
  handshakes, pings and messages under ~1.4 KB worked while every full
  segment was lost: larger replies never arrived, `send-file` failed, and
  `bench` reported a few kbit/s until its retransmissions gave up. Segments
  are now at most 1152 bytes (`SendSegmentSize`), a 1231-byte datagram on the
  relay path — within what fits IPv6's minimum MTU, so within any path that
  carries IP. This is a sender-side change: receivers accept segments up to
  the old size, so old and new nodes interoperate in both directions. With
  non-first fragments dropped at the receiver, a 3 KB message, a 60 KB
  message and 64 KB and 1 MB file transfers all failed before and all
  succeed now.
  - The peer's receive window is advertised in segments, not bytes, and is
    now enforced as such. A sender of short segments used to put more of
    them in flight than the peer had slots for.
  - A short write no longer stalls its sender. Nagle's algorithm held a
    short segment until everything before it was acknowledged, and the
    writer was blocked until it had gone out. The ACK it waited for is
    delayed by the peer when the full segments before it are an odd number
    (5ms; 40ms up to v1.14.1), nothing could join a held write because its
    writer could not write again, so a stream of short writes moved at one
    write per round trip, and since a client's sends are handled in order on
    its IPC connection, everything else that client asked for waited too.
    With 1152-byte segments every 4 KB write ends in a short tail, so this
    had to go. Now:
    - the tail of a write of a segment or more leaves with it;
    - a write shorter than a segment waits only for an earlier short
      segment, which is what lets small writes coalesce;
    - a held write does not block: it stays buffered, later writes join it,
      and it is sent when that earlier segment is acknowledged, after 40ms
      at the latest, or ahead of the FIN when the connection is closed.

    This also removes the stall per file chunk that held transfers back. A
    60 MB file between two nodes on one host took 4.8s and takes 1.2s; from
    an upgraded node into v1.13.5 it takes 1.8s, where v1.13.5 to itself
    takes 22.7s.
  - A receiver acknowledges a lone segment at once for the first 32
    segments of a connection, and again after each time its delayed-ACK
    timer has had to fire. A peer that waits for an ACK before sending its
    next small write no longer stalls for the timer each time; the first
    exchange on a connection goes from 5.4ms to 0.3ms.
  - The congestion window grows and backs off over the same number of bytes
    as before.

  Mixed versions were checked in both directions against v1.13.5, v1.14.1
  and the previous main: messages up to 100 KB, files up to 60 MB, four
  concurrent transfers, echo and pub/sub, on a clean network, under a stock
  kernel's socket buffer limit, at 1% loss over a 30ms path, and through the
  relay. Two things to know while a network is part upgraded:
  - Only an upgraded sender stops fragmenting. A reply of more than a
    packet from a node that is not upgraded is still lost on a path that
    drops fragments.
  - A node that is not upgraded and writes back what it reads piece by
    piece (the echo service, so `pilotctl bench` against it) now reads
    1152-byte pieces, each below its own 4096-byte segment size, and its
    own Nagle rule sends one per round trip: 1 MB echoed over a 30ms path
    takes about 35s. Its replies to requests, files and pub/sub are not
    affected, and upgrading that node removes it (1.5–2s).
- **A transfer no longer collapses after a burst of losses.** Three faults
  in loss recovery, found at 2% packet loss on a 30ms path, where 2 of 5
  5 MB transfers failed after several minutes:
  - In fast recovery, segments the peer had already reported (SACK) were
    left out of the amount in flight while the window was also grown by one
    segment per duplicate ACK, counting each twice: the amount outstanding
    doubled every round trip for as long as the first loss stayed
    unrepaired.
  - The peer holds at most 128 out-of-order segments and silently drops the
    rest; the sender did not know and ran past it. It now keeps at most 128
    segments unacknowledged.
  - After a retransmission timeout, every further segment missing from that
    window waited for a timeout of its own, and the timeout doubles each
    time (1s, 2s, 4s … 10s). The next missing segment is now retransmitted
    as soon as an ACK shows the previous one arrived.

  Measured, 5 MB over a 30ms path, five runs each: at 2% loss, 9.7–12.4s
  with 2 of 5 failing before, 10.3–11.8s with none failing after; at 0.5%
  loss 9.4–10.5s before, 7.3–7.6s after; without loss 8.2–8.4s before,
  7.6–7.7s after.
- **A message larger than 256 KB is delivered instead of silently dropped.**
  The daemon refused any single stream write bigger than its send buffer, and
  an IPC send has no reply, so the client never knew: `send-message` printed
  `"status":"ok"` for a 1 MB message that never left the node. A large write is
  now fed through the buffer in pieces, blocking on the window like any other
  write. The buffer's size cap is unchanged.
- **`pilotctl send-message` fails when the receiver does not acknowledge the
  message.** Every receiver answers a stored message with an ACK; with none,
  the command used to exit 0.
- **A peer whose direct path is dead stays on the relay.** After the
  blackhole heuristic moved a peer to the relay, the relay probe loop put
  it back on the direct path within 15 s: to let direct win again it has to
  unpin the peer, and it did that with a call that clears the relay flag
  too. Traffic then went to the dead address until three more silent sends
  tripped the heuristic again, so the daemon spent roughly 75 s of every
  90 s sending into the void and logged `direct path silent, flipping to
  relay` on a loop. Seen for over half an hour against a peer whose
  registry endpoint was stale. The probe loop now removes only the pin; the
  peer leaves the relay when direct packets from it actually arrive.
- **The cached key of a peer is no longer overwritten by the next packet.**
  The key-exchange handler cached a peer's Ed25519 key as a slice of the
  socket's reused receive buffer, so the following packet replaced the
  cached key with its own bytes. The next key exchange from that peer then
  mismatched the cache and made the daemon look the key up in the registry
  from the packet read loop, holding up every other packet for the length
  of that round trip; the log line `auth key exchange: peer pubkey updated
  from registry` (97 in one six-hour session) was this, not peers changing
  keys. The key is now copied.
- **`-advertise-endpoint` survives a re-registration.** When the daemon
  re-registered (registry reconnect, transport watchdog recovery) it sent
  the tunnel socket's local address instead of the advertised endpoint, so
  the registry replaced the operator's address with `<observed-ip>:<local
  port>`. The override is now applied on re-registration as it is at start.
- **A node on a private network no longer reports a loopback endpoint.** With
  the beacon and registry on the node's own private network (a container on
  a Docker bridge, a lab LAN) the daemon logged `daemon registered ...
  endpoint=[::1]:<port>` and `pilotctl info` showed the same, although the
  registry had recorded — and peers resolved — the node's private address
  with the real tunnel port. The daemon now reports that address. Nothing
  sent to the registry changes.
- **Datagrams no longer use up the daemon's ports.** Every datagram sent
  (`pilotctl dgram`, `SendTo`, broadcasts) took an ephemeral source port and
  never gave it back, because only closing a connection released one. After
  about 16,000 datagrams no stream could be opened — sends failed with what
  looked like an unreachable peer — until the daemon restarted. The port is now
  released as soon as the datagram is sent. A dial that does fail for lack of
  ports says so instead of telling the operator to check the peer.
- **Large writes and first exchanges no longer stall for 40ms with both ends
  idle.** A write held by Nagle waits for the data before it to be
  acknowledged, and the receiver delayed a lone or odd segment's ACK by 40ms.
  That cost 40ms on the first exchange of every connection, and one stall per
  48KB chunk of a file transfer — about 1.5 MB/s on any link. The delayed-ACK
  timer is now 5ms: a 60 MB transfer between two containers went from 31s to
  3.5s.
- **A dial returns when its handshake completes**, not on the next 10ms poll.
  A local dial took 11ms and now takes under 1ms; with the change above,
  connecting and exchanging one message dropped from 55ms to 6ms.
- **`pilotctl send-message` fails when the receiver could not store the
  message.** The receiver answers `ERR ...` when its disk is full or its inbox
  is unwritable; the command printed that as the ack and exited 0. It now exits
  non-zero, as `send-file` already did.
- **`pilotctl appstore install` cleans up after itself.** Each install unpacked
  the bundle into a temporary directory and left it there — a copy of every app
  ever installed, and on a small `/tmp` the reason later installs failed with
  "no space left on device". The directory is removed when the install ends,
  whether it succeeded or not.
- **`pilotctl appstore call` waits for an app that was just installed.** The
  daemon starts an app a few seconds after `install` returns, so a call made
  straight away failed with "socket not present". It now waits up to 15s for
  the socket, and says so plainly when the app is suspended after crashing.
- **`pilotctl received --clear` removes interrupted transfers too.** Their
  bytes stay in `received/.partial` for a resume and count against the disk,
  but were never listed or cleared. The reply gains a `cleared_partial` count.
- **Parallel sends to one peer no longer stall or time out on the peer's
  SYN limiter.** The per-source limit admitted 10 connections at once and
  silently dropped the rest; the dialers retransmitted together, so a burst
  of 64 connections from one node took 9 s and larger bursts ended in dial
  timeouts (and flipped a healthy direct peer to relay). A source may now
  open 64 connections at once; the sustained rate is still 10 per second.
  The per-source limit is also checked before the shared one, so a source
  over its own limit no longer uses up the tokens other peers need
  (previously every SYN it had rejected still took a shared token).
  `-syn-whitelist` is unchanged.
- **A trust handshake between two private nodes takes seconds, not two
  minutes.** Neither side can reach the other before trust exists, so the
  request and the answer are parked at the registry until each node polls —
  once per keepalive interval (60s). Measured before: request visible on the
  target after ~59s, approval back at the requester ~57s later. Now:
  - a node that has sent a handshake request polls every 2s until it is
    answered, for at most 2 minutes;
  - `pilotctl pending`, `trust`, `approve` and `reject` poll first (at most
    one such poll every 2s), so a relayed request is there as soon as
    someone looks. Waiting for trust polls only while a request this node
    sent that peer is unanswered, so checking a peer that is already trusted
    — which pilotctl does before every send — costs nothing. The caller is
    held at most 3s by a slow registry; the poll itself still completes and
    delivers what it fetched;
  - the beacon can tell a node that something is waiting for it (a two-byte
    notify that carries nothing else; needs the matching registry/beacon
    release), and the node polls at once — at most 3 polls in a burst and
    one per 5s after that, whatever arrives.
  An idle node still makes one poll per minute, as before. Nodes and
  servers that are not updated keep working at the old pace for their part.
- **Dial timeouts while other dials succeed no longer read as a wedged
  transport.** The watchdog's `outbound-dial-wedged` check counted every
  dial timeout, so a burst of parallel sends to one peer whose SYN limiter
  dropped some of them (`dial_timeouts=32`) made a healthy node re-register
  with the beacon and registry, and could escalate to a restart. A timeout
  is no longer counted when another dial completed while it ran: that dial's
  SYN-ACK shows the outbound path was working. Traffic merely received from
  the peer does not count as evidence, because a node whose outbound path is
  dead still receives its peers' keepalives.
- **A node whose IP address changes recovers in about a second instead of
  about half a minute.** When the host's address changed under a running
  daemon (new DHCP lease, Wi-Fi to Ethernet, a VPN taking the default route, a
  container moved to another address), nothing in the daemon noticed. Peers
  kept sending to the old address until their own timeouts moved them to the
  relay or the node's 25 s keepalive reached them, the node's own registry
  connections stayed bound to the old address until a 30 s read timeout, and
  the registry kept handing out the old endpoint for a minute or more. The
  daemon now checks once a second which source address the kernel would use
  toward the beacon (a route lookup; nothing is sent) and, when it changes,
  re-registers with the beacon, sends one authenticated probe straight to
  every tunnel peer so each learns the new address from it, and sends the
  registry its new endpoint and LAN addresses over a fresh connection. Only
  the endpoint is sent: the registry still has the node's visibility,
  hostname and trust pairs, so they are not written again (the full restore
  still runs if the registry has not answered for 5 minutes or its reply
  shows it lost the node). The beacon registration is repeated 31 s later,
  because the beacon accepts one endpoint update per node every 30 s and
  drops the rest; a move within 30 s of the last keepalive registration
  otherwise reached the beacon only with the next one, up to a minute later.
  Measured in a three-node Docker lab, moving one node to a new address: peer
  to moved node 32 s before, under 1 s after; moved node to peer 30 s before,
  no failed send after; a node with no existing tunnel timed out after 30 s
  before and connected directly in 0.2 s after. Peers need no update.
  - An interface that drops and returns with the same address triggers
    nothing, and neither does an unrelated interface appearing (a Docker
    bridge, a VPN that does not take the route), nor a switch to another
    beacon by the beacon-list refresh, which may be reached over another
    route: the comparison starts over with the new beacon (a change still
    waiting to be announced at that moment still runs). Recoveries are at
    least 10 s apart, and the gap doubles up to 2 minutes while changes keep
    coming, so a flapping interface cannot flood the registry; a change seen
    during the gap runs when the gap ends, unless the address has gone back.
    The gaps are measured on the wall clock, so time asleep counts toward
    them.
  - Behind NAT the local address does not change when the public one does.
    The daemon also reads the address the beacon reports seeing it at (the
    reply to its beacon registration, every keepalive interval, 60 s by
    default) and runs the same recovery when that IP changes. A reply counts
    only if it arrives within 2 s of a registration the node sent, and a new
    IP only once two replies in a row agree on it; when one reply differs,
    the node registers once more at once to check it. Because a NAT that maps
    a node to several public IPs looks like a stream of changes, the gap
    between these recoveries starts at 1 minute and grows to 1 hour. This
    path has unit tests only; it was not exercised against a real NAT.
  - A host waking from sleep on a new network no longer has its two
    recoveries (wake and address change) abort each other's registry calls:
    registry reconnects and re-registrations, the heartbeat's included, run
    one at a time, and the wake or rx-watchdog recovery is skipped when a
    full re-registration succeeded in the last 5 s.
  - `-no-addr-watch` (config.json `no_addr_watch`) turns the watcher off.
  - Publishes `tunnel.addr_changed` (`reason`: `local_address`,
    `observed_endpoint` or `registry_retry`; `previous` and `current`: the
    local address, or for `observed_endpoint` the IP the beacon sees;
    `peers_notified`; `registry_ok`: whether the registry accepted the
    re-registration). A relay-only or compat-mode node does not probe peers
    directly.
- **Proxy credential hints no longer send an operator who already set
  `proxy_cmd` off to set it.** When the daemon re-reads its credentials with
  a proxy command and the proxy still rejects them (407, or Meta Muse's
  garbled answer), `pilotctl daemon start` names the command in use and says
  to check what it prints from a fresh shell; the daemon's own hint covers
  both cases. The installer's sandbox `proxy_cmd` is now checked in CI to be
  the command `pilotctl daemon start` hands the daemon (they must not drift).
- **`pilotctl --json trusted list` printed the text table**; it now returns
  `{"trusted": [{"hostname", "address", "node_id"}], "count"}`.
- **A new pilotctl starting a pilot-daemon that predates proxy support**
  (v1.13.10 and earlier) from a shell with `$HTTPS_PROXY` / `$ALL_PROXY` now warns that
  the daemon will not use the proxy, instead of leaving a bare "did not
  become ready" to explain it.
- **Downgrading after `transport=auto` was saved no longer bricks the daemon.**
  A pilot-daemon that predates `auto` exits on `"transport":"auto"` in
  config.json. Reinstalling an older release with `install.sh --version` and
  `pilotctl update --pin <tag>` now rewrite it to `udp` for such a daemon, and
  nothing writes `auto` implicitly any more. `pilotctl config --set
  transport=` (also `proxy=`, `proxy_cmd=`) removes the key instead of saving
  an empty value.
- **`-transport=compat -registry-tls` without `-registry-trust`** (also
  `registry_tls` in config.json) exited with "registry TLS with
  -registry-trust=pinned requires RegistryFingerprint"; trust defaults to
  `system` (or `pinned` with a configured fingerprint) again, and so does TLS
  to `registry.pilotprotocol.network:443` in udp mode.
- **An explicit proxy in udp mode asked the proxy for the raw-TCP registry**
  (`CONNECT 34.71.57.205:9000`, which CONNECT-443-only proxies refuse). When
  the registry dial goes through a proxy, the compiled-in registry moves to
  `registry.pilotprotocol.network:443` over TLS in any transport, as pilotctl
  already did.
- **`-transport=auto` exited during a beacon outage** because a TCP connect
  to the compat front counted as a working compat path; see the 426 check
  above — auto now stays on udp and the daemon starts degraded.
- **Compat daemons started by `pilotctl` were pinned to the raw-TCP registry.**
  `pilotctl init` writes `34.71.57.205:9000` into config.json and `daemon
  start` forwarded it as an explicit `-registry`, which stops pilot-daemon from
  switching to `registry.pilotprotocol.network:443` (TLS) in compat mode — the
  handshake then failed, or the proxy refused the `:9000` CONNECT. In compat
  mode the compiled-in registry/beacon defaults are now left to the daemon.
- **`PILOT_TRANSPORT=compat` had no effect through `pilotctl daemon start`.**
  pilot-daemon's `-transport` flag defaults to `udp`, masking the env var;
  pilotctl now resolves it and passes an explicit `-transport`.
- **`pilotctl daemon start` on a fresh home failed with "PID file locked".**
  Without an existing `~/.pilot`, the PID-file claim hit ENOENT and was
  reported as a concurrent start on every attempt.
- **`daemon start --endpoint` / `--motd-feed-url` / `--motd-interval`** were
  documented but never forwarded to the daemon.
- **`-transport=compat -registry=34.71.57.205:9000 -registry-tls=false`** (the
  raw TCP/9000 registry fallback) keeps the raw registry again instead of
  sending plaintext to the TLS registry on :443; a custom registry in
  config.json is also kept in compat mode.
- **Switching back from compat.** A udp daemon given
  `registry.pilotprotocol.network:443` now uses TLS for it, and `install.sh
  --transport udp` / `pilotctl config --set transport=udp|auto` restore the
  raw-TCP registry an older compat install saved.
- **An https:// proxy was verified with the beacon's pinned roots** under
  `-tls-trust=pinned`; the proxy's certificate is now checked against the
  system roots and the beacon's trust store applies to the beacon only.
- **`pilotctl update` no longer reports success when the update failed.** It
  used to print `Update check complete` (or `{"status":"ok"}`) and exit 0 even
  when the check failed, for example on a GitHub rate limit. It now exits 1
  with code `update_failed` and the updater's error. A successful run says
  whether it installed a release or found the node up to date. When the
  updater has recorded a failed daemon restart (`restart_error`), pilotctl asks
  the daemon over IPC which version it runs before it says anything. The
  record alone can be out of date: updater v0.2.5 keeps an earlier
  `restart_error` after a manual update that restarted the daemon, and on
  macOS it never clears it on a later check. If the daemon runs another
  version, pilotctl warns and names the command that restarts it. If an
  update leaves no daemon running, it says so and how to start it. If the
  daemon already runs the installed version, it says nothing. `--json` adds
  `result`, `updated`, `current_version`, `latest_version`, `restart_error`
  (empty when the daemon runs the installed version), `restart_needed`,
  `daemon_running`, `daemon_version` and `status_file`. Manual runs are now
  recorded in `~/.pilot/update-state.json`, the file the pilot-updater service
  writes.
- **`pilotctl update status` shows what the updater last did.** Before, it only
  showed whether auto-update was on. It now also shows the last check (time,
  auto or manual, result), the last error, the failure streak, the installed
  and latest versions and the last update. When a `restart_error` is recorded
  it checks the daemon too, and shows one of three results.
  `Daemon restart: NEEDED` means the daemon runs another version.
  `daemon not running` means it runs the installed version once started.
  `not needed` means the record is out of date. `--json` adds `status_file`,
  `last_result`, `last_error`, `restart_error`, `restart_needed`,
  `daemon_running`, `daemon_version` and the full record as `update_state`
  (null when no check has been recorded).
- **`pilotctl skills check`, `skills enable` and the `pilotctl update` skills
  summary now count removals and print notes.** Retired surfaces that
  skillinject cleaned up are counted (`remove:` and `removes` in `--json`) and
  listed with what happened to each file. A helper or plugin file is
  `deleted`. From a heartbeat file only the pilot block is stripped, and from
  `openclaw.json` only the plugin entry is removed; both files are kept. When
  skill injection is disabled, the summary says so: that pass installs nothing
  and only cleans up retired surfaces. `--json` adds `disabled`. Rows that
  carry a note are printed under `Notes:` and returned as `notes` in `--json`:
  a heartbeat file shared with another tool, or a retired plugin that was
  neutralized instead of removed. `skills disable all` counts `neutralized`
  rows and prints their notes. `skills status --json` includes each row's
  `note`, and `--verbose` prints it.
- **`pilotctl skills status --verbose` prints per-file detail again.** `main`
  consumed `--verbose` (and `-v`) as the global flag before the subcommand
  saw it, so only `--verbose=true` worked.
- **Watchdog restarts no longer orphan app-store apps.** When the inbound-path
  watchdog gave up on a wedged transport it called `os.Exit(86)` directly,
  skipping the graceful shutdown that stops plugins — so every installed app
  (each in its own process group) was left running on every respawn. One
  laptop accumulated 94 copies of each of 12 apps (~2.8 GB RSS) in a week.
  The watchdog now asks the daemon's shutdown loop to stop the daemon and its
  plugins, then exits with code 86 as before so launchd/systemd still respawn
  it; a 15 s hard deadline forces the exit if the teardown hangs. Startup
  failures after plugins have started now stop them before exiting, too.
  (Complements the app-store's orphan reaping at spawn,
  pilot-protocol/app-store#38.)
- **The `pilotctl skills disable` opt-out now survives updates and explicit
  reconciles.** A forced reconcile — `pilotctl skills check`, `pilotctl update`,
  or an installer re-run — bypassed the disabled flag and re-injected skills a
  user had turned off. The opt-out is now a hard gate on every write path; only
  the read-only `pilotctl skills` status still previews. (skillinject)
- **App-store installs and upgrades keep an app's saved state.**
  `pilotctl appstore install --force` and `appstore upgrade` (which the updater
  runs hourly as `upgrade --all`) deleted everything an app kept in its own
  directory, such as the wallet's EVM key (`identity-evm.json`) and `data.db`,
  smol's `secrets.json` and per-app identities. Every file that is not part of
  the bundle is now carried into the new install, and the replaced install is
  kept as a backup in `app-backups/<id>/` beside the install root
  (`$PILOT_APPSTORE_BACKUP_ROOT` overrides). The newest 3 routine backups of
  each kind are kept; a backup that may be the only copy of state is never
  pruned. `uninstall` lists the backups that remain.
  - `install <id>` on an installed app is now a no-op (exit 0) that points to
    `upgrade`. Before, it failed with `conflict`. `conflict` now means
    `--version` or a local bundle names another version without `--force`.
  - New `--reset-state` (implies `--force`) reinstalls without the old state,
    with a warning. The backup is still kept.
  - Installs of one app are serialized. A second one waits up to 5 minutes,
    then fails with `timeout`.
  - `upgrade --all` tries every app and exits 1 at the end with
    `upgrade_failed`, naming the apps that failed.
  - Install JSON adds `already_installed`, `hint`, `preserved_state`,
    `state_reset`, `state_not_carried`, `backup_dir` and `backup_warning`.
    Uninstall JSON adds `backups`.
  - The check that refuses a bundle whose binary cannot run on this host now
    also covers universal Mach-O and PE images. The refusal names the app,
    version and host platform, and says nothing was installed.
  - The catalogue lint blocks releases of stateful apps until nodes run a
    pilotctl with this fix.
- **The path watchdog no longer resets healthy, quiet peers.** Two kinds of
  authenticated inbound traffic were thrown away as "spoofed" before they
  could count as liveness. The first was the pong to the watchdog's own path
  probe: the probe had no destination, so the pong came back claiming node 0.
  The second was the NAT keepalive from peers older than v1.12.1, which carries
  a zero source. A quiet peer therefore looked inbound-silent about 55s after
  every handshake, and its path was reset about 30s later, which could leave
  the session unusable until a restart. Probes now name the peer, and the
  empty zero-source keepalive counts as liveness. The pong to a probe from a
  v1.13.0–v1.13.9 node, which still has no destination, now names the
  responder, so those nodes also stop resetting their paths to this one. Any
  other frame whose source does not match the authenticated peer is still
  dropped. No wire change.

## [1.12.8] - 2026-07-16

Reliable P2P data transfer across NAT, plus cold-start onboarding fixes: agents
now reach the network on their first install instead of stalling before it.

### Added
- **Inbound-path watchdog — the long-uptime NAT wedge now auto-recovers.**
  A daemon could run for days transmitting into a stale NAT/relay mapping
  while receiving nothing (2026-07-13 incident: 43.5 MB sent vs 102 KB
  received over 2d19h, every `send-message` failing with "cannot connect
  (data exchange port 1001)") — the registry heartbeat is TCP and kept
  succeeding, so nothing noticed until a manual restart. The daemon now
  watches for delivered-packet silence while transmit stays active, first
  soft-recovers (beacon re-registration — whose discover reply doubles as
  an active inbound probe — plus registry re-registration), and if the
  wedge persists on a supervised daemon, exits with code 86 so
  launchd/systemd respawns it with a fresh transport. Guarded against
  flapping: never exits when the registry is also unreachable (machine
  offline), when inbound never worked this process, or within 30 min of
  start. Emits `tunnel.rx_silence` / `tunnel.rx_recovered` /
  `tunnel.rx_wedged_exit` webhook events. Disable with `-no-rx-watchdog`.
- **Chunked, ACK'd, resumable file transfer (`TypeFileStream`).** `pilotctl
  send-file` now streams files in 48 KiB chunks with per-chunk ACKs, an
  end-to-end SHA-256 integrity check, and automatic resume from the last
  contiguous byte after an interrupted transfer. Replaces the single
  atomic frame that stalled large transfers on any non-trivial path.
  Backward compatible: falls back to the legacy `TypeFile` path when the
  receiver is too old to answer the stream handshake. `--no-stream` forces
  the legacy path.
- **`pilotctl prefer-direct <peer>`** and **`send-file --prefer-direct`** —
  drop a peer's tunnel + cached resolution so the next dial re-runs the
  full resolve + NAT hole-punch flow and prefers the direct path.
- `send-file` reports `transport`, `sha256`, and `throughput_mbps`; adds
  `--timeout`.
- **Goose joins skill injection.** `pilotctl skills` now lists the real
  injection targets — Claude Code, OpenClaw, PicoClaw, OpenHands, Hermes, and
  Goose — instead of naming Cursor, which was never a target. (The daemon's
  runtime inject-manifest adds `~/.config/goose` with its heartbeat in
  `.goosehints`.)
- **Installer GET STARTED walkthrough.** The post-install output now walks a new
  operator through the send-`--wait` / read-newest-inbox idiom, pilot-director
  (live data), list-agents (known specialists), the app store (local
  capabilities), and peers/trust — with copy-paste examples — instead of a
  four-line hint.

### Changed
- **Message of the day now rides the pilot-changelog pipeline.** The daemon's
  default MOTD source moved from the bespoke `pilot-motd` repo to
  `pilot-changelog`'s `feed-motd.json` (the `scope: motd` per-scope output of
  the existing changelog render pipeline). A MOTD is now authored as a
  `scope: motd` changelog entry whose `date` is the UTC day it is active and
  whose `title` is the banner text; motd entries are isolated from the human
  changelog feeds (feed.json/RSS/site). No behavior change for users — the
  banner, `important_update` field, and `motd` in `info` work exactly as
  before; only the source feed and its shape changed. Override with
  `--motd-feed-url` / `$PILOT_MOTD_URL` as before. (motd)
- **`pilotctl skills` and `pilotctl skills paths` are now read-only.** They ran a
  mutating reconcile and then reported the *pre-write* state, so the first
  `pilotctl skills` on a fresh host both created the skill files and labelled them
  "absent — next: create" — a false failure an agent reads as a broken install.
  They now use the injector's read-only dry run: nothing is written just by
  looking, and the reported state reflects what is actually on disk. The mutating
  `skills check` / `skills enable` are unchanged.

### Fixed
- **`pilotctl daemon start` no longer reports a false failure on slow boots.**
  The launchd path waited only 10 s for the IPC socket; a daemon with
  installed app-store apps spawns them before IPC comes up and can take
  longer, producing "socket did not become ready within 10s" for a start
  that succeeds moments later. The wait is now 30 s and the timeout message
  says launchd is still supervising the boot.
- **NAT traversal now actually establishes (and holds) a direct path.** The
  relay→direct upgrade sent a one-way probe that a stateful NAT/firewall
  always dropped, so peers stayed on the beacon relay indefinitely. The
  daemon now runs a beacon-coordinated hole-punch and immediately probes
  the peer's real address to promote the path, retrying every 15 s (was
  5 min). Result on the dual-NAT rig: relay→direct in ~8 s, held through a
  50 MB transfer, ~7–15× the relay throughput.
- **Dual-NAT key-exchange convergence.** Key exchange is now sent over both
  the direct and relay paths, so two NAT'd peers reconverge in ~1 RTT
  instead of waiting 28 s–3 min for blackhole detection.
- **The installer now reaches the skill-injection step on the hosts agents
  actually run on.** Where `systemctl` exists but systemd is not PID 1
  (containers, WSL, CI), the systemd setup ran `systemctl daemon-reload`, which
  returns non-zero — and under `set -e` aborted the install ~200 lines before the
  `pilotctl skills check` first pass, so injection fired on 0 of the tested cold
  starts. The systemd block is now gated on a booted system
  (`[ -d /run/systemd/system ]`), its calls can no longer abort the script, and a
  non-systemd host is told to run `pilotctl daemon start`.
- **Headless installs no longer die at the email prompt.** A non-interactive
  install (piped, no controlling terminal) blocked on `read … < /dev/tty` and
  exited `rc=2`; email is now prompted only when a TTY is present, otherwise the
  daemon auto-synthesizes its `<fingerprint>@nodes.pilotprotocol.network`
  identity. `PILOT_EMAIL` is documented for headless installs.

## [1.12.0] - 2026-06-21

### Added

- **Consent-gated Ed25519 telemetry client (PILOT-400, #263).** The daemon now
  includes a telemetry subsystem that emits signed events to
  `telemetry.pilotprotocol.network`. Each daemon derives a stable Ed25519
  identity (`seed = SHA-256(node_id)`), signs every event with three headers
  (`X-Pilot-Timestamp`, `X-Pilot-Public-Key`, `X-Pilot-Signature`), and emits
  only when the operator has given explicit consent. Consent is stored in
  `~/.pilot/consent.json` and checked on every emission. (telemetry)

- **Telemetry events: `app_installed`, `catalogue_viewed`, `app_detail_viewed`,
  `app_usage` (PILOT-401, 402, 406, 407, #277).** Emitted at the appropriate
  points in the app-store flow, each carrying `app_id` in the signed payload.
  `app_usage` fires on every successful `pilotctl appstore call`. All events are
  gated behind the consent check. (telemetry)

- **`pilotctl update` — self-update command (PILOT-396, #262).** Checks the
  latest GitHub release, downloads the matching binary for the current OS/arch,
  verifies the SHA-256 checksum, and replaces the running binary. Respects
  `--dry-run` and `--version <tag>`. (pilotctl)

- **`pilotctl appstore review` — leave a signed review (PILOT-410, #276).**
  `pilotctl appstore review <id> --subject <text> --rating <1-5>` submits a
  signed review. Subject is capped at 140 characters; rating must be 1–5;
  both validated client-side before the signed POST. (pilotctl)

- **Agent-first CLI overhaul (#247).** `pilotctl send-message`, `list-agents`,
  and related commands now produce bounded, human-readable output by default —
  truncated at a configurable line count with specialist name + summary
  highlighted. `--json` still emits raw envelopes. (pilotctl)

- **Consent + sandbox controls.** `pilotctl consent` sub-commands
  (`grant`/`revoke`/`show`) manage the consent file interactively.
  `pilot-daemon --sandbox` prevents all outbound emission including telemetry.
  `skillinject` gains `--mode=append|prepend|replace`. Install-time and review
  flows show a consent-disclosure section before writing. (consent)

- **Signed app-store catalogue + Pages catalogue site (#249).** Catalogue JSON
  is now Ed25519-signed; `pilotctl appstore install` rejects any catalogue
  whose signature fails. A static GitHub Pages site renders the catalogue as a
  human-browsable app directory. CI validates catalogue schema on every PR
  (#259). (app store)

- **Catalogue list UX: name + headline only, with `view:` pointer (PILOT-404,
  PILOT-405, #275).** `pilotctl appstore catalogue` shows one line per app
  (`<id>  <display_name> — <headline>`) and a trailing `view:` pointer to
  `pilotctl appstore view <id>`. (app store)

- **Per-platform app bundles — v3 catalogue format (#296).** App manifests now
  carry a `platforms` map (`linux/amd64`, `darwin/arm64`, etc.) so
  `pilotctl appstore install` downloads only the binary matching the current
  OS and architecture. The catalogue format is versioned at v3; older `pilotctl`
  treats missing platform keys as a single universal bundle (backward compat).
  (app store)

- **`io.pilot.sixtyfour` v0.1.0 — new app in the catalogue (#289).** First
  non-preview app published under the signed per-platform bundle format.

- **Verified-badge client layer (#295).** Daemons can now request and cache a
  cryptographic verification badge from the Pilot CA. The badge is exposed via
  IPC and surfaced in `pilotctl info` and `pilotctl verify status`. Serves as
  the groundwork for badge-gated specialist trust in a future release.

- **`pilotctl verify status` with offline check (#297).** New sub-command
  reports the local badge state (verified / unverified / expired) without a
  network round-trip, with a `--how-to` flag that prints the steps to earn
  verification. (pilotctl)

### Fixed

- **Decompression bomb protection in `untarUnder` (PILOT-418, #288).** App-store
  bundle extractor now enforces a 256 MiB per-entry cap and a 1 GiB total cap;
  oversized archives are rejected and partial extracts cleaned up. (security)

- **`crypto/rand` replaces `math/rand` in three daemon files (PILOT-417, #283).**
  Key-exchange nonces, ephemeral-port selection, and session-token generation
  now use `crypto/rand.Read`. (security)

- **`node_id` now populated in all telemetry events (#281, #282).** The telemetry
  client was initialized before the daemon identity resolved, leaving `node_id`
  empty. Client now reads it lazily. A missing `app_id` in `catalogue_viewed`
  payload was also corrected.

- **Consent gates added to all app-store telemetry paths (#278).** Several
  app-store emission sites skipped the consent check. Each now calls
  `consent.IsGranted()` and short-circuits if consent is absent or revoked.

- **Review prompt output no longer captured by `pilotctl appstore call`
  (PILOT-409, #268).** The stdio intercept is now scoped to the method's
  structured-output phase only; LLM sub-call progress streams to the terminal.

- **`pilotctl skills disable/enable` rejects non-`all` skill IDs (PILOT-394,
  #260).** Previously silently matched nothing and exited 0. Now returns a
  non-zero exit code with a clear message when no skills match.

- **Default telemetry endpoint set to production.** The daemon no longer ships
  with a localhost fallback; default is
  `https://telemetry.pilotprotocol.network/v1/events`. The `PILOT_TELEMETRY_URL`
  env override remains for staging.

- **Inner packet `Src` bound to authenticated `peerNodeID` (#294).** Previously
  the source node ID in the inner packet was taken from the unverified frame
  header. It is now always overwritten with the node ID authenticated by the
  key-exchange layer, preventing a peer from spoofing a different node's address
  inside an established tunnel.

### Changed

- **MOTD sourced from `pilot-changelog` feed-motd.json (#285).** The poll loop
  introduced in v1.11.2 now fetches from `pilot-changelog`'s `scope: motd`
  output instead of the bespoke `pilot-motd` repo. No behavior change for users;
  `--motd-feed-url` / `$PILOT_MOTD_URL` overrides still work. (motd)

- **Module path renamed: `TeoSlayer` → `pilot-protocol` (#287).** All internal
  imports updated from `github.com/TeoSlayer/pilotprotocol/...` to
  `github.com/pilot-protocol/pilotprotocol/...`. The GitHub repository rename
  provides a redirect for existing `go get` users.

- **Catalogue CI moved into `web4` (#272).** App-store catalogue validation
  now ships as a workflow inside this repo so catalogue PRs validate in place.

### Infrastructure

- `CODEOWNERS` restricted to `@TeoSlayer` only.
- WAL torn-tail registry test reconciled with current protocol contract.
- Daemon package tests now isolate `$HOME` to prevent cross-test interference
  (#252).

## [1.11.2] - 2026-06-15

### Added
- **Message of the day — a network-wide banner on every `pilotctl` command.**
  The Pilot Protocol team can surface a short notice for a single UTC calendar
  day. When a message is active it is prepended to the output of every
  `pilotctl` command in text mode (`Message of the day: <text>`), carried as a
  top-level `important_update` field in the `--json` envelope (including error
  envelopes), and exposed as `motd` in `pilotctl info`. When no message is
  active for the current UTC day, output is unchanged. (motd)
- **Lightweight poll-and-mirror design — fast CLI, no per-command calls.** The
  daemon is the only component that touches the network: a background loop
  (`motdPollLoop`) fetches a central feed every `--motd-interval` (default
  15m), selects the entry dated for the current UTC day, holds it in memory,
  and mirrors it to `~/.pilot/motd.json`. `pilotctl` reads only that local
  mirror — one file read, no network, no IPC — and re-validates the UTC day on
  read, so a stale mirror never shows a message past its day. No new binary
  ships; the poll is a goroutine inside `pilot-daemon`. A withdrawn message
  self-clears within one poll interval. (motd)
- **New daemon configuration.** Flags `--motd-feed-url <url>` (empty disables
  polling entirely) and `--motd-interval <dur>`, plus the `PILOT_MOTD_URL`
  environment override. Surfaced in `pilotctl daemon start` help. (motd)

## [1.11.1] - 2026-06-15

### Added
- **`pilotctl appstore view <id>` — a detail page for store apps.** Shows a
  human-app-store-style listing: structured description, vendor, latest
  changelog (`--all-changelog` for full history), download/installed size,
  source-code URL, license, methods, and — when the app is installed — its
  verified integrity state and granted permissions. Works whether or not the
  app is installed, and whether or not it is in the catalogue (a sideloaded app
  renders from local manifest facts). `--json` emits the merged report. The
  catalogue listing now also shows vendor, categories, license, and size, plus
  a `view:` hint. (app store)
- **Catalogue schema v2 + per-app detail docs.** The catalogue index gains
  optional teaser fields (`display_name`, `vendor`, `categories`,
  `bundle_size`, `source_url`, `license`) and a `metadata_url` +
  `metadata_sha256` pin to a per-app `catalogue/apps/<id>/metadata.json` detail
  document, fetched lazily by `view` and sha-verified the same way bundles are.
  v1 catalogues still load unchanged, and an older `pilotctl` ignores the new
  fields — the bump is backward and forward compatible. The `reviews` slot in
  the detail schema is reserved for a future signed reviews service. (app store)

## [1.11.0] - 2026-06-09

### Added
- **Local app sideloading — `pilotctl appstore install <dir> --local`.** Install
  an app bundle directly from a local directory during development, without
  publishing it to the signed catalogue. Sideloaded apps run under a clamped
  grant set (filesystem under `$APP` and `audit.log` only — no `net.dial`, no
  inter-app `ipc.call`, no daemon hooks), so an unreviewed local bundle cannot
  reach the network or other apps. Catalogue installs are unaffected and keep
  the grants their signed manifest declares. (#240)

### Fixed
- **`pilotctl appstore call` no longer times out on legitimately slow app
  methods.** The command hard-coded an 8-second socket read deadline, which cut
  off any method that ran longer — multi-step research, cold LLM synthesis —
  with a spurious `i/o timeout` even though the app and its backend had
  completed normally. The reply deadline now defaults to **120s** and is
  configurable per call with `--timeout <duration>` or globally via
  `$PILOT_APPSTORE_CALL_TIMEOUT`; the dial timeout for the local socket stays
  short, so fast calls still fail fast. (#244)

## [1.10.7] - 2026-06-06

### Fixed
- **Auto-handshake dial-storm against unreachable trusted agents no longer
  saturates the ephemeral-port pool.** When `DialConnection` targeted a
  peer in the `trustedagents` allowlist that wasn't yet trusted, it
  unconditionally spawned `go HandshakeSendRequest(peer, "")` on every
  call. The existing per-peer in-flight dedup collapsed CONCURRENT
  callers to a single underlying `SendRequest`, but did NOT collapse
  SEQUENTIAL ones: when `sendMessage` returned fast (e.g. hit
  `ErrEphemeralExhausted` in microseconds, or the registry-relay
  fallback completed), the in-flight slot was released immediately and
  the next dial re-fired the goroutine — re-entering `SendRequest`,
  re-emitting `"direct handshake failed, relaying via registry"`, and
  re-allocating an ephemeral port.

  In steady state against a reachable-but-key-exchange-stuck peer
  (`blockchain-ticker`, node 19418, on 2026-06-06) this produced
  ~4000 log lines per second — 1 GB of `daemon.log` written in under
  four hours — while every outbound dial to that peer and every
  concurrent tenant of the port pool failed with `"ephemeral ports
  exhausted"`. `pilotctl info`, `pilotctl peers`, and new specialist
  handshakes all wedged because the IPC server couldn't get a port
  through the saturated bitmap.

  Fix: `Daemon.shouldAutoHandshake` adds a per-peer time-keyed gate
  (`autoHandshakeCooldown` = 30 s) that runs BEFORE the goroutine
  spawn in `DialConnection`. Concurrent racers atomic-CAS for the
  slot; sequential callers within the cooldown window short-circuit
  silently and never reach `HandshakeSendRequest`. Explicit
  `pilotctl handshake <peer>` IPC calls bypass the gate so user
  intent is never throttled. Regression-pinned by
  `TestShouldAutoHandshake*` (six cases including a 50k-call tight
  loop that asserts exactly one spawn).

## [1.10.5] - 2026-05-20

### Fixed
- **WSS reconnect supervisor no longer wedges on a failed first redial.**
  v1.10.4 introduced the reconnect supervisor but contained an
  early-exit bug: when the supervisor cleared `t.conn` after a read
  failure and then the first redial attempt itself failed (network
  hiccup, beacon 5xx, nginx restart still in progress), the next
  loop iteration saw `conn == nil` at the top and `return`ed,
  killing the supervisor goroutine for the lifetime of the daemon.
  Operators saw a long stretch of `wss: reconnecting` Warn lines
  followed by silence; every subsequent `Send` then returned
  `ErrReconnecting` forever and only a daemon restart recovered.
  Observed in production today on a v1.10.4 daemon that ran ~10 h
  before the supervisor exited.

  The supervisor now treats `t.closed.Load()` as the only exit
  condition. A nil `conn` at iteration start just skips
  `drainReads` and goes straight to backoff + redial — so a
  transient outage drains the backoff budget instead of killing
  the goroutine. Regression-pinned by
  `TestReconnect_SurvivesFailedRedialAttempts` (3 forced 503
  redial failures followed by recovery).

- **Duplicate key_exchange frames coalesced; no more "encrypted
  tunnel established" log storm.** Direct + relay copies of the
  same PILA frame plus peer-side retransmits caused the daemon to
  fire the full side-effect path (log, `tunnel.established` bus
  event, PostInstallHook with salvage replay + flushPending) 4–5×
  per peer within milliseconds. A new
  `DuplicateHandshakeDebounce = 250 ms` window coalesces
  same-X25519-pubkey frames arriving on top of a freshly-installed
  Crypto.

  Crucially, the SendKeyExchangeToNode-when-stale path is NOT
  gated by the debounce: the asymmetric-recovery scenario (peer
  dropped crypto for us, retransmits PILA, our InboundDecryptStale
  is true) still elicits our PILA reply so the peer can re-derive
  the shared secret. Regression-pinned by
  `TestDuplicatePILACoalescedSuppressesLogAndHook`,
  `TestDuplicatePILAOutsideDebounceFiresHookAgain`, and
  `TestDuplicatePILAStillRepliesForAsymmetricRecovery`. The
  existing `TestAsymmetricRecoveryRepliesOnDuplicatePILAWhenStale`
  also still passes.

- **Compat-mode dial no longer burns 25–78 s on direct-retry
  attempts that can't succeed.** A compat-mode daemon has no
  public UDP socket — its data plane lives entirely on the WSS
  bridge to the beacon. Pre-v1.10.5, every outbound dial still
  ran the full 3-attempt direct phase before falling back to
  relay; each attempt consumed an ephemeral port and idled for
  the SYN-RTO budget. Under fan-out (e.g. the trusted-agents
  auto-handshake on first dial) this exhausted local ephemeral
  ports on macOS.

  `DialConnectionContext` now pre-flips the peer's routing state
  to relay BEFORE sending the initial SYN when `-transport=compat`,
  and the existing `relayActive → directRetries=0` branch picks
  it up — first SYN goes out via the WSS bridge on the first try.

### Tests
- `pkg/daemon/transport/wss/zz_wss_test.go::TestReconnect_SurvivesFailedRedialAttempts`
  — `fakeBeacon` accepts an initial dial, kills the conn on
  the 2nd binary frame, then refuses the next 3 redial attempts
  with 503. Pre-fix: supervisor exits, test wedges out.
  Post-fix: supervisor exhausts the 503 streak with exponential
  backoff and the 4th attempt succeeds; a probe frame round-trips
  on the fresh conn.
- `pkg/daemon/keyexchange/zz_duplicate_debounce_test.go` — three
  scenarios covering coalescing inside the window, re-firing
  after the window, and asymmetric-recovery preservation.

### Verified
- Live smoke test against `beacon.pilotprotocol.network` from a
  fresh v1.10.5 daemon: `-transport compat` binds only TCP/443,
  WSS auth completes, trust handshake with `list-agents` lands
  within ~88 s of first dial, `send-message list-agents` returns
  2521 bytes of structured JSON in ~3 s end-to-end. No
  `wss: reconnecting` storm, no "tunnel established" log noise
  burst.

## [1.10.4] - 2026-05-19

### Fixed
- **Compat-mode WSS connection auto-recovers from drops.** Before this
  fix, when the daemon's WSS connection to the beacon died (network
  blip, nginx restart, GFW-style spoofed RST, peer-side hangup), the
  transport stayed permanently dead — every subsequent `Send` returned
  `wss send: failed to write msg: use of closed network connection`
  and a manual daemon restart was the only recovery. Observed in
  production today (v1.10.3) twice in one hour.

  The new design introduces a supervisor goroutine that owns both the
  read loop AND the reconnect lifecycle. When the underlying conn
  fails, the supervisor:
    1. tears down the dead conn
    2. waits with exponential backoff (250 ms → 30 s cap)
    3. re-dials + re-auths against the same `-compat-beacon` URL
    4. installs the fresh conn and resumes reading
  All under `lifetimeCtx`, so `Close()` interrupts an in-flight dial
  or read within ~100 ms.

  `Send` now returns the new `wss.ErrReconnecting` (instead of a raw
  conn-write error) when no live conn is installed — caller's
  higher-level retransmit (key-exchange retx, dial-retry, write-frame
  retry) refires naturally on the next conn. Transient read errors
  during the gap are no longer surfaced to `Recv()` so the daemon's
  tunnel read loop doesn't tear itself down over a temporary blip.

### Tests
- `pkg/daemon/transport/wss/zz_wss_test.go::TestReconnect_AfterServerCloseRestoresSendAndRecv`
  — `fakeBeacon` is configured to `CloseNow()` the WS conn after the
  second incoming frame. The test then drives a polling probe loop
  and asserts the supervisor (a) flags ErrReconnecting during the
  reconnect window and (b) successfully echoes a third frame on the
  newly-established conn.

## [1.10.3] - 2026-05-19

### Added
- **Compat mode is now single-port-443.** A new `-registry-trust system` flag
  on `pilot-daemon` lets the registry client validate the production cert via
  the OS x509 root store instead of requiring a pinned SHA-256 fingerprint.
  When `-transport=compat` is selected and the operator hasn't overridden
  `-registry`, the daemon now auto-targets
  `registry.pilotprotocol.network:443` with TLS + system trust — same
  hostname:port as the existing beacon WSS bridge. The two endpoints are
  multiplexed on a single nginx `listen 443;` via the stream module's
  `ssl_preread` SNI router (see `docs/RUNBOOK-compat-443-only.md`).
  Net effect: a daemon running in Render, Replit Agent, or any other
  managed-claw sandbox that allows only outbound TCP/443 can now register +
  resolve + tunnel data — **zero TCP/9000, zero UDP**.

### Changed
- `pilot-daemon -registry-tls` no longer requires `-registry-fingerprint` if
  `-registry-trust=system` is set. The two modes coexist:
    - `pinned` (default): cert pinned by SHA-256 fingerprint — back-compat
      with the existing single-VM deploy
    - `system`: OS root store — works against any publicly-trusted CA cert,
      i.e. the Let's Encrypt cert on `registry.pilotprotocol.network`

### Tests
- `tests/zz_compat_registry_tls_test.go::TestCompatRegistryTLSPinned` —
  spins up an in-process TLS registry + beacon, points a compat daemon at
  the TLS registry with a pinned cert, and verifies Register + WSS bridge
  attach end-to-end.
- `tests/zz_compat_registry_tls_test.go::TestCompatRegistryTrustSystemRejectsBadCert` —
  pins that `-registry-trust=system` refuses an untrusted self-signed cert
  (MITM defence-in-depth).

### Ops / deployment

Single runbook covers the production rollout:
[`docs/RUNBOOK-compat-443-only.md`](docs/RUNBOOK-compat-443-only.md). Steps:

1. DNS A record `registry.pilotprotocol.network → 34.71.57.205`
2. `certbot certonly --nginx -d registry.pilotprotocol.network`
3. Move existing nginx HTTP-on-443 vhosts (`beacon.*`, `console.*`,
   `polo.*`) to internal `listen 127.0.0.1:14443 ssl;`
4. Add nginx `stream {}` block: `ssl_preread` on, SNI map →
   `registry.*` to a stream-mode TLS terminator on 14444 (which proxies
   plain TCP to the existing registry on `127.0.0.1:9000`),
   everything else to 14443.
5. Smoke-test via `openssl s_client` + a real compat daemon.

Rollback is one `nginx -t && systemctl reload nginx` after restoring the
sed-backed-up sites-enabled files.

### Operational changes applied to `pilot-service-agents` (2026-05-19)

These are server-side ops changes that landed alongside the v1.10.3 code work
to make all 435+ specialist agents responsive under high traffic:

- **`/usr/local/bin/responder-wave-restart.sh` was no-op'd**. Original backed
  up alongside as `responder-wave-restart.sh.full-backup-1779223695`. The
  every-~10-min wave restart was killing in-flight reply queues across all
  agents (each restart SIGTERM'd Python responder workers mid-`pilot-send-stdin`
  subprocess), so list-agents queries from outside the fleet timed out
  even though dispatch worked. Reply latency dropped from 30s+ timeouts to
  sub-second after disabling.
- **Per-agent systemd drop-in
  `/etc/systemd/system/pilot-responder-*.service.d/high-traffic.conf`** on
  all 435 responders:
    - `RESPONDER_REPLY_WORKERS=16` (default `2`)
    - `RESPONDER_INBOX_WORKERS=6` (default `2`)
    - `RESPONDER_REPLY_QUEUE_MAX=2048`, `RESPONDER_INBOX_QUEUE_MAX=2048`
    - `RESPONDER_STALE_REPLY_AFTER=60s` (default `60s`),
      `RESPONDER_INBOX_MAX_AGE=60s`
    16 workers absorb the swarm noise (failing sends to unreachable swarm
    nodes each pin a worker for the hardcoded 25s `pilot-send-stdin`
    timeout) while leaving slots for legitimate user traffic.
- **`/opt/pilot-dashboard/metrics-snapshot.json` despiked**. The
  restart-wave at 21:29:54 UTC inflated cumulative request counters by
  2,866,001 over 133s (21,548 req/s artefact). A second pass at 21:34:11
  added another 903,719 over 103s (8,740 req/s). Both spikes flattened to
  the 300 req/s baseline rate; the excess subtracted from all subsequent
  entries to keep cumulative totals consistent. Backup at
  `metrics-snapshot.json.pre-despike-1779227221`.
- **`/opt/pilot-dashboard/server.py::/api/metrics-history` default range**
  changed from "all 17,280 samples" to **720 samples (1 hour at 5s
  intervals)**. The full buffer is ~213 MB JSON which crashed the
  network-stats page when fetched with no query params; the default now
  returns ~9 MB in ~1.6s. Callers that want the full 24h window can still
  pass `?range=17280`. Backup at
  `server.py.pre-metricshistory-default-1779227619`.

## [1.10.2] - 2026-05-19

### Fixed
- **Compat mode: outbound-initiated dials to fresh peers**. In v1.10.1, a
  compat-mode (WSS-only) daemon's first SYN to a peer went raw through the WSS
  pipe because `routing.WriteFrame` only wrapped frames in `BeaconMsgRelay`
  after the blackhole heuristic flipped the peer to relay mode (3 misses, ~8s
  silence). For brand-new peers, the unwrapped frame reached the beacon as an
  unknown protocol byte and was dropped silently — every outbound-initiated
  dial timed out. Managed claws (Docker on Render/Railway/Lambda, UDP-blocked
  corp networks) could RECEIVE traffic via the bridge but couldn't INITIATE
  connections to UDP-only peers. Fix: a `forceRelay` flag on `routing.Manager`
  set by `TunnelManager.ConnectCompat`, so every outbound write in compat mode
  is BeaconMsgRelay-wrapped regardless of blackhole state.

### Added
- `tests/zz_compat_dial_test.go` — end-to-end regression test: a compat daemon
  dials a UDP peer's echo service through an in-process beacon and asserts the
  three-way handshake completes and echo data flows both ways.
- `tests/compat/zz_real_beacon_test.go` — 4 integration tests exercising the
  production beacon binary's WSS↔UDP bridge with real `bwss.Server` +
  `dwss.Transport` (not the synthetic in-memory bridge used by the existing
  4-cell matrix).
- `beacon.Server.WSSAddr()` and `WSSIsConnected(nodeID)` — exposed for tests
  that bind to `:0` and need to wait for post-handshake WSS registration.

### Platform compatibility

Researched egress policies of common managed-claw / agent-sandbox platforms.
Verified live: a fresh compat daemon (`node_id=205787`) fetched the
weather-agent list from `list-agents` over **TCP/443 (beacon WSS) + TCP/9000
(registry), zero UDP**. From that, the picture is:

| Platform                | UDP egress         | TCP arbitrary port   | UDP mode works  | Compat mode works |
|-------------------------|--------------------|----------------------|-----------------|-------------------|
| Render                  | ❌ blocked         | ✅                   | No              | **✅ Yes**        |
| Railway                 | ✅                 | ✅                   | ✅              | ✅                |
| Fly.io                  | ✅                 | ✅                   | ✅              | ✅                |
| AWS Lambda              | ✅ (port 25 blkd)  | ✅                   | ✅              | ✅                |
| Google Cloud Run        | ✅ (via VPC)       | ✅                   | ✅              | ✅                |
| Vercel Functions        | (ephemeral; wrong runtime for a persistent daemon)                | —               | —                 |
| Modal Sandboxes         | ✅ default-allow   | ✅                   | ✅              | ✅                |
| E2B Sandboxes           | ✅ (IP rules only) | ✅                   | ✅              | ✅                |
| Daytona Sandboxes       | ✅ default-allow   | ✅                   | ✅              | ✅                |
| Cursor Cloud Agents     | allowlist-driven   | allowlist-driven     | only if allowed | only if allowed   |
| Replit Agent / Docker AI Sandbox | ❌ hard-blocked | ❌ hard-blocked  | No              | ❌ No (needs `HTTPS_PROXY`) |
| Devin (Cognition)       | undocumented; likely Docker-AI-class | ❌  | No              | likely No         |

**v1.10.2 fully unblocks**: Render (the original Garry Tan report case).
**Already worked in v1.10.0 UDP mode**: Railway, Fly.io, Lambda, Cloud Run,
Modal, E2B, Daytona.
**Still blocked in v1.10.2**: platforms enforcing the Docker AI Sandbox
HTTP-proxy-only egress model (Replit Agent, Devin, locked-down Cursor
sandboxes). These need an `HTTP_PROXY`/`HTTPS_PROXY`-honoring transport and
a registry-over-WSS bridge — tracked for v1.10.3.

## [1.10.1] - 2026-05-19

### Fixed
- **Heartbeat signature verification** (Garry Tan bug report #1): the registry-client
  signer captured `d.identity` once at startup; after key rotation, heartbeats kept
  signing with the stale identity and got rejected. Signer now reads `d.identity`
  under `d.identityMu` on every call. Affected every daemon that rotated keys
  after registration; symptom was a `"registry: signature verification failed"`
  loop with re-register every 60 s and no peer connectivity.

### Added
- **Compat mode**: tunnel Pilot packets over WebSocket Secure to the beacon for
  daemons in UDP-blocked environments (Docker on Render/Railway/Vercel/Lambda,
  restrictive corp networks). Opt-in via `-transport=compat` on the daemon;
  default behavior unchanged. Live at `wss://beacon.pilotprotocol.network/v1/compat`.
  See [docs/SPEC-compat-mode.md](docs/SPEC-compat-mode.md) and
  [docs/firewalls](https://pilotprotocol.network/docs/firewalls).
- `pilotctl skills disable` / `enable` — safe removal of the daemon's auto-installed
  agent skill files. Strip-only on co-inhabited files (`CLAUDE.md`, `AGENTS.md`,
  `AGENT.md`, `SOUL.md`); delete in our own subdirs. OpenClaw plugin allow-list
  restored from `.pilot-bak` snapshot. Idempotent.
- Marker block self-disclosure: the `<!-- pilot:begin ... -->` comment now embeds
  `Inserted by pilot-daemon. Remove with: pilotctl skills disable` so anyone
  opening their agent config file in one read knows what it is and how to remove it.
- `data_b64` field in dataexchange inbox messages (opt-in via `-dataexchange-b64`):
  lossless base64 alongside the existing `data` string for binary payloads
  (e.g. zlib-compressed HealthKit envelopes).
- `cmd/pilot-ca` offline tool to mint the future production Pilot root CA and beacon
  leaf certs; see [docs/RUNBOOK-pilot-ca.md](docs/RUNBOOK-pilot-ca.md).

### Changed
- `install.sh` post-install banner now points at `pilotctl skills disable` for users
  who want to opt out of skill auto-injection.
- Beacon's relay worker checks for a WSS-connected destination before the UDP
  tier-1/2 lookups, so existing UDP daemons reach compat-mode peers transparently
  (the bridging happens entirely on the beacon).
- Registry `LookupPublicKey(nodeID)` exposed for in-process beacon to authenticate
  WSS daemons against registered pubkeys.

## [1.9.1] - 2026-05-05

- Rekey storm fix: `decryptFailDropGrace` (3 s) prevents tearing down a freshly-installed
  `peerCrypto` before in-flight frames from the old key have drained
- AEAD divergence recovery: 5 consecutive auth failures drop `tm.crypto[peer]` and trigger
  fresh key exchange automatically
- Relay-flag pinning: `relayPinned` replaces "auto-clear after 3 direct receipts" heuristic
  that caused relay/direct flapping every ~60 s in production
- Cold `pilotctl` latency: 10–30 s → ~600 ms; warm: ~170 ms

## [1.9.0] - 2026-04-30

- Registry lock contention closed end-to-end
- P1-010 tunnel-desync recovery: salvage in-flight plaintext on peer-initiated rekey
- Registry hardening: panic recovery, WAL replay, 3-phase rotate-key/set-key-expiry
- Multi-beacon discovery; peer IPs hidden by default; member counts admin-gated

## [1.8.0] - 2026-04-20

- Auto-updater sidecar: hourly GitHub releases check, client-only binary updates
- Version reporting in all binaries; dashboard simplification

## [1.7.0] - 2026-04-09

- Gateway overlay: `pilot-gateway` TCP bridge mapping pilot addresses to local IPs
- `send-file` with resume support; Whitepaper v1.6

## [1.6.0] - 2026-04-08

- HTTP-over-Pilot: `pilotctl http` command
- Managed networks: expression-based policy engine (tag, evict, fill_trust, cycle)
- Fix: stale endpoint blackhole; registry client `Send()` concurrency; STUN/readLoop race

## [1.5.0] - 2026-03-27

- Pubsub: topic-filtered publish/subscribe
- Send-message command; nameserver plugin; flow-control window in packet header

## [1.4.0] - 2026-03-23

- Symmetric NAT relay through beacon (auto-detected)
- Restricted Cone NAT: beacon hole-punch; `DialConnection` direct→relay fallback

## [1.3.0] - 2026-03-15

- Policy engine phase 1: join rules, port gates, cycle actions
- Webhook plugin: outbound HTTP callbacks on protocol events

## [1.2.0] - 2026-02-10

- Trusted-agents auto-accept: embedded service-agent allow-list
- Security phase 2: 8 resource-exhaustion fixes; CodeQL workflow
- Fix: FIN-ACK storm bounded; `list_nodes` cache invalidation; `sendSegment` backpressure

## [1.1.0] - 2026-02-08

- Initial public release: daemon, rendezvous, `pilotctl`, gateway
- 48-bit addresses (`N:NNNN.HHHH.LLLL`), UDP tunnels, key exchange, trust model
