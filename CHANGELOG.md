# Changelog

All notable changes to Pilot Protocol are recorded here. This file follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions. The
project uses [Semantic Versioning](https://semver.org/).

Detailed per-release notes are on the
[GitHub Releases page](https://github.com/TeoSlayer/pilotprotocol/releases).

## [Unreleased]

### Added
- **Opt out of automatic app-store updates with `PILOT_APP_UPDATE_OPT_OUT`.** The
  `pilot-updater` keeps installed apps current by periodically running
  `pilotctl appstore upgrade --all`. Set `PILOT_APP_UPDATE_OPT_OUT=true` in the
  updater's environment and it stops checking for and installing app updates —
  installed apps stay at the version you installed. Unset it or set it to
  `false` (the default) to switch app auto-updates back on. Pilot daemon/CLI
  binary updates are never affected. Honors the existing
  `PILOT_UPDATER_NO_APP_UPGRADE` as a back-compat alias.

### Changed
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

### Fixed
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
