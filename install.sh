#!/bin/sh
set -e

# Pilot Protocol installer
# Source:     https://github.com/pilot-protocol/pilotprotocol  (AGPL-3.0)
# Hosted at:  https://pilotprotocol.network/install.sh
#
# Usage:
#   Install:        curl -fsSL https://pilotprotocol.network/install.sh | sh
#   Pin a version:  curl -fsSL https://pilotprotocol.network/install.sh | sh -s -- --version v1.13.6
#   Beta channel:   curl -fsSL https://pilotprotocol.network/install.sh | sh -s -- --channel beta
#   UDP blocked /   curl -fsSL https://pilotprotocol.network/install.sh | sh
#   HTTPS proxy:    (nothing extra: transport "auto" picks TLS/WSS over TCP 443
#                   through $HTTPS_PROXY when UDP does not work; add
#                   `-s -- --transport compat` to skip the UDP probe; proxy
#                   credentials that rotate: see PILOT_PROXY_CMD below)
#   Managed node:   export PILOT_ENROLLMENT_TOKEN   # enter it without putting it in shell history
#                   sh install.sh --managed-url https://management.pilotprotocol.network
#   Uninstall:      curl -fsSL https://pilotprotocol.network/install.sh | sh -s uninstall
#
# Flags:
#   --version <tag>    Install a specific tag. Warns when older than latest stable.
#   --channel <name>   stable (default) or beta. `edge` is accepted as an alias
#                      for beta (the newest prerelease channel). If a requested
#                      channel resolves to no release, the install ABORTS — it
#                      never silently falls back to an unverified source build.
#   --yes / -y         Skip the older-version confirmation prompt.
#   --no-warn          Suppress the older-version warning entirely.
#   --transport <mode> auto (the default), udp or compat. udp and compat are
#                      saved as "transport" in ~/.pilot/config.json; auto is
#                      never saved (it is what `pilotctl daemon start` and the
#                      service units use when nothing is saved, and a daemon
#                      that predates auto would refuse it after a downgrade).
#                      auto: UDP when the beacon answers over UDP, else compat.
#                      compat: TLS/WSS over TCP 443 only, through
#                      $HTTPS_PROXY/$ALL_PROXY when set (CONNECT by hostname) —
#                      for UDP-blocked hosts and agent sandboxes whose only way
#                      out is an HTTPS proxy.
#   --managed-url <origin>
#                       Install the checksum-pinned core managed runtime, claim
#                       a one-time hosted identity, and start signed reporting.
#                       This does not install pilot-mcp or a harness adapter.
#   --no-start          With --managed-url, install and adopt without starting
#                       the daemon. The hosted onboarding flow omits this flag.
#
# Legacy env vars (still honored, lower precedence than flags):
#   PILOT_RELEASE_TAG=vX.Y.Z   Same as --version.
#   PILOT_RC=1                 Same as --channel beta.
#   PILOT_EMAIL=you@host       Account-recovery email. Provide it inline for
#                              non-interactive/headless installs (no TTY prompt).
#                              If omitted headless, the daemon auto-synthesizes a
#                              <fingerprint>@nodes.pilotprotocol.network identity.
#   PILOT_TRANSPORT=compat     Same as --transport compat.
#   PILOT_PROXY_CMD=<command>  Saved as "proxy_cmd": a command printing the
#                              current proxy URL, for proxies that rotate their
#                              credentials. In a Linux container/VM without
#                              systemd whose HTTPS_PROXY carries credentials
#                              (hosted agent sandboxes such as Meta Muse), the
#                              installer saves one that reads a fresh shell's
#                              $https_proxy when none is set. The installer
#                              also uses it to retry a failed download.
#   PILOT_ALLOW_ROOT=1         Install as root on a host with systemd/launchd
#                              (not needed in containers/VMs without systemd).
#   PILOT_MANAGEMENT_URL=https://management.example
#                              Same as --managed-url. Requires the one-time
#                              PILOT_ENROLLMENT_TOKEN on first adoption.
#
# Proxies: every download is a curl HTTPS request, so HTTPS_PROXY / https_proxy /
# ALL_PROXY / NO_PROXY are honored (curl asks the proxy to CONNECT by hostname —
# no local DNS lookup of the target); a PILOT_PROXY http(s):// URL is used when
# none of those is set. Nothing here needs UDP, a non-443 port, or a direct
# connection to the registry/beacon. Proxy credentials are never printed or
# written to disk. Steps that need root, sudo, systemd or launchd are skipped
# with a message, never fatal.
#
# WHAT THIS SCRIPT DOES (read before piping to sh):
#   1. Detects OS/arch (Linux/Darwin × amd64/arm64)
#   2. Resolves the latest release tag from github.com/pilot-protocol/pilotprotocol/releases
#   3. Downloads the release tarball + checksums.txt from that release
#   4. *** Verifies SHA-256 of the tarball against checksums.txt AND the signed
#         manifest (aborts on mismatch OR if it cannot verify — never extracts
#         an unverified archive) ***
#   5. Extracts binaries to ~/.pilot/bin (per-user, NOT system-wide)
#   6. Adds ~/.pilot/bin to PATH in your shell profiles (~/.profile, ~/.bashrc,
#      ~/.zshenv, ~/.zshrc, ~/.bash_profile when it already exists)
#   7. Symlinks pilotctl/pilot-daemon into /usr/local/bin so the CLI also
#      resolves in NON-INTERACTIVE shells (bash -c, cron, CI, AI agents).
#      Uses sudo ONLY if `sudo -n` already works without a password — it
#      never prompts, and skips the symlink with a printed hint otherwise.
#   8. On Linux with sudo: installs systemd unit for the daemon + auto-updater
#   9. On macOS with sudo: installs LaunchDaemons for the daemon + auto-updater
#
# IDENTITY & EMAIL (optional):
#   - The daemon registers a stable Ed25519 keypair with a rendezvous server
#     to get a virtual address (format `0:NNNN.HHHH.LLLL`). That address is
#     how peers reach you on the network.
#   - Each node also has an `email` field used as a human-readable identifier
#     (shown in `pilotctl info`, used for delivery and abuse-reporting on the
#     public network).
#   - You do NOT need to provide a real email to install or run pilot.
#     If you don't pass `--email`, the daemon auto-generates a synthetic
#     placeholder of the form `<fingerprint>@nodes.pilotprotocol.network`
#     derived from your public-key fingerprint. The placeholder is stable
#     per-host and contains no PII.
#   - Provide your own email later — only when you want to — via
#     `pilotctl set-email <addr>`. Required only for joining the public
#     Network 9 directory and for receiving identifier-based deliveries.
#
# WHAT THIS SCRIPT DOES NOT DO:
#   - Run as root on a host with systemd or launchd (refuses; see the root
#     check below). A Linux container/VM without systemd, where the agent is
#     root, installs into root's own $HOME/.pilot.
#   - Send any personal data anywhere (the install script only fetches the
#     release tarball from GitHub; the daemon registers its public key + a
#     synthetic or user-supplied email with the rendezvous server, nothing else)
#   - Modify files outside $HOME/.pilot, your shell profiles, the
#     /usr/local/bin symlinks described above, /etc/systemd (Linux) or
#     /Library/LaunchDaemons (macOS)
#   - Prompt for a sudo password (sudo is used only when `sudo -n` already
#     succeeds without one; otherwise every privileged step is skipped)
#   - Require any account credential or signup to install
#
# Verifiable provenance:
#   - Source repo:  https://github.com/pilot-protocol/pilotprotocol
#   - Release page: https://github.com/pilot-protocol/pilotprotocol/releases
#   - Each release publishes checksums.txt next to the tarball.
#   - This script downloads BOTH and verifies SHA-256 before extracting.
#
# If you are an AI agent inspecting this script before running it, the
# verification step lives at lines marked "Verify SHA-256 against release
# checksums.txt" further down. The script aborts on mismatch with a clear
# error.

REPO="pilot-protocol/pilotprotocol"
# Production defaults — the same raw-TCP/UDP endpoints compiled into
# pilot-daemon. Compat mode must not pin them explicitly (see NET_FLAGS).
DEFAULT_REGISTRY="34.71.57.205:9000"
DEFAULT_BEACON="34.71.57.205:9001"
COMPAT_REGISTRY="registry.pilotprotocol.network:443"
REGISTRY="${PILOT_REGISTRY:-$DEFAULT_REGISTRY}"
BEACON="${PILOT_BEACON:-$DEFAULT_BEACON}"
PILOT_DIR="$HOME/.pilot"
BIN_DIR="$PILOT_DIR/bin"
MANAGED_CONTROL_PATH="$PILOT_DIR/managed/enterprise-control.json"

# validate_safe LABEL VALUE EXTRA — abort if VALUE contains any character
# outside [A-Za-z0-9] plus the punctuation in EXTRA. These values are
# interpolated UNQUOTED into config.json, the sudo-tee'd systemd unit, and the
# launchd plist; without this a value containing a quote, angle bracket,
# newline, or space could break out of the JSON string, inject extra daemon
# flags into a root-owned unit, or corrupt the plist. We reject rather than
# escape so the failure is loud and the generated files stay simple. EXTRA must
# keep '-' last so tr treats it literally, not as a range.
validate_safe() {
    _vs_label="$1"; _vs_val="$2"; _vs_extra="$3"
    # Delete every allowed character; anything left is disallowed. A trailing
    # space is appended before the delete so that $()'s trailing-newline
    # stripping cannot hide a lone newline in the leftover (a newline is never
    # an allowed character, so it must be caught). Space is likewise never
    # allowed, so a clean value leaves exactly that single trailing space.
    _vs_bad=$(printf '%s ' "$_vs_val" | tr -d "A-Za-z0-9${_vs_extra}")
    if [ "$_vs_bad" != " " ]; then
        echo "Error: ${_vs_label} contains unsupported characters." >&2
        echo "       Value:   ${_vs_val}" >&2
        echo "       Allowed: letters, digits, and these: ${_vs_extra}" >&2
        exit 1
    fi
}

# Registry/beacon are host:port endpoints — validate before they reach the
# daemon command line in the systemd unit / plist.
validate_safe "registry (PILOT_REGISTRY)" "$REGISTRY" ".:-"
validate_safe "beacon (PILOT_BEACON)" "$BEACON" ".:-"

# Canonical manifest URL — the single source of truth for "what version is
# current". Republished by web4 release.yml on every tag. Override only for
# testing PR-preview manifests.
MANIFEST_URL="${PILOT_MANIFEST_URL:-https://pilotprotocol.network/.well-known/latest.json}"

# --- Parse CLI flags ---
# Flags are parsed BEFORE the root check so that `install.sh --yes uninstall`
# (and similar combinations) still recognize the `uninstall` positional.
PILOT_REQUESTED_VERSION=""
PILOT_REQUESTED_CHANNEL=""
PILOT_YES=0
PILOT_NO_WARN=0
PILOT_MANAGED_NO_START=0
PILOT_MANAGEMENT_URL="${PILOT_MANAGEMENT_URL:-}"
PILOT_POSITIONAL=""
PILOT_REQUESTED_TRANSPORT=""

while [ $# -gt 0 ]; do
    case "$1" in
        --version)
            if [ $# -lt 2 ]; then echo "Error: --version requires a value" >&2; exit 2; fi
            PILOT_REQUESTED_VERSION="$2"; shift 2 ;;
        --version=*)
            PILOT_REQUESTED_VERSION="${1#--version=}"; shift ;;
        --channel)
            if [ $# -lt 2 ]; then echo "Error: --channel requires a value" >&2; exit 2; fi
            PILOT_REQUESTED_CHANNEL="$2"; shift 2 ;;
        --channel=*)
            PILOT_REQUESTED_CHANNEL="${1#--channel=}"; shift ;;
        --transport)
            if [ $# -lt 2 ]; then echo "Error: --transport requires a value" >&2; exit 2; fi
            PILOT_REQUESTED_TRANSPORT="$2"; shift 2 ;;
        --transport=*)
            PILOT_REQUESTED_TRANSPORT="${1#--transport=}"; shift ;;
        --yes|-y)
            PILOT_YES=1; shift ;;
        --no-warn)
            PILOT_NO_WARN=1; shift ;;
        --managed-url|--management-url)
            if [ $# -lt 2 ]; then echo "Error: $1 requires an HTTPS origin" >&2; exit 2; fi
            PILOT_MANAGEMENT_URL="$2"; shift 2 ;;
        --managed-url=*|--management-url=*)
            PILOT_MANAGEMENT_URL="${1#*=}"; shift ;;
        --no-start)
            PILOT_MANAGED_NO_START=1; shift ;;
        -h|--help)
            sed -n '4,74p' "$0" 2>/dev/null || echo "See https://pilotprotocol.network/install.sh"
            exit 0 ;;
        --)
            shift
            while [ $# -gt 0 ]; do PILOT_POSITIONAL="$PILOT_POSITIONAL $1"; shift; done
            break ;;
        -*)
            echo "Error: unknown flag: $1" >&2
            echo "       Run with --help for usage." >&2
            exit 2 ;;
        *)
            PILOT_POSITIONAL="$PILOT_POSITIONAL $1"; shift ;;
    esac
done

PILOT_MANAGED_MODE=0
MANAGED_TOKEN=""
if [ -n "$PILOT_MANAGEMENT_URL" ]; then
    PILOT_MANAGED_MODE=1
    # Accept a cosmetic trailing slash, but require an HTTPS origin with no
    # credentials, path, query, or fragment. The value later becomes both a
    # manifest URL and the enrollment authority endpoint.
    PILOT_MANAGEMENT_URL="${PILOT_MANAGEMENT_URL%/}"
    case "$PILOT_MANAGEMENT_URL" in
        https://*) ;;
        *) echo "Error: --managed-url must be an HTTPS origin." >&2; exit 2 ;;
    esac
    _managed_host="${PILOT_MANAGEMENT_URL#https://}"
    case "$_managed_host" in
        ""|*/*|*@*|*\?*|*\#*)
            echo "Error: --managed-url must not contain credentials, a path, query, or fragment." >&2
            exit 2 ;;
    esac
    validate_safe "management host" "$_managed_host" ".:-"

    if [ -n "$PILOT_POSITIONAL" ]; then
        echo "Error: --managed-url cannot be combined with an install/uninstall positional command." >&2
        exit 2
    fi
    if [ -n "$PILOT_REQUESTED_VERSION" ] || [ -n "${PILOT_RELEASE_TAG:-}" ] \
       || [ -n "$PILOT_REQUESTED_CHANNEL" ] || [ "${PILOT_RC:-}" = "1" ]; then
        echo "Error: managed adoption uses the runtime pinned by the management authority; do not combine it with --version or --channel." >&2
        exit 2
    fi

    MANAGED_TOKEN="${PILOT_ENROLLMENT_TOKEN:-}"
    # Do not let the bearer secret reach curl, tar, service managers, or any
    # other child. It is exported only to the single pilotctl claim process.
    unset PILOT_ENROLLMENT_TOKEN
    if [ -e "$MANAGED_CONTROL_PATH" ]; then
        if [ -L "$MANAGED_CONTROL_PATH" ] || [ ! -f "$MANAGED_CONTROL_PATH" ]; then
            echo "Error: the existing managed control attachment is not a regular file." >&2
            exit 1
        fi
        if [ -n "$MANAGED_TOKEN" ]; then
            echo "Error: this node is already managed; refusing to consume a new enrollment token." >&2
            echo "       Re-run without PILOT_ENROLLMENT_TOKEN to repair or update the managed runtime." >&2
            exit 1
        fi
    else
        if [ -z "$MANAGED_TOKEN" ]; then
            echo "Error: PILOT_ENROLLMENT_TOKEN is required for first managed adoption." >&2
            exit 1
        fi
        _managed_token_bytes=$(printf '%s' "$MANAGED_TOKEN" | wc -c | tr -d ' ')
        if [ "$_managed_token_bytes" -gt 4096 ] \
           || LC_ALL=C printf '%s' "$MANAGED_TOKEN" | grep -q '[[:cntrl:]]'; then
            echo "Error: PILOT_ENROLLMENT_TOKEN is invalid." >&2
            exit 1
        fi
    fi
    # Managed credentials and state created by this process default owner-only.
    umask 077
    MANIFEST_URL="${PILOT_MANAGEMENT_URL}/.well-known/pilot-managed-runtime.json"
elif [ "$PILOT_MANAGED_NO_START" = "1" ]; then
    echo "Error: --no-start is only valid with --managed-url." >&2
    exit 2
fi

# Validate channel value early so we fail fast. `edge` is a back-compat alias
# for `beta`: the manifest publishes channels.stable and channels.beta only, so
# a literal `edge` lookup would resolve empty and (previously) silently fall
# through to an unverified source build. Normalise it to `beta` here.
if [ "$PILOT_REQUESTED_CHANNEL" = "edge" ]; then
    PILOT_REQUESTED_CHANNEL="beta"
fi
if [ -n "$PILOT_REQUESTED_CHANNEL" ] \
   && [ "$PILOT_REQUESTED_CHANNEL" != "stable" ] \
   && [ "$PILOT_REQUESTED_CHANNEL" != "beta" ]; then
    echo "Error: --channel must be 'stable' or 'beta' (got: $PILOT_REQUESTED_CHANNEL)" >&2
    exit 2
fi

# --transport beats the PILOT_TRANSPORT env var. Empty means "not requested on
# this run": a re-run keeps whatever transport config.json already has.
TRANSPORT="$(printf '%s' "${PILOT_REQUESTED_TRANSPORT:-${PILOT_TRANSPORT:-}}" | tr '[:upper:]' '[:lower:]')"
case "$TRANSPORT" in
    ""|udp|compat|auto) ;;
    *)
        echo "Error: --transport must be 'udp', 'compat' or 'auto' (got: $TRANSPORT)" >&2
        exit 2 ;;
esac

# Restore positional args so the existing uninstall handler still uses $1.
# shellcheck disable=SC2086 # intentional word-split on PILOT_POSITIONAL
set -- $PILOT_POSITIONAL

# Refuse to run as root on a regular host — the daemon must run as the
# invoking user so identity.json and received files land under that user's
# home, not /root. A Linux container or VM without systemd (CI runners,
# hosted agent sandboxes such as Meta Muse, where the agent IS root) has no
# other user to install for and no system service to protect, so root is
# allowed there.
SANDBOX_HOST=false
if [ "$(uname -s)" = "Linux" ] && [ ! -d /run/systemd/system ]; then
    SANDBOX_HOST=true
fi
if [ "${1:-}" != "uninstall" ] && [ "$(id -u)" = "0" ] && [ -z "${PILOT_ALLOW_ROOT:-}" ]; then
    if [ "$SANDBOX_HOST" = true ]; then
        echo "Note: installing as root (no systemd: container/VM sandbox) into ${HOME}/.pilot"
    else
        echo "Error: refusing to install as root."
        echo "       Run as a regular user; the installer uses sudo only when needed."
        echo "       Set PILOT_ALLOW_ROOT=1 to override (not recommended)."
        exit 1
    fi
fi

# A managed identity is per node, but the CLI links, service label and daemon
# socket are machine-wide. A different HOME therefore does not make a second
# installation safe. Refuse before downloading, stopping services, replacing
# links or consuming the enrollment token. An existing attachment in this
# same PILOT_DIR remains the ordinary repair/update path handled above.
if [ "$PILOT_MANAGED_MODE" = "1" ] && [ ! -e "$MANAGED_CONTROL_PATH" ] \
   && [ "${PILOT_REPLACE_EXISTING_NODE:-}" != "1" ]; then
    _pilot_collision=""
    for _pilot_link in /usr/local/bin/pilotctl /usr/local/bin/pilot-daemon; do
        if [ -L "$_pilot_link" ]; then
            _pilot_target=$(readlink "$_pilot_link" 2>/dev/null || true)
            case "$_pilot_target" in
                "$BIN_DIR"/*) ;;
                */.pilot/bin/*) _pilot_collision="${_pilot_collision}${_pilot_collision:+, }$_pilot_link -> $_pilot_target" ;;
            esac
        fi
    done
    _pilot_os=$(uname -s | tr '[:upper:]' '[:lower:]')
    if [ "$_pilot_os" = "darwin" ] && command -v launchctl >/dev/null 2>&1; then
        _pilot_service=$(launchctl print "gui/$(id -u)/network.pilotprotocol.pilot-daemon" 2>/dev/null || true)
        if [ -n "$_pilot_service" ] && ! printf '%s\n' "$_pilot_service" | grep -Fq "$BIN_DIR/pilot-daemon"; then
            _pilot_collision="${_pilot_collision}${_pilot_collision:+, }LaunchAgent network.pilotprotocol.pilot-daemon"
        fi
    elif [ "$_pilot_os" = "linux" ] && command -v systemctl >/dev/null 2>&1; then
        _pilot_service=$(systemctl cat pilot-daemon 2>/dev/null || true)
        if [ -n "$_pilot_service" ] && ! printf '%s\n' "$_pilot_service" | grep -Fq "$BIN_DIR/pilot-daemon"; then
            _pilot_collision="${_pilot_collision}${_pilot_collision:+, }systemd pilot-daemon"
        fi
    fi
    if [ -n "$_pilot_collision" ]; then
        MANAGED_TOKEN=""
        unset MANAGED_TOKEN
        echo "Error: another Pilot node installation already owns machine-wide resources." >&2
        echo "       Detected: $_pilot_collision" >&2
        echo "       This enrollment token was not consumed and nothing was changed." >&2
        echo "       Manage or remove the existing node first; do not run two node identities under one service label." >&2
        exit 1
    fi
    _pilot_collision=""; _pilot_target=""; _pilot_service=""; _pilot_os=""
fi

# The transport already saved in config.json, if any ("udp", "compat",
# "auto"). A re-run without --transport keeps it, so regenerated service
# units stay consistent with it.
CONFIG_TRANSPORT=""
if [ -f "$PILOT_DIR/config.json" ]; then
    CONFIG_TRANSPORT=$(sed -n 's/.*"transport"[[:space:]]*:[[:space:]]*"\([A-Za-z]*\)".*/\1/p' "$PILOT_DIR/config.json" 2>/dev/null | head -n 1 | tr '[:upper:]' '[:lower:]')
fi
# Without any choice, new installs get auto (settled below, once the
# installed daemon is known to support it).
EFFECTIVE_TRANSPORT="${TRANSPORT:-${CONFIG_TRANSPORT:-auto}}"

# --- Egress proxy ---
#
# Every download below is a curl HTTPS request, and curl honors HTTPS_PROXY /
# https_proxy / ALL_PROXY / NO_PROXY on its own, asking the proxy to CONNECT
# by hostname (no local DNS lookup of the target — which matters where local
# DNS for pilotprotocol.network is poisoned). PILOT_PROXY_URL is only used in
# messages, and only ever printed redacted: the userinfo of an
# authenticating proxy is a credential. Nothing in this script writes a proxy
# URL to disk.
#
# PILOT_PROXY is the daemon's own proxy setting; an http(s):// URL there
# carries this run's downloads too when the environment names no proxy
# (exported to this process and its children only).
if [ -z "${https_proxy:-}${HTTPS_PROXY:-}${all_proxy:-}${ALL_PROXY:-}" ]; then
    case "${PILOT_PROXY:-}" in
        http://*|https://*|HTTP://*|HTTPS://*)
            https_proxy="$PILOT_PROXY"
            HTTPS_PROXY="$PILOT_PROXY"
            export https_proxy HTTPS_PROXY ;;
    esac
fi
# The order curl uses for an https:// URL.
PILOT_PROXY_URL="${https_proxy:-${HTTPS_PROXY:-${all_proxy:-${ALL_PROXY:-}}}}"

# Rotating proxy credentials. Hosted agent sandboxes (Meta Muse) put the proxy
# credentials in HTTPS_PROXY and replace them every few minutes; a process
# keeps the ones it started with, and the proxy answers its next CONNECT with
# 407. A fresh shell sees the current ones. PROXY_REFRESH_CMD prints the
# current proxy URL: $PILOT_PROXY_CMD, else — in a Linux container/VM without
# systemd whose HTTPS_PROXY or https_proxy carries credentials — what a fresh
# bash has: whichever of $https_proxy and $HTTPS_PROXY carries credentials
# ($https_proxy when both do, the variable Meta Muse's guidance reads), else
# ${HTTPS_PROXY:-$https_proxy}, so a URL with credentials is never traded for
# one without (pilotctl uses the same command). It is saved as the daemon's
# proxy_cmd further down, and pcurl uses it here to retry a download once
# after the credentials rotated mid-install.
# shellcheck disable=SC2016 # literal: the fresh bash expands it, not this shell
SANDBOX_PROXY_CMD='bash -c '\''case $https_proxy in *@*) printf %s "$https_proxy";; *) printf %s "${HTTPS_PROXY:-$https_proxy}";; esac'\'''
PROXY_REFRESH_CMD="${PILOT_PROXY_CMD:-}"
if [ -z "$PROXY_REFRESH_CMD" ] && [ "$SANDBOX_HOST" = true ] \
   && command -v bash >/dev/null 2>&1; then
    case "${https_proxy:-}${HTTPS_PROXY:-}" in
        *@*) PROXY_REFRESH_CMD="$SANDBOX_PROXY_CMD" ;;
    esac
fi

# proxy_refresh — run PROXY_REFRESH_CMD (at most 10s where `timeout` exists)
# and, when it prints an http(s):// URL different from the current one, use
# that for the rest of this run. The URL is never printed; only this process's
# environment changes. Returns 0 when the proxy URL changed.
proxy_refresh() {
    [ -n "$PROXY_REFRESH_CMD" ] || return 1
    if command -v timeout >/dev/null 2>&1; then
        _pr_url=$(timeout 10 sh -c "$PROXY_REFRESH_CMD" 2>/dev/null </dev/null | head -n 1 | tr -d '[:space:]') || _pr_url=""
    else
        _pr_url=$(sh -c "$PROXY_REFRESH_CMD" 2>/dev/null </dev/null | head -n 1 | tr -d '[:space:]') || _pr_url=""
    fi
    case "$_pr_url" in
        http://*|https://*|HTTP://*|HTTPS://*) ;;
        *) _pr_url=""; return 1 ;;
    esac
    if [ "$_pr_url" = "${https_proxy:-${HTTPS_PROXY:-}}" ]; then
        _pr_url=""
        return 1
    fi
    https_proxy="$_pr_url"
    HTTPS_PROXY="$_pr_url"
    export https_proxy HTTPS_PROXY
    PILOT_PROXY_URL="$_pr_url"
    _pr_url=""
    return 0
}

# pcurl ARGS... — curl, retried once when it failed and proxy_refresh found
# new proxy credentials (the old ones rotated while this script ran).
pcurl() {
    curl "$@" && return 0
    _pc_rc=$?
    proxy_refresh || return "$_pc_rc"
    curl "$@"
}

# redact_proxy URL — print URL with any "user:pass@" replaced by "***@".
redact_proxy() {
    case "$1" in
        *@*)
            _rp_scheme=""
            case "$1" in *://*) _rp_scheme="${1%%://*}://" ;; esac
            printf '%s***@%s\n' "$_rp_scheme" "${1##*@}" ;;
        *)
            printf '%s\n' "$1" ;;
    esac
}

# net_hint — after a failed download, say what to check. Behind an egress
# proxy the usual cause is the proxy refusing the CONNECT (407: bad
# credentials, 403: host not allowed), not a missing release.
net_hint() {
    if [ -n "$PILOT_PROXY_URL" ]; then
        echo "  Note: downloads go through the proxy $(redact_proxy "$PILOT_PROXY_URL")." >&2
        echo "        Check that it accepts CONNECT to pilotprotocol.network:443, github.com:443" >&2
        echo "        and *.githubusercontent.com:443, and that its credentials are right." >&2
    else
        echo "  Note: check outbound HTTPS to pilotprotocol.network and github.com. If this host" >&2
        echo "        can only reach the internet through a proxy, export HTTPS_PROXY and re-run." >&2
    fi
}

# --- Manifest + version helpers ---

# fetch_manifest writes the manifest JSON to $1 and returns 0 on success.
# Soft-fails (returns 1) so callers fall back to the GitHub-redirect path
# when the manifest host is unreachable.
fetch_manifest() {
    pcurl -fsSL --max-time 10 "$MANIFEST_URL" -o "$1" 2>/dev/null
}

# manifest_field "<path>" "<file>" extracts a string field. Supports nested
# paths like "channels.stable" with a one-level sed slice — POSIX shell only,
# no jq dependency. Returns empty if the field is absent.
manifest_field() {
    _mf_field="$1"; _mf_file="$2"
    case "$_mf_field" in
        *.*)
            _mf_outer="${_mf_field%%.*}"
            _mf_inner="${_mf_field#*.}"
            sed -n "/\"${_mf_outer}\"[[:space:]]*:[[:space:]]*{/,/^[[:space:]]*}/p" "$_mf_file" \
              | grep "\"${_mf_inner}\"" | head -1 \
              | sed -E "s/.*\"${_mf_inner}\"[[:space:]]*:[[:space:]]*\"([^\"]*)\".*/\\1/"
            ;;
        *)
            grep "\"${_mf_field}\"" "$_mf_file" | head -1 \
              | sed -E "s/.*\"${_mf_field}\"[[:space:]]*:[[:space:]]*\"([^\"]*)\".*/\\1/"
            ;;
    esac
}

# manifest_platform_sha256 "<os>-<arch>" "<file>" extracts the per-platform
# sha256 from the manifest's "platforms" map, e.g. the hash inside
#   "platforms": { "darwin-arm64": { "url": "...", "sha256": "abc..." } }
# Returns empty if the platform block or its sha256 is absent. This is a second,
# independent integrity anchor (served from pilotprotocol.network) alongside the
# release's checksums.txt (served from GitHub).
manifest_platform_sha256() {
    _mp_plat="$1"; _mp_file="$2"
    # The authority is free to emit compact JSON. A line-range parser sees all
    # platform objects on that one line and a greedy replacement can therefore
    # return the final platform's hash. Collapse whitespace deliberately, then
    # constrain the match to this platform's first closing brace.
    tr -d '\r\n' < "$_mp_file" \
      | sed -n -E "s/.*\"${_mp_plat}\"[[:space:]]*:[[:space:]]*\\{[^}]*\"sha256\"[[:space:]]*:[[:space:]]*\"([^\"]*)\"[^}]*\\}.*/\\1/p" \
      | head -1
}

# version_compare a b emits -1 / 0 / 1 for a<b / a==b / a>b.
# Honors semver: a prerelease tag ("X.Y.Z-rcN") is LOWER than the same base
# without it ("X.Y.Z"). Plain `sort -V` gets this backwards on hyphenated
# suffixes, so we split on "-" and compare the base versions first, then
# break ties on the prerelease suffix.
version_compare() {
    _vc_a="${1#v}"; _vc_b="${2#v}"
    if [ "$_vc_a" = "$_vc_b" ]; then echo 0; return; fi
    _vc_a_base="${_vc_a%%-*}"; _vc_b_base="${_vc_b%%-*}"
    if [ "$_vc_a_base" = "$_vc_b_base" ]; then
        _vc_a_pre=0; case "$_vc_a" in *-*) _vc_a_pre=1 ;; esac
        _vc_b_pre=0; case "$_vc_b" in *-*) _vc_b_pre=1 ;; esac
        if [ "$_vc_a_pre" = "1" ] && [ "$_vc_b_pre" = "0" ]; then printf '%s\n' -1; return; fi
        if [ "$_vc_a_pre" = "0" ] && [ "$_vc_b_pre" = "1" ]; then echo 1; return; fi
        _vc_a_suf="${_vc_a#*-}"; _vc_b_suf="${_vc_b#*-}"
        _vc_older=$(printf '%s\n%s\n' "$_vc_a_suf" "$_vc_b_suf" | sort -V | head -1)
        if [ "$_vc_older" = "$_vc_a_suf" ]; then printf '%s\n' -1; else echo 1; fi
        return
    fi
    _vc_older=$(printf '%s\n%s\n' "$_vc_a_base" "$_vc_b_base" | sort -V | head -1)
    if [ "$_vc_older" = "$_vc_a_base" ]; then printf '%s\n' -1; else echo 1; fi
}

# --- Uninstall ---

if [ "${1}" = "uninstall" ]; then
    echo ""
    echo "  Uninstalling Pilot Protocol..."
    echo ""

    OS=$(uname -s | tr '[:upper:]' '[:lower:]')

    # Stop daemon
    if [ -x "$BIN_DIR/pilotctl" ]; then
        "$BIN_DIR/pilotctl" daemon stop 2>/dev/null || true
        # Gateway is extras-only in the core CLI: plain `pilotctl gateway stop`
        # hard-errors ("gateway commands are not in the core CLI"), so the
        # gateway was never actually stopped on uninstall.
        "$BIN_DIR/pilotctl" extras gateway stop 2>/dev/null || true
    elif command -v pilotctl >/dev/null 2>&1; then
        pilotctl daemon stop 2>/dev/null || true
        pilotctl extras gateway stop 2>/dev/null || true
    fi

    # Remove the /usr/local/bin symlinks the installer creates. Without this a
    # dangling `pilotctl` stays on the default PATH after uninstall and fails
    # with a confusing "No such file or directory". Only ever unlinks a SYMLINK
    # that actually points into this user's ~/.pilot/bin — an unrelated real
    # file of the same name is left alone. Same `sudo -n` gate as install: no
    # password prompt, skip silently when we cannot write.
    UNLINK_DIR="/usr/local/bin"
    UNLINK_SUDO=""
    if [ ! -w "$UNLINK_DIR" ] && sudo -n true 2>/dev/null; then
        UNLINK_SUDO="sudo"
    fi
    for _b in pilotctl pilot-daemon pilot-gateway pilot-updater; do
        if [ -L "$UNLINK_DIR/$_b" ]; then
            case "$(readlink "$UNLINK_DIR/$_b" 2>/dev/null)" in
                "$BIN_DIR"/*)
                    # shellcheck disable=SC2086 # "" or "sudo" — intentional split
                    if $UNLINK_SUDO rm -f "$UNLINK_DIR/$_b" 2>/dev/null; then
                        echo "  Removed ${UNLINK_DIR}/${_b}"
                    fi
                    ;;
            esac
        fi
    done

    # Remove system services (daemon + updater)
    if [ "$OS" = "linux" ]; then
        if [ "$(id -u)" = "0" ] || sudo -n true 2>/dev/null; then
            for svc in pilot-daemon pilot-updater; do
                if [ -f "/etc/systemd/system/${svc}.service" ]; then
                    sudo systemctl stop "$svc" 2>/dev/null || true
                    sudo systemctl disable "$svc" 2>/dev/null || true
                    sudo rm -f "/etc/systemd/system/${svc}.service"
                fi
            done
            # Never let daemon-reload abort the uninstall under `set -e`: on a
            # host with sudo but no systemd (container / WSL / CI) systemctl is
            # missing or fails, and the abort left ~/.pilot in place after the
            # user asked to uninstall. Matches the install-side handling below.
            sudo systemctl daemon-reload 2>/dev/null || true
            echo "  Removed systemd services"
        else
            echo "  Skipped systemd removal (run with sudo to remove)"
        fi
    fi
    if [ "$OS" = "darwin" ]; then
        # New labels + legacy labels (migration cleanup from earlier installs)
        for label in network.pilotprotocol.pilot-daemon network.pilotprotocol.pilot-updater com.vulturelabs.pilot-daemon com.vulturelabs.pilot-updater; do
            PLIST="$HOME/Library/LaunchAgents/${label}.plist"
            if [ -f "$PLIST" ]; then
                launchctl unload "$PLIST" 2>/dev/null || true
                rm -f "$PLIST"
            fi
        done
        echo "  Removed LaunchAgents"
    fi

    # Remove pilot directory (binaries, config, identity, received files)
    if [ -d "$PILOT_DIR" ]; then
        rm -rf "$PILOT_DIR"
        echo "  Removed $PILOT_DIR"
    fi

    # Remove socket
    rm -f /tmp/pilot.sock

    echo ""
    echo "  Pilot Protocol uninstalled."
    echo ""
    exit 0
fi

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    arm64)   ARCH="arm64" ;;
    *)       echo "Error: unsupported architecture: $ARCH"; exit 1 ;;
esac

case "$OS" in
    linux|darwin) ;;
    *) echo "Error: unsupported OS: $OS"; exit 1 ;;
esac

# --- Privilege helper ---
#
# Every privileged step (systemd units, service start/stop, /usr/local/bin
# symlinks) goes through this gate. It NEVER prompts: sudo is used only when
# `sudo -n` already succeeds without a password, and no prefix at all is used
# when we are already root — minimal containers frequently ship no sudo binary,
# so an unconditional `sudo systemctl ...` would fail there under PILOT_ALLOW_ROOT.
# CAN_PRIV says whether privileged steps can run at all.
PILOT_SUDO=""
CAN_PRIV=false
if [ "$(id -u)" = "0" ]; then
    CAN_PRIV=true
elif sudo -n true 2>/dev/null; then
    PILOT_SUDO="sudo"
    CAN_PRIV=true
fi

echo ""
echo "  Pilot Protocol"
echo "  The network stack for AI agents."
echo ""
echo "  Platform:   ${OS}/${ARCH}"
case "$EFFECTIVE_TRANSPORT" in
    compat)
        echo "  Transport:  compat (TLS + WSS over TCP 443 only)" ;;
    auto)
        echo "  Transport:  auto (UDP when it works, else TLS + WSS over TCP 443)"
        if [ -z "$PILOT_PROXY_URL" ]; then
            echo "  Registry:   ${REGISTRY}"
            echo "  Beacon:     ${BEACON}"
        fi ;;
    *)
        echo "  Registry:   ${REGISTRY}"
        echo "  Beacon:     ${BEACON}" ;;
esac
if [ -n "$PILOT_PROXY_URL" ]; then
    echo "  Proxy:      $(redact_proxy "$PILOT_PROXY_URL") (from environment)"
fi
echo ""

# --- Resolve email ---

EMAIL="${PILOT_EMAIL:-}"

# Recover an email this host already has. account.json is written by the daemon,
# config.json by a previous run of this installer. Doing this on EVERY run — not
# just fresh installs — matters because the service unit is now regenerated on
# re-run: without it an upgrade would silently drop the address the operator
# configured at first install.
#
# Synthesised @nodes.pilotprotocol.network placeholders are deliberately NOT
# recovered. The daemon re-derives the identical value from the same identity
# key, so baking one into the unit adds nothing — and it would turn a soft
# default into a hard override that outranks the account file, silently
# defeating a later `pilotctl set-email`.
if [ -z "$EMAIL" ]; then
    for _ef in "$PILOT_DIR/account.json" "$PILOT_DIR/config.json"; do
        if [ -f "$_ef" ]; then
            EMAIL=$(grep '"email"' "$_ef" 2>/dev/null | head -1 | cut -d'"' -f4 || true)
        fi
        case "$EMAIL" in
            *@nodes.pilotprotocol.network) EMAIL="" ;;
        esac
        if [ -n "$EMAIL" ]; then
            break
        fi
    done
fi

# On a fresh install with no email anywhere, ask for one — but only when there
# is a terminal to ask.
if [ -z "$EMAIL" ] && [ ! -x "$BIN_DIR/pilotctl" ]; then
    # Interactive (TTY): prompt. Non-interactive (piped into a headless
    # agent, no controlling terminal): do NOT block on /dev/tty — the
    # daemon auto-synthesizes a <fingerprint>@nodes.pilotprotocol.network
    # identity when email is empty, so a missing email must not abort.
    if [ -t 0 ]; then
        printf "  Email (for account recovery): "
        read -r EMAIL < /dev/tty
    fi
    if [ -z "$EMAIL" ]; then
        if [ -t 0 ]; then
            echo "  Error: email is required. Set PILOT_EMAIL or enter when prompted."
            exit 1
        else
            echo "  Note: no email provided (non-interactive). Set PILOT_EMAIL= for account recovery."
        fi
    fi
fi

# The email is interpolated unquoted into config.json (a JSON string), the
# systemd unit ExecStart, and the launchd plist. Reject anything that could
# break out of those contexts (quotes, backslash, angle brackets, spaces,
# newlines). Standard email punctuation is allowed. Empty is fine here — an
# existing install without a new email keeps whatever it had.
if [ -n "$EMAIL" ]; then
    validate_safe "email (PILOT_EMAIL)" "$EMAIL" "@.+_%-"
fi

# PILOT_HOSTNAME becomes a `-hostname <value>` argument in the root-owned
# systemd unit and the plist. A value with whitespace would inject additional
# daemon flags; validate it to hostname-safe characters.
if [ -n "${PILOT_HOSTNAME:-}" ]; then
    validate_safe "hostname (PILOT_HOSTNAME)" "$PILOT_HOSTNAME" "._-"
fi

# --- Detect existing installation ---

UPDATING=false
if [ -x "$BIN_DIR/pilotctl" ]; then
    UPDATING=true
    CURRENT=$("$BIN_DIR/pilotctl" version 2>/dev/null || echo "unknown")
    echo "  Existing install detected (${CURRENT})"
    echo "  Updating binaries..."
    echo ""
fi

# --- Download or build ---

TMPDIR=$(mktemp -d)

# Clean up both the download staging dir and any `<binary>.new.<pid>` file left
# behind by an interrupted atomic install (see install_bin below). The staging
# files live next to the real binaries so that rename(2) stays within one
# filesystem; they must never survive a failed run.
pilot_cleanup() {
    rm -rf "$TMPDIR"
    rm -f "$BIN_DIR"/*.new."$$" 2>/dev/null || true
}
trap pilot_cleanup EXIT

ARCHIVE="pilot-${OS}-${ARCH}.tar.gz"

# Resolve the release tag. Precedence (highest to lowest):
#   1. --version <tag>            explicit pin via flag
#   2. PILOT_RELEASE_TAG env       legacy explicit pin (back-compat)
#   3. --channel <name>            manifest channel lookup
#   4. PILOT_RC=1 env              legacy "beta" channel (back-compat)
#   5. Manifest "latest_stable"    preferred for the default install
#   6. GitHub /releases/latest redirect — fallback when the manifest host
#      is unreachable. Unauthenticated CDN, not subject to the 60/hr
#      api.github.com rate limit.
MANIFEST_FILE="$TMPDIR/manifest.json"
HAVE_MANIFEST=0
if fetch_manifest "$MANIFEST_FILE"; then
    HAVE_MANIFEST=1
fi
if [ "$PILOT_MANAGED_MODE" = "1" ] && [ "$HAVE_MANIFEST" != "1" ]; then
    echo "Error: the management authority did not publish a managed-runtime manifest." >&2
    echo "       No binary or enrollment state was changed." >&2
    exit 1
fi

if [ -n "$PILOT_REQUESTED_VERSION" ]; then
    TAG="$PILOT_REQUESTED_VERSION"
elif [ -n "${PILOT_RELEASE_TAG:-}" ]; then
    TAG="$PILOT_RELEASE_TAG"
elif [ -n "$PILOT_REQUESTED_CHANNEL" ] && [ "$HAVE_MANIFEST" = "1" ]; then
    TAG=$(manifest_field "channels.${PILOT_REQUESTED_CHANNEL}" "$MANIFEST_FILE")
elif [ "${PILOT_RC:-}" = "1" ] && [ "$HAVE_MANIFEST" = "1" ]; then
    TAG=$(manifest_field "channels.beta" "$MANIFEST_FILE")
elif [ "${PILOT_RC:-}" = "1" ]; then
    # Manifest unreachable; fall back to api.github.com for the newest tag.
    API_BODY="$TMPDIR/releases.json"
    API_CODE=$(curl -sSL -o "$API_BODY" -w '%{http_code}' "https://api.github.com/repos/${REPO}/releases" 2>/dev/null || echo "000")
    if [ "$API_CODE" = "403" ]; then
        echo "Error: GitHub API rate-limited (403) while resolving the latest pre-release." >&2
        echo "  Workarounds:" >&2
        echo "    - retry in ~1 hour, OR" >&2
        echo "    - pin the tag:  --version vX.Y.Z-rcN" >&2
        echo "  Refusing to silently source-build an unstamped binary." >&2
        exit 1
    fi
    if [ "$API_CODE" = "200" ]; then
        TAG=$(grep '"tag_name"' "$API_BODY" | head -1 | cut -d'"' -f4 || true)
    fi
    rm -f "$API_BODY"
elif [ "$HAVE_MANIFEST" = "1" ]; then
    TAG=$(manifest_field "latest_stable" "$MANIFEST_FILE")
else
    TAG=$(pcurl -fsSI "https://github.com/${REPO}/releases/latest/download/${ARCHIVE}" 2>/dev/null \
        | grep -i '^location:' \
        | sed -n 's|.*/releases/download/\([^/]*\)/.*|\1|p' \
        | tr -d '\r' | head -1)
fi

if [ "$PILOT_MANAGED_MODE" = "1" ]; then
    case "$TAG" in
        managed-runtime-v[0-9]*.[0-9]*.[0-9]*) ;;
        *)
            echo "Error: the management authority published an invalid managed-runtime version." >&2
            exit 1 ;;
    esac
    validate_safe "managed runtime version" "$TAG" ".-"
fi

# Fail loudly if the user explicitly asked for a released version/channel but it
# resolved to nothing. Silently dropping to the unpinned, UNVERIFIED source
# build below would give the user a binary they never asked for, with none of
# the provenance guarantees of a release. Only the fully-automatic default path
# (no explicit request) is allowed to fall back to a source build.
if [ -z "$TAG" ]; then
    if [ -n "$PILOT_REQUESTED_VERSION" ]; then
        echo "Error: requested version '$PILOT_REQUESTED_VERSION' could not be resolved to a release." >&2
        exit 1
    fi
    if [ -n "${PILOT_RELEASE_TAG:-}" ]; then
        echo "Error: PILOT_RELEASE_TAG='$PILOT_RELEASE_TAG' could not be resolved to a release." >&2
        exit 1
    fi
    if [ -n "$PILOT_REQUESTED_CHANNEL" ]; then
        echo "Error: channel '$PILOT_REQUESTED_CHANNEL' resolved to no release (manifest reachable: $HAVE_MANIFEST)." >&2
        echo "       Refusing to fall back to an unverified source build for an explicit channel request." >&2
        [ "$HAVE_MANIFEST" = "1" ] || net_hint
        exit 1
    fi
    if [ "${PILOT_RC:-}" = "1" ]; then
        echo "Error: the beta/prerelease channel resolved to no release." >&2
        echo "       Refusing to fall back to an unverified source build for an explicit channel request." >&2
        [ "$HAVE_MANIFEST" = "1" ] || net_hint
        exit 1
    fi
fi

# Warn when the resolved tag is older than the manifest's latest_stable.
# A confirmation prompt fires only when stdin is a TTY *and* --yes was not
# passed; non-interactive pipes (curl | sh) get the warning text without a
# prompt and proceed, so existing automation does not break.
if [ -n "$TAG" ] && [ "$HAVE_MANIFEST" = "1" ] && [ "$PILOT_NO_WARN" = "0" ]; then
    LATEST_STABLE=$(manifest_field "latest_stable" "$MANIFEST_FILE")
    if [ -n "$LATEST_STABLE" ] && [ "$TAG" != "$LATEST_STABLE" ]; then
        CMP=$(version_compare "$TAG" "$LATEST_STABLE")
        if [ "$CMP" = "-1" ]; then
            echo "" >&2
            echo "Warning: ${TAG} is older than the latest stable release (${LATEST_STABLE})." >&2
            echo "         Older versions miss security fixes. To install the latest stable," >&2
            echo "         re-run without --version, or pass --version ${LATEST_STABLE}." >&2
            if [ "$PILOT_YES" != "1" ] && [ -t 0 ]; then
                printf "Continue installing %s anyway? [y/N] " "$TAG" >&2
                read -r _confirm
                case "$_confirm" in
                    y|Y|yes|YES) ;;
                    *) echo "Aborted." >&2; exit 1 ;;
                esac
            fi
            echo "" >&2
        fi
    fi
fi

if [ -n "$TAG" ]; then
    URL="https://github.com/${REPO}/releases/download/${TAG}/${ARCHIVE}"
    CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${TAG}/checksums.txt"
    echo "Downloading ${TAG}..."
    if pcurl -fsSL "$URL" -o "$TMPDIR/$ARCHIVE" 2>/dev/null; then
        # --- Verify SHA-256 (fail closed) ---
        # This block NEVER extracts an archive it could not verify. Two
        # independent anchors are used:
        #   EXPECTED_CKS  — from the release's checksums.txt (GitHub)
        #   EXPECTED_MAN  — the per-platform sha256 in the signed manifest
        #                   (pilotprotocol.network)
        # When both are present they must AGREE (defends against a compromise
        # of either single source). At least one must be present, a working
        # SHA-256 tool must exist, and the computed hash must match — otherwise
        # the install aborts. (Previously a missing checksums.txt, a missing
        # archive line, or the absence of shasum/sha256sum silently extracted
        # the archive UNVERIFIED.)
        EXPECTED_CKS=""
        if pcurl -fsSL "$CHECKSUMS_URL" -o "$TMPDIR/checksums.txt" 2>/dev/null; then
            EXPECTED_CKS=$(grep " ${ARCHIVE}\$" "$TMPDIR/checksums.txt" | awk '{print $1}')
        fi
        EXPECTED_MAN=""
        if [ "$HAVE_MANIFEST" = "1" ]; then
            EXPECTED_MAN=$(manifest_platform_sha256 "${OS}-${ARCH}" "$MANIFEST_FILE")
        fi

        # Cross-check the two anchors when both are available.
        if [ -n "$EXPECTED_CKS" ] && [ -n "$EXPECTED_MAN" ] \
           && [ "$EXPECTED_CKS" != "$EXPECTED_MAN" ]; then
            echo "Error: integrity anchors disagree for ${ARCHIVE}" >&2
            echo "  checksums.txt: $EXPECTED_CKS" >&2
            echo "  manifest:      $EXPECTED_MAN" >&2
            echo "  Refusing to install." >&2
            exit 1
        fi

        # Pick the expected hash (prefer checksums.txt; fall back to manifest).
        EXPECTED="$EXPECTED_CKS"
        [ -z "$EXPECTED" ] && EXPECTED="$EXPECTED_MAN"
        if [ -z "$EXPECTED" ]; then
            echo "Error: no SHA-256 available for ${ARCHIVE}." >&2
            echo "  checksums.txt was missing/incomplete and the manifest carried no hash." >&2
            echo "  Refusing to install an unverified binary." >&2
            exit 1
        fi

        # Compute the actual hash; a missing tool is a hard failure, not a skip.
        if command -v shasum >/dev/null 2>&1; then
            ACTUAL=$(shasum -a 256 "$TMPDIR/$ARCHIVE" | awk '{print $1}')
        elif command -v sha256sum >/dev/null 2>&1; then
            ACTUAL=$(sha256sum "$TMPDIR/$ARCHIVE" | awk '{print $1}')
        else
            echo "Error: no SHA-256 tool (shasum or sha256sum) found." >&2
            echo "  Cannot verify ${ARCHIVE}; refusing to install unverified." >&2
            echo "  Install coreutils (sha256sum) or perl (shasum) and retry." >&2
            exit 1
        fi
        if [ -z "$ACTUAL" ]; then
            echo "Error: failed to compute SHA-256 of ${ARCHIVE}." >&2
            exit 1
        fi
        if [ "$ACTUAL" != "$EXPECTED" ]; then
            echo "Error: checksum mismatch for ${ARCHIVE}" >&2
            echo "  expected: $EXPECTED" >&2
            echo "  actual:   $ACTUAL" >&2
            exit 1
        fi
        if [ -n "$EXPECTED_CKS" ] && [ -n "$EXPECTED_MAN" ]; then
            echo "  Verified SHA-256 (checksums.txt + manifest)"
        elif [ -n "$EXPECTED_CKS" ]; then
            echo "  Verified SHA-256 (checksums.txt)"
        else
            echo "  Verified SHA-256 (manifest)"
        fi
        tar -xzf "$TMPDIR/$ARCHIVE" -C "$TMPDIR" --strip-components=1
    else
        if [ "$PILOT_MANAGED_MODE" = "1" ]; then
            echo "Error: managed runtime ${TAG} could not be downloaded." >&2
            echo "       Refusing to fall back to an unmanaged build." >&2
            exit 1
        fi
        # Archive download failed. Only the automatic default path may fall
        # back to a source build; an explicit request already hard-failed
        # above, so reaching here means no version/channel was pinned.
        echo "  Could not download ${URL}" >&2
        TAG=""
    fi
fi

if [ -z "$TAG" ]; then
    net_hint
    echo "No release available. Building from source..."
    if ! command -v go >/dev/null 2>&1; then
        echo "Error: Go is required to build from source."
        echo "Install Go: https://go.dev/dl/"
        exit 1
    fi
    if ! command -v git >/dev/null 2>&1; then
        echo "Error: git is required to build from source."
        exit 1
    fi
    echo "Cloning..."
    git clone --depth 1 "https://github.com/${REPO}.git" "$TMPDIR/src" >/dev/null 2>&1
    # Build from inside the cloned tree with GOWORK=off so a parent go.work
    # in the user's $PWD does not reject the cloned module.
    (
        cd "$TMPDIR/src"
        echo "Building daemon..."
        GOWORK=off CGO_ENABLED=0 go build -o "$TMPDIR/pilot-daemon" ./cmd/daemon
        echo "Building pilotctl..."
        GOWORK=off CGO_ENABLED=0 go build -o "$TMPDIR/pilotctl" ./cmd/pilotctl
        # gateway was extracted to a sibling repo (pilot-protocol/gateway)
        # — only build from source when ./cmd/gateway still exists in this
        # checkout. Release tarballs ship daemon/pilotctl/updater only.
        if [ -d ./cmd/gateway ]; then
            echo "Building gateway..."
            GOWORK=off CGO_ENABLED=0 go build -o "$TMPDIR/pilot-gateway" ./cmd/gateway
        fi
        echo "Building updater..."
        GOWORK=off CGO_ENABLED=0 go build -o "$TMPDIR/pilot-updater" ./cmd/updater
    )
fi

# --- Install binaries to ~/.pilot/bin ---

echo "Installing binaries..."
mkdir -p "$BIN_DIR"

# Resolve every staged binary BEFORE touching the installed ones. Both naming
# conventions are accepted (release tarball: daemon/gateway; source build:
# pilot-daemon/pilot-gateway). If the payload is incomplete we abort here, with
# the existing install still fully intact — never half-way through a copy loop.
STAGED_DAEMON=""
if [ -f "$TMPDIR/daemon" ]; then
    STAGED_DAEMON="$TMPDIR/daemon"
elif [ -f "$TMPDIR/pilot-daemon" ]; then
    STAGED_DAEMON="$TMPDIR/pilot-daemon"
fi
STAGED_CTL=""
if [ -f "$TMPDIR/pilotctl" ]; then
    STAGED_CTL="$TMPDIR/pilotctl"
fi
if [ -z "$STAGED_DAEMON" ] || [ -z "$STAGED_CTL" ]; then
    echo "Error: the downloaded payload is missing pilot-daemon and/or pilotctl." >&2
    echo "       Nothing was replaced — your existing install is untouched." >&2
    exit 1
fi
if [ "$PILOT_MANAGED_MODE" = "1" ]; then
    _managed_probe=$(PILOT_ENROLLMENT_TOKEN='' "$STAGED_CTL" --json enterprise adopt --endpoint "$PILOT_MANAGEMENT_URL" 2>&1 || true)
    case "$_managed_probe" in
        *PILOT_ENROLLMENT_TOKEN*) ;;
        *)
            echo "Error: ${TAG} does not contain core managed-adoption support." >&2
            echo "       Nothing was replaced and the enrollment token was not consumed." >&2
            exit 1 ;;
    esac
    _managed_probe=""
fi
# gateway is optional: extracted to a sibling repo, no longer ships in
# release tarballs (release.yml BINS=daemon/pilotctl/updater) and the
# source build only runs when ./cmd/gateway is present in the checkout.
STAGED_GATEWAY=""
if [ -f "$TMPDIR/gateway" ]; then
    STAGED_GATEWAY="$TMPDIR/gateway"
elif [ -f "$TMPDIR/pilot-gateway" ]; then
    STAGED_GATEWAY="$TMPDIR/pilot-gateway"
fi
STAGED_UPDATER=""
if [ -f "$TMPDIR/updater" ]; then
    STAGED_UPDATER="$TMPDIR/updater"
elif [ -f "$TMPDIR/pilot-updater" ]; then
    STAGED_UPDATER="$TMPDIR/pilot-updater"
fi

# --- Stop managed services before swapping binaries ---
#
# The installer now auto-enables and STARTS pilot-updater, so on any re-run
# (the advertised upgrade path) its binary is a live executable image. Two
# problems follow, and both are fixed here:
#
#   1. `cp` over a running executable fails with ETXTBSY ("Text file busy"),
#      which under `set -e` aborted the whole re-run mid-install — binaries
#      partially replaced, unit file never rewritten.
#   2. Even a successful swap does nothing until the process re-execs; the
#      running service keeps the old image.
#
# We stop what is running, remember it, and restart it after the units have
# been regenerated. install_bin below independently defeats ETXTBSY via
# rename(2), which also covers daemons we do not manage (e.g. one started with
# `pilotctl daemon start` on a systemd-less host).
RESTART_SYSTEMD=""
RESTART_LAUNCHD=""

if [ "$OS" = "linux" ] && [ "$CAN_PRIV" = true ] \
   && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    for _svc in pilot-daemon pilot-updater; do
        _state=$(systemctl is-active "$_svc" 2>/dev/null || true)
        _want=""
        case "$_state" in
            active|activating|reloading)
                _want=1 ;;
            failed)
                # A unit crashlooping on a bad ExecStart — exactly what the
                # empty `-email` produced — alternates between activating and
                # failed. Repairing its unit has to bring it back up, so an
                # ENABLED failed unit counts as "should be running" too. A unit
                # the operator deliberately disabled is left alone.
                if systemctl is-enabled --quiet "$_svc" 2>/dev/null; then
                    _want=1
                fi ;;
        esac
        if [ -n "$_want" ]; then
            if { [ "$PILOT_MANAGED_MODE" != "1" ] || [ "$PILOT_MANAGED_NO_START" != "1" ]; } \
               && { [ "$PILOT_MANAGED_MODE" != "1" ] || [ "$_svc" != "pilot-updater" ]; }; then
                RESTART_SYSTEMD="${RESTART_SYSTEMD}${RESTART_SYSTEMD:+ }${_svc}"
            fi
            # shellcheck disable=SC2086 # $PILOT_SUDO is "" or "sudo" — intentional split
            $PILOT_SUDO systemctl stop "$_svc" 2>/dev/null || true
            echo "  Stopped ${_svc} (will restart after upgrade)"
        fi
    done
fi
if [ "$OS" = "darwin" ]; then
    for _label in network.pilotprotocol.pilot-daemon network.pilotprotocol.pilot-updater; do
        _lp="$HOME/Library/LaunchAgents/${_label}.plist"
        if [ -f "$_lp" ] && launchctl list 2>/dev/null | grep -q "$_label"; then
            if { [ "$PILOT_MANAGED_MODE" != "1" ] || [ "$PILOT_MANAGED_NO_START" != "1" ]; } \
               && { [ "$PILOT_MANAGED_MODE" != "1" ] || [ "$_label" != "network.pilotprotocol.pilot-updater" ]; }; then
                RESTART_LAUNCHD="${RESTART_LAUNCHD}${RESTART_LAUNCHD:+ }${_label}"
            fi
            launchctl unload "$_lp" 2>/dev/null || true
            echo "  Unloaded ${_label} (will reload after upgrade)"
        fi
    done
fi

# install_bin SRC DEST — put SRC at DEST atomically.
#
# Writes to a temp file in the SAME directory (so rename(2) never crosses a
# filesystem) and renames it into place. Renaming over a busy executable is
# always allowed: the old inode is simply unlinked and any process still
# running it keeps its own copy. That makes this immune to ETXTBSY and means a
# failure part-way through can never leave a truncated binary at the real path.
install_bin() {
    _ib_tmp="${2}.new.$$"
    cp "$1" "$_ib_tmp"
    chmod 755 "$_ib_tmp"
    mv -f "$_ib_tmp" "$2"
}

install_bin "$STAGED_DAEMON" "$BIN_DIR/pilot-daemon"
install_bin "$STAGED_CTL" "$BIN_DIR/pilotctl"
[ -n "$STAGED_GATEWAY" ] && install_bin "$STAGED_GATEWAY" "$BIN_DIR/pilot-gateway"
[ -n "$STAGED_UPDATER" ] && install_bin "$STAGED_UPDATER" "$BIN_DIR/pilot-updater"

# --- Optional hosted adoption (core Pilot, not MCP) ---
#
# The one-time token is exposed only to this process. pilotctl validates the
# delegated key, root pin, trust bundle, bootstrap policy, authority origins,
# and owner-only output before atomically installing ~/.pilot/managed.
MANAGED_ADOPTED=0
if [ "$PILOT_MANAGED_MODE" = "1" ] && [ ! -e "$MANAGED_CONTROL_PATH" ]; then
    if ! _managed_result=$(PILOT_ENROLLMENT_TOKEN="$MANAGED_TOKEN" "$BIN_DIR/pilotctl" --json enterprise adopt --endpoint "$PILOT_MANAGEMENT_URL" 2>&1); then
        MANAGED_TOKEN=""
        unset MANAGED_TOKEN
        echo "Error: the hosted authority did not complete managed adoption." >&2
        printf '%s\n' "$_managed_result" >&2
        exit 1
    fi
    MANAGED_TOKEN=""
    unset MANAGED_TOKEN
    _managed_result=""
    if [ -L "$MANAGED_CONTROL_PATH" ] || [ ! -f "$MANAGED_CONTROL_PATH" ]; then
        echo "Error: managed adoption returned without installing the verified control attachment." >&2
        exit 1
    fi
    MANAGED_ADOPTED=1
fi
MANAGED_TOKEN=""
unset MANAGED_TOKEN

# --- Symlink into /usr/local/bin so NON-INTERACTIVE shells can find pilotctl ---
#
# This symlink is the only thing that makes `pilotctl` resolve from a
# non-interactive shell. `bash -c 'pilotctl version'` reads NEITHER ~/.bashrc
# (bash skips it entirely for -c) NOR ~/.profile (login shells only), and
# Debian/Ubuntu's stock ~/.bashrc returns early for non-interactive shells
# anyway. So a PATH line in a shell rc file is invisible to scripts, cron, CI
# and AI agents shelling out — which are this CLI's primary callers. A binary
# on the default system PATH is visible to all of them.
#
# Escalation order (never prompts, never escalates beyond what this installer
# already does elsewhere):
#   1. write directly when /usr/local/bin is already writable
#   2. `sudo -n` — the SAME passwordless-sudo gate the systemd block below
#      uses. If sudo would prompt, we do not use it.
#   3. give up and print the exact command for the user to run themselves.

LINK_DIR="/usr/local/bin"
LINK_SUDO=""
LINK_OK=false

if [ -d "$LINK_DIR" ] && [ -w "$LINK_DIR" ]; then
    LINK_OK=true
elif sudo -n true 2>/dev/null; then
    LINK_SUDO="sudo"
    LINK_OK=true
    if [ ! -d "$LINK_DIR" ]; then
        sudo mkdir -p "$LINK_DIR" 2>/dev/null || LINK_OK=false
    fi
fi

if [ "$LINK_OK" = true ]; then
    # shellcheck disable=SC2086 # $LINK_SUDO is "" or "sudo" — intentional split
    $LINK_SUDO ln -sf "$BIN_DIR/pilot-daemon" "$LINK_DIR/pilot-daemon" 2>/dev/null || LINK_OK=false
    # shellcheck disable=SC2086
    $LINK_SUDO ln -sf "$BIN_DIR/pilotctl" "$LINK_DIR/pilotctl" 2>/dev/null || LINK_OK=false
    if [ -f "$BIN_DIR/pilot-gateway" ]; then
        # shellcheck disable=SC2086
        $LINK_SUDO ln -sf "$BIN_DIR/pilot-gateway" "$LINK_DIR/pilot-gateway" 2>/dev/null || true
    fi
    if [ "$PILOT_MANAGED_MODE" != "1" ] && [ -f "$BIN_DIR/pilot-updater" ]; then
        # shellcheck disable=SC2086
        $LINK_SUDO ln -sf "$BIN_DIR/pilot-updater" "$LINK_DIR/pilot-updater" 2>/dev/null || true
    fi
fi

if [ "$LINK_OK" = true ]; then
    if [ -n "$LINK_SUDO" ]; then
        echo "  Symlinked to ${LINK_DIR} (via passwordless sudo)"
    else
        echo "  Symlinked to ${LINK_DIR}"
    fi
    echo "  pilotctl now resolves in non-interactive shells (bash -c, cron, CI, agents)"
fi

# --- What the installed binaries support ---
#
# pilot_config_set merges one key into config.json through pilotctl (atomic
# write, 0600, every other key kept) instead of rewriting the file, so a
# hand-edited config survives a re-run. PILOT_HOME is blanked so the write
# lands in THIS install's $HOME/.pilot, which is also the file pilot-daemon
# auto-loads. An empty value removes the key (used only with a pilotctl whose
# daemon supports transport auto, which clears keys that way).
pilot_config_set() {
    PILOT_HOME='' "$BIN_DIR/pilotctl" config --set "$1" >/dev/null 2>&1
}

# The probes are local (no network).
DAEMON_HAS_TRANSPORT=false
DAEMON_HAS_PROXY=false
DAEMON_HAS_AUTO=false
_daemon_help=$("$BIN_DIR/pilot-daemon" -help 2>&1 || true)
if printf '%s\n' "$_daemon_help" | grep -qE '^[[:space:]]+-transport([[:space:]]|$)'; then
    DAEMON_HAS_TRANSPORT=true
    # -transport=auto: its usage line names 'auto'.
    if printf '%s\n' "$_daemon_help" | sed -n '/^[[:space:]]*-transport/,/^[[:space:]]*-[a-z]/p' | grep -q "'auto'"; then
        DAEMON_HAS_AUTO=true
    fi
fi
if printf '%s\n' "$_daemon_help" | grep -qE '^[[:space:]]+-proxy([[:space:]]|$)'; then
    DAEMON_HAS_PROXY=true
fi
DAEMON_HAS_PROXY_CMD=false
if printf '%s\n' "$_daemon_help" | grep -qE '^[[:space:]]+-proxy-cmd([[:space:]]|$)'; then
    DAEMON_HAS_PROXY_CMD=true
fi

# --- Transport: auto, udp or compat ---
#
# auto is never saved in config.json. It is already the default wherever
# this install starts the daemon — `pilotctl daemon start` asks a daemon
# that supports it for auto, and the service units below set
# PILOT_TRANSPORT_DEFAULT=auto — while a pilot-daemon that predates auto
# (reinstalled with --version, or `pilotctl update --pin`) refuses to start
# with "transport":"auto" in config.json. udp and compat are saved.
TRANSPORT_TO_SAVE=""
TRANSPORT_CLEAR=false
case "$TRANSPORT" in
    udp|compat)
        TRANSPORT_TO_SAVE="$TRANSPORT" ;;
    auto)
        if [ "$DAEMON_HAS_AUTO" = true ]; then
            if [ -n "$CONFIG_TRANSPORT" ]; then TRANSPORT_CLEAR=true; fi
        else
            echo "  Note: this pilot-daemon (${TAG:-source}) predates -transport=auto; it keeps its default (udp)."
        fi ;;
esac
if [ "$CONFIG_TRANSPORT" = "auto" ] && [ "$DAEMON_HAS_AUTO" != true ] && [ -z "$TRANSPORT_TO_SAVE" ]; then
    # Downgrade: this daemon would exit with "invalid -transport auto".
    TRANSPORT_TO_SAVE="udp"
    echo "  Note: this pilot-daemon (${TAG:-source}) predates -transport=auto, which config.json"
    echo "        selects; switching it to udp (the daemon's default) so the daemon still starts."
fi

# What the daemon will run: the saved transport, else auto where the
# daemon supports it, else its default (udp).
if [ -n "$TRANSPORT_TO_SAVE" ]; then
    EFFECTIVE_TRANSPORT="$TRANSPORT_TO_SAVE"
elif [ "$TRANSPORT_CLEAR" != true ] && [ -n "$CONFIG_TRANSPORT" ] && [ "$CONFIG_TRANSPORT" != "auto" ]; then
    EFFECTIVE_TRANSPORT="$CONFIG_TRANSPORT"
elif [ "$DAEMON_HAS_AUTO" = true ]; then
    EFFECTIVE_TRANSPORT="auto"
else
    EFFECTIVE_TRANSPORT="udp"
fi

# pilotctl releases before `daemon start --transport` pass config.json's
# registry (else the raw-TCP default) to the daemon verbatim, and a daemon
# given the raw-TCP registry explicitly stays on it even in compat mode.
# Probed only for compat, and only with a daemon that has -transport (v1.11+):
# every pilotctl since v1.10 prints help for `daemon start --help` instead of
# starting a daemon.
PILOTCTL_HAS_TRANSPORT=false
if [ "$EFFECTIVE_TRANSPORT" = "compat" ] && [ "$DAEMON_HAS_TRANSPORT" = true ] \
   && "$BIN_DIR/pilotctl" daemon start --help 2>&1 | grep -q -- '--transport'; then
    PILOTCTL_HAS_TRANSPORT=true
fi

# The stock raw-TCP registry (34.71.57.205:9000) and UDP beacon are left out
# of what this installer writes when the node runs compat, or auto behind a
# proxy: the daemon then applies the endpoints that fit the transport it
# runs (registry.pilotprotocol.network:443 over TLS in compat mode or through
# a proxy), and an address that a 443-only network or HTTPS proxy never
# carries is not pinned anywhere. Custom PILOT_REGISTRY / PILOT_BEACON values
# are always kept.
STOCK_ENDPOINTS=true
if [ "$DAEMON_HAS_TRANSPORT" = true ]; then
    case "$EFFECTIVE_TRANSPORT" in
        compat) STOCK_ENDPOINTS=false ;;
        auto) if [ -n "$PILOT_PROXY_URL" ]; then STOCK_ENDPOINTS=false; fi ;;
    esac
fi

# --- Fresh install: write config ---
#
# config.json is written ONLY when there isn't one already. A re-run must never
# clobber registry/beacon/consent settings the operator edited by hand.
#
# The UPDATING check alone did not deliver that promise: UPDATING is derived
# purely from `[ -x "$BIN_DIR/pilotctl" ]`, i.e. whether the BINARY exists. A
# host with a hand-edited ~/.pilot/config.json but no binary — binaries removed
# for a clean reinstall, config restored from backup, or a config pre-seeded
# before first install — took the "fresh install" branch and had its config
# silently overwritten.
#
# That also made consent settings impossible to set BEFORE first start:
# pre-seeding {"consent":{...}} or {"skill_inject":{"mode":"disabled"}} was
# erased by this write, and the erase happened before the first skills pass
# further below. Guarding on the file itself makes the documented opt-outs
# reachable at install time instead of only after the fact. Defaults are
# unchanged — a host with no config still gets the standard one (without the
# stock endpoints in compat mode or behind a proxy, see STOCK_ENDPOINTS).
if [ "$UPDATING" != true ] && [ ! -f "$PILOT_DIR/config.json" ]; then
    CONF_REGISTRY="$REGISTRY"
    CONF_BEACON="$BEACON"
    if [ "$STOCK_ENDPOINTS" != true ]; then
        if [ "$REGISTRY" = "$DEFAULT_REGISTRY" ]; then
            CONF_REGISTRY=""
            # A pilotctl that predates --transport would pass the raw
            # default instead: name the compat TLS registry explicitly.
            if [ "$EFFECTIVE_TRANSPORT" = "compat" ] && [ "$PILOTCTL_HAS_TRANSPORT" != true ]; then
                CONF_REGISTRY="$COMPAT_REGISTRY"
            fi
        fi
        if [ "$BEACON" = "$DEFAULT_BEACON" ]; then CONF_BEACON=""; fi
    fi
    CONF_NET=""
    if [ -n "$CONF_REGISTRY" ]; then
        CONF_NET="${CONF_NET}  \"registry\": \"${CONF_REGISTRY}\",
"
    fi
    if [ -n "$CONF_BEACON" ]; then
        CONF_NET="${CONF_NET}  \"beacon\": \"${CONF_BEACON}\",
"
    fi
    cat > "$PILOT_DIR/config.json" <<CONF
{
${CONF_NET}  "socket": "/tmp/pilot.sock",
  "encrypt": true,
  "identity": "${PILOT_DIR}/identity.json",
  "email": "${EMAIL}"
}
CONF
    echo "Config written to ${PILOT_DIR}/config.json"
fi

if [ -n "$TRANSPORT_TO_SAVE" ]; then
    if pilot_config_set "transport=$TRANSPORT_TO_SAVE"; then
        echo "Transport set to ${TRANSPORT_TO_SAVE} in ${PILOT_DIR}/config.json"
    else
        echo "  Note: could not save transport=${TRANSPORT_TO_SAVE} — run: pilotctl config --set transport=${TRANSPORT_TO_SAVE}"
    fi
elif [ "$TRANSPORT_CLEAR" = true ]; then
    if pilot_config_set "transport="; then
        echo "Transport: auto (the default; removed \"transport\" from ${PILOT_DIR}/config.json)"
    fi
fi

# --- Rotating proxy credentials: proxy_cmd ---
#
# A long-running daemon keeps its launch-time proxy credentials; where they
# rotate (Meta Muse: every few minutes) its new connections start failing
# with 407. proxy_cmd (see PROXY_REFRESH_CMD above) makes the daemon re-read
# the proxy URL every 60s and on a 407. Only the command is stored — never a
# proxy URL or its credentials. $PILOT_PROXY_CMD is saved as given; the
# sandbox default is saved only where none is saved yet. A daemon that
# predates -proxy-cmd ignores the key until it is upgraded.
PROXY_CMD_TO_SAVE=""
if [ -n "${PILOT_PROXY_CMD:-}" ]; then
    PROXY_CMD_TO_SAVE="$PILOT_PROXY_CMD"
elif [ "$PROXY_REFRESH_CMD" = "$SANDBOX_PROXY_CMD" ] \
     && ! grep -q '"proxy_cmd"' "$PILOT_DIR/config.json" 2>/dev/null; then
    PROXY_CMD_TO_SAVE="$SANDBOX_PROXY_CMD"
fi
if [ -n "$PROXY_CMD_TO_SAVE" ]; then
    if ! pilot_config_set "proxy_cmd=$PROXY_CMD_TO_SAVE"; then
        echo "  Note: could not save proxy_cmd in ${PILOT_DIR}/config.json"
    elif [ "$DAEMON_HAS_PROXY_CMD" = true ]; then
        echo "Proxy credentials: re-read by the daemon via proxy_cmd (${PILOT_DIR}/config.json stores the command, not the credentials)"
    else
        echo "Proxy credentials: proxy_cmd saved in ${PILOT_DIR}/config.json (the command, not the credentials)."
        echo "  This pilot-daemon (${TAG:-source}) predates -proxy-cmd and ignores it until upgraded;"
        echo "  until then, if the proxy rotates its credentials, restart the daemon from a fresh shell."
    fi
fi
PROXY_CMD_SAVED=false
if grep -q '"proxy_cmd"' "$PILOT_DIR/config.json" 2>/dev/null; then
    PROXY_CMD_SAVED=true
fi

# --- Registry for the transport ---
#
# No "proxy" key is written: the daemon's default, auto, already uses
# $HTTPS_PROXY / $ALL_PROXY where it needs a proxy, and a saved "auto" would
# only get in the way of a proxy passed later with --proxy or $PILOT_PROXY.
CONFIG_REGISTRY=$(sed -n 's/.*"registry"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$PILOT_DIR/config.json" 2>/dev/null | head -n 1)
if [ "$EFFECTIVE_TRANSPORT" = "compat" ]; then
    if [ "$DAEMON_HAS_TRANSPORT" != true ]; then
        echo ""
        echo "  WARNING: this pilot-daemon (${TAG:-source}) predates compat mode (-transport)."
        echo "           It will keep using UDP. Re-run without --version to get the latest release."
    fi

    # A pilotctl that predates --transport passes config.json's registry,
    # else the raw-TCP default, to the daemon verbatim: point it at the
    # compat TLS registry — only when the file holds the stock default or
    # no registry at all.
    if [ "$DAEMON_HAS_TRANSPORT" = true ] && [ "$PILOTCTL_HAS_TRANSPORT" != true ] \
       && { [ "$CONFIG_REGISTRY" = "$DEFAULT_REGISTRY" ] || [ -z "$CONFIG_REGISTRY" ]; }; then
        if pilot_config_set "registry=${COMPAT_REGISTRY}"; then
            echo "  Registry set to ${COMPAT_REGISTRY} for compat mode (this pilotctl"
            echo "  always passes config.json's registry to the daemon). Switching back to"
            echo "  UDP later: re-run this installer with --transport udp"
        fi
    fi
elif [ "$CONFIG_REGISTRY" = "$COMPAT_REGISTRY" ]; then
    # Leaving compat after an install that pointed the registry at the
    # compat TLS host: a udp daemon needs the raw-TCP registry back.
    if pilot_config_set "registry=${DEFAULT_REGISTRY}"; then
        echo "  Registry restored to ${DEFAULT_REGISTRY} for transport ${EFFECTIVE_TRANSPORT}"
    fi
fi

# A proxy in the environment that this daemon cannot use: say so, and where
# the proxy is the only way out, point at the recipe that works with it.
PROXY_UNSUPPORTED=false
if [ -n "$PILOT_PROXY_URL" ] && [ "$DAEMON_HAS_PROXY" != true ]; then
    PROXY_UNSUPPORTED=true
    echo ""
    echo "  WARNING: a proxy is set ($(redact_proxy "$PILOT_PROXY_URL")), but this pilot-daemon"
    echo "           (${TAG:-source}) cannot use one. If the proxy is this host's only way"
    echo "           out (UDP blocked, e.g. an agent sandbox), \`pilotctl daemon start\` will"
    echo "           not come online with this release. Use the pilot-sandbox recipe:"
    echo "           https://pilotprotocol.network/learn/install-pilot-skills-in-meta-muse"
fi

# Network flags for the service units. The transport itself comes from
# config.json, which the daemon reads, so `pilotctl config --set transport=`
# applies to the service too. Where the stock endpoints are left out (compat,
# or auto behind a proxy; see STOCK_ENDPOINTS) the daemon's built-in defaults
# apply — the same raw-TCP/UDP endpoints for udp, the TLS registry for
# compat (an older daemon given -registry explicitly stays pinned to a port
# no 443-only network or HTTPS proxy will carry); a custom PILOT_REGISTRY /
# PILOT_BEACON is kept.
if [ "$STOCK_ENDPOINTS" != true ]; then
    NET_FLAGS=""
    if [ "$REGISTRY" != "$DEFAULT_REGISTRY" ]; then NET_FLAGS="$NET_FLAGS -registry $REGISTRY"; fi
    if [ "$BEACON" != "$DEFAULT_BEACON" ]; then NET_FLAGS="$NET_FLAGS -beacon $BEACON"; fi
    NET_FLAGS="${NET_FLAGS# }"
else
    NET_FLAGS="-registry $REGISTRY -beacon $BEACON"
fi

# The service units ask for transport auto through PILOT_TRANSPORT_DEFAULT:
# it applies only when neither -transport, $PILOT_TRANSPORT nor config.json
# chooses, and a daemon that predates auto ignores it (a -transport auto
# flag would stop it from starting after a downgrade).
UNIT_ENV=""
PLIST_ENV=""
if [ "$DAEMON_HAS_AUTO" = true ]; then
    UNIT_ENV="
Environment=PILOT_TRANSPORT_DEFAULT=auto"
    PLIST_ENV="    <key>EnvironmentVariables</key>
    <dict>
        <key>PILOT_TRANSPORT_DEFAULT</key>
        <string>auto</string>
    </dict>
"
fi

# service_proxy_note UNIT — a service manager starts the daemon with its own
# environment, not this shell's, so an HTTPS_PROXY exported here never
# reaches it. config.json (0600, read by the daemon itself) does.
# This installer never writes the URL itself: with credentials in it, where
# to store them is the operator's call.
service_proxy_note() {
    if [ "$EFFECTIVE_TRANSPORT" != "udp" ] && [ -n "$PILOT_PROXY_URL" ] \
       && ! grep -q '"proxy"[[:space:]]*:[[:space:]]*"http' "$PILOT_DIR/config.json" 2>/dev/null; then
        echo "  Note: $1 does not inherit this shell's HTTPS_PROXY. For the service to use"
        case "$PILOT_PROXY_URL" in
            *@*)
                echo "        the proxy, save it in config.json (0600; this stores its credentials):"
                echo "          pilotctl config --set proxy='<your HTTPS_PROXY URL>'"
                echo "        or save a command that prints it: pilotctl config --set proxy_cmd='<command>'" ;;
            *)
                echo "        the proxy, save it in config.json:"
                echo "          pilotctl config --set proxy='${PILOT_PROXY_URL}'" ;;
        esac
    fi
}

# Enable background auto-updates by default (opt-out). The install output and
# the systemd/launchd units below promise the updater keeps binaries current;
# the pilot-updater treats a MISSING control file as "disabled", so without
# this a fresh node would run an updater that never applies anything. Written
# only when the file is absent so an operator who later runs `pilotctl update
# disable` is never silently re-enabled. Turn off any time with
# `pilotctl update disable`.
if [ "$PILOT_MANAGED_MODE" = "1" ]; then
    # Stable-channel updater builds do not yet carry the managed control
    # client. Pin this authority-selected runtime instead of allowing
    # a background downgrade to silently remove enforcement.
    printf '{\n  "enabled": false,\n  "reason": "managed-runtime-pinned-by-authority"\n}\n' > "$PILOT_DIR/auto-update.json"
    echo "Auto-updates pinned to the management authority runtime channel"
elif [ "$UPDATING" != true ] && [ ! -f "$PILOT_DIR/auto-update.json" ]; then
    printf '{\n  "enabled": true\n}\n' > "$PILOT_DIR/auto-update.json"
    echo "Auto-updates ENABLED (opt-out) — disable with: pilotctl update disable"
fi

# --- Set up system service ---
#
# The units are (re)generated on EVERY run, fresh install or upgrade. That is
# what makes re-running the installer a real repair path: a host whose unit was
# written by an older, buggy installer gets a correct one without uninstalling.

MANAGED_START_STYLE=""

if [ "$OS" = "linux" ] && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    if [ "$CAN_PRIV" = true ]; then
    echo "Setting up systemd service..."
    DAEMON_UNIT=/etc/systemd/system/pilot-daemon.service

    # Preserve operator flags baked into an existing unit when the matching env
    # var is not supplied on THIS run. Regenerating the unit must not silently
    # strip a -hostname or -public the operator set at first install.
    if [ -z "${PILOT_HOSTNAME:-}" ] && [ -f "$DAEMON_UNIT" ]; then
        PILOT_HOSTNAME=$(grep -o -- '-hostname [^ \\]*' "$DAEMON_UNIT" 2>/dev/null \
            | head -1 | cut -d' ' -f2)
        if [ -n "$PILOT_HOSTNAME" ]; then
            validate_safe "hostname (existing unit)" "$PILOT_HOSTNAME" "._-"
        fi
    fi
    if [ -z "${PILOT_PUBLIC:-}" ] && [ -f "$DAEMON_UNIT" ] \
       && grep -q -- '-public' "$DAEMON_UNIT" 2>/dev/null; then
        PILOT_PUBLIC=1
    fi

    # EVERY optional argument is emitted as a complete flag+value pair or not at
    # all. Emitting a bare `-email` with an empty value made Go's flag parser
    # swallow the NEXT flag as the email value, so the daemon died on
    # `invalid email: email address must contain @` every 5s forever and
    # `-encrypt` was silently consumed. An omitted -email is well-defined: the
    # daemon falls back to ~/.pilot/account.json and, failing that, synthesises
    # <fingerprint>@nodes.pilotprotocol.network.
    EMAIL_FLAG=""
    if [ -n "$EMAIL" ]; then
        EMAIL_FLAG="-email $EMAIL"
    fi
    HOSTNAME_FLAG=""
    if [ -n "${PILOT_HOSTNAME:-}" ]; then
        HOSTNAME_FLAG="-hostname $PILOT_HOSTNAME"
    fi
    PUBLIC_FLAG=""
    if [ -n "${PILOT_PUBLIC:-}" ]; then
        PUBLIC_FLAG="-public"
    fi
    # shellcheck disable=SC2086 # $PILOT_SUDO is "" or "sudo" — intentional split
    $PILOT_SUDO tee "$DAEMON_UNIT" >/dev/null <<SVC
[Unit]
Description=Pilot Protocol Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$(whoami)${UNIT_ENV}
ExecStart=${BIN_DIR}/pilot-daemon \\
  ${NET_FLAGS} \\
  -listen :4000 \\
  -socket /tmp/pilot.sock \\
  -identity ${PILOT_DIR}/identity.json \\
  -encrypt ${EMAIL_FLAG} ${HOSTNAME_FLAG} ${PUBLIC_FLAG}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SVC
    # Auto-updater service
    if [ "$PILOT_MANAGED_MODE" != "1" ] && [ -f "$BIN_DIR/pilot-updater" ]; then
    # shellcheck disable=SC2086
    $PILOT_SUDO tee /etc/systemd/system/pilot-updater.service >/dev/null <<USVC
[Unit]
Description=Pilot Protocol Auto-Updater
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$(whoami)
ExecStart=${BIN_DIR}/pilot-updater \\
  -install-dir ${BIN_DIR}
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
USVC
    fi

    # daemon-reload can fail on hosts where systemctl exists but systemd is
    # not PID 1 (older containers, chroots). Never let it abort the install
    # under `set -e` — the binaries and skill injection still matter.
    # shellcheck disable=SC2086
    $PILOT_SUDO systemctl daemon-reload || true
    if [ "$PILOT_MANAGED_MODE" = "1" ]; then
        # A stale stable-channel updater could replace the authority-pinned
        # managed runtime with a build that lacks hosted control support.
        # shellcheck disable=SC2086
        $PILOT_SUDO systemctl disable --now pilot-updater 2>/dev/null || true
    fi
    echo "  Service: pilot-daemon.service"
    if [ "$PILOT_MANAGED_MODE" != "1" ] && [ -f "$BIN_DIR/pilot-updater" ]; then
        echo "  Service: pilot-updater.service (auto-updates)"
    fi
    service_proxy_note "pilot-daemon.service"

    # Auto-enable + start the updater so future releases land without
    # operator action. The unit file alone is not enough — without this,
    # fresh installs sit on whatever release shipped at install time and
    # never see security/perf fixes, while ~/.pilot/auto-update.json and
    # the consent block above both tell the operator auto-updates are ON.
    # `enable --now` is idempotent, so this is also what restarts the updater
    # we stopped above to swap its binary.
    # The daemon is left as opt-in on a FRESH install because it has
    # operator-tunable flags (-public, -hostname, registry overrides) that the
    # operator may want to set before first start; on a re-run anything that
    # was already running is restored below.
    if [ "$PILOT_MANAGED_MODE" != "1" ] && [ -f "$BIN_DIR/pilot-updater" ]; then
        # shellcheck disable=SC2086
        if $PILOT_SUDO systemctl enable --now pilot-updater; then
            echo "  Started: pilot-updater (auto-updates enabled)"
        else
            echo "  Note: could not enable pilot-updater via systemd (non-fatal)."
        fi
    fi

    # Restart whatever we stopped to swap binaries, now that the units are
    # regenerated and reloaded. A restart failure is reported, never fatal.
    # shellcheck disable=SC2086 # intentional word-split on the service list
    for _svc in $RESTART_SYSTEMD; do
        # shellcheck disable=SC2086
        if $PILOT_SUDO systemctl start "$_svc" 2>/dev/null; then
            echo "  Restarted: ${_svc}"
        else
            echo "  Note: could not restart ${_svc} — start it with: sudo systemctl start ${_svc}"
        fi
    done

    if [ "$PILOT_MANAGED_MODE" = "1" ] && [ "$PILOT_MANAGED_NO_START" != "1" ]; then
        # Managed onboarding promises a live signed check-in, so unlike an
        # ordinary local install it explicitly enables the daemon now.
        # shellcheck disable=SC2086
        $PILOT_SUDO systemctl enable --now pilot-daemon
        MANAGED_START_STYLE="systemd"
        echo "  Started: pilot-daemon (managed reporting enabled)"
    elif [ "$PILOT_MANAGED_MODE" != "1" ]; then
        case " $RESTART_SYSTEMD " in
            *" pilot-daemon "*) ;;
            *) echo "  Start daemon: sudo systemctl enable --now pilot-daemon" ;;
        esac
    fi
    else
    echo "  Skipped systemd setup (run as root or with passwordless sudo to enable)"
    if [ "$PILOT_MANAGED_MODE" != "1" ]; then
        echo "  Start the daemon without a service manager: pilotctl daemon start"
    fi
    fi
elif [ "$OS" = "linux" ]; then
    # systemd is not the init system here (container / WSL / CI runner /
    # hosted agent sandbox). There is no service to install — tell the agent
    # the portable start path instead of silently leaving it with no daemon.
    if [ "$PILOT_MANAGED_MODE" != "1" ]; then
        echo "No systemd detected (container / WSL / CI / sandbox) — start the daemon manually:"
        echo "  pilotctl daemon start"
        if [ "$PROXY_UNSUPPORTED" = true ]; then
            echo "  (proxy-only host: see the WARNING above)"
        elif [ "$EFFECTIVE_TRANSPORT" != "udp" ]; then
            echo "  (transport=${EFFECTIVE_TRANSPORT}; start it from a shell that has HTTPS_PROXY"
            echo "   set if this host reaches the internet only through a proxy)"
        fi
    fi
fi

if [ "$OS" = "darwin" ]; then
    PLIST_DIR="$HOME/Library/LaunchAgents"
    PLIST="$PLIST_DIR/network.pilotprotocol.pilot-daemon.plist"
    mkdir -p "$PLIST_DIR"

    # Preserve operator flags already present in an existing plist when the
    # matching env var is not supplied on THIS run — the plist is regenerated
    # on every run, and an upgrade must not silently strip them. In
    # ProgramArguments the value of a flag is the <string> immediately after it.
    if [ -z "${PILOT_HOSTNAME:-}" ] && [ -f "$PLIST" ]; then
        PILOT_HOSTNAME=$(awk '
            found { sub(/^[[:space:]]*<string>/, ""); sub(/<\/string>[[:space:]]*$/, ""); print; exit }
            index($0, "<string>-hostname</string>") { found = 1 }
        ' "$PLIST" 2>/dev/null)
        if [ -n "$PILOT_HOSTNAME" ]; then
            validate_safe "hostname (existing plist)" "$PILOT_HOSTNAME" "._-"
        fi
    fi
    if [ -z "${PILOT_PUBLIC:-}" ] && [ -f "$PLIST" ] \
       && grep -q '<string>-public</string>' "$PLIST" 2>/dev/null; then
        PILOT_PUBLIC=1
    fi

    # Same empty-argument hazard as the systemd unit: emit each optional
    # argument as a complete flag+value pair or not at all. An `-email` with an
    # empty <string> value passes a blank argv element to the daemon; omitting
    # it lets the daemon do the documented thing instead — fall back to
    # ~/.pilot/account.json, then synthesise a fingerprint identity.
    # One <string> per word of NET_FLAGS (host:port / flag names only —
    # validate_safe already rejected anything with spaces or markup).
    PLIST_NET_ARGS=""
    for _a in $NET_FLAGS; do
        PLIST_NET_ARGS="${PLIST_NET_ARGS}        <string>${_a}</string>
"
    done
    EXTRA_ARGS=""
    if [ -n "$EMAIL" ]; then
        EXTRA_ARGS="${EXTRA_ARGS}        <string>-email</string>
        <string>${EMAIL}</string>
"
    fi
    if [ -n "${PILOT_HOSTNAME:-}" ]; then
        EXTRA_ARGS="${EXTRA_ARGS}        <string>-hostname</string>
        <string>${PILOT_HOSTNAME}</string>
"
    fi
    if [ -n "${PILOT_PUBLIC:-}" ]; then
        EXTRA_ARGS="${EXTRA_ARGS}        <string>-public</string>
"
    fi
    cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>network.pilotprotocol.pilot-daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>${BIN_DIR}/pilot-daemon</string>
${PLIST_NET_ARGS}        <string>-listen</string>
        <string>:4000</string>
        <string>-socket</string>
        <string>/tmp/pilot.sock</string>
        <string>-identity</string>
        <string>${PILOT_DIR}/identity.json</string>
        <string>-encrypt</string>
${EXTRA_ARGS}    </array>
${PLIST_ENV}    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>${PILOT_DIR}/daemon.log</string>
    <key>StandardErrorPath</key>
    <string>${PILOT_DIR}/daemon.log</string>
</dict>
</plist>
PLIST
    # Auto-updater LaunchAgent
    if [ "$PILOT_MANAGED_MODE" != "1" ] && [ -f "$BIN_DIR/pilot-updater" ]; then
        UPLIST="$PLIST_DIR/network.pilotprotocol.pilot-updater.plist"
        cat > "$UPLIST" <<UPLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>network.pilotprotocol.pilot-updater</string>
    <key>ProgramArguments</key>
    <array>
        <string>${BIN_DIR}/pilot-updater</string>
        <string>-install-dir</string>
        <string>${BIN_DIR}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${PILOT_DIR}/updater.log</string>
    <key>StandardErrorPath</key>
    <string>${PILOT_DIR}/updater.log</string>
</dict>
</plist>
UPLIST
    fi

    echo "  Service: network.pilotprotocol.pilot-daemon"
    if [ "$PILOT_MANAGED_MODE" = "1" ]; then
        _managed_updater_plist="$PLIST_DIR/network.pilotprotocol.pilot-updater.plist"
        if [ -f "$_managed_updater_plist" ]; then
            launchctl unload -w "$_managed_updater_plist" 2>/dev/null || true
        fi
    fi
    if [ "$PILOT_MANAGED_MODE" != "1" ] && [ -f "$BIN_DIR/pilot-updater" ]; then
        echo "  Service: network.pilotprotocol.pilot-updater (auto-updates)"
    fi
    service_proxy_note "the launchd agent"

    # Auto-load the updater LaunchAgent so future releases land without
    # operator action. Without this, install.sh writes the plist but leaves
    # it cold — fresh installs sit on whatever release shipped at install
    # time and never see security/perf fixes. Symmetric with the Linux
    # `systemctl enable --now pilot-updater` branch above.
    #
    # unload-then-load makes re-running install.sh (the upgrade path)
    # idempotent: any stale running agent is replaced cleanly. -w persists
    # the load across reboots. The daemon is left as opt-in for the same
    # reason as the Linux branch.
    if [ "$PILOT_MANAGED_MODE" != "1" ] && [ -f "$BIN_DIR/pilot-updater" ] && [ -f "$UPLIST" ]; then
        launchctl unload "$UPLIST" 2>/dev/null || true
        launchctl load -w "$UPLIST"
        echo "  Started: pilot-updater (auto-updates enabled)"
    fi

    # Reload the daemon agent if it was loaded before we swapped its binary,
    # so it actually picks up the new image and the regenerated plist.
    # shellcheck disable=SC2086 # intentional word-split on the label list
    for _label in $RESTART_LAUNCHD; do
        [ "$_label" = "network.pilotprotocol.pilot-updater" ] && continue
        _lp="$PLIST_DIR/${_label}.plist"
        if [ -f "$_lp" ]; then
            launchctl unload "$_lp" 2>/dev/null || true
            if launchctl load -w "$_lp" 2>/dev/null; then
                echo "  Reloaded: ${_label}"
            else
                echo "  Note: could not reload ${_label} — run: launchctl load -w ${_lp}"
            fi
        fi
    done

    if [ "$PILOT_MANAGED_MODE" != "1" ]; then
        case " $RESTART_LAUNCHD " in
            *" network.pilotprotocol.pilot-daemon "*) ;;
            *)
                echo "  Start daemon: launchctl load -w $PLIST"
                echo "  Stop daemon:  launchctl unload $PLIST"
                ;;
        esac
    fi
fi

# A managed Connect Agent run is complete only when the newly adopted core
# daemon is locally responsive. The management console independently waits for
# the signed remote report, so this check cannot forge onboarding success.
if [ "$PILOT_MANAGED_MODE" = "1" ]; then
    if [ "$PILOT_MANAGED_NO_START" = "1" ]; then
        echo "Managed runtime adopted but not started (--no-start)."
    elif [ "$MANAGED_START_STYLE" = "systemd" ]; then
        _managed_wait=0
        until "$BIN_DIR/pilotctl" daemon status --check >/dev/null 2>&1; do
            _managed_wait=$((_managed_wait + 1))
            if [ "$_managed_wait" -ge 30 ]; then
                echo "Error: the managed daemon did not become ready under systemd." >&2
                exit 1
            fi
            sleep 1
        done
    else
        # Portable and launchd installs need an explicit restart so a daemon
        # that was already running cannot keep the pre-adoption configuration.
        if "$BIN_DIR/pilotctl" daemon status --check >/dev/null 2>&1; then
            "$BIN_DIR/pilotctl" daemon stop >/dev/null
        fi
        "$BIN_DIR/pilotctl" daemon start --wait 30s >/dev/null
        "$BIN_DIR/pilotctl" daemon status --check >/dev/null
    fi
fi

# --- Add to PATH ---
#
# Writing to ONE rc file picked from $SHELL is not enough. The file that a
# given shell reads depends on how it was started:
#   ~/.profile       login sh/bash — sets PATH once for the whole session, so
#                    every child process (including `bash -c`) inherits it
#   ~/.bash_profile  bash login shells; when present it SHADOWS ~/.profile,
#                    so we must append there too (but never create it — doing
#                    so would newly shadow a working ~/.profile)
#   ~/.bashrc        interactive bash only (Debian/Ubuntu's stock copy
#                    `return`s immediately for non-interactive shells)
#   ~/.zshenv        zsh — read for EVERY invocation, including `zsh -c`
#   ~/.zshrc         interactive zsh
# Together with the /usr/local/bin symlink above this covers login shells,
# interactive shells and non-interactive shells.

PATH_FILES=""

pilot_add_path() {
    _ap_rc="$1"
    if [ -e "$_ap_rc" ] && grep -qF "$BIN_DIR" "$_ap_rc" 2>/dev/null; then
        return 0
    fi
    {
        echo ""
        echo "# Pilot Protocol"
        echo "export PATH=\"${BIN_DIR}:\$PATH\""
    } >> "$_ap_rc" 2>/dev/null || return 1
    PATH_FILES="${PATH_FILES}${PATH_FILES:+, }${_ap_rc}"
    return 0
}

pilot_add_path "$HOME/.profile" || true
if [ -f "$HOME/.bash_profile" ]; then
    pilot_add_path "$HOME/.bash_profile" || true
fi
pilot_add_path "$HOME/.bashrc" || true
if command -v zsh >/dev/null 2>&1 || [ -f "$HOME/.zshrc" ] || [ -f "$HOME/.zshenv" ]; then
    # .zshenv is the only zsh file read by `zsh -c` (non-interactive).
    pilot_add_path "$HOME/.zshenv" || true
    if [ -f "$HOME/.zshrc" ]; then
        pilot_add_path "$HOME/.zshrc" || true
    fi
fi

if [ -n "$PATH_FILES" ]; then
    echo "  Added ${BIN_DIR} to PATH in: ${PATH_FILES}"
fi

# If we could not put a binary on the default system PATH, say so loudly and
# give the exact command — otherwise `bash -c 'pilotctl version'` keeps
# failing for this user until they start a new login shell.
if [ "$LINK_OK" != true ]; then
    echo ""
    echo "  NOTE: could not write ${LINK_DIR} (not writable, and no passwordless sudo)."
    echo "        Shell profiles were updated, but non-interactive shells"
    echo "        (bash -c '...', cron, CI, AI agents shelling out) will not see"
    echo "        pilotctl until you start a new LOGIN shell. To fix it now:"
    echo ""
    echo "          sudo ln -sf ${BIN_DIR}/pilotctl     ${LINK_DIR}/pilotctl"
    echo "          sudo ln -sf ${BIN_DIR}/pilot-daemon ${LINK_DIR}/pilot-daemon"
    echo ""
fi

# --- Verify ---

# Write version file for the auto-updater
[ -n "$TAG" ] && echo "$TAG" > "$BIN_DIR/.pilot-version"

if [ "$PILOT_MANAGED_MODE" = "1" ]; then
    echo ""
    echo "Managed Pilot node ready:"
    echo "  Runtime:    ${TAG}"
    echo "  Authority:  ${PILOT_MANAGEMENT_URL}"
    echo "  Control:    ${MANAGED_CONTROL_PATH}"
    if [ "$MANAGED_ADOPTED" = "1" ]; then
        echo "  Enrollment: claimed once and installed"
    else
        echo "  Enrollment: existing managed identity preserved"
    fi
    if [ "$PILOT_MANAGED_NO_START" = "1" ]; then
        echo "  Daemon:     not started (--no-start)"
    else
        echo "  Daemon:     running; signed fleet reporting enabled"
    fi
    echo "  MCP:        not installed (optional, separate product)"
    echo ""
    echo "Harness interception is a separate optional attachment step."
    echo "The management console will verify the node's signed report before"
    echo "it marks onboarding complete."
    exit 0
fi

# --- Upgrade: short summary, skip the first-run onboarding text ---
#
# Everything above this point (binary swap, unit/plist regeneration, service
# restart, PATH) runs on BOTH paths, so a re-run is a complete repair: it is
# what gets a host off a stale pinned version AND off a unit written by an
# older installer. Only the first-run onboarding is skipped.
if [ "$UPDATING" = true ]; then
    echo ""
    echo "Updated to ${TAG:-source}:"
    echo "  pilot-daemon    ${BIN_DIR}/pilot-daemon"
    echo "  pilotctl         ${BIN_DIR}/pilotctl"
    [ -f "$BIN_DIR/pilot-gateway" ] && echo "  pilot-gateway    ${BIN_DIR}/pilot-gateway"
    [ -f "$BIN_DIR/pilot-updater" ] && echo "  pilot-updater    ${BIN_DIR}/pilot-updater"
    echo ""
    if [ -z "$RESTART_SYSTEMD" ] && [ -z "$RESTART_LAUNCHD" ]; then
        echo "No managed service was running. If you run the daemon yourself,"
        echo "restart it to pick up the new version:"
        echo "  pilotctl daemon stop && pilotctl daemon start"
        echo ""
    fi
    exit 0
fi

echo ""
echo "Installed:"
echo "  pilot-daemon    ${BIN_DIR}/pilot-daemon"
echo "  pilotctl         ${BIN_DIR}/pilotctl"
[ -f "$BIN_DIR/pilot-gateway" ] && echo "  pilot-gateway    ${BIN_DIR}/pilot-gateway"
[ -f "$BIN_DIR/pilot-updater" ] && echo "  pilot-updater    ${BIN_DIR}/pilot-updater (auto-updates in background)"
echo ""
echo "Config: ${PILOT_DIR}/config.json"
case "$EFFECTIVE_TRANSPORT" in
    compat)
        _summary_registry="$COMPAT_REGISTRY"
        if [ "$REGISTRY" != "$DEFAULT_REGISTRY" ]; then _summary_registry="$REGISTRY"; fi
        echo "  Transport: compat (registry ${_summary_registry} over TLS, beacon over WSS)" ;;
    auto)
        echo "  Transport: auto (UDP when it works, else compat over TCP 443)"
        if [ "$STOCK_ENDPOINTS" = true ]; then
            echo "  Registry: ${REGISTRY}"
            echo "  Beacon:   ${BEACON}"
        else
            echo "  Registry: picked by the daemon for its transport (${COMPAT_REGISTRY} over TLS via the proxy)"
        fi ;;
    *)
        echo "  Registry: ${REGISTRY}"
        echo "  Beacon:   ${BEACON}" ;;
esac
if [ "$EFFECTIVE_TRANSPORT" != "udp" ] && [ -n "$PILOT_PROXY_URL" ] && [ "$DAEMON_HAS_PROXY" = true ]; then
    echo "  Proxy:    auto -> $(redact_proxy "$PILOT_PROXY_URL") (from environment)"
    if [ "$PROXY_CMD_SAVED" = true ] && [ "$DAEMON_HAS_PROXY_CMD" = true ]; then
        echo "            credentials re-read by the daemon (proxy_cmd): rotation needs no restart"
    fi
fi
echo "  Socket:   /tmp/pilot.sock"
echo "  Identity: ${PILOT_DIR}/identity.json"
if [ -n "$EMAIL" ]; then
    echo "  Email:    ${EMAIL}"
else
    echo "  Email:    not set (the daemon uses <key fingerprint>@nodes.pilotprotocol.network;"
    echo "            set a real one any time: pilotctl set-email <addr>)"
fi
echo ""
echo "============================================"
echo "  GET STARTED"
echo ""
echo "  0) Put pilotctl on your PATH and bring the node online."
echo "     ------------------------------------------------------------------"
echo "     export PATH=\"${BIN_DIR}:\$PATH\"   # only needed in THIS shell, before you open a new one"
cat <<'PILOT_GET_STARTED'
     pilotctl daemon start --hostname my-agent         # blocks until registered; email already saved
     pilotctl daemon status                            # confirm it's running
     pilotctl info                                      # node ID, address, peer count, uptime

     Ask with --wait: the reply comes back in the send's own output. If
     it fails or times out there is no reply to read — do not substitute
     the newest inbox message, which may answer an older question:
     ------------------------------------------------------------------
     pilotctl send-message <agent> --data '<cmd>' --wait
     pilotctl --json send-message <agent> --data '<cmd>' --wait   # reply in .data.reply

     # Every reply is also kept in the inbox:
     pilotctl inbox                       # 10 newest, one-line previews
     pilotctl inbox --from pilot-mom --limit 3


  1) MOM (pilot-mom) — your default for anything LIVE or fresh.
     Describe the whole task in plain English; it picks the specialist
     agents + filters and returns a validated, ready-to-run plan.
     ------------------------------------------------------------------
     pilotctl send-message pilot-mom --data 'current weather and air quality for Berlin' --wait

     # More examples — hand it the whole sentence, don't hunt for agents yourself:
     pilotctl send-message pilot-mom --data 'summarize this season F1 drivers' --wait
     pilotctl send-message pilot-mom --data 'latest CVEs for nginx' --wait
     pilotctl send-message pilot-mom --data "what's BTC at right now in USD" --wait


  2) DISCOVER SERVICE AGENTS — when you already know the specialist you want.
     list-agents is the phonebook. Search is LITERAL token match, so use
     short, single-word keywords (bitcoin, weather, nba, joke, iss).
     Service agents auto-approve — no handshake required.
     ------------------------------------------------------------------
     # Browse the whole live catalogue:
     pilotctl send-message list-agents --data '/data' --wait

     # Search by keyword:
     pilotctl send-message list-agents --data '/data {"search":"bitcoin","limit":10}' --wait

     # Learn a specialist's query schema, then query it with filters:
     pilotctl send-message <agent-name> --data '/help' --wait
     pilotctl send-message <agent-name> --data '/data {"<filter>":"<value>"}' --wait



  3) APP STORE — install a LOCAL capability, then call it (JSON in → JSON out).
     Use this to *do* something (run SQL, sandbox code, drive a browser,
     enrich a contact, get a phone number) rather than look up fresh data.
     ------------------------------------------------------------------
     # Browse — one line per app; the catalogue is your router:
     pilotctl appstore catalogue

     # See an app's full details (methods, source, permissions, pricing):
     pilotctl appstore view io.pilot.sqlite

     # Install it once (daemon auto-spawns it; re-run `list` if state != ready).
     # Do not add --force routinely: it reinstalls over the app and can
     # delete its saved state (keys).
     pilotctl appstore install io.pilot.sqlite
     pilotctl appstore list

     # ALWAYS call <app>.help first — lists every method, its params,
     # a latency class (fast <1s / med 1-5s / slow 5-30s), and cost:
     pilotctl appstore call io.pilot.sqlite sqlite.help '{}'

     # Then do the work — JSON in, JSON on stdout:
     pilotctl appstore call io.pilot.sqlite sqlite.query '{"sql":"select 1"}'

     # A few concrete capability examples (install first, then call):
     pilotctl appstore install io.pilot.smol
     pilotctl appstore call io.pilot.smol smol.push '{"image":"alpine","net":true}'

     pilotctl appstore install io.pilot.bowmark
     pilotctl appstore call io.pilot.bowmark bowmark.ask '{"site":"amazon.com","task":"search for a product"}'

     pilotctl appstore install io.pilot.orthogonal
     pilotctl appstore call io.pilot.orthogonal orthogonal.search '{"prompt":"work email for a person given name + company"}'

     Cost: most apps run locally and are free. A few (orthogonal, sixtyfour,
     agentphone, cloud smol) are metered against a per-user $5 budget —
     <app>.help and `view` show the price, and discovery calls are free, so
     check before the one call that spends.


  4) PEERS & TRUST — only for peer nodes (other AIs / human-run nodes).
     Service agents and apps need NO handshake; this is just the p2p half.
     ------------------------------------------------------------------
     pilotctl handshake <hostname|node_id|address> "<reason>"   # request trust
     pilotctl pending                                            # incoming requests waiting on you
     pilotctl approve <node_id>                                  # accept one
     pilotctl trust                                              # confirm mutual trust
     pilotctl send-message <peer> --data '<message>'            # talk, once trust is mutual
     pilotctl send-file <peer> /path/to/file.tar.gz            # exchange artifacts

  Full operator manual & task→agent/app maps: the pilotctl skill
  (`pilotctl skills` lists where it is installed, e.g.
  ~/.claude/skills/pilotctl/SKILL.md).
============================================
PILOT_GET_STARTED
echo ""
# pilot-gateway no longer ships in release tarballs (extracted to the
# sibling pilot-protocol/gateway repo) — only show the bridge hint when
# the binary actually exists on this host.
if [ -f "$BIN_DIR/pilot-gateway" ]; then
    echo "Bridge IP traffic (requires root for ports < 1024):"
    echo ""
    echo "  sudo ${BIN_DIR}/pilotctl extras gateway start --ports 80,3000 <pilot-addr>"
    echo "  curl http://10.4.0.1:3000/status"
    echo ""
fi
echo "Agent skill auto-injection:"
echo ""
echo "  The daemon scans every 15 minutes and injects the Pilot Protocol"
echo "  skill into installed agent tools. Triggering a first pass right now"
echo "  so your agents know about Pilot before the daemon is even started:"
echo ""
# pilotctl fetches the skills through this process's proxy settings: hand it
# the current credentials if they rotated since the downloads.
proxy_refresh || true
if "${BIN_DIR}/pilotctl" skills check 2>&1 | sed 's/^/    /'; then
    :
else
    echo "    (skills check failed — non-fatal; will re-attempt on daemon start)"
fi
echo ""
echo "  Per-tool target paths:"
echo "    Claude Code   ~/.claude/skills/pilotctl/SKILL.md"
echo "                  + heartbeat ref in ~/.claude/CLAUDE.md"
echo "    OpenClaw      ~/.openclaw/skills/pilotctl/SKILL.md"
echo "                  + heartbeat ref in ~/.openclaw/workspace/AGENTS.md"
echo "    PicoClaw      ~/.picoclaw/workspace/skills/pilotctl/SKILL.md"
echo "                  + heartbeat ref in ~/.picoclaw/workspace/HEARTBEAT.md"
echo "    OpenHands     ~/.openhands/microagents/pilotctl.md (self-heartbeat)"
echo "    Hermes        ~/.hermes/skills/pilotctl/SKILL.md"
echo "                  + heartbeat ref in ~/.hermes/SOUL.md"
echo "    Goose         ~/.config/goose/skills/pilotctl/SKILL.md"
echo "                  + heartbeat ref in ~/.config/goose/.goosehints"
echo ""
echo "  Inspect / force a refresh anytime:"
echo "    pilotctl skills           # status of every install path"
echo "    pilotctl skills check     # run one reconcile pass right now"
echo ""
echo "============================================"
echo "  CONSENT & PRIVACY"
echo ""
echo "  The following features are ON by default. Each can be disabled"
echo "  at any time — disabling does NOT affect core messaging or"
echo "  networking functionality."
echo ""
echo "  TELEMETRY (on by default)"
echo "  When you browse or install apps from the app store, we record"
echo "  the app ID and action (view / install). This helps app developers"
echo "  understand interest in their apps. No personal data or message"
echo "  contents are ever sent."
echo "  To disable: set consent.telemetry = false in config.json (below)."
echo ""
echo "  BROADCASTS (on by default)"
echo "  Pilot Protocol can send messages to your agent through the daemon"
echo "  to deliver updates or trigger coordinated actions across a network."
echo "  If disabled, broadcast messages are silently dropped and never"
echo "  reach your agent."
echo "  To disable: set consent.broadcasts = false in config.json (below)."
echo ""
echo "  REVIEWS (on by default)"
echo "  Occasionally, after using Pilot or installing an app, you may be"
echo "  prompted to leave a short review. It is entirely optional — press"
echo "  Enter to skip, or just use pilot again normally. Your rating and"
echo "  optional text are the only data sent."
echo "  To disable: set consent.reviews = false in config.json (below)."
echo ""
echo "  SKILL INJECTION (on by default, auto mode)"
echo "  Automatically installs the Pilot Protocol skill into supported"
echo "  agent toolchains (Claude Code, Cursor, OpenHands, etc.) so agents"
echo "  on this host can discover and call Pilot services. In AUTO mode"
echo "  (the default), a background reconcile pass refreshes the injected"
echo "  skills every 15 minutes. Switch to MANUAL to install once and"
echo "  refresh only when you run 'pilotctl update', or disable entirely:"
echo "    pilotctl skills set-mode auto      # always up to date"
echo "    pilotctl skills set-mode manual    # install once, update on upgrade"
echo "    pilotctl skills disable all        # remove skills, stop injection"
echo ""
echo "  AUTO-UPDATES (on by default)"
echo "  The pilot-updater service checks GitHub for new stable releases and"
echo "  installs them automatically. Every update is integrity-checked: the"
echo "  release checksums are verified against a GitHub SLSA provenance"
echo "  attestation (bound to the exact release tag) before anything is"
echo "  replaced — an unverifiable update is refused, not applied."
echo "    pilotctl update disable    # turn auto-updates off"
echo "    pilotctl update enable     # turn them back on"
echo "    pilotctl update status     # show current setting + version"
echo ""
echo "  To opt out of telemetry, broadcasts, or reviews, edit:"
echo "    ${PILOT_DIR}/config.json"
echo ""
echo "  Add or merge the following (valid JSON, no comments):"
echo "    {"
echo "      \"consent\": {"
echo "        \"telemetry\": false,"
echo "        \"broadcasts\": false,"
echo "        \"reviews\": false"
echo "      },"
echo "      \"skill_inject\": { \"mode\": \"disabled\" }"
echo "    }"
echo ""
echo "  Changes to config.json take effect on daemon restart."
echo ""
echo "  Full details: https://pilotprotocol.network/docs/consent"
echo ""
echo "============================================"
echo ""
