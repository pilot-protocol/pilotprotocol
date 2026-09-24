# pilotctl Reference

> **Auto-generated** from `pilotctl --help`. Do not edit by hand — CI regenerates
> on every PR via `scripts/gen-cli-reference.sh` and fails if the committed copy
> differs from a fresh `pilotctl --help` capture (PILOT-54).
>
> Source: [`cmd/pilotctl/main.go`](../cmd/pilotctl/main.go).

```text
pilotctl — Pilot Protocol CLI

Global flags:
  --json                        Output structured JSON (for agent/programmatic use)

Getting started:
  pilotctl quickstart             3-command getting-started flow

Bootstrap:
  pilotctl init [--registry <addr>] [--hostname <name>] [--beacon <addr>] [--socket <path>]
  pilotctl config [--set key=value]

Daemon lifecycle:
  pilotctl daemon start [--config <path>] [--registry <addr>] [--beacon <addr>] [--email <addr>] [--webhook <url>] [--trust-auto-approve]
  pilotctl daemon stop
  pilotctl daemon status

Registry commands:
  pilotctl register [listen_addr]
  pilotctl lookup <node_id>
  pilotctl rotate-key
  pilotctl set-public
  pilotctl set-private
  pilotctl deregister

Discovery commands:
  pilotctl find <hostname>
  pilotctl set-hostname <hostname>
  pilotctl clear-hostname
  (discovery tags are operator setup: pilotctl extras set-tags / clear-tags)

Communication commands:
  pilotctl connect <address|hostname> [port] [--message <msg>] [--timeout <dur>]
  pilotctl send <address|hostname> <port> --data <msg> [--timeout <dur>]
  pilotctl recv <port> [--count <n>] [--timeout <dur>]
  pilotctl send-file <address|hostname> <filepath> [--enterprise-control <path> --governed-resource <resource>]
  pilotctl send-message <address|hostname> --data <text> [--type text|json|binary] [--count <n>] [--reuse-conn] [--wait <dur>]
  pilotctl dgram <address|hostname> <port> --data <msg>
  pilotctl subscribe <address|hostname> <topic> [--count <n>] [--timeout <dur>]
  pilotctl publish <address|hostname> <topic> --data <message>

Trust commands:
  pilotctl handshake <node_id|hostname> [justification]
  pilotctl approve <node_id>
  pilotctl reject <node_id> [reason]
  pilotctl untrust <node_id>
  pilotctl pending
  pilotctl trust [--search <substr>]                  live trust state (peers you trust)
  pilotctl trusted list                               embedded directory of auto-approved service agents
  pilotctl prefer-direct <node_id|address|hostname>   prefer a direct tunnel over the relay (daemon v1.12+)

Identity & recovery:
  pilotctl verify [status]                            show this node's verified-address badge state
  pilotctl verify --provider <name>                   run a device-flow to get a verified-address badge
  pilotctl recovery <enroll|new-key|recover> ...      enroll / rotate / reclaim the address if the key is lost
  pilotctl review <pilot|app-id> [--rating <1-5>] [--text "..."]   rate Pilot or an installed app

Request signing (prove a request originates from this node):
  pilotctl sign-request --audience <a> (--body-file <f> | --body-hash <64hex> | --body '<string>')
  pilotctl verify-request --envelope '<canonical>' --signature '<b64>' [--standing] [--max-skew <secs>]

Management commands:
  pilotctl connections
  pilotctl disconnect <conn_id>

Mailbox:
  pilotctl received [--limit <n>] [--since <dur>] [--clear [--before <dur>]]
  pilotctl inbox [--clear]

Service Agents:
  pilotctl send-message list-agents --data "list all agents"

Agent tool discovery:
  pilotctl context
  pilotctl skills [status]            show where the daemon installs SKILL.md per detected agent tool
  pilotctl skills paths               print only the install paths (shell-friendly)
  pilotctl skills check               run one reconcile pass right now
  pilotctl skills enable|disable all  turn skill injection on/off (only 'all' is implemented)
  pilotctl skills set-mode auto|manual|disabled   persist the reconcile mode

App store (install + call local capability apps; full help: pilotctl appstore help):
  pilotctl appstore catalogue                         list apps available for one-command install
  pilotctl appstore view <id> [--all-changelog]       app detail page (description, methods, permissions)
  pilotctl appstore install <app-id> [--force]        install by catalogue ID (fetch + verify + extract)
  pilotctl appstore list                              list installed apps + their IPC methods
  pilotctl appstore call <id> <method> [json-args]    dispatch an IPC call into an app
  pilotctl appstore status|caps|audit|restart|uninstall <id>

Updates:
  pilotctl update [status|enable|disable] [--pin <tag>]   self-update (auto-update OFF by default)
  pilotctl updates [--count <n>] [--scope <scope>]        read the Pilot changelog feed

Operator / admin (run 'pilotctl extras' or 'pilotctl context' for the full list):
  pilotctl enterprise status|dashboard-url|policy|mandate|receipt --endpoint <URL> --tenant <tenant>  inspect or submit signed enterprise control state
  pilotctl extras <cmd>              network / managed / policy / member-tags / enterprise / low-level plumbing
  pilotctl extras gateway start|stop|map|unmap|list       IP gateway (requires root — creates loopback interface aliases)

Diagnostic commands:
  pilotctl info
  pilotctl health
  pilotctl peers [--search <query>]
  pilotctl ping <address|hostname> [--count <n>] [--timeout <dur>]
  pilotctl traceroute <address> [--timeout <dur>]
  pilotctl bench <address|hostname> [size_mb] [--timeout <dur>]
  pilotctl listen <port> [--count <n>] [--timeout <dur>]
  pilotctl broadcast <network_id> <message>

Environment:
  PILOT_REGISTRY     Registry address (default: 34.71.57.205:9000)
  PILOT_SOCKET       Daemon socket path (default: /tmp/pilot.sock)

Version:
  pilotctl version

Config file: ~/.pilot/config.json

Companion binaries:
  daemon start / start --foreground exec the separately-shipped
  pilot-daemon binary; gateway start / map exec pilot-gateway
  (optional — no longer ships in release tarballs; build it from
  github.com/pilot-protocol/gateway). Both are discovered (in order):
  $PILOT_DAEMON_BIN / $PILOT_GATEWAY_BIN, next to the pilotctl
  executable, then $PATH.
```
