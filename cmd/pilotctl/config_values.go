// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pilot-protocol/pilotprotocol/internal/proxyconf"
)

// Config keys mirror the daemon flags, using the underscore spelling read
// by pilotctl as well as the daemon. Unknown keys must never look successful.
var configValueKinds = map[string]string{
	"admin_token":            "String",
	"advertise_endpoint":     "String",
	"beacon":                 "String",
	"beacon_rtt_probe":       "Bool",
	"compat_beacon":          "String",
	"dataexchange_b64":       "Bool",
	"email":                  "String",
	"encrypt":                "Bool",
	"endpoint":               "String",
	"enterprise_control":     "String",
	"hostname":               "String",
	"identity":               "String",
	"idle_timeout":           "Duration",
	"keepalive":              "Duration",
	"listen":                 "String",
	"log_format":             "String",
	"log_level":              "String",
	"log_max_backups":        "Int",
	"log_max_size":           "Int",
	"max_conns_per_port":     "Int",
	"max_conns_total":        "Int",
	"motd_feed_url":          "String",
	"motd_interval":          "Duration",
	"networks":               "String",
	"no_dataexchange":        "Bool",
	"no_echo":                "Bool",
	"no_eventstream":         "Bool",
	"no_path_watch":          "Bool",
	"no_rx_watchdog":         "Bool",
	"no_skillinject":         "Bool",
	"owner":                  "String",
	"proxy":                  "String",
	"proxy_cmd":              "String",
	"public":                 "Bool",
	"registry":               "String",
	"registry_fingerprint":   "String",
	"registry_tls":           "Bool",
	"registry_trust":         "String",
	"rekey_whitelist":        "String",
	"relay_only":             "Bool",
	"reply_whitelist":        "String",
	"sandbox":                "Bool",
	"sandbox_dir":            "String",
	"security_profile":       "String",
	"socket":                 "String",
	"strict_dataplane_trust": "Bool",
	"syn_rate_limit":         "Int",
	"syn_whitelist":          "String",
	"telemetry_url":          "String",
	"time_wait":              "Duration",
	"tls_trust":              "String",
	"transport":              "String",
	"trust_auto_approve":     "Bool",
	"webhook":                "String",
	"webhook_secret":         "String",
}

func validateConfigValue(key, raw string) (interface{}, error) {
	kind, ok := configValueKinds[key]
	if !ok {
		return nil, fmt.Errorf("unknown key %q", key)
	}
	if raw == "" && clearableConfigKeys[key] {
		return "", nil
	}
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, fmt.Errorf("%s must not be empty", key)
	}
	switch kind {
	case "Bool":
		if value != "true" && value != "false" {
			return nil, fmt.Errorf("%s must be true or false", key)
		}
		return value == "true", nil
	case "Int":
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("%s must be a non-negative integer", key)
		}
		return n, nil
	case "Duration":
		d, err := time.ParseDuration(value)
		if err != nil || d < 0 {
			return nil, fmt.Errorf("%s must be a non-negative duration", key)
		}
		return value, nil
	}
	switch key {
	case "transport":
		t, err := normalizeTransport(value)
		if err == nil && t == "" {
			err = validateTransport(value)
		}
		return t, err
	case "proxy":
		return proxyconf.Normalize(value)
	case "registry", "beacon", "endpoint", "advertise_endpoint", "listen":
		host, port, err := net.SplitHostPort(value)
		n, portErr := strconv.Atoi(port)
		if err != nil || portErr != nil || n < 0 || n > 65535 ||
			(key != "listen" && (host == "" || n == 0)) ||
			strings.ContainsAny(host, " /\\?#@\t\r\n") {
			return nil, fmt.Errorf("%s must be a host:port address", key)
		}
	case "socket", "identity", "enterprise_control", "sandbox_dir":
		if strings.ContainsRune(raw, 0) {
			return nil, fmt.Errorf("%s contains a NUL byte", key)
		}
	case "hostname":
		if len(value) > 63 || strings.Trim(value, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" || strings.HasPrefix(value, "-") || strings.HasSuffix(value, "-") {
			return nil, fmt.Errorf("hostname must be 1-63 lowercase letters, digits or internal hyphens")
		}
	case "webhook", "motd_feed_url", "telemetry_url", "compat_beacon":
		u, err := url.Parse(value)
		if err != nil || u.Hostname() == "" || u.User != nil ||
			(key == "compat_beacon" && u.Scheme != "wss") ||
			(key != "compat_beacon" && u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("invalid URL for %s", key)
		}
	case "registry_trust", "tls_trust":
		if value != "pinned" && value != "system" {
			return nil, fmt.Errorf("%s must be pinned or system", key)
		}
	case "registry_fingerprint":
		b, err := hex.DecodeString(value)
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("registry_fingerprint must be a SHA-256 hex digest")
		}
	case "log_level":
		if value != "debug" && value != "info" && value != "warn" && value != "error" {
			return nil, fmt.Errorf("invalid log_level")
		}
	case "log_format":
		if value != "text" && value != "json" {
			return nil, fmt.Errorf("log_format must be text or json")
		}
	case "security_profile":
		if value != "compatible" && value != "enterprise" {
			return nil, fmt.Errorf("security_profile must be compatible or enterprise")
		}
	}
	return raw, nil
}
