// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

const (
	securityProfileCompatible = "compatible"
	securityProfileEnterprise = "enterprise"
)

type daemonSecurityOptions struct {
	RegistryAddr                    string
	RegistryTLS                     bool
	RegistryFingerprint             string
	RegistryTrust                   string
	Encrypt                         bool
	StrictDataPlaneTrust            bool
	IdentityPath                    string
	TrustAutoApprove                bool
	DisableSkillinject              bool
	SkillinjectVerificationKeyFound bool
	MOTDFeedURL                     string
	WebhookURL                      string
}

func applyDaemonSecurityProfile(name string, o *daemonSecurityOptions) error {
	if o == nil {
		return fmt.Errorf("security profile options are nil")
	}
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", securityProfileCompatible:
		return nil
	case securityProfileEnterprise:
		o.Encrypt = true
		o.RegistryTLS = true
		o.StrictDataPlaneTrust = true
		o.MOTDFeedURL = "" // the current feed has no signed-content format
		if !o.SkillinjectVerificationKeyFound {
			o.DisableSkillinject = true
		}
		if strings.TrimSpace(o.RegistryAddr) == "" {
			return fmt.Errorf("enterprise profile requires an explicit registry address")
		}
		if strings.TrimSpace(o.IdentityPath) == "" {
			return fmt.Errorf("enterprise profile requires a persistent -identity path")
		}
		if o.TrustAutoApprove {
			return fmt.Errorf("enterprise profile forbids -trust-auto-approve")
		}
		switch strings.ToLower(strings.TrimSpace(o.RegistryTrust)) {
		case "pinned":
			if strings.TrimSpace(o.RegistryFingerprint) == "" {
				return fmt.Errorf("enterprise profile with pinned registry trust requires -registry-fingerprint")
			}
		case "system":
		default:
			return fmt.Errorf("enterprise profile requires registry trust to be pinned or system, got %q", o.RegistryTrust)
		}
		if o.WebhookURL != "" {
			if err := requireSecureOrLoopbackURL(o.WebhookURL); err != nil {
				return fmt.Errorf("enterprise webhook: %w", err)
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown security profile %q (want %q or %q)", name, securityProfileCompatible, securityProfileEnterprise)
	}
}

func requireSecureOrLoopbackURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("invalid URL %q", raw)
	}
	if strings.EqualFold(u.Scheme, "https") {
		return nil
	}
	if !strings.EqualFold(u.Scheme, "http") {
		return fmt.Errorf("URL must use HTTPS or loopback HTTP")
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("HTTP URL must target loopback, got %q", host)
	}
	return nil
}
