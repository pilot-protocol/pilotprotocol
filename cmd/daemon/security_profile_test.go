// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "testing"

func validEnterpriseDaemonOptions() daemonSecurityOptions {
	return daemonSecurityOptions{
		RegistryAddr:        "registry.example:443",
		RegistryFingerprint: "abcdef",
		RegistryTrust:       "pinned",
		IdentityPath:        "/var/lib/pilot/identity.json",
	}
}

func TestEnterpriseDaemonProfileLocksSafeSettings(t *testing.T) {
	t.Parallel()
	o := validEnterpriseDaemonOptions()
	o.MOTDFeedURL = "https://example.invalid/motd.json"
	if err := applyDaemonSecurityProfile(securityProfileEnterprise, &o); err != nil {
		t.Fatal(err)
	}
	if !o.Encrypt || !o.RegistryTLS || !o.StrictDataPlaneTrust {
		t.Fatalf("required settings not locked: %+v", o)
	}
	if !o.DisableSkillinject {
		t.Fatal("unsigned skill injection was not disabled")
	}
	if o.MOTDFeedURL != "" {
		t.Fatal("unsigned MOTD feed was not disabled")
	}
}

func TestEnterpriseDaemonProfileAllowsConfiguredSkillVerificationKey(t *testing.T) {
	t.Parallel()
	o := validEnterpriseDaemonOptions()
	o.SkillinjectVerificationKeyFound = true
	if err := applyDaemonSecurityProfile(securityProfileEnterprise, &o); err != nil {
		t.Fatal(err)
	}
	if o.DisableSkillinject {
		t.Fatal("signed skill injection was disabled")
	}
}

func TestEnterpriseDaemonProfileRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()
	cases := map[string]func(*daemonSecurityOptions){
		"ephemeral identity": func(o *daemonSecurityOptions) { o.IdentityPath = "" },
		"auto trust":         func(o *daemonSecurityOptions) { o.TrustAutoApprove = true },
		"missing pin":        func(o *daemonSecurityOptions) { o.RegistryFingerprint = "" },
		"bad trust mode":     func(o *daemonSecurityOptions) { o.RegistryTrust = "insecure" },
		"HTTP webhook":       func(o *daemonSecurityOptions) { o.WebhookURL = "http://example.com/hook" },
	}
	for name, mutate := range cases {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			o := validEnterpriseDaemonOptions()
			mutate(&o)
			if err := applyDaemonSecurityProfile(securityProfileEnterprise, &o); err == nil {
				t.Fatalf("unsafe configuration accepted: %+v", o)
			}
		})
	}
}

func TestEnterpriseDaemonProfileAllowsSystemTrustAndLoopbackWebhook(t *testing.T) {
	t.Parallel()
	o := validEnterpriseDaemonOptions()
	o.RegistryTrust = "system"
	o.RegistryFingerprint = ""
	o.WebhookURL = "http://127.0.0.1:8080/hook"
	if err := applyDaemonSecurityProfile(securityProfileEnterprise, &o); err != nil {
		t.Fatal(err)
	}
}

func TestCompatibleDaemonProfilePreservesLegacySettings(t *testing.T) {
	t.Parallel()
	o := daemonSecurityOptions{MOTDFeedURL: "http://example.com/feed"}
	if err := applyDaemonSecurityProfile(securityProfileCompatible, &o); err != nil {
		t.Fatal(err)
	}
	if o.Encrypt || o.RegistryTLS || o.StrictDataPlaneTrust || o.DisableSkillinject || o.MOTDFeedURL == "" {
		t.Fatalf("compatible profile changed settings: %+v", o)
	}
}
