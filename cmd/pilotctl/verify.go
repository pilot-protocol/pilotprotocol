// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/pilot-protocol/common/badgeverify"
	"github.com/pilot-protocol/common/crypto"
	"github.com/pilot-protocol/common/protocol"
	registry "github.com/pilot-protocol/common/registry/client"
)

// loadJSONFile reads a small JSON credential file into v, exiting on error.
func loadJSONFile(path string, v interface{}) {
	data, err := os.ReadFile(path)
	if err != nil {
		fatalCode("invalid_argument", "read %s: %v", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		fatalCode("invalid_argument", "parse %s: %v", path, err)
	}
}

// nodeArgToID accepts either a textual Pilot address (N:NNNN.HHHH.LLLL) or a
// decimal node ID and returns the 32-bit node ID.
func nodeArgToID(s string) uint32 {
	if addr, err := protocol.ParseAddr(s); err == nil {
		return addr.Node
	}
	return parseNodeID(s)
}

// cmdVerify attaches a verified-address badge to this node. The badge and its
// issuer signature are produced by the verifier (`pilot-verify verify`); this
// command hands them to the daemon, which proves ownership with the node key
// and submits to the registry.
//
//	pilotctl verify                          # show your own verification status
//	pilotctl verify status                   # same
//	pilotctl verify --provider github        # self-service: device-flow via the verifier
//	pilotctl verify --badge <badge> --badge-sig <sig>
//	pilotctl verify --from cred.json        # {"badge":..,"badge_sig":..}
func cmdVerify(args []string) {
	if len(args) >= 1 && args[0] == "status" {
		cmdVerifyStatus(args[1:])
		return
	}
	flags, _ := parseFlags(args)
	// Self-service device-flow: dial the verifier, run the browser flow, submit.
	if provider := flagString(flags, "provider", ""); provider != "" {
		cmdVerifyProvider(flags, provider)
		return
	}
	badge := flagString(flags, "badge", "")
	badgeSig := flagString(flags, "badge-sig", "")
	if from := flagString(flags, "from", ""); from != "" {
		var m struct {
			Badge    string `json:"badge"`
			BadgeSig string `json:"badge_sig"`
		}
		loadJSONFile(from, &m)
		if badge == "" {
			badge = m.Badge
		}
		if badgeSig == "" {
			badgeSig = m.BadgeSig
		}
	}
	// Bare `pilotctl verify` with nothing to submit is a status check — show
	// the user whether they are verified and, if not, how to become verified.
	if badge == "" || badgeSig == "" {
		cmdVerifyStatus(args)
		return
	}
	d := connectDriver()
	defer d.Close()
	resp, err := d.SubmitBadge(badge, badgeSig)
	if err != nil {
		fatalCode("connection_failed", "verify: %v", err)
	}
	output(resp)
}

// cmdVerifyStatus shows whether THIS node carries a verified-address badge.
// The badge is read from the registry (untrusted transport) and then verified
// OFFLINE against the pinned issuer key — we never take the registry's word for
// it. When unverified, it prints how to get verified.
//
//	pilotctl verify status [--node <addr|id>]
func cmdVerifyStatus(args []string) {
	flags, _ := parseFlags(args)

	var nodeID uint32
	var address string
	if n := flagString(flags, "node", ""); n != "" {
		nodeID = nodeArgToID(n)
	} else {
		d := connectDriver()
		info, err := d.Info()
		d.Close()
		if err != nil {
			fatalCode("connection_failed",
				"verify status: cannot reach the daemon (is it running?): %v", err)
		}
		if v, ok := info["node_id"].(float64); ok {
			nodeID = uint32(v)
		}
		address, _ = info["address"].(string)
	}

	rc := connectRegistry()
	defer rc.Close()
	resp, err := rc.Lookup(nodeID)
	if err != nil {
		fatalCode("connection_failed", "verify status: registry lookup: %v", err)
	}

	badge, _ := resp["badge"].(string)
	badgeSig, _ := resp["badge_sig"].(string)
	provider, _ := resp["verification_provider"].(string)
	verifiedAt, _ := resp["verified_at"].(string)

	out := map[string]interface{}{"node_id": nodeID}
	if address != "" {
		out["address"] = address
	}

	status := "not_verified"
	verified := false
	var detail string
	if badge != "" {
		if _, verr := badgeverify.VerifyForNode(badge, badgeSig, nodeID); verr == nil {
			status, verified = "verified", true
		} else {
			status, detail = "badge_present_unvalidated", verr.Error()
		}
	}
	out["verified"] = verified
	out["status"] = status
	if provider != "" {
		out["provider"] = provider
	}
	if verifiedAt != "" {
		out["verified_at"] = verifiedAt
	}
	if status == "not_verified" {
		out["how_to_verify"] = []string{
			fmt.Sprintf("1. pilot-verify verify --provider github --node-id %d --github-client-id <client-id>", nodeID),
			"   (authorize in your browser; it prints a badge + signature)",
			"2. pilotctl verify --badge <badge> --badge-sig <sig>",
		}
	}
	if detail != "" {
		out["detail"] = detail
	}

	if jsonOutput {
		output(out)
		return
	}
	switch status {
	case "verified":
		line := fmt.Sprintf("✓ Verified via %s", provider)
		if verifiedAt != "" {
			line += fmt.Sprintf(" (since %s)", verifiedAt)
		}
		fmt.Println(line)
	case "badge_present_unvalidated":
		fmt.Printf("A %s badge is on file but could not be validated by this build.\n", provider)
		fmt.Println("(the issuer key may not be pinned yet)")
	default:
		fmt.Println("Not verified.")
		fmt.Println()
		fmt.Println("To get a verified badge:")
		fmt.Printf("  1. pilot-verify verify --provider github --node-id %d --github-client-id <client-id>\n", nodeID)
		fmt.Println("     (authorize in your browser; it prints a badge + signature)")
		fmt.Println("  2. pilotctl verify --badge <badge> --badge-sig <sig>")
	}
}

// cmdRecovery dispatches the recovery subcommands.
func cmdRecovery(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl recovery <enroll|new-key|recover> ...")
	}
	switch args[0] {
	case "enroll":
		cmdRecoveryEnroll(args[1:])
	case "new-key":
		cmdRecoveryNewKey(args[1:])
	case "recover":
		cmdRecoveryRecover(args[1:])
	default:
		fatalCode("invalid_argument", "unknown recovery subcommand %q (want enroll|new-key|recover)", args[0])
	}
}

// cmdRecoveryEnroll records this node's opaque recovery commitment so the
// address can be recovered later if the key is lost. The enrollment + signature
// come from `pilot-verify enroll`.
//
//	pilotctl recovery enroll --enrollment <e> --enrollment-sig <sig>
//	pilotctl recovery enroll --from enroll.json
func cmdRecoveryEnroll(args []string) {
	flags, _ := parseFlags(args)
	enrollment := flagString(flags, "enrollment", "")
	enrollSig := flagString(flags, "enrollment-sig", "")
	if from := flagString(flags, "from", ""); from != "" {
		var m struct {
			Enrollment    string `json:"enrollment"`
			EnrollmentSig string `json:"enrollment_sig"`
		}
		loadJSONFile(from, &m)
		if enrollment == "" {
			enrollment = m.Enrollment
		}
		if enrollSig == "" {
			enrollSig = m.EnrollmentSig
		}
	}
	if enrollment == "" || enrollSig == "" {
		fatalCode("invalid_argument",
			"usage: pilotctl recovery enroll --enrollment <e> --enrollment-sig <sig>  (or --from enroll.json)")
	}
	d := connectDriver()
	defer d.Close()
	resp, err := d.EnrollRecovery(enrollment, enrollSig)
	if err != nil {
		fatalCode("connection_failed", "recovery enroll: %v", err)
	}
	output(resp)
}

// cmdRecoveryNewKey generates a fresh keypair for an address that is being
// recovered and prints its public key. The custodian of the cold recovery key
// signs an authorization binding this public key; `pilotctl recovery recover`
// then submits it. The private key stays local in --out.
//
//	pilotctl recovery new-key [--out <path>]
func cmdRecoveryNewKey(args []string) {
	flags, _ := parseFlags(args)
	out := flagString(flags, "out", configDir()+"/recovery-identity.json")
	id, err := crypto.GenerateIdentity()
	if err != nil {
		fatalCode("internal_error", "recovery new-key: generate: %v", err)
	}
	if err := crypto.SaveIdentity(out, id); err != nil {
		fatalCode("internal_error", "recovery new-key: save %s: %v", out, err)
	}
	output(map[string]interface{}{
		"new_identity_path": out,
		"new_public_key":    crypto.EncodePublicKey(id.PublicKey),
		"next": "give new_public_key and your node address to the recovery-key custodian; " +
			"they return a recovery authorization for `pilotctl recovery recover`",
	})
}

// cmdRecoveryRecover force-rotates a lost address to the new key created by
// `recovery new-key`, using a cold-key-signed authorization. No current key is
// required — that is the point of recovery. On success the new identity is
// installed at the daemon identity path; restart the daemon to adopt it.
//
//	pilotctl recovery recover --node <addr|id> --new-key <path> \
//	    --recovery <auth> --recovery-sig <sig> [--from recover.json] \
//	    [--identity <path>] [--registry host:port]
func cmdRecoveryRecover(args []string) {
	flags, _ := parseFlags(args)
	nodeArg := flagString(flags, "node", "")
	recovery := flagString(flags, "recovery", "")
	recoverySig := flagString(flags, "recovery-sig", "")
	newKeyPath := flagString(flags, "new-key", "")
	if from := flagString(flags, "from", ""); from != "" {
		var m struct {
			Recovery    string `json:"recovery"`
			RecoverySig string `json:"recovery_sig"`
		}
		loadJSONFile(from, &m)
		if recovery == "" {
			recovery = m.Recovery
		}
		if recoverySig == "" {
			recoverySig = m.RecoverySig
		}
	}
	if nodeArg == "" || recovery == "" || recoverySig == "" || newKeyPath == "" {
		fatalCode("invalid_argument",
			"usage: pilotctl recovery recover --node <addr|id> --new-key <path> --recovery <auth> --recovery-sig <sig>")
	}
	nodeID := nodeArgToID(nodeArg)
	id, err := crypto.LoadIdentity(newKeyPath)
	if err != nil {
		fatalCode("invalid_argument", "recovery recover: load new key %s: %v", newKeyPath, err)
	}
	newPub := crypto.EncodePublicKey(id.PublicKey)

	addr := flagString(flags, "registry", getRegistry())
	// TODO(netproxy): raw-TCP registry dial; bypasses HTTPS_PROXY until
	// common/netproxy lands in pilotctl (see connectRegistry).
	rc, err := registry.Dial(addr)
	if err != nil {
		fatalHint("connection_failed", registryDialHint(addr),
			"recovery recover: cannot reach registry at %s: %v", addr, err)
	}
	defer rc.Close()

	resp, err := rc.RecoverIdentity(nodeID, recovery, recoverySig, newPub)
	if err != nil {
		fatalCode("permission_denied", "recovery recover: %v", err)
	}

	// The registry rotated the address to the new key; install it locally so
	// the daemon can authenticate as the recovered node after a restart.
	idPath := flagString(flags, "identity", configDir()+"/identity.json")
	// Irreversible-overwrite guard: SaveIdentity replaces the live daemon
	// identity in place. If one already exists, copy it aside first so a
	// recovery run can never silently destroy the prior key. Refuse rather
	// than overwrite blind if the backup can't be written.
	if bak, err := backupIdentity(idPath); err != nil {
		fatalCode("internal_error",
			"recovery recover: refusing to overwrite existing identity %s: backup failed: %v", idPath, err)
	} else if bak != "" && !jsonOutput {
		fmt.Fprintf(os.Stderr, "backed up existing identity to %s\n", bak)
	}
	if err := crypto.SaveIdentity(idPath, id); err != nil {
		fatalCode("internal_error",
			"recovery recover: registry rotated key but installing new identity at %s failed: %v", idPath, err)
	}
	output(map[string]interface{}{
		"recovered":      true,
		"node_id":        nodeID,
		"new_public_key": newPub,
		"identity_path":  idPath,
		"next":           "restart the daemon so it authenticates with the recovered key",
		"registry":       resp,
	})
}

// backupIdentity copies an existing identity file to
// "<path>.bak-<unix-ts>" before it is overwritten by a recovery run.
// Returns the backup path on success, "" if no file existed at path (so
// there was nothing to back up), or an error if a file exists but the
// backup could not be written — in which case the caller MUST refuse to
// overwrite. Timestamped so repeated recovery attempts never clobber an
// earlier backup. Crypto is untouched: this is a pure file copy.
func backupIdentity(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	bakPath := fmt.Sprintf("%s.bak-%d", path, time.Now().Unix())
	if err := os.WriteFile(bakPath, data, 0o600); err != nil {
		return "", err
	}
	return bakPath, nil
}
