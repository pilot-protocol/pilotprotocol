// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pilot-protocol/trustedagents"
)

// `pilotctl --json trusted list` printed the text table (phase-2 E2E).
func TestCLITrustedListJSON(t *testing.T) {
	t.Parallel()
	stdout, stderr, code := runCLI(t, []string{"--json", "trusted", "list"}, cliEnvCleared(nil))
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	var res struct {
		Status string `json:"status"`
		Data   struct {
			Trusted []struct {
				Hostname string `json:"hostname"`
				Address  string `json:"address"`
				NodeID   uint32 `json:"node_id"`
			} `json:"trusted"`
			Count int `json:"count"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &res); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	if res.Status != "ok" || res.Data.Count != len(trustedagents.All()) || len(res.Data.Trusted) != res.Data.Count {
		t.Fatalf("result = %+v, want every trusted agent", res)
	}
}
