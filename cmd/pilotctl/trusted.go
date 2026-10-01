// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"

	"github.com/pilot-protocol/trustedagents"
)

func cmdTrusted(args []string) {
	if len(args) < 1 || args[0] != "list" {
		fatalHint("invalid_argument",
			"available: pilotctl trusted list",
			"usage: pilotctl trusted list")
	}
	agents := trustedagents.All()
	if jsonOutput {
		list := make([]map[string]interface{}, 0, len(agents))
		for _, a := range agents {
			list = append(list, map[string]interface{}{
				"hostname": a.Hostname,
				"address":  a.Address,
				"node_id":  a.NodeID,
			})
		}
		outputOK(map[string]interface{}{"trusted": list, "count": len(list)})
		return
	}
	if len(agents) == 0 {
		fmt.Println("(no trusted agents — daemon will not auto-accept any handshakes via this path)")
		return
	}
	for _, a := range agents {
		fmt.Printf("  %-32s %s  node_id=%d\n", a.Hostname, a.Address, a.NodeID)
	}
}
