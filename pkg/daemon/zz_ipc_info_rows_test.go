// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/json"
	"testing"
)

// The info reply's rows moved from maps to structs for speed. Clients parse
// the JSON by key, so the keys and their order must not have changed.
func TestInfoRowsMarshalLikeTheMapsTheyReplaced(t *testing.T) {
	conn := ipcInfoConn{
		BytesRecv: 1, BytesSent: 2, CongWin: 3, DupACKs: 4, FastRetx: 5, ID: 6, InFlight: 7,
		InRecovery: true, LocalPort: 8, OOOBuf: 9, PeerRecvWin: 10, RecvWin: 11,
		RemoteAddr: "0:0000.0000.0001", RemotePort: 12, Retransmits: 13, RTTVARMs: 14,
		SACKRecv: 15, SACKSent: 16, SegsRecv: 17, SegsSent: 18, SRTTMs: 19, SSThresh: 20,
		State: "ESTABLISHED", Unacked: 21,
	}
	connMap := map[string]interface{}{
		"id": uint32(6), "local_port": uint16(8), "remote_addr": "0:0000.0000.0001", "remote_port": uint16(12),
		"state": "ESTABLISHED", "cong_win": 3, "ssthresh": 20, "in_flight": 7, "srtt_ms": float64(19),
		"rttvar_ms": float64(14), "unacked": 21, "ooo_buf": 9, "peer_recv_win": 10, "recv_win": 11,
		"in_recovery": true, "bytes_sent": uint64(2), "bytes_recv": uint64(1), "segs_sent": uint64(18),
		"segs_recv": uint64(17), "retransmits": uint64(13), "fast_retx": uint64(5), "sack_recv": uint64(15),
		"sack_sent": uint64(16), "dup_acks": uint64(4),
	}
	peer := ipcInfoPeer{Authenticated: true, Encrypted: true, Endpoint: "127.0.0.1:1", NodeID: 7, Relay: true}
	peerMap := map[string]interface{}{
		"node_id": uint32(7), "endpoint": "127.0.0.1:1", "encrypted": true, "authenticated": true, "relay": true,
	}
	for name, pair := range map[string][2]interface{}{"conn": {conn, connMap}, "peer": {peer, peerMap}} {
		got, err := json.Marshal(pair[0])
		if err != nil {
			t.Fatal(err)
		}
		want, err := json.Marshal(pair[1])
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Errorf("%s row changed:\n got %s\nwant %s", name, got, want)
		}
	}
}
