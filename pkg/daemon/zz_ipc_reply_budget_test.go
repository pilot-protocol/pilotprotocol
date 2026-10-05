// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/common/ipcutil"
	"github.com/pilot-protocol/common/protocol"
)

// A node with more peers than one IPC message can list still answers info:
// the scalar fields and connections are whole, the peer list is cut to fit
// and says so, and peers with an open connection are kept. Before, the
// daemon could not send the reply and closed the client's connection
// (seen on a service agent with 10,909 peers).
func TestInfoReplyFitsOneIPCMessage(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"networks": []interface{}{float64(0)}}
	})
	defer cleanup()
	d, s := newSimpleHandlerDaemon(t, client)

	const nPeers = 12000
	const inUse = 20000 + nPeers - 1 // last in node order: cut first unless kept for its connection
	d.tunnels.mu.Lock()
	for i := 0; i < nPeers; i++ {
		d.tunnels.peers[uint32(20000+i)] = &net.UDPAddr{IP: net.IPv4(203, 0, byte(i/250), byte(i%250)), Port: 40000 + i%20000}
	}
	d.tunnels.mu.Unlock()
	d.ports.NewConnection(49152, protocol.Addr{Node: inUse}, protocol.PortDataExchange).State = StateEstablished

	ic, conn := newIPCTestConn(t)
	reply := runHandler(t, conn, func() { s.handleInfo(ic, 0) })
	if len(reply) > ipcutil.MaxMessageSize {
		t.Fatalf("reply is %d bytes, over the IPC limit", len(reply))
	}
	var info struct {
		Peers     int  `json:"peers"`
		Truncated bool `json:"peer_list_truncated"`
		PeerList  []struct {
			NodeID uint32 `json:"node_id"`
		} `json:"peer_list"`
		ConnList []json.RawMessage `json:"conn_list"`
		NodeID   uint32            `json:"node_id"`
	}
	if err := json.Unmarshal(reply[1:], &info); err != nil {
		t.Fatalf("info JSON: %v", err)
	}
	if info.Peers != nPeers || info.NodeID != 7 || len(info.ConnList) != 1 {
		t.Fatalf("peers=%d node_id=%d conns=%d, want %d, 7, 1", info.Peers, info.NodeID, len(info.ConnList), nPeers)
	}
	if !info.Truncated || len(info.PeerList) >= nPeers || len(info.PeerList) < 9000 {
		t.Fatalf("truncated=%v with %d of %d peer rows", info.Truncated, len(info.PeerList), nPeers)
	}
	if info.PeerList[0].NodeID != inUse {
		t.Fatalf("first row is node %d; the peer with an open connection must come first", info.PeerList[0].NodeID)
	}
	t.Logf("%d of %d peer rows in %d bytes", len(info.PeerList), nPeers, len(reply))
}

// The same for the trusted-peers list: service agents hold over 20,000
// trust records, and `pilotctl trust` failed on every one of them.
func TestTrustedReplyFitsOneIPCMessage(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	fs := installFakeHandshake(d)
	const n = 24000
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for i := 0; i < n; i++ {
		fs.trustedRecs = append(fs.trustedRecs, HandshakeTrustRecord{
			NodeID: uint32(20000 + i), PublicKey: key, ApprovedAt: time.Unix(1790000000+int64(i), 0), Mutual: true,
		})
	}
	ic, conn := newIPCTestConn(t)
	reply := runHandler(t, conn, func() { d.ipc.handleHandshake(ic, 0, []byte{SubHandshakeTrusted}) })
	var r struct {
		Trusted []struct {
			NodeID uint32 `json:"node_id"`
		} `json:"trusted"`
		Truncated bool `json:"trusted_truncated"`
	}
	if err := json.Unmarshal(reply[1:], &r); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if !r.Truncated || len(r.Trusted) == 0 || len(r.Trusted) >= n {
		t.Fatalf("truncated=%v with %d of %d records", r.Truncated, len(r.Trusted), n)
	}
	if newest := uint32(20000 + n - 1); r.Trusted[0].NodeID != newest {
		t.Fatalf("first record is node %d, want the newest, %d", r.Trusted[0].NodeID, newest)
	}
	t.Logf("%d of %d trust records in %d bytes", len(r.Trusted), n, len(reply))
}

// The cut keeps as many rows as fit, and no more.
func TestMarshalRowsWithinBudgetKeepsAllThatFit(t *testing.T) {
	t.Parallel()
	rows := make([]string, 100)
	for i := range rows {
		rows[i] = fmt.Sprintf("row-%03d", i)
	}
	for _, budget := range []int{60, 100, 333, 1000} {
		body := map[string]interface{}{"total": len(rows)}
		data, err := marshalRowsWithinBudget(body, "list", rows, budget)
		if err != nil {
			t.Fatal(err)
		}
		var got struct {
			Total     int      `json:"total"`
			List      []string `json:"list"`
			Truncated bool     `json:"list_truncated"`
		}
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("budget %d: %v", budget, err)
		}
		if len(data) > budget || !got.Truncated || got.Total != 100 {
			t.Fatalf("budget %d: %d bytes, truncated=%v, total=%d", budget, len(data), got.Truncated, got.Total)
		}
		// One more row would not have fit.
		body["list"] = rows[:len(got.List)+1]
		if more, _ := json.Marshal(body); len(more) <= budget {
			t.Fatalf("budget %d: kept %d rows, but %d fit", budget, len(got.List), len(got.List)+1)
		}
	}
}
