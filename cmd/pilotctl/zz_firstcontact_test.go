// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pilot-protocol/common/driver"
	"github.com/pilot-protocol/common/protocol"
)

func writeInboxMsg(t *testing.T, dir, name, from, data string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"from": from, "data": data})
	if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func tempInbox(t *testing.T) string {
	t.Helper()
	tmp := withTempHomeFull(t)
	dir := filepath.Join(tmp, ".pilot", "inbox")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A reply already in the inbox when the request is sent (an earlier
// query's answer, or a service's late duplicate) is never taken for this
// request's reply.
func TestInboxWatchIgnoresFilesPresentBeforeTheSend(t *testing.T) {
	dir := tempInbox(t)
	writeInboxMsg(t, dir, "TEXT-20260924T100000.000-1.json", "0:0000.0002.BBE4", "stale")
	w := newInboxWatch("0:0000.0002.BBE4")
	if msg, err := w.poll(); err != nil || msg != nil {
		t.Fatalf("poll before any new file = %v, %v; want nothing", msg, err)
	}
	writeInboxMsg(t, dir, "TEXT-20260924T100005.000-2.json", "0:0000.0002.BBE4", "fresh")
	msg, err := w.poll()
	if err != nil || msg == nil || msg["data"] != "fresh" {
		t.Fatalf("poll = %v, %v; want the fresh reply", msg, err)
	}
}

// With two new replies (a service that answers twice, or the answer to a
// re-sent request), the oldest wins, whatever the directory order, and a
// different sender's message is skipped.
func TestInboxWatchTakesOldestReplyFromThePeer(t *testing.T) {
	dir := tempInbox(t)
	w := newInboxWatch("0:0000.0002.BBE4")
	writeInboxMsg(t, dir, "TEXT-20260924T100007.000-3.json", "0:0000.0002.BBE4", "second")
	writeInboxMsg(t, dir, "JSON-20260924T100006.000-2.json", "0:0000.0002.BBE4", "first")
	writeInboxMsg(t, dir, "BINARY-20260924T100005.000-1.json", "0:0000.0009.0001", "other sender")
	msg, err := w.poll()
	if err != nil || msg == nil || msg["data"] != "first" {
		t.Fatalf("poll = %v, %v; want the oldest reply from the peer", msg, err)
	}
}

func TestAwaitReplyReturnsWithoutResendWhenReplyArrives(t *testing.T) {
	dir := tempInbox(t)
	w := newInboxWatch("peer")
	var resends atomic.Int32
	go func() {
		time.Sleep(200 * time.Millisecond)
		writeInboxMsg(t, dir, "TEXT-1-1.json", "peer", "ok")
	}()
	out, err := awaitReply(w, time.Now(), replyWait{
		wait:        3 * time.Second,
		resendAfter: time.Second,
		resend:      func() (time.Time, error) { resends.Add(1); return time.Now(), nil },
	})
	if err != nil || out.reply == nil {
		t.Fatalf("awaitReply = %+v, %v", out, err)
	}
	if out.resent || resends.Load() != 0 {
		t.Fatal("request re-sent although the reply arrived in time")
	}
}

// First contact: the first reply is lost; the request is sent once more
// on a new stream at mid-window and its reply is taken.
func TestAwaitReplyResendsOnceAndTakesTheSecondReply(t *testing.T) {
	dir := tempInbox(t)
	w := newInboxWatch("peer")
	var resends atomic.Int32
	start := time.Now()
	out, err := awaitReply(w, start, replyWait{
		wait:        4 * time.Second,
		resendAfter: 600 * time.Millisecond,
		resend: func() (time.Time, error) {
			resends.Add(1)
			go func() {
				time.Sleep(300 * time.Millisecond)
				writeInboxMsg(t, dir, "TEXT-2-1.json", "peer", "answer to the re-sent request")
			}()
			return time.Now(), nil
		},
	})
	if err != nil || out.reply == nil {
		t.Fatalf("awaitReply = %+v, %v", out, err)
	}
	if !out.resent || resends.Load() != 1 {
		t.Fatalf("resent=%v resends=%d; want one re-send", out.resent, resends.Load())
	}
	if el := time.Since(start); el < 600*time.Millisecond || el > 3*time.Second {
		t.Fatalf("reply taken after %s", el)
	}
}

// A re-sent request gets at least half a window of its own, even when
// sending it again took most of the original window.
func TestAwaitReplyExtendsTheWindowForTheResentRequest(t *testing.T) {
	tempInbox(t)
	w := newInboxWatch("peer")
	start := time.Now()
	out, err := awaitReply(w, start, replyWait{
		wait:        2 * time.Second,
		resendAfter: 500 * time.Millisecond,
		resend: func() (time.Time, error) {
			time.Sleep(1200 * time.Millisecond) // a slow dial on a busy path
			return time.Now(), nil
		},
	})
	if err != nil || out.reply != nil || !out.resent {
		t.Fatalf("awaitReply = %+v, %v", out, err)
	}
	// Re-send acknowledged at ~1.7 s: waits until ~2.7 s, not 2 s.
	if el := time.Since(start); el < 2500*time.Millisecond {
		t.Fatalf("gave up after %s, before the re-sent request had half a window", el)
	}
}

func TestAwaitReplyRecordsResendFailure(t *testing.T) {
	tempInbox(t)
	w := newInboxWatch("peer")
	out, err := awaitReply(w, time.Now(), replyWait{
		wait:        time.Second,
		resendAfter: 300 * time.Millisecond,
		resend:      func() (time.Time, error) { return time.Time{}, errors.New("dial: dial timeout") },
	})
	if err != nil || out.reply != nil || !out.resent || out.resendErr == nil {
		t.Fatalf("awaitReply = %+v, %v", out, err)
	}
	if h := replyTimeoutHint("list-agents", out, true); !strings.Contains(h, "re-sending it failed") {
		t.Fatalf("hint does not mention the failed re-send: %s", h)
	}
}

func TestAwaitReplyCountsReplyConnections(t *testing.T) {
	tempInbox(t)
	w := newInboxWatch("peer")
	out, _ := awaitReply(w, time.Now(), replyWait{wait: 1200 * time.Millisecond, observe: func() int { return 2 }})
	if out.replyConns != 2 {
		t.Fatalf("replyConns = %d, want 2", out.replyConns)
	}
	if h := replyTimeoutHint("list-agents", out, true); !strings.Contains(h, "gave up on the reply") {
		t.Fatalf("hint: %s", h)
	}
}

func TestResendDelay(t *testing.T) {
	for _, c := range []struct{ wait, want time.Duration }{
		{30 * time.Second, 15 * time.Second},
		{60 * time.Second, 15 * time.Second},
		{10 * time.Second, 5 * time.Second},
		{4 * time.Second, 0},
	} {
		if got := resendDelay(c.wait); got != c.want {
			t.Errorf("resendDelay(%s) = %s, want %s", c.wait, got, c.want)
		}
	}
}

func TestReplyTimeoutHintNamesTheStep(t *testing.T) {
	first := replyTimeoutHint("list-agents", replyOutcome{resent: true}, true)
	for _, want := range []string{"acknowledged the request", "sent twice", "service side"} {
		if !strings.Contains(first, want) {
			t.Errorf("first-contact hint missing %q: %s", want, first)
		}
	}
	if warm := replyTimeoutHint("list-agents", replyOutcome{}, false); !strings.Contains(warm, "No reply connection") {
		t.Errorf("warm-path hint: %s", warm)
	}
}

func TestDialFailureHint(t *testing.T) {
	kx := dialFailureHint("list-agents", errors.New("dial: daemon: dial timeout: key exchange with peer did not complete"), 2, 55*time.Second)
	if !strings.Contains(kx, "never completed the tunnel key exchange") || !strings.Contains(kx, "2 dial attempt") {
		t.Errorf("key-exchange hint: %s", kx)
	}
	syn := dialFailureHint("list-agents", errors.New("dial: daemon: dial timeout"), 1, 17*time.Second)
	if !strings.Contains(syn, "did not accept a connection on port 1001") {
		t.Errorf("dial-timeout hint: %s", syn)
	}
}

func TestDialErrorClassification(t *testing.T) {
	daemonKX := errors.New("dial: daemon: dial timeout: key exchange with peer did not complete")
	sdk := errors.New("dial: dial timeout")
	refused := errors.New("dial: daemon: connection refused")
	if !isConvergingDialError(daemonKX) || !isConvergingDialError(sdk) || isConvergingDialError(refused) {
		t.Error("isConvergingDialError misclassifies")
	}
	if isDriverSideTimeout(daemonKX) || !isDriverSideTimeout(sdk) {
		t.Error("isDriverSideTimeout misclassifies")
	}
}

func TestInfoHelpers(t *testing.T) {
	var info map[string]interface{}
	raw := `{"features":["reply_window","dial_awaits_key"],
	  "peer_list":[{"node_id":179172,"encrypted":true},{"node_id":7,"encrypted":false}],
	  "conn_list":[{"local_port":1001,"remote_addr":"0:0000.0002.BBE4"},
	               {"local_port":1001,"remote_addr":"0:0000.0000.0007"},
	               {"local_port":49152,"remote_addr":"0:0000.0002.BBE4"}]}`
	if err := json.Unmarshal([]byte(raw), &info); err != nil {
		t.Fatal(err)
	}
	f := featuresOf(info)
	if !f["reply_window"] || !f["dial_awaits_key"] || f["key_request"] {
		t.Errorf("featuresOf = %v", f)
	}
	if !peerSessionUp(info, 179172) || peerSessionUp(info, 7) || peerSessionUp(info, 99) {
		t.Error("peerSessionUp misreads the peer list")
	}
	if n := replyConnsFrom(info, "0:0000.0002.BBE4"); n != 1 {
		t.Errorf("replyConnsFrom = %d, want 1", n)
	}
}

// With a reply-window daemon, sending to a trusted agent (list-agents)
// no longer blocks on a trust handshake first: pilotctl sends no
// handshake request at all (the daemon fires one itself, alongside the
// dial). Measured: that block cost ~17-22 s of the first query.
func TestAutoHandshakeDoesNotBlockWithReplyWindow(t *testing.T) {
	fd := newFakeDaemon(t)
	fd.useDaemon(t)
	daemonFeatureSet = nil
	t.Cleanup(func() { daemonFeatureSet = nil })
	fd.onJSON(tdCmdInfo, tdCmdInfoOK, `{"node_id":1,"features":["reply_window"]}`)
	fd.onJSON(tdCmdHandshake, tdCmdHandshakeOK, `{"trusted":false}`)

	d, err := driver.Connect(fd.path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	start := time.Now()
	maybeAutoHandshake(d, protocol.Addr{Node: 179172}, false)
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("maybeAutoHandshake blocked for %s", el)
	}
	fd.mu.Lock()
	defer fd.mu.Unlock()
	for _, f := range fd.received {
		if f[0] == tdCmdHandshake && len(f) > 1 && f[1] == 0x01 {
			t.Fatal("a handshake request was sent although the daemon admits the reply without trust")
		}
	}
}

// An older daemon (no features) keeps the old behaviour: the trusted
// agent gets a handshake request first.
func TestAutoHandshakeKeepsHandshakeForOlderDaemon(t *testing.T) {
	fd := newFakeDaemon(t)
	fd.useDaemon(t)
	daemonFeatureSet = nil
	t.Cleanup(func() { daemonFeatureSet = nil })
	fd.onJSON(tdCmdInfo, tdCmdInfoOK, `{"node_id":1}`)
	fd.onJSON(tdCmdHandshake, tdCmdHandshakeOK, `{"trusted":false}`)
	prev := jsonOutput
	jsonOutput = true
	t.Cleanup(func() { jsonOutput = prev })

	d, err := driver.Connect(fd.path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	maybeAutoHandshake(d, protocol.Addr{Node: 179172}, false)
	fd.mu.Lock()
	defer fd.mu.Unlock()
	sent := false
	for _, f := range fd.received {
		if f[0] == tdCmdHandshake && len(f) > 1 && f[1] == 0x01 {
			sent = true
		}
	}
	if !sent {
		t.Fatal("older daemon: the trusted-agent handshake request must still be sent")
	}
}
