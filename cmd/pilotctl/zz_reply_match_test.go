// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pilot-protocol/dataexchange"
)

func writeInboxRecord(t *testing.T, dir, name string, rec map[string]any) {
	t.Helper()
	if err := putInboxRecord(dir, name, rec); err != nil {
		t.Fatal(err)
	}
}

// putInboxRecord writes an inbox record as the daemon does. It returns the
// error rather than failing the test, for goroutines and receiver callbacks,
// which must not call t.Fatal.
func putInboxRecord(dir, name string, rec map[string]any) error {
	body, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), body, 0o600)
}

// putInboxRecordLater writes an inbox record after delay, from a goroutine.
// The returned channel is closed once it is written (or failed to be).
func putInboxRecordLater(t *testing.T, delay time.Duration, dir, name string, rec map[string]any) <-chan struct{} {
	written := make(chan struct{})
	go func() {
		defer close(written)
		time.Sleep(delay)
		if err := putInboxRecord(dir, name, rec); err != nil {
			t.Error(err)
		}
	}()
	return written
}

// awaitClosed fails the test if ch is not closed within a few seconds.
func awaitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// atOnce bounds how long an untagged reply that is not held may take: well
// under the hold, with room for a loaded machine.
const atOnce = 400 * time.Millisecond

const replyPeer = "0:0000.0002.BBE4"

// Two `send-message --wait` to the same peer are in flight (A and B). The
// peer's answer to B lands first and names B's request in reply_to. A used
// to take it as its own reply.
func TestInboxWatchLeavesAnotherRequestsReply(t *testing.T) {
	dir := tempInbox(t)
	watchA := newInboxWatch(replyPeer)
	watchA.addID("request-a")
	watchB := newInboxWatch(replyPeer)
	watchB.addID("request-b")

	writeInboxRecord(t, dir, "TEXT-20260924-100005.000-000001.json", map[string]any{
		"from": replyPeer, "data": "answer to B", "reply_to": "request-b",
	})
	gotB, err := watchB.poll()
	if err != nil || gotB == nil || gotB["data"] != "answer to B" {
		t.Fatalf("B's watch = %v, %v; want B's answer", gotB, err)
	}
	if gotA, err := watchA.poll(); err != nil || gotA != nil {
		t.Fatalf("A's watch = %v, %v: the answer to another request was handed to A", gotA, err)
	}

	writeInboxRecord(t, dir, "TEXT-20260924-100006.000-000002.json", map[string]any{
		"from": replyPeer, "data": "answer to A", "reply_to": "request-a",
	})
	gotA, err := watchA.poll()
	if err != nil || gotA == nil || gotA["data"] != "answer to A" {
		t.Fatalf("A's watch = %v, %v; want A's answer", gotA, err)
	}
}

// The reply that names our request wins over an older message from the peer
// that names none (here a request of the peer's own).
func TestInboxWatchPrefersTheReplyNamingOurRequest(t *testing.T) {
	dir := tempInbox(t)
	watch := newInboxWatch(replyPeer)
	watch.addID("our-request")

	writeInboxRecord(t, dir, "TEXT-20260924-100005.000-000001.json", map[string]any{
		"from": replyPeer, "data": "/data {\"unrelated\":\"request from the peer\"}", "message_id": "peers-own-request",
	})
	writeInboxRecord(t, dir, "TEXT-20260924-100006.000-000002.json", map[string]any{
		"from": replyPeer, "data": "the actual answer", "reply_to": "our-request",
	})
	got, err := watch.poll()
	if err != nil || got == nil || got["data"] != "the actual answer" {
		t.Fatalf("poll = %v, %v; want the reply, not the peer's unrelated message", got, err)
	}
}

// A peer that does not echo the ID (every responder so far) is matched as
// before: the oldest new message from it, whether or not it carries a
// message_id of its own.
func TestInboxWatchFallsBackToSenderAndTime(t *testing.T) {
	dir := tempInbox(t)
	watch := newInboxWatch(replyPeer)
	watch.addID("our-request")

	writeInboxRecord(t, dir, "TEXT-20260924-100007.000-000003.json", map[string]any{"from": replyPeer, "data": "second"})
	writeInboxRecord(t, dir, "TEXT-20260924-100006.000-000002.json", map[string]any{"from": replyPeer, "data": "first", "message_id": "its-own-id"})
	writeInboxRecord(t, dir, "TEXT-20260924-100005.000-000001.json", map[string]any{"from": "0:0000.0009.0001", "data": "other sender"})
	writeInboxRecord(t, dir, "TEXT-20260924-100004.000-000000.json", map[string]any{"from": replyPeer, "data": "for someone else", "reply_to": "not-ours"})
	got, err := watch.poll()
	if err != nil || got == nil || got["data"] != "first" {
		t.Fatalf("poll = %v, %v; want the oldest message from the peer that names no request", got, err)
	}
}

// The re-sent request has an ID of its own; a reply to either is the reply,
// including one that arrived before the re-send's ID was registered.
func TestInboxWatchTakesReplyToEitherSend(t *testing.T) {
	dir := tempInbox(t)
	watch := newInboxWatch(replyPeer)
	watch.addID("first-send")

	writeInboxRecord(t, dir, "TEXT-20260924-100005.000-000001.json", map[string]any{
		"from": replyPeer, "data": "answer to the re-send", "reply_to": "second-send",
	})
	if got, err := watch.poll(); err != nil || got != nil {
		t.Fatalf("poll before the re-send's ID is known = %v, %v; want nothing", got, err)
	}
	watch.addID("second-send")
	got, err := watch.poll()
	if err != nil || got == nil || got["data"] != "answer to the re-send" {
		t.Fatalf("poll = %v, %v; want the answer to the re-sent request", got, err)
	}
}

// A watch that was given no ID has nothing to compare reply_to with and
// keeps the sender-and-time rule for every message.
func TestInboxWatchWithoutIDsIgnoresReplyTo(t *testing.T) {
	dir := tempInbox(t)
	watch := newInboxWatch(replyPeer)
	writeInboxRecord(t, dir, "TEXT-20260924-100005.000-000001.json", map[string]any{
		"from": replyPeer, "data": "tagged", "reply_to": "whatever",
	})
	got, err := watch.poll()
	if err != nil || got == nil || got["data"] != "tagged" {
		t.Fatalf("poll = %v, %v", got, err)
	}
}

// ── send-message against receivers of each generation ────────────────────

// dxDropConnection, returned by a dxReceiver's answer, closes the connection
// instead of acknowledging the frame: the sender's ack read fails.
const dxDropConnection = "\x00drop"

// dxCutAck, returned by a dxReceiver's answer, sends the first bytes of an
// ack and then closes the connection: the sender's ack read fails with
// "unexpected EOF" rather than "EOF".
const dxCutAck = "\x00cut"

// dxReceiver turns the stream daemon's echo into a data-exchange receiver:
// answer is called with each complete wire frame (its type and payload) the
// client wrote and returns the acknowledgement text (or dxDropConnection).
// Like a real daemon, it discards what is written to a connection it has
// closed: the client's driver does not notice, and its writes "succeed".
type dxReceiver struct {
	mu     sync.Mutex
	buf    map[uint32][]byte
	closed map[uint32]bool
	types  []uint32
	frames []*dataexchange.Frame // decoded with the current library
}

func newDXReceiver(sd *streamDaemon, answer func(ftype uint32, payload []byte, decoded *dataexchange.Frame) string) *dxReceiver {
	r := &dxReceiver{buf: map[uint32][]byte{}, closed: map[uint32]bool{}}
	sd.on(tdCmdSend, func(frame []byte) [][]byte {
		sd.sendCount.Add(1)
		if len(frame) < 5 {
			return nil
		}
		connID := binary.BigEndian.Uint32(frame[1:5])
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.closed[connID] {
			return nil
		}
		r.buf[connID] = append(r.buf[connID], frame[5:]...)
		var out [][]byte
		for {
			b := r.buf[connID]
			if len(b) < 8 {
				break
			}
			n := int(binary.BigEndian.Uint32(b[4:8]))
			if len(b) < 8+n {
				break
			}
			ftype, payload := binary.BigEndian.Uint32(b[0:4]), append([]byte(nil), b[8:8+n]...)
			decoded, _ := dataexchange.ReadFrame(bytes.NewReader(b[:8+n]))
			r.buf[connID] = b[8+n:]
			r.types = append(r.types, ftype)
			r.frames = append(r.frames, decoded)
			text := answer(ftype, payload, decoded)
			if text == dxCutAck {
				part := make([]byte, 5+3)
				part[0] = tdCmdRecv
				binary.BigEndian.PutUint32(part[1:5], connID)
				out = append(out, part)
				text = dxDropConnection
			}
			if text == dxDropConnection {
				closed := make([]byte, 5)
				closed[0] = tdCmdCloseOK
				binary.BigEndian.PutUint32(closed[1:5], connID)
				out = append(out, closed)
				r.closed[connID] = true
				delete(r.buf, connID)
				break
			}
			var ack bytes.Buffer
			_ = dataexchange.WriteFrame(&ack, &dataexchange.Frame{Type: dataexchange.TypeText, Payload: []byte(text)})
			push := make([]byte, 5+ack.Len())
			push[0] = tdCmdRecv
			binary.BigEndian.PutUint32(push[1:5], connID)
			copy(push[5:], ack.Bytes())
			out = append(out, push)
		}
		return out
	})
	return r
}

func (r *dxReceiver) seen() ([]uint32, []*dataexchange.Frame) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]uint32(nil), r.types...), append([]*dataexchange.Frame(nil), r.frames...)
}

func sendMessageJSON(t *testing.T, args ...string) map[string]interface{} {
	t.Helper()
	out := captureStdout(t, func() { withJSON(func() { cmdSendMessage(args) }) })
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	data, ok := env["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("no data object: %s", out)
	}
	return data
}

// A current receiver gets the message with its ID, and --reply-to is carried
// as reply_to. The JSON result reports the ID that was sent.
func TestSendMessageTagsEveryMessage(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	rcv := newDXReceiver(sd, func(_ uint32, _ []byte, f *dataexchange.Frame) string {
		return fmt.Sprintf("ACK %s %d bytes", dataexchange.TypeName(f.Type), len(f.Payload))
	})

	data := sendMessageJSON(t, "0:0000.0000.002A", "--data", "hello", "--reply-to", "req-42")
	types, frames := rcv.seen()
	if len(types) != 1 || types[0] != dataexchange.TypeTagged {
		t.Fatalf("receiver saw frame types %v, want one TAGGED frame", types)
	}
	f := frames[0]
	if f == nil || f.Type != dataexchange.TypeText || string(f.Payload) != "hello" {
		t.Fatalf("receiver decoded %+v", f)
	}
	if !dataexchange.ValidMessageID(f.MessageID) || f.ReplyTo != "req-42" {
		t.Fatalf("frame message_id=%q reply_to=%q", f.MessageID, f.ReplyTo)
	}
	if data["message_id"] != f.MessageID || data["tagged"] != true || data["reply_to"] != "req-42" || data["ack"] != "ACK TEXT 5 bytes" {
		t.Fatalf("result = %v; frame message_id %q", data, f.MessageID)
	}
}

// Each of several sends has an ID of its own: the receiver suppresses a
// second delivery of the same ID and bytes as a duplicate.
func TestSendMessageCountUsesAnIDPerSend(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	newDXReceiver(sd, func(uint32, []byte, *dataexchange.Frame) string { return "ACK TEXT 1 bytes" })
	multi := sendMessageJSON(t, "0:0000.0000.002A", "--data", "x", "--count", "3")
	ids := map[interface{}]bool{}
	for _, r := range multi["results"].([]interface{}) {
		ids[r.(map[string]interface{})["message_id"]] = true
	}
	if len(ids) != 3 || ids[nil] {
		t.Fatalf("--count 3 used message IDs %v, want three different ones", ids)
	}
}

// --trace keeps its TRACE wrapper and carries the ID outside it.
func TestSendMessageTraceIsTagged(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	rcv := newDXReceiver(sd, func(uint32, []byte, *dataexchange.Frame) string { return "ACK TEXT 5 bytes" })

	data := sendMessageJSON(t, "0:0000.0000.002A", "--data", "hello", "--trace")
	types, frames := rcv.seen()
	if len(types) != 1 || types[0] != dataexchange.TypeTagged || frames[0] == nil || frames[0].Type != dataexchange.TypeTrace {
		t.Fatalf("receiver saw types %v frame %+v, want one TAGGED frame wrapping TRACE", types, frames)
	}
	tf, err := dataexchange.ReadTracePayload(frames[0])
	if err != nil || tf.InnerType != dataexchange.TypeText || string(tf.Payload) != "hello" || tf.SentAtNs <= 0 {
		t.Fatalf("trace payload = %+v, %v", tf, err)
	}
	if data["message_id"] != frames[0].MessageID || data["tagged"] != true {
		t.Fatalf("result = %v; frame message_id %q", data, frames[0].MessageID)
	}
}

// A receiver that predates message IDs stores nothing for the tagged frame
// and says so in one of two ways, depending on its age. The message then
// reaches it in the old format, once, and the result says the ID did not get
// through.
func TestSendMessageReachesReceiversThatPredateMessageIDs(t *testing.T) {
	for name, unknownAck := range map[string]string{
		"dataexchange up to v0.2.1 (ACK for a frame it dropped)": "ACK UNKNOWN(10) %d bytes",
		"dataexchange v0.2.2 (rejects unknown types)":            "ERR UNKNOWN(10) save failed: unsupported frame type 10",
	} {
		t.Run(name, func(t *testing.T) {
			sd := newStreamDaemon(t)
			sd.useDaemonNoRegistry(t)
			var stored []string
			rcv := newDXReceiver(sd, func(ftype uint32, payload []byte, _ *dataexchange.Frame) string {
				if ftype != dataexchange.TypeText {
					if bytes.Contains([]byte(unknownAck), []byte("%d")) {
						return fmt.Sprintf(unknownAck, len(payload))
					}
					return unknownAck
				}
				stored = append(stored, string(payload))
				return fmt.Sprintf("ACK TEXT %d bytes", len(payload))
			})

			data := sendMessageJSON(t, "0:0000.0000.002A", "--data", "hello")
			types, _ := rcv.seen()
			if len(types) != 2 || types[0] != dataexchange.TypeTagged || types[1] != dataexchange.TypeText {
				t.Fatalf("old receiver saw frame types %v, want [TAGGED TEXT]", types)
			}
			if len(stored) != 1 || stored[0] != "hello" {
				t.Fatalf("old receiver stored %q, want exactly [hello]", stored)
			}
			if data["ack"] != "ACK TEXT 5 bytes" || data["tagged"] != false {
				t.Fatalf("result = %v, want the plain frame's ack and tagged=false", data)
			}
			if id, _ := data["message_id"].(string); !dataexchange.ValidMessageID(id) {
				t.Fatalf("result has no message_id: %v", data)
			}
		})
	}
}

// A receiver that could not store the message answers "ERR ...". The message
// is sent once (the fallback is only for receivers that do not know the
// frame), and the answer reaches the caller as it did when the message was
// sent untagged: as the ack, or, once send-message treats an "ERR " ack as a
// failed send, as that error.
func TestSendMessageReportsReceiverRejection(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	const rejection = "ERR TEXT save failed: no space left on device"
	rcv := newDXReceiver(sd, func(uint32, []byte, *dataexchange.Frame) string { return rejection })

	var stdout string
	var failure *trappedFatal
	withJSON(func() {
		stdout, _, failure = runTrapped(t, func() { cmdSendMessage([]string{"0:0000.0000.002A", "--data", "hello"}) })
	})
	if types, _ := rcv.seen(); len(types) != 1 {
		t.Fatalf("a rejected message was sent %d times, want once", len(types))
	}
	if failure != nil {
		if !strings.Contains(failure.Message, rejection) {
			t.Fatalf("send failed with %+v, want the receiver's rejection", failure)
		}
		return
	}
	if !strings.Contains(stdout, `"ack":"`+rejection+`"`) {
		t.Fatalf("result = %s, want the rejection as the ack", stdout)
	}
}

// End to end: the peer answers two requests at once and echoes each
// request's ID. The answer to the other request arrives first; --wait
// returns the one that names this request.
func TestSendMessageWaitTakesTheReplyToItsOwnRequest(t *testing.T) {
	sd := newStreamDaemon(t)
	home := sd.useDaemonNoRegistry(t)
	inbox := filepath.Join(home, ".pilot", "inbox")
	if err := os.MkdirAll(inbox, 0o700); err != nil {
		t.Fatal(err)
	}
	const peer = "0:0000.0000.002A"
	newDXReceiver(sd, func(_ uint32, _ []byte, f *dataexchange.Frame) string {
		if err := putInboxRecord(inbox, "TEXT-20260924-100005.000-000001.json", map[string]any{
			"from": peer, "data": "answer to somebody else's request", "reply_to": "somebody-else",
		}); err != nil {
			t.Error(err)
		}
		if err := putInboxRecord(inbox, "TEXT-20260924-100006.000-000002.json", map[string]any{
			"from": peer, "data": "pong", "reply_to": f.MessageID,
		}); err != nil {
			t.Error(err)
		}
		return "ACK TEXT 4 bytes"
	})

	data := sendMessageJSON(t, peer, "--data", "ping", "--wait", "5s")
	reply, ok := data["reply"].(map[string]interface{})
	if !ok {
		t.Fatalf("no reply in %v", data)
	}
	if reply["data"] != "pong" || reply["reply_to"] != data["message_id"] {
		t.Fatalf("reply = %v for message_id %v; want the answer to this request", reply, data["message_id"])
	}
}

func TestSendMessageRejectsInvalidReplyTo(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	for _, bad := range []string{"has space", "semi;colon", ""} {
		_, _, f := runTrapped(t, func() { cmdSendMessage([]string{"0:0000.0000.002A", "--data", "x", "--reply-to=" + bad}) })
		if f == nil || f.Code != "invalid_argument" {
			t.Errorf("--reply-to %q: %+v, want invalid_argument", bad, f)
		}
	}
}

// ── an untagged message ahead of our tagged reply ─────────────────────────

// storeEchoHistory puts an earlier answer from peer into the inbox, one
// that named a request in reply_to: the peer is known to echo IDs. It has
// to be there before the watch snapshots the inbox.
func storeEchoHistory(t *testing.T, dir, peer string) {
	t.Helper()
	writeInboxRecord(t, dir, "TEXT-20260924-090000.000-000000.json", map[string]any{
		"from": peer, "data": "an earlier answer", "reply_to": "an-earlier-request",
	})
}

// A peer with no echo history (every service responder today) has its
// untagged reply taken at once, even though our request was tagged. The
// inbox holds an earlier message from the peer without reply_to, and one
// from another peer with reply_to, which says nothing about this peer.
func TestAwaitReplyTakesAnUntaggedReplyAtOnceFromAPeerWithNoEchoHistory(t *testing.T) {
	dir := tempInbox(t)
	writeInboxRecord(t, dir, "TEXT-20260924-090000.000-000000.json", map[string]any{"from": replyPeer, "data": "an earlier answer"})
	storeEchoHistory(t, dir, "0:0000.0009.0001")
	watch := newInboxWatch(replyPeer)
	watch.addID("our-request")
	watch.markTagged()
	writeInboxRecord(t, dir, "TEXT-20260924-100005.000-000001.json", map[string]any{"from": replyPeer, "data": "the answer"})

	start := time.Now()
	out, err := awaitReply(watch, start, replyWait{wait: 5 * time.Second})
	if err != nil || out.reply == nil || out.reply["data"] != "the answer" {
		t.Fatalf("awaitReply = %+v, %v; want the untagged answer", out, err)
	}
	if el := time.Since(start); el >= atOnce {
		t.Fatalf("answer taken after %s; a peer with no echo history is not held back", el)
	}
}

// Our request reached the receiver with its ID, and the peer is known to
// echo IDs. First comes an untagged message from the peer (its answer to an
// untagged request another client on this host sent it), then, 400 ms
// later, the reply that names our request. The untagged one used to be
// taken at once.
func TestAwaitReplyHoldsAnUntaggedMessageForALaterTaggedReply(t *testing.T) {
	dir := tempInbox(t)
	storeEchoHistory(t, dir, replyPeer)
	watch := newInboxWatch(replyPeer)
	watch.addID("our-request")
	watch.markTagged()

	writeInboxRecord(t, dir, "TEXT-20260924-100005.000-000001.json", map[string]any{
		"from": replyPeer, "data": "answer to another client's untagged request",
	})
	written := putInboxRecordLater(t, 400*time.Millisecond, dir, "TEXT-20260924-100006.000-000002.json", map[string]any{
		"from": replyPeer, "data": "our answer", "reply_to": "our-request",
	})
	defer awaitClosed(t, written, "the tagged reply to be written")
	out, err := awaitReply(watch, time.Now(), replyWait{wait: 5 * time.Second})
	if err != nil || out.reply == nil || out.reply["data"] != "our answer" {
		t.Fatalf("awaitReply = %+v, %v; want the reply naming our request", out, err)
	}
}

// From a peer known to echo IDs, an untagged reply is held for the grace
// period, then taken when no reply naming our request came.
func TestAwaitReplyHoldsAnUntaggedReplyFromAPeerThatEchoedBefore(t *testing.T) {
	dir := tempInbox(t)
	storeEchoHistory(t, dir, replyPeer)
	watch := newInboxWatch(replyPeer)
	watch.addID("our-request")
	watch.markTagged()
	writeInboxRecord(t, dir, "TEXT-20260924-100005.000-000001.json", map[string]any{"from": replyPeer, "data": "the answer"})

	start := time.Now()
	out, err := awaitReply(watch, start, replyWait{wait: 5 * time.Second})
	if err != nil || out.reply == nil || out.reply["data"] != "the answer" {
		t.Fatalf("awaitReply = %+v, %v; want the untagged answer", out, err)
	}
	if el := time.Since(start); el < untaggedReplyGrace || el > untaggedReplyGrace+time.Second {
		t.Fatalf("answer taken after %s, want about %s", el, untaggedReplyGrace)
	}
}

// The grace period never outlasts the wait: when the wait ends first, the
// held message is the reply rather than a timeout.
func TestAwaitReplyTakesTheHeldMessageWhenTheWaitEnds(t *testing.T) {
	dir := tempInbox(t)
	storeEchoHistory(t, dir, replyPeer)
	watch := newInboxWatch(replyPeer)
	watch.addID("our-request")
	watch.markTagged()
	writeInboxRecord(t, dir, "TEXT-20260924-100005.000-000001.json", map[string]any{"from": replyPeer, "data": "the answer"})

	out, err := awaitReply(watch, time.Now(), replyWait{wait: 300 * time.Millisecond})
	if err != nil || out.reply == nil || out.reply["data"] != "the answer" {
		t.Fatalf("awaitReply = %+v, %v; want the held answer when the wait ends", out, err)
	}
}

// A request delivered without its ID (a receiver that predates IDs) cannot
// be named by any reply: an untagged message is taken at once, even from a
// peer known to echo IDs.
func TestAwaitReplyTakesAnUntaggedReplyAtOnceForAnUntaggedRequest(t *testing.T) {
	dir := tempInbox(t)
	storeEchoHistory(t, dir, replyPeer)
	watch := newInboxWatch(replyPeer)
	watch.addID("our-request")
	writeInboxRecord(t, dir, "TEXT-20260924-100005.000-000001.json", map[string]any{"from": replyPeer, "data": "the answer"})

	start := time.Now()
	out, err := awaitReply(watch, start, replyWait{wait: 5 * time.Second})
	if err != nil || out.reply == nil || out.reply["data"] != "the answer" {
		t.Fatalf("awaitReply = %+v, %v", out, err)
	}
	if el := time.Since(start); el >= atOnce {
		t.Fatalf("answer taken after %s; an untagged request has nothing to wait for", el)
	}
}

// A peer seen naming another request in reply_to during the wait echoes
// IDs, even with no history in the inbox, so an untagged message from it is
// not the answer to our tagged request, not even when the wait ends.
func TestAwaitReplyWantsATaggedReplyFromAPeerThatEchoesIDs(t *testing.T) {
	dir := tempInbox(t)
	watch := newInboxWatch(replyPeer)
	watch.addID("our-request")
	watch.markTagged()
	writeInboxRecord(t, dir, "TEXT-20260924-100005.000-000001.json", map[string]any{
		"from": replyPeer, "data": "answer to another request", "reply_to": "another-request",
	})
	writeInboxRecord(t, dir, "TEXT-20260924-100006.000-000002.json", map[string]any{
		"from": replyPeer, "data": "answer to an untagged request",
	})

	out, err := awaitReply(watch, time.Now(), replyWait{wait: 1200 * time.Millisecond})
	if err != nil || out.reply != nil {
		t.Fatalf("awaitReply = %+v, %v; want no reply", out, err)
	}
}

// The look for echo history stops after the newest echoHistoryPeerRecords
// records from the peer and the newest echoHistoryFiles records in all, so
// a big inbox does not slow the send.
func TestPeerEchoedBeforeIsBounded(t *testing.T) {
	echoed := func(dir string) bool {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		return peerEchoedBefore(dir, entries, replyPeer)
	}
	fill := func(dir, from string, n int) {
		for i := 0; i < n; i++ {
			writeInboxRecord(t, dir, fmt.Sprintf("TEXT-20260924-100000.000-%06d.json", i+1), map[string]any{"from": from, "data": "x"})
		}
	}

	dir := t.TempDir()
	storeEchoHistory(t, dir, replyPeer)
	fill(dir, replyPeer, echoHistoryPeerRecords-1)
	if !echoed(dir) {
		t.Fatalf("echo record behind %d newer records from the peer not found", echoHistoryPeerRecords-1)
	}
	fill(dir, replyPeer, echoHistoryPeerRecords)
	if echoed(dir) {
		t.Fatalf("echo record behind %d newer records from the peer was read", echoHistoryPeerRecords)
	}

	dir = t.TempDir()
	storeEchoHistory(t, dir, replyPeer)
	fill(dir, "0:0000.0009.0001", echoHistoryFiles)
	if echoed(dir) {
		t.Fatalf("echo record behind %d newer files was read", echoHistoryFiles)
	}

	// By bytes: past echoHistoryBytes nothing more is read. A record over
	// echoHistoryRecordBytes (a large message) is skipped, not read.
	big := func(dir, name string, size int) {
		writeInboxRecord(t, dir, name, map[string]any{"from": "0:0000.0009.0001", "data": strings.Repeat("x", size)})
	}
	dir = t.TempDir()
	storeEchoHistory(t, dir, replyPeer)
	half := echoHistoryRecordBytes / 2
	for i := 0; i <= echoHistoryBytes/half; i++ {
		big(dir, fmt.Sprintf("TEXT-20260924-100000.000-%06d.json", i+1), half)
	}
	if echoed(dir) {
		t.Fatalf("echo record behind %d MiB of newer records was read", echoHistoryBytes>>20)
	}
	dir = t.TempDir()
	storeEchoHistory(t, dir, replyPeer)
	big(dir, "TEXT-20260924-100000.000-000001.json", echoHistoryBytes)
	if !echoed(dir) {
		t.Fatal("a record as large as the byte budget stopped the scan instead of being skipped")
	}
}

// The echo-history scan runs beside the send: the request leaves while it
// is still running, and the scan is waited for only when the untagged reply
// has to be judged.
func TestSendMessageDoesNotWaitForTheEchoHistoryScan(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	var scanDone atomic.Bool
	defer func(old func(string, []os.DirEntry, string) bool) { peerEchoScan = old }(peerEchoScan)
	peerEchoScan = func(string, []os.DirEntry, string) bool {
		select {
		case <-release:
		case <-time.After(3 * time.Second):
		}
		scanDone.Store(true)
		return false
	}

	sd := newStreamDaemon(t)
	home := sd.useDaemonNoRegistry(t)
	inbox := filepath.Join(home, ".pilot", "inbox")
	if err := os.MkdirAll(inbox, 0o700); err != nil {
		t.Fatal(err)
	}
	const peer = "0:0000.0000.002A"
	var sentDuringScan atomic.Bool
	newDXReceiver(sd, func(uint32, []byte, *dataexchange.Frame) string {
		sentDuringScan.Store(!scanDone.Load())
		if err := putInboxRecord(inbox, "TEXT-20260924-100005.000-000001.json", map[string]any{"from": peer, "data": "pong"}); err != nil {
			t.Error(err)
		}
		releaseOnce.Do(func() { close(release) })
		return "ACK TEXT 4 bytes"
	})

	data := sendMessageJSON(t, peer, "--data", "ping", "--wait", "5s")
	if !sentDuringScan.Load() {
		t.Fatal("the request left only after the echo-history scan finished")
	}
	if reply, _ := data["reply"].(map[string]interface{}); reply == nil || reply["data"] != "pong" {
		t.Fatalf("result = %v; want the pong", data)
	}
}

// The hold runs from the message's arrival (its received_at), not from the
// poll that first sees it, and awaitReply polls again when it ends rather
// than at the next 250 ms tick: a message that arrived 50 ms short of the
// grace period before the first poll is taken about 50 ms later.
func TestAwaitReplyHoldEndsTheGracePeriodAfterArrival(t *testing.T) {
	dir := tempInbox(t)
	storeEchoHistory(t, dir, replyPeer)
	watch := newInboxWatch(replyPeer)
	watch.addID("our-request")
	watch.markTagged()
	const left = 50 * time.Millisecond
	ackAt := time.Now().Add(-(untaggedReplyGrace - left))
	writeInboxRecord(t, dir, "TEXT-20260924-100005.000-000001.json", map[string]any{
		"from": replyPeer, "data": "the answer", "received_at": ackAt.Add(time.Millisecond).Format(time.RFC3339Nano),
	})

	start := time.Now()
	out, err := awaitReply(watch, ackAt, replyWait{wait: 5 * time.Second})
	if err != nil || out.reply == nil || out.reply["data"] != "the answer" {
		t.Fatalf("awaitReply = %+v, %v; want the untagged answer", out, err)
	}
	if el := time.Since(start); el < left-20*time.Millisecond || el >= replyPollInterval-50*time.Millisecond {
		t.Fatalf("answer taken %s after the first poll, want about %s", el, left)
	}
}

// An untagged message that arrived before our request was acknowledged (a
// slow first-contact dial, a large payload, a lost-ack retry) is held for
// the whole grace period from the acknowledgement, not from its arrival. In
// review it was taken at the first poll, ahead of our tagged reply.
func TestAwaitReplyHoldStartsNoEarlierThanTheAck(t *testing.T) {
	dir := tempInbox(t)
	storeEchoHistory(t, dir, replyPeer)
	watch := newInboxWatch(replyPeer)
	watch.addID("our-request")
	watch.markTagged()
	ackAt := time.Now()
	writeInboxRecord(t, dir, "TEXT-20260924-100005.000-000001.json", map[string]any{
		"from": replyPeer, "data": "something else", "received_at": ackAt.Add(-untaggedReplyGrace).Format(time.RFC3339Nano),
	})
	go func() {
		time.Sleep(200 * time.Millisecond)
		if err := putInboxRecord(dir, "TEXT-20260924-100006.000-000002.json", map[string]any{
			"from": replyPeer, "data": "the answer", "reply_to": "our-request",
		}); err != nil {
			t.Error(err)
		}
	}()
	out, err := awaitReply(watch, ackAt, replyWait{wait: 5 * time.Second})
	if err != nil || out.reply == nil || out.reply["data"] != "the answer" {
		t.Fatalf("awaitReply = %+v, %v; want the tagged answer, not the earlier untagged message", out, err)
	}
}

// Through send-message, to a peer with no echo history: the request is
// tagged, and the peer's untagged reply is returned without a hold.
func TestSendMessageWaitTakesAnUntaggedReplyAtOnceWithoutEchoHistory(t *testing.T) {
	sd := newStreamDaemon(t)
	home := sd.useDaemonNoRegistry(t)
	inbox := filepath.Join(home, ".pilot", "inbox")
	if err := os.MkdirAll(inbox, 0o700); err != nil {
		t.Fatal(err)
	}
	const peer = "0:0000.0000.002A"
	newDXReceiver(sd, func(uint32, []byte, *dataexchange.Frame) string {
		if err := putInboxRecord(inbox, "TEXT-20260924-100005.000-000001.json", map[string]any{"from": peer, "data": "pong"}); err != nil {
			t.Error(err)
		}
		return "ACK TEXT 4 bytes"
	})

	data := sendMessageJSON(t, peer, "--data", "ping", "--wait", "5s")
	reply, _ := data["reply"].(map[string]interface{})
	if reply == nil || reply["data"] != "pong" || data["tagged"] != true {
		t.Fatalf("result = %v; want the untagged pong for a tagged request", data)
	}
	if ms, _ := data["reply_after_ms"].(float64); ms >= float64(atOnce.Milliseconds()) {
		t.Fatalf("reply taken after %v ms; a peer with no echo history is not held back", ms)
	}
}

// The same through send-message, to a peer known to echo IDs: the request
// is tagged; the peer's untagged message lands first and the reply naming
// the request 400 ms later.
func TestSendMessageWaitHoldsAnUntaggedMessageForItsTaggedReply(t *testing.T) {
	sd := newStreamDaemon(t)
	home := sd.useDaemonNoRegistry(t)
	inbox := filepath.Join(home, ".pilot", "inbox")
	if err := os.MkdirAll(inbox, 0o700); err != nil {
		t.Fatal(err)
	}
	const peer = "0:0000.0000.002A"
	storeEchoHistory(t, inbox, peer)
	written := make(chan (<-chan struct{}), 1)
	newDXReceiver(sd, func(_ uint32, _ []byte, f *dataexchange.Frame) string {
		if err := putInboxRecord(inbox, "TEXT-20260924-100005.000-000001.json", map[string]any{
			"from": peer, "data": "answer to another client's untagged request",
		}); err != nil {
			t.Error(err)
		}
		written <- putInboxRecordLater(t, 400*time.Millisecond, inbox, "TEXT-20260924-100006.000-000002.json", map[string]any{
			"from": peer, "data": "pong", "reply_to": f.MessageID,
		})
		return "ACK TEXT 4 bytes"
	})

	data := sendMessageJSON(t, peer, "--data", "ping", "--wait", "5s")
	select {
	case w := <-written:
		awaitClosed(t, w, "the tagged reply to be written")
	case <-time.After(5 * time.Second):
		t.Fatal("the receiver never got the request")
	}
	reply, _ := data["reply"].(map[string]interface{})
	if reply == nil || reply["data"] != "pong" || reply["reply_to"] != data["message_id"] {
		t.Fatalf("reply = %v for message_id %v; want the answer to this request", reply, data["message_id"])
	}
}

// ── --reply-to values ─────────────────────────────────────────────────────

// withoutDaemon points pilotctl at a socket nobody listens on: a --reply-to
// value that got past validation fails on connecting instead.
func withoutDaemon(t *testing.T) {
	t.Helper()
	t.Setenv("PILOT_SOCKET", filepath.Join(t.TempDir(), "no-daemon.sock"))
}

// A bare --reply-to parses as "true", a valid message ID, which no request
// was ever sent with.
func TestSendMessageRejectsABareReplyTo(t *testing.T) {
	withTempHomeFull(t)
	withoutDaemon(t)
	for _, args := range [][]string{
		{"0:0000.0000.002A", "--data", "x", "--reply-to"},
		{"0:0000.0000.002A", "--reply-to", "--data", "x"},
	} {
		_, _, f := runTrapped(t, func() { cmdSendMessage(args) })
		if f == nil || f.Code != "invalid_argument" || !strings.Contains(f.Message, "needs a value") {
			t.Errorf("%v: %+v, want invalid_argument asking for a value", args, f)
		}
	}
}

// The id `pilotctl inbox` lists is the record's file name. Given as
// --reply-to, it is replaced by the message_id stored in that record.
func TestSendMessageReplyToLooksUpAnInboxID(t *testing.T) {
	sd := newStreamDaemon(t)
	home := sd.useDaemonNoRegistry(t)
	inbox := filepath.Join(home, ".pilot", "inbox")
	if err := os.MkdirAll(inbox, 0o700); err != nil {
		t.Fatal(err)
	}
	const requestID = "5d1e9c0a7b3f4e21a8c6d0b9e2f71a34"
	writeInboxRecord(t, inbox, "TEXT-20260924-100005.000-000001.json", map[string]any{
		"from": "0:0000.0000.002A", "data": "ping", "message_id": requestID,
	})
	rcv := newDXReceiver(sd, func(uint32, []byte, *dataexchange.Frame) string { return "ACK TEXT 4 bytes" })

	data := sendMessageJSON(t, "0:0000.0000.002A", "--data", "pong", "--reply-to", "TEXT-20260924-100005.000-000001")
	_, frames := rcv.seen()
	if len(frames) != 1 || frames[0] == nil || frames[0].ReplyTo != requestID {
		t.Fatalf("receiver got %+v, want reply_to %s", frames, requestID)
	}
	if data["reply_to"] != requestID {
		t.Fatalf("result reply_to = %v, want %s", data["reply_to"], requestID)
	}
	// The file name as ls shows it, with .json, is looked up the same way.
	if got, err := resolveReplyTo("TEXT-20260924-100005.000-000001.json"); err != nil || got != requestID {
		t.Fatalf("--reply-to with .json = %q, %v; want %s", got, err, requestID)
	}
}

// An inbox id whose record has no message_id (or no record at all) has no
// ID to name: refused before anything is sent.
func TestSendMessageReplyToRefusesAnInboxIDWithoutMessageID(t *testing.T) {
	inbox := tempInbox(t)
	withoutDaemon(t)
	writeInboxRecord(t, inbox, "TEXT-20260924-100005.000-000001.json", map[string]any{"from": "0:0000.0000.002A", "data": "ping"})
	for id, want := range map[string]string{
		"TEXT-20260924-100005.000-000001": "carries no message_id",
		"TEXT-20260924-100009.000-000009": "not a message_id",
	} {
		_, _, f := runTrapped(t, func() { cmdSendMessage([]string{"0:0000.0000.002A", "--data", "x", "--reply-to", id}) })
		if f == nil || f.Code != "invalid_argument" || !strings.Contains(f.Message, want) {
			t.Errorf("--reply-to %s: %+v, want invalid_argument %q", id, f, want)
		}
	}
}

// ── the inbox shows message_id and reply_to ───────────────────────────────

func TestInboxShowsMessageIDAndReplyTo(t *testing.T) {
	dir := tempInbox(t)
	for name, rec := range map[string]map[string]any{
		"TEXT-20260924-100004.000-000000.json": {"from": replyPeer, "type": "TEXT", "data": "untagged", "bytes": 8, "received_at": "2026-09-24T10:00:04Z"},
		"TEXT-20260924-100005.000-000001.json": {"from": replyPeer, "type": "TEXT", "data": "ping", "bytes": 4, "received_at": "2026-09-24T10:00:05Z", "message_id": "req-1"},
		"TEXT-20260924-100006.000-000002.json": {"from": replyPeer, "type": "TEXT", "data": "pong", "bytes": 4, "received_at": "2026-09-24T10:00:06Z", "message_id": "ans-1", "reply_to": "req-1"},
	} {
		writeInboxRecord(t, dir, name, rec)
	}

	var env struct {
		Data struct {
			Messages []map[string]interface{} `json:"messages"`
		} `json:"data"`
	}
	out := captureStdout(t, func() { withJSON(func() { cmdInbox(nil) }) })
	if err := json.Unmarshal([]byte(out), &env); err != nil || len(env.Data.Messages) != 3 {
		t.Fatalf("inbox --json: %v\n%s", err, out)
	}
	byID := map[string]map[string]interface{}{}
	for _, m := range env.Data.Messages {
		byID[m["id"].(string)] = m
	}
	if m := byID["TEXT-20260924-100005.000-000001"]; m["message_id"] != "req-1" || m["from"] != replyPeer || m["preview"] != "ping" {
		t.Errorf("request entry = %v", m)
	}
	if m := byID["TEXT-20260924-100006.000-000002"]; m["message_id"] != "ans-1" || m["reply_to"] != "req-1" {
		t.Errorf("answer entry = %v", m)
	}
	m := byID["TEXT-20260924-100004.000-000000"]
	if _, has := m["message_id"]; has {
		t.Errorf("untagged entry = %v, want no message_id", m)
	}
	if _, has := m["reply_to"]; has {
		t.Errorf("untagged entry = %v, want no reply_to", m)
	}

	text := captureStdout(t, func() { withText(func() { cmdInbox(nil) }) })
	for _, want := range []string{"message_id req-1", "message_id ans-1 · reply_to req-1"} {
		if !strings.Contains(text, want) {
			t.Errorf("inbox listing lacks %q:\n%s", want, text)
		}
	}
	read := captureStdout(t, func() { withText(func() { cmdInbox([]string{"read", "TEXT-20260924-100006.000-000002"}) }) })
	for _, want := range []string{"ID:         TEXT-20260924-100006.000-000002\n", "Bytes:      4\n", "Message ID: ans-1\n", "Reply to:   req-1\n"} {
		if !strings.Contains(read, want) {
			t.Errorf("inbox read lacks %q:\n%s", want, read)
		}
	}
}

// ── a lost ack ────────────────────────────────────────────────────────────

// The first connection drops before the receiver's ack comes back.
func TestSendMessageSendsAgainWhenTheAckIsLost(t *testing.T) {
	const peer = "0:0000.0000.002A"

	// A receiver through v1.13.9 stored nothing for the tagged frame. Sent
	// again on a new connection, the message reaches it untagged, once.
	t.Run("receiver that predates message IDs", func(t *testing.T) {
		sd := newStreamDaemon(t)
		sd.useDaemonNoRegistry(t)
		calls := 0
		var stored []string
		rcv := newDXReceiver(sd, func(ftype uint32, payload []byte, _ *dataexchange.Frame) string {
			calls++
			if calls == 1 {
				return dxDropConnection
			}
			if ftype != dataexchange.TypeText {
				return fmt.Sprintf("ACK UNKNOWN(10) %d bytes", len(payload))
			}
			stored = append(stored, string(payload))
			return fmt.Sprintf("ACK TEXT %d bytes", len(payload))
		})

		data := sendMessageJSON(t, peer, "--data", "hello")
		types, _ := rcv.seen()
		if len(types) != 3 || types[0] != dataexchange.TypeTagged || types[1] != dataexchange.TypeTagged || types[2] != dataexchange.TypeText {
			t.Fatalf("receiver saw frame types %v, want [TAGGED TAGGED TEXT]", types)
		}
		if len(stored) != 1 || stored[0] != "hello" {
			t.Fatalf("receiver stored %q, want exactly [hello]", stored)
		}
		if data["retried"] != true || data["tagged"] != false || data["ack"] != "ACK TEXT 5 bytes" {
			t.Fatalf("result = %v", data)
		}
	})

	// A receiver that knows message IDs may have stored the first copy. The
	// second carries the same ID, which it recognises as a repeat.
	t.Run("receiver that knows message IDs", func(t *testing.T) {
		sd := newStreamDaemon(t)
		sd.useDaemonNoRegistry(t)
		calls := 0
		rcv := newDXReceiver(sd, func(uint32, []byte, *dataexchange.Frame) string {
			calls++
			if calls == 1 {
				return dxDropConnection
			}
			return "ACK TEXT 5 bytes (duplicate)"
		})

		data := sendMessageJSON(t, peer, "--data", "hello")
		_, frames := rcv.seen()
		if len(frames) != 2 || frames[0] == nil || frames[1] == nil {
			t.Fatalf("receiver saw %+v, want two frames", frames)
		}
		if frames[0].MessageID != frames[1].MessageID || frames[0].MessageID != data["message_id"] {
			t.Fatalf("message IDs %q then %q (result %v), want the same one twice", frames[0].MessageID, frames[1].MessageID, data["message_id"])
		}
		if data["retried"] != true || data["tagged"] != true {
			t.Fatalf("result = %v", data)
		}
	})

	// The retry is lost too: the message was sent twice before the send was
	// judged, and with no ack at all it fails, with the retry's ack error.
	t.Run("retry unacknowledged too", func(t *testing.T) {
		sd := newStreamDaemon(t)
		sd.useDaemonNoRegistry(t)
		calls := 0
		rcv := newDXReceiver(sd, func(uint32, []byte, *dataexchange.Frame) string {
			if calls++; calls == 1 {
				return dxDropConnection
			}
			return dxCutAck
		})

		var f *trappedFatal
		withJSON(func() {
			_, _, f = runTrapped(t, func() { cmdSendMessage([]string{peer, "--data", "hello"}) })
		})
		if f == nil || f.Code != "connection_failed" || !strings.Contains(f.Message, "did not acknowledge") || !strings.HasSuffix(f.Message, ": dataexchange: read ack: unexpected EOF") || strings.Contains(f.Message, "sending again failed") {
			t.Fatalf("send = %+v, want connection_failed: not acknowledged, with only the retry's ack error", f)
		}
		if types, _ := rcv.seen(); len(types) != 2 {
			t.Fatalf("receiver saw frame types %v, want the message and its retry", types)
		}
	})

	// --trace: receivers do not suppress a repeated trace frame, so even a
	// current receiver would store the message twice. It is sent once, and
	// with no ack the send fails.
	t.Run("--trace", func(t *testing.T) {
		sd := newStreamDaemon(t)
		sd.useDaemonNoRegistry(t)
		rcv := newDXReceiver(sd, func(uint32, []byte, *dataexchange.Frame) string { return dxDropConnection })

		var f *trappedFatal
		withJSON(func() {
			_, _, f = runTrapped(t, func() { cmdSendMessage([]string{peer, "--data", "hello", "--trace"}) })
		})
		if f == nil || f.Code != "connection_failed" || !strings.Contains(f.Message, "did not acknowledge") {
			t.Fatalf("send = %+v, want connection_failed: not acknowledged", f)
		}
		if types, _ := rcv.seen(); len(types) != 1 {
			t.Fatalf("receiver saw frame types %v, want the traced message once", types)
		}
	})

	// --no-resend: sent once, and with no ack the send fails. Whether the
	// receiver got the ID is not known without its ack, so the result does
	// not claim either.
	t.Run("--no-resend", func(t *testing.T) {
		sd := newStreamDaemon(t)
		sd.useDaemonNoRegistry(t)
		rcv := newDXReceiver(sd, func(uint32, []byte, *dataexchange.Frame) string { return dxDropConnection })
		t.Cleanup(func() { fatalResults = nil })

		var stderr string
		var f *trappedFatal
		withJSON(func() {
			_, stderr, f = runTrapped(t, func() { cmdSendMessage([]string{peer, "--data", "hello", "--no-resend", "--count", "2"}) })
		})
		if f == nil || f.Code != "connection_failed" || !strings.Contains(f.Message, "not acknowledged") {
			t.Fatalf("send = %+v, want connection_failed for the unacknowledged messages", f)
		}
		if types, _ := rcv.seen(); len(types) != 2 {
			t.Fatalf("receiver saw frame types %v, want one frame per message", types)
		}
		var env struct {
			Results []map[string]interface{} `json:"results"`
		}
		if err := json.Unmarshal([]byte(stderr[strings.Index(stderr, "{"):]), &env); err != nil || len(env.Results) != 2 {
			t.Fatalf("error envelope: %v\n%s", err, stderr)
		}
		for _, r := range env.Results {
			for _, key := range []string{"tagged", "retried", "ack"} {
				if v, has := r[key]; has {
					t.Errorf("result has %s=%v: %v", key, v, r)
				}
			}
			if _, has := r["ack_error"]; !has {
				t.Errorf("result has no ack_error: %v", r)
			}
		}
	})
}

// ── --reuse-conn after a lost ack ─────────────────────────────────────────

// dials is how many connections the client has dialled.
func (sd *streamDaemon) dials() int {
	sd.streamMu.Lock()
	defer sd.streamMu.Unlock()
	return len(sd.dialed)
}

// errorResults decodes the "results" in the --json error envelope a failed
// command printed to stderr.
func errorResults(t *testing.T, stderr string) []map[string]interface{} {
	t.Helper()
	var env struct {
		Results []map[string]interface{} `json:"results"`
	}
	i := strings.Index(stderr, "{")
	if i < 0 {
		t.Fatalf("no error envelope in stderr:\n%s", stderr)
	}
	if err := json.Unmarshal([]byte(stderr[i:]), &env); err != nil {
		t.Fatalf("error envelope: %v\n%s", err, stderr)
	}
	return env.Results
}

// The first message's ack is lost, so the shared connection is gone: no read
// deadline is set, so the ack read failed because the connection ended, and
// writes to it would still "succeed" (the driver only notices a local close)
// and be dropped. The messages after it go on the retry's connection, which
// is still open: two dials in all and one retry, and only the later messages
// are reported as reused. Each of them used to be written into the dead
// connection, lose its ack and be sent again on a new one.
func TestSendMessageReuseConnContinuesOnTheRetrysConnection(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	calls := 0
	rcv := newDXReceiver(sd, func(uint32, []byte, *dataexchange.Frame) string {
		if calls++; calls == 1 {
			return dxDropConnection
		}
		return "ACK TEXT 5 bytes"
	})

	data := sendMessageJSON(t, "0:0000.0000.002A", "--data", "hello", "--count", "3", "--reuse-conn")
	if n := sd.dials(); n != 2 {
		t.Errorf("%d dials, want 2: the shared connection and the retry's", n)
	}
	if types, _ := rcv.seen(); len(types) != 4 {
		t.Errorf("receiver got %d frames, want 4: the lost one, its retry and two more", len(types))
	}
	results, _ := data["results"].([]interface{})
	if len(results) != 3 {
		t.Fatalf("results = %v, want 3", data["results"])
	}
	for i, want := range []struct{ retried, reused bool }{{true, false}, {false, true}, {false, true}} {
		r := results[i].(map[string]interface{})
		if retried, _ := r["retried"].(bool); retried != want.retried || r["reused"] != want.reused || r["ack"] != "ACK TEXT 5 bytes" {
			t.Errorf("message %d = %v, want retried=%v reused=%v", i, r, want.retried, want.reused)
		}
	}
}

// With --no-resend the message whose ack was lost is not sent again, and its
// connection is gone: the next message goes on a new one. One message of
// three is undelivered, where all three used to be.
func TestSendMessageReuseConnRedialsAfterALostAckWithoutResend(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	fatalResults = nil
	t.Cleanup(func() { fatalResults = nil })
	calls := 0
	newDXReceiver(sd, func(uint32, []byte, *dataexchange.Frame) string {
		if calls++; calls == 1 {
			return dxDropConnection
		}
		return "ACK TEXT 5 bytes"
	})

	var stderr string
	var f *trappedFatal
	withJSON(func() {
		_, stderr, f = runTrapped(t, func() {
			cmdSendMessage([]string{"0:0000.0000.002A", "--data", "hello", "--count", "3", "--reuse-conn", "--no-resend"})
		})
	})
	if f == nil || f.Code != "connection_failed" || !strings.HasPrefix(f.Message, "1 of 3 messages") {
		t.Fatalf("send = %+v, want connection_failed for 1 of 3 messages", f)
	}
	if n := sd.dials(); n != 2 {
		t.Errorf("%d dials, want 2: the shared connection and the one after it was lost", n)
	}
	results := errorResults(t, stderr)
	if len(results) != 3 {
		t.Fatalf("results = %v, want 3", results)
	}
	if _, acked := results[0]["ack"]; acked || results[0]["ack_error"] == nil || results[0]["retried"] != nil {
		t.Errorf("message 0 = %v, want unacknowledged and not sent again", results[0])
	}
	for i, reused := range []bool{false, true} {
		if r := results[i+1]; r["ack"] != "ACK TEXT 5 bytes" || r["reused"] != reused {
			t.Errorf("message %d = %v, want acknowledged with reused=%v", i+1, r, reused)
		}
	}
}

// The new connection for the message after a lost one cannot be dialled:
// that message fails with the reason, and the one after it dials again.
func TestSendMessageReuseConnReportsAFailedRedialAndGoesOn(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	fatalResults = nil
	t.Cleanup(func() { fatalResults = nil })
	sd.mu.Lock()
	accept := sd.handlers[tdCmdDial]
	sd.mu.Unlock()
	var attempts atomic.Int32
	sd.on(tdCmdDial, func(frame []byte) [][]byte {
		if attempts.Add(1) == 2 {
			return [][]byte{append([]byte{tdCmdError, 0, 1}, "dial timeout"...)}
		}
		return accept(frame)
	})
	calls := 0
	newDXReceiver(sd, func(uint32, []byte, *dataexchange.Frame) string {
		if calls++; calls == 1 {
			return dxDropConnection
		}
		return "ACK TEXT 5 bytes"
	})

	var stderr string
	var f *trappedFatal
	withJSON(func() {
		_, stderr, f = runTrapped(t, func() {
			cmdSendMessage([]string{"0:0000.0000.002A", "--data", "hello", "--count", "3", "--reuse-conn", "--no-resend"})
		})
	})
	if f == nil || !strings.HasPrefix(f.Message, "2 of 3 messages") {
		t.Fatalf("send = %+v, want 2 of 3 messages undelivered", f)
	}
	results := errorResults(t, stderr)
	if len(results) != 3 {
		t.Fatalf("results = %v, want 3", results)
	}
	if e, _ := results[1]["error"].(string); !strings.Contains(e, "cannot connect") || !strings.Contains(e, "dial timeout") {
		t.Errorf("message 1 = %v, want the dial failure", results[1])
	}
	if r := results[2]; r["ack"] != "ACK TEXT 5 bytes" || r["reused"] != false {
		t.Errorf("message 2 = %v, want acknowledged on a new connection", r)
	}
}

// A message whose first ack was lost and whose retry was acknowledged was
// delivered: a --count run with it succeeds.
func TestUndeliveredCountsARetriedAndAcknowledgedMessageAsDelivered(t *testing.T) {
	results := []map[string]interface{}{
		{"seq": 0, "ack": "ACK TEXT 5 bytes", "retried": true, "tagged": true},
		{"seq": 1, "ack": "ACK TEXT 5 bytes"},
	}
	if failed, _, first := undelivered(results); failed != 0 {
		t.Fatalf("undelivered = %d (%s), want 0", failed, first)
	}
}
