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
	"testing"

	"github.com/pilot-protocol/dataexchange"
)

func writeInboxRecord(t *testing.T, dir, name string, rec map[string]any) {
	t.Helper()
	body, _ := json.Marshal(rec)
	if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

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

// dxReceiver turns the stream daemon's echo into a data-exchange receiver:
// answer is called with each complete wire frame (its type and payload) the
// client wrote and returns the acknowledgement text.
type dxReceiver struct {
	mu     sync.Mutex
	buf    map[uint32][]byte
	types  []uint32
	frames []*dataexchange.Frame // decoded with the current library
}

func newDXReceiver(sd *streamDaemon, answer func(ftype uint32, payload []byte, decoded *dataexchange.Frame) string) *dxReceiver {
	r := &dxReceiver{buf: map[uint32][]byte{}}
	sd.on(tdCmdSend, func(frame []byte) [][]byte {
		sd.sendCount.Add(1)
		if len(frame) < 5 {
			return nil
		}
		connID := binary.BigEndian.Uint32(frame[1:5])
		r.mu.Lock()
		defer r.mu.Unlock()
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
			var ack bytes.Buffer
			_ = dataexchange.WriteFrame(&ack, &dataexchange.Frame{Type: dataexchange.TypeText, Payload: []byte(answer(ftype, payload, decoded))})
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
		writeInboxRecord(t, inbox, "TEXT-20260924-100005.000-000001.json", map[string]any{
			"from": peer, "data": "answer to somebody else's request", "reply_to": "somebody-else",
		})
		writeInboxRecord(t, inbox, "TEXT-20260924-100006.000-000002.json", map[string]any{
			"from": peer, "data": "pong", "reply_to": f.MessageID,
		})
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
