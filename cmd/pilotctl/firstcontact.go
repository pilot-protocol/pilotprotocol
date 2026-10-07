// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// First-contact request/reply for send-message --wait.
//
// A fresh node's first query to a service (the onboarding step
// `pilotctl send-message list-agents --data ... --wait`) has to build the
// whole path inside one command: resolve the peer, key exchange, SYN,
// the request, then the service's reply, which comes back on a NEW
// connection the service dials to our port 1001. Measured on clean
// GitHub runners the first query failed most of the time, for reasons
// that stack:
//
//   - the reply SYN was dropped by our own private-node trust gate until
//     a trust handshake with the service finished (fixed in the daemon:
//     reply window, replywindow.go);
//   - pilotctl blocked up to ~22 s on that handshake before it even
//     dialed, eating the dial budget;
//   - the dial spent its SYN retries while the key exchange was still
//     running (fixed in the daemon: dial_awaits_key);
//   - the service answers once, from a responder with a sub-second send
//     budget, so a reply lost while the service's side of the new path is
//     still settling is never retried.
//
// This file holds the client half: detect what the daemon supports,
// dial with one retry while the path is still converging, match the
// reply to this request, re-send the request once on a new stream when a
// first-contact reply does not show up, and say which step failed.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pilot-protocol/common/driver"
	"github.com/pilot-protocol/common/protocol"
)

// daemonFeatureSet caches the "features" list of the daemon's info reply
// for the life of this process (it only changes when the daemon does).
var daemonFeatureSet map[string]bool

// daemonHasFeature reports whether the local daemon advertises feature
// (see daemonFeatures in pkg/daemon/ipc.go). An older daemon reports no
// features, so every caller falls back to the behaviour it had before.
func daemonHasFeature(d *driver.Driver, feature string) bool {
	if daemonFeatureSet == nil {
		daemonFeatureSet = map[string]bool{}
		if info, err := d.Info(); err == nil {
			for f := range featuresOf(info) {
				daemonFeatureSet[f] = true
			}
		}
	}
	return daemonFeatureSet[feature]
}

func featuresOf(info map[string]interface{}) map[string]bool {
	out := map[string]bool{}
	list, _ := info["features"].([]interface{})
	for _, v := range list {
		if s, ok := v.(string); ok {
			out[s] = true
		}
	}
	return out
}

// peerSessionUp reports whether the daemon already holds an encrypted
// session with node: if not, this command is making first contact.
func peerSessionUp(info map[string]interface{}, node uint32) bool {
	list, _ := info["peer_list"].([]interface{})
	for _, v := range list {
		p, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		if id, ok := p["node_id"].(float64); ok && uint32(id) == node {
			enc, _ := p["encrypted"].(bool)
			return enc
		}
	}
	return false
}

// replyConnsFrom counts inbound data-exchange connections from target in
// the daemon's connection table: the service dialing its reply back.
func replyConnsFrom(info map[string]interface{}, target string) int {
	list, _ := info["conn_list"].([]interface{})
	n := 0
	for _, v := range list {
		c, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		lp, _ := c["local_port"].(float64)
		ra, _ := c["remote_addr"].(string)
		if uint16(lp) == protocol.PortDataExchange && ra == target {
			n++
		}
	}
	return n
}

// isConvergingDialError reports whether a failed dial is worth one more
// try on first contact: the peer did not answer in time (key exchange
// or SYN), as opposed to a refusal or a local error.
func isConvergingDialError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "dial timeout") || strings.Contains(s, "key exchange")
}

// isDriverSideTimeout reports whether the dial error is the SDK giving up
// on the IPC reply (the daemon may still be dialing), as opposed to an
// error the daemon returned.
func isDriverSideTimeout(err error) bool {
	return err != nil && strings.Contains(err.Error(), "dial timeout") && !strings.Contains(err.Error(), "daemon:")
}

// dialFailureHint explains a failed data-exchange dial.
func dialFailureHint(target string, err error, attempts int, elapsed time.Duration) string {
	s := ""
	if err != nil {
		s = err.Error()
	}
	switch {
	case strings.Contains(s, "ephemeral ports exhausted"):
		// A local condition: the peer was never contacted, so pointing at
		// its reachability sends the operator the wrong way.
		return "this node has no free local ports for a new connection; close idle connections (`pilotctl connections`) or restart the daemon"
	case strings.Contains(s, "key exchange"):
		return fmt.Sprintf("%s never completed the tunnel key exchange (%d dial attempt(s), %s): the service is overloaded or offline. "+
			"Retry in a minute; `pilotctl peers` shows the tunnel state.", target, attempts, elapsed.Round(time.Second))
	case strings.Contains(s, "dial timeout"):
		return fmt.Sprintf("%s did not accept a connection on port %d (%d dial attempt(s), %s). "+
			"It may be overloaded; retry in a minute or check reachability with `pilotctl ping %s`.",
			target, protocol.PortDataExchange, attempts, elapsed.Round(time.Second), target)
	}
	if h := classifyDaemonError(err); h != "" {
		return h
	}
	return fmt.Sprintf("check that %s is reachable: pilotctl ping %s", target, target)
}

// inboxWatch finds the reply to one request in the inbox. It snapshots
// the files present before the request is sent, so a reply to an
// earlier request (or the late duplicate some services send) that is
// already sitting in the inbox is never taken for this one.
//
// Which new message is the reply:
//
//   - Every request is sent with a message ID (addID). A message from the
//     peer whose reply_to is one of our IDs is the reply, whatever else
//     arrived before it.
//   - A message whose reply_to names some other request is never taken: it
//     answers another send-message --wait to the same peer.
//   - A message without reply_to comes from a peer that does not echo the
//     ID (every responder older than this, and old daemons, which drop the
//     ID). The oldest such message from the peer is taken, as before IDs
//     existed. Two concurrent requests to such a peer, or anything else it
//     sends in the window, still cannot be told apart.
//   - From a peer known to echo IDs, an untagged message can instead be the
//     answer to someone else's untagged request, with our own tagged reply
//     still on its way. A peer is known to echo when one of its earlier
//     messages in the inbox carries a reply_to (peerEchoedBefore). If our
//     request reached the receiver with its ID (markTagged), an untagged
//     message from such a peer is held for untaggedReplyGrace first, and
//     taken only if no reply naming our request arrives meanwhile (or when
//     the wait ends). Holding replies from peers with no such history would
//     only delay them: no service responder echoes IDs yet.
//   - Once the peer has been seen naming another request in reply_to during
//     this wait, it evidently echoes IDs, and only a reply naming ours is
//     taken.
type inboxWatch struct {
	dir    string
	from   string
	cutoff time.Time
	seen   map[string]bool

	// echoedBefore is set by newInboxWatch and only read afterwards: an
	// earlier message from the peer in the inbox carries a reply_to.
	echoedBefore bool

	mu     sync.Mutex
	ids    map[string]bool // message IDs of our request (and of its re-send)
	tagged bool            // a request of ours reached the receiver with its ID

	// Used only by the goroutine that polls.
	peerEchoes bool                   // the peer named another request in reply_to
	held       map[string]interface{} // untagged message held back (see untaggedReply)
	heldSince  time.Time
}

// untaggedReplyGrace is how long an untagged message from a peer known to
// echo IDs is held back, after our request reached the receiver with its
// ID, in case the reply that names our request follows. Replies from such
// a peer normally name our request and are not delayed at all. The
// send-message help quotes this value.
const untaggedReplyGrace = 750 * time.Millisecond

// The look for a peer's echo history reads at most echoHistoryFiles of the
// newest inbox records, and stops after echoHistoryPeerRecords of them from
// the peer: the sender is only known once a record is read, and a big inbox
// must not slow the send. A peer whose last reply_to lies further back is
// treated as not echoing, which is how every peer was treated before.
const (
	echoHistoryPeerRecords = 200
	echoHistoryFiles       = 1000
)

func inboxDirPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".pilot", "inbox"), nil
}

// newInboxWatch snapshots the inbox now. from is the sender address the
// daemon writes into each inbox record ("" matches any sender).
func newInboxWatch(from string) *inboxWatch {
	w := &inboxWatch{from: from, cutoff: time.Now().Add(-time.Second), seen: map[string]bool{}}
	dir, err := inboxDirPath()
	if err != nil {
		return w
	}
	w.dir = dir
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			w.seen[e.Name()] = true
		}
		w.echoedBefore = peerEchoedBefore(dir, entries, from)
	}
	return w
}

// inboxNameKey orders inbox files by arrival. Their names are
// {TYPE}-{timestamp}-{seq}.json, so the part after the type sorts by time
// whatever the message types.
func inboxNameKey(name string) string {
	if i := strings.Index(name, "-"); i >= 0 {
		return name[i:]
	}
	return name
}

// peerEchoedBefore reports whether one of the newest records in entries
// (the inbox at dir) from peer carries a reply_to: the peer has answered a
// message by naming its ID, so it is known to echo IDs. The scan is bounded
// by echoHistoryFiles and echoHistoryPeerRecords.
func peerEchoedBefore(dir string, entries []os.DirEntry, peer string) bool {
	if peer == "" {
		return false
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Slice(names, func(i, j int) bool { return inboxNameKey(names[i]) > inboxNameKey(names[j]) })
	if len(names) > echoHistoryFiles {
		names = names[:echoHistoryFiles]
	}
	fromPeer := 0
	for _, name := range names {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		var rec struct {
			From    string `json:"from"`
			ReplyTo string `json:"reply_to"`
		}
		if json.Unmarshal(body, &rec) != nil || rec.From != peer {
			continue
		}
		if rec.ReplyTo != "" {
			return true
		}
		if fromPeer++; fromPeer == echoHistoryPeerRecords {
			break
		}
	}
	return false
}

// addID registers the message ID of a request this watch waits on. The
// re-sent request has an ID of its own; a reply to either one is ours.
func (w *inboxWatch) addID(id string) {
	if id == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.ids == nil {
		w.ids = map[string]bool{}
	}
	w.ids[id] = true
}

// markTagged records that a request reached the receiver with its message
// ID (SendResult.Tagged), so the peer can name it in reply_to. Until then
// an untagged message is taken at once even from a peer known to echo: a
// receiver that predates IDs dropped ours, and the peer can never name our
// request.
func (w *inboxWatch) markTagged() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.tagged = true
}

// replyKind says how a message's reply_to relates to this watch's requests.
type replyKind int

const (
	replyUntagged replyKind = iota // no reply_to: only sender and time to go by
	replyOurs                      // reply_to is one of our message IDs
	replyOther                     // reply_to names somebody else's request
)

func (w *inboxWatch) classify(msg map[string]interface{}) replyKind {
	replyTo, _ := msg["reply_to"].(string)
	if replyTo == "" {
		return replyUntagged
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.ids) == 0 {
		// A caller that sent without an ID has nothing to compare with.
		return replyUntagged
	}
	if w.ids[replyTo] {
		return replyOurs
	}
	return replyOther
}

// poll returns the reply that arrived since the snapshot: the message that
// names one of our requests in reply_to, else the oldest one from the peer
// that names none, subject to untaggedReply.
func (w *inboxWatch) poll() (map[string]interface{}, error) {
	if w.dir == "" {
		dir, err := inboxDirPath()
		if err != nil {
			return nil, err
		}
		w.dir = dir
	}
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read inbox: %w", err)
	}
	// Oldest first, so the oldest new message wins.
	sort.Slice(entries, func(i, j int) bool { return inboxNameKey(entries[i].Name()) < inboxNameKey(entries[j].Name()) })
	var untagged map[string]interface{}
	for _, e := range entries {
		if e.IsDir() || w.seen[e.Name()] {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.ModTime().After(w.cutoff) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(w.dir, e.Name()))
		if err != nil {
			continue
		}
		var msg map[string]interface{}
		if json.Unmarshal(data, &msg) != nil {
			continue
		}
		if w.from != "" {
			if from, _ := msg["from"].(string); from != w.from {
				continue
			}
		}
		switch w.classify(msg) {
		case replyOurs:
			return msg, nil
		case replyOther:
			// Another request's answer. It stays out of w.seen: an ID
			// added later (the re-send) is checked against it again.
			w.peerEchoes = true
		case replyUntagged:
			if untagged == nil {
				untagged = msg
			}
		}
	}
	return w.untaggedReply(untagged, time.Now()), nil
}

// untaggedReply decides whether msg, the oldest untagged message from the
// peer (nil if there is none), is taken as the reply now. It is when our
// request went out without its ID, or when the peer is not known to echo
// IDs (as before IDs existed). From a peer with an echo history it is held
// back for untaggedReplyGrace from the poll that first saw it, so a reply
// naming our request that arrives meanwhile wins; and it is never taken
// from a peer seen naming another request during this wait.
func (w *inboxWatch) untaggedReply(msg map[string]interface{}, now time.Time) map[string]interface{} {
	if msg == nil {
		w.held = nil
		return nil
	}
	w.mu.Lock()
	tagged := w.tagged
	w.mu.Unlock()
	if !tagged || !w.echoedBefore && !w.peerEchoes {
		return msg
	}
	if w.held == nil {
		w.heldSince = now
	}
	w.held = msg
	if w.peerEchoes || now.Sub(w.heldSince) < untaggedReplyGrace {
		return nil
	}
	return msg
}

// heldReply returns the untagged message untaggedReply is holding back, if
// it may still be taken. awaitReply takes it when the wait runs out before
// its grace period does, rather than report no reply at all.
func (w *inboxWatch) heldReply() map[string]interface{} {
	if w.peerEchoes {
		return nil
	}
	return w.held
}

// replyWait configures awaitReply.
type replyWait struct {
	// wait is the reply budget, counted from the moment the request was
	// acknowledged by the receiver.
	wait time.Duration
	// resendAfter, when > 0, re-sends the request once if no reply has
	// arrived that long after the acknowledgement.
	resendAfter time.Duration
	// resend sends the request again on a new stream and returns when the
	// receiver acknowledged it. It runs on its own goroutine.
	resend func() (ackAt time.Time, err error)
	// observe returns how many reply connections from the peer the daemon
	// currently holds (the service dialing back). Optional; polled ~1/s.
	observe func() int
}

// replyOutcome is what awaitReply saw.
type replyOutcome struct {
	reply      map[string]interface{}
	resent     bool
	resendErr  error
	replyConns int // most reply connections from the peer seen at once
	waited     time.Duration
}

// awaitReply polls the inbox until the reply arrives or the budget runs
// out. When cfg.resend is set and nothing has arrived after
// cfg.resendAfter, the request is sent once more on a new stream, and the
// budget is extended so the second request gets at least half a window.
func awaitReply(w *inboxWatch, ackAt time.Time, cfg replyWait) (replyOutcome, error) {
	type resendResult struct {
		ackAt time.Time
		err   error
	}
	var out replyOutcome
	deadline := ackAt.Add(cfg.wait)
	var resendCh chan resendResult // non-nil while the re-send is in flight
	lastObserve := time.Time{}
	for {
		msg, err := w.poll()
		if err != nil {
			return out, err
		}
		if msg != nil {
			out.reply = msg
			out.waited = time.Since(ackAt)
			return out, nil
		}
		now := time.Now()
		if cfg.observe != nil && now.Sub(lastObserve) >= time.Second {
			lastObserve = now
			if n := cfg.observe(); n > out.replyConns {
				out.replyConns = n
			}
		}
		if resendCh != nil {
			select {
			case r := <-resendCh:
				resendCh = nil
				out.resendErr = r.err
				if r.err == nil {
					if extended := r.ackAt.Add(cfg.wait / 2); extended.After(deadline) {
						deadline = extended
					}
				}
			default:
			}
		}
		// No re-send while an untagged message is held back: something did
		// arrive, and it is most likely the reply.
		if !out.resent && cfg.resend != nil && cfg.resendAfter > 0 && now.Sub(ackAt) >= cfg.resendAfter && now.Before(deadline) && w.heldReply() == nil {
			out.resent = true
			resendCh = make(chan resendResult, 1)
			go func(ch chan<- resendResult) {
				at, err := cfg.resend()
				ch <- resendResult{ackAt: at, err: err}
			}(resendCh)
		}
		if now.After(deadline) && resendCh == nil {
			// The grace period for a held untagged message is bounded by
			// the wait: when the wait ends first, it is the reply.
			out.reply = w.heldReply()
			out.waited = time.Since(ackAt)
			return out, nil
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// replyTimeoutHint explains a request that was acknowledged but never
// answered.
func replyTimeoutHint(target string, out replyOutcome, firstContact bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s acknowledged the request but no reply arrived", target)
	if out.resent {
		if out.resendErr != nil {
			fmt.Fprintf(&b, " (re-sending it failed: %v)", out.resendErr)
		} else {
			b.WriteString(" (the request was sent twice)")
		}
	}
	b.WriteString(". ")
	switch {
	case out.replyConns > 0:
		fmt.Fprintf(&b, "%s did dial its reply back (%d connection(s)) but no data arrived on it: the service gave up on the reply. ", target, out.replyConns)
	case firstContact:
		fmt.Fprintf(&b, "The reply comes back on a new connection from %s, and none was seen: the service is overloaded or dropped the reply while the new path was still settling. ", target)
	default:
		fmt.Fprintf(&b, "No reply connection from %s was seen. ", target)
	}
	b.WriteString("This is on the service side; retry in a minute, or use a longer --wait.")
	return b.String()
}

// errNoReply is the error text scripts already match on.
func errNoReply(target string, wait time.Duration) error {
	return fmt.Errorf("no reply from %q within %s", target, wait)
}

// resendDelay is how long after the acknowledgement a first-contact
// request with no reply is sent again: half the reply window, at most
// 15 s, and never when the window is too short to fit a second request.
func resendDelay(wait time.Duration) time.Duration {
	d := wait / 2
	if d > 15*time.Second {
		d = 15 * time.Second
	}
	if d < 3*time.Second {
		return 0
	}
	return d
}
