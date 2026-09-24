// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// web4-470-muse-rejection-diagnostics-misdirect: Meta Muse's proxy answers
// wrong or expired credentials with a status line that cannot be parsed.
// The registry and compat beacon dials (and so "registry dial (after N
// attempts)") must still get a hint, and it must be about the credentials.
func TestProxyRefusalHintGarbledAnswer(t *testing.T) {
	clearProxyEnv(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if _, err := http.ReadRequest(bufio.NewReader(c)); err == nil {
					fmt.Fprint(c, "HTTP/1.1 4O7 Proxy Authentication Required\r\n\r\n")
				}
			}()
		}
	}()
	r, err := ResolveProxy("http://muse:stale@"+ln.Addr().String(), TransportCompat)
	if err != nil {
		t.Fatal(err)
	}
	d := New(Config{Proxy: r})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, dialErr := d.proxyDialer()(ctx, "tcp", "registry.pilotprotocol.network:443")
	if dialErr == nil {
		t.Fatal("dial through a proxy rejecting the credentials succeeded")
	}
	err = fmt.Errorf("registry dial (after 10 attempts): %w", dialErr)
	hint := ProxyRefusalHint(err)
	for _, want := range []string{"could not be parsed", "credentials", "-proxy-cmd"} {
		if !strings.Contains(hint, want) {
			t.Errorf("hint %q lacks %q", hint, want)
		}
	}
	if strings.Contains(hint, "udp") || strings.Contains(err.Error(), "4O7") || strings.Contains(err.Error(), "stale") {
		t.Errorf("hint %q / error %v", hint, err)
	}
}
