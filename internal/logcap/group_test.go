// SPDX-License-Identifier: AGPL-3.0-or-later

package logcap

import "testing"

// TestUserPrivateGroup: only a group that is the account's primary group,
// named after it and with no one else in it counts as private; anything
// the files do not show to be that counts as shared.
func TestUserPrivateGroup(t *testing.T) {
	const passwd = `# comment
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin

alice:x:1000:1000:Alice:/home/alice:/bin/bash
bob:x:1001:1001:Bob:/home/bob:/bin/bash
carol:x:1002:100:Carol:/home/carol:/bin/bash
`
	const group = `root:x:0:
daemon:x:1:
users:x:100:
alice:x:1000:
bob:x:1001:
`
	for _, tc := range []struct {
		name          string
		uid, gid      int
		passwd, group string
		want          bool
	}{
		{"private group", 1000, 1000, passwd, group, true},
		{"root's group", 0, 0, passwd, group, true},
		{"lists the user itself", 1000, 1000, passwd, "alice:x:1000:alice\n", true},
		{"another user's group", 1000, 1001, passwd, group, false},
		{"not the primary group", 1000, 100, passwd, group, false},
		{"named after the user, not its primary", 1000, 2000, passwd, "alice:x:2000:\n", false},
		{"shared group, one member so far", 1002, 100, passwd, group, false},
		{"another member listed", 1000, 1000, passwd, "alice:x:1000:alice,bob\n", false},
		{"another account's primary group", 1000, 1000,
			passwd + "dave:x:1003:1000::/home/dave:/bin/sh\n", group, false},
		{"duplicate entry with a member", 1000, 1000, passwd,
			group + "alice:x:1000:bob\n", false},
		{"differently named", 1000, 1000, passwd, "staff:x:1000:\n", false},
		{"group missing", 1000, 1000, passwd, "root:x:0:\n", false},
		{"account missing", 1005, 1005, passwd, "eve:x:1005:\n", false},
		{"NIS compat in passwd", 1000, 1000, passwd + "+::::::\n", group, false},
		{"NIS compat in group", 1000, 1000, passwd, group + "+:::\n", false},
		{"malformed passwd", 1000, 1000, passwd + "broken:x:12\n", group, false},
		{"malformed group", 1000, 1000, passwd, group + "broken:x\n", false},
		{"non-numeric gid", 1000, 1000, passwd + "frank:x:1004:abc::/:/bin/sh\n", group, false},
		{"empty files", 1000, 1000, "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := userPrivateGroup(tc.uid, tc.gid, []byte(tc.passwd), []byte(tc.group)); got != tc.want {
				t.Fatalf("userPrivateGroup(%d, %d) = %v, want %v", tc.uid, tc.gid, got, tc.want)
			}
		})
	}
}
