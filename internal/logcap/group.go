// SPDX-License-Identifier: AGPL-3.0-or-later

package logcap

import (
	"strconv"
	"strings"
)

// userPrivateGroup reports whether gid is uid's user private group, going
// by passwd and group, the contents of /etc/passwd and /etc/group: the
// primary group of uid's account, with the account's name, and no other
// member — no other account has it as its primary group and the group
// lists no one else.
//
// That is the user-private-group scheme of Debian/Ubuntu and Fedora/RHEL
// (useradd's USERGROUPS_ENAB), under which the login umask is 002 — RHEL's
// /etc/bashrc applies it on the same test, group name equal to user name —
// so the user's directories, ~/.pilot among them, are group-writable with
// a group no one else is in. The name check keeps out a shared group such
// as "users" that the account happens to be the only member of so far.
//
// Anything else counts as shared: an account or group missing from the
// files (from LDAP, say), a line it cannot parse, and a NIS compat entry
// ("+..." or "-..."), which pulls in accounts from elsewhere.
func userPrivateGroup(uid, gid int, passwd, group []byte) bool {
	users, ok := dbEntries(passwd, 7)
	if !ok {
		return false
	}
	name := ""
	for _, f := range users {
		u, uerr := strconv.Atoi(f[2])
		g, gerr := strconv.Atoi(f[3])
		if uerr != nil || gerr != nil {
			return false
		}
		switch {
		case u == uid && name == "":
			// The first entry is the one getpwuid returns.
			if g != gid {
				return false
			}
			name = f[0]
		case u != uid && g == gid:
			return false // another account's primary group
		}
	}
	if name == "" {
		return false
	}

	groups, ok := dbEntries(group, 4)
	if !ok {
		return false
	}
	found := false
	for _, f := range groups {
		g, err := strconv.Atoi(f[2])
		if err != nil {
			return false
		}
		if g != gid {
			continue
		}
		if f[0] != name {
			return false
		}
		for _, m := range strings.Split(f[3], ",") {
			if m != "" && m != name {
				return false
			}
		}
		found = true
	}
	return found
}

// dbEntries splits the lines of a passwd- or group-format file into their
// colon-separated fields, skipping blank lines and comments. It fails on
// a line without exactly n fields and on a NIS compat entry.
func dbEntries(data []byte, n int) ([][]string, bool) {
	var entries [][]string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-") {
			return nil, false
		}
		f := strings.Split(line, ":")
		if len(f) != n {
			return nil, false
		}
		entries = append(entries, f)
	}
	return entries, true
}
