// SPDX-License-Identifier: AGPL-3.0-or-later

// Package logcap caps the size of the daemon's own log file.
//
// Under launchd the daemon's stdout/stderr are a plain file
// (StandardOutPath/StandardErrorPath = ~/.pilot/daemon.log) that launchd
// opens and never rotates, and nothing else is set up to: one laptop's
// daemon.log reached 22 MB, a June log 13 MB compressed. Renaming it away
// would not help — the daemon, and every child it spawns (they inherit
// the descriptor), keep writing to the open file.
//
// So the daemon rotates it from the inside, copy-truncate style: when
// the file exceeds the limit, copy it to <log>.pilot.1, truncate the
// original through the daemon's own descriptor, then gzip the copy into
// <log>.pilot.1.gz, shifting older generations up to <log>.pilot.N.gz.
// Truncation is safe for every writer: launchd (and `pilotctl daemon
// start`) open the log O_APPEND, so each write lands at the new end of
// file, and children share that same open file description. Lines
// written between the copy and the truncate are lost — the usual
// copy-truncate trade-off, a window of milliseconds.
//
// Files logcap did not create are left alone. The ".pilot" infix keeps
// its names apart from the ones other rotators give the same log
// (logrotate's <log>.1 and <log>.N.gz, newsyslog's <log>.0.gz), so an
// operator's own rotation keeps its history. Within its own names,
// logcap reads back, renames or removes only a regular file owned by
// the current user; a symlink, a directory or another user's file at
// one of them stops that round's backup (the log is still truncated).
// Files are created O_EXCL|O_NOFOLLOW, never through an existing name.
// When the log's directory is writable by group or others, or owned by
// another user (not root), logcap keeps no backups at all and only
// truncates, so it creates nothing where someone else could have
// planted a link.
//
// Options.Anywhere and Options.Within set where it applies: the daemon
// rotates by default only a log inside ~/.pilot, where launchd and
// `pilotctl daemon start` put it, and a log elsewhere only when the
// operator asks for rotation explicitly.
//
// When the log is not a regular file — journald under systemd, a
// terminal, a pipe — there is nothing to cap and the package does
// nothing.
package logcap

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// Options configure a Rotator.
type Options struct {
	// MaxBytes is the size past which the log is rotated; <= 0 disables
	// rotation.
	MaxBytes int64
	// MaxBackups is the number of gzipped generations kept; 0 truncates
	// without keeping any.
	MaxBackups int
	// Anywhere rotates the log wherever it lives. Without it only a log
	// inside one of the Within directories (at any depth) is rotated, so
	// the zero Options rotate nothing.
	Anywhere bool
	Within   []string
}

// Rotator caps one log file, identified by the descriptor the process
// writes it through (os.Stderr in the daemon).
type Rotator struct {
	file       *os.File
	maxBytes   int64
	maxBackups int
	anywhere   bool
	within     []string
}

// New returns a Rotator that rotates f once it exceeds opts.MaxBytes.
func New(f *os.File, opts Options) *Rotator {
	backups := opts.MaxBackups
	if backups < 0 {
		backups = 0
	}
	return &Rotator{
		file:       f,
		maxBytes:   opts.MaxBytes,
		maxBackups: backups,
		anywhere:   opts.Anywhere,
		within:     opts.Within,
	}
}

// errOutOfScope reports a log outside the directories rotation is
// limited to (Options.Within).
var errOutOfScope = errors.New("log is outside the directories rotation is limited to")

// Watch checks f every interval until ctx is done, rotating it whenever it
// has grown past opts.MaxBytes. It returns false, starting nothing, when
// capping is disabled (MaxBytes <= 0), f is not a regular file, the
// platform cannot map a descriptor back to its path, or the log is out of
// scope (see Options.Anywhere).
func Watch(ctx context.Context, f *os.File, opts Options, interval time.Duration) bool {
	if opts.MaxBytes <= 0 || !fdPathSupported {
		return false
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	r := New(f, opts)
	if !r.anywhere {
		path, err := fdPath(f)
		if err != nil || !namesFile(path, fi) || !r.inScope(path) {
			return false
		}
	}
	go r.run(ctx, interval)
	return true
}

func (r *Rotator) run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		// Check first so a log already over the limit at startup is
		// rotated right away rather than an interval later.
		rotated, err := r.Check()
		switch {
		case err == nil:
		case errors.Is(err, errOutOfScope):
			// Moved out of the pilot directory: someone else's log now.
			slog.Info("log rotation stopped", "reason", err)
			return
		case rotated:
			slog.Warn("log truncated without keeping a backup", "err", err)
		default:
			slog.Warn("log rotation failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Check rotates the log if it has grown past the limit and reports
// whether it did. A non-nil error with rotated == true means the log was
// truncated but its backup could not be kept.
func (r *Rotator) Check() (rotated bool, err error) {
	fi, err := r.file.Stat()
	if err != nil {
		return false, err
	}
	if !fi.Mode().IsRegular() || fi.Size() <= r.maxBytes {
		return false, nil
	}
	return r.rotate(fi)
}

func (r *Rotator) rotate(fi os.FileInfo) (bool, error) {
	var backupErr error
	path, src, err := r.openByPath(fi)
	if err != nil {
		// No readable path for the log (deleted, or not openable by
		// name): still truncate — capping disk use is the point —
		// without a backup. fdPath follows renames, so a log moved out of
		// scope still resolves, and is caught below.
		backupErr = err
	} else if !r.inScope(path) {
		_ = src.Close()
		return false, fmt.Errorf("%w: %s", errOutOfScope, path)
	}

	staged := ""
	if src != nil {
		if r.maxBackups > 0 {
			staged, backupErr = stage(src, path, r.maxBackups)
		}
		_ = src.Close()
	}

	if err := truncate(r.file); err != nil {
		if staged != "" {
			// Keep the next round from compressing a duplicate.
			_ = os.Remove(staged)
		}
		return false, fmt.Errorf("truncate log: %w", err)
	}

	backup := ""
	if staged != "" {
		backup = backupName(path, 1)
		if err := compress(staged, backup); err != nil {
			backupErr = fmt.Errorf("compress %s: %w", staged, err)
			backup = ""
		}
	}
	slog.Info("log rotated",
		"path", path,
		"size_bytes", fi.Size(),
		"max_bytes", r.maxBytes,
		"backup", backup)
	return true, backupErr
}

// openByPath opens the log for reading via its path — the write-only
// descriptor the process holds cannot be read — and confirms the path
// still names the same file. O_NOFOLLOW plus the same-file check mean it
// only ever reads the file this descriptor writes.
func (r *Rotator) openByPath(fi os.FileInfo) (string, *os.File, error) {
	path, err := fdPath(r.file)
	if err != nil {
		return "", nil, fmt.Errorf("resolve log path: %w", err)
	}
	// #nosec G304 -- path is resolved from the daemon's own stderr
	// descriptor, not from any peer or user input.
	src, err := os.OpenFile(path, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		return path, nil, err
	}
	sfi, err := src.Stat()
	if err != nil || !os.SameFile(fi, sfi) {
		_ = src.Close()
		return path, nil, fmt.Errorf("%s no longer names the open log file", path)
	}
	return path, src, nil
}

// namesFile reports whether path (not following a final symlink) is fi.
func namesFile(path string, fi os.FileInfo) bool {
	pfi, err := os.Lstat(path)
	return err == nil && os.SameFile(fi, pfi)
}

// inScope reports whether path lies inside one of r.within. Directories
// are compared by identity, so a symlinked ~/.pilot, or /var against
// macOS's /private/var, still matches.
func (r *Rotator) inScope(path string) bool {
	if r.anywhere {
		return true
	}
	var roots []os.FileInfo
	for _, d := range r.within {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			roots = append(roots, fi)
		}
	}
	if len(roots) == 0 {
		return false
	}
	dir := filepath.Dir(path)
	for {
		if fi, err := os.Stat(dir); err == nil {
			for _, root := range roots {
				if os.SameFile(fi, root) {
					return true
				}
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

// stage prepares this round's backup: it finishes an interrupted
// rotation, shifts the older generations up and copies the log (src,
// open at offset 0) to <path>.pilot.1, whose name it returns. An error
// means no backup is kept this round.
func stage(src *os.File, path string, keep int) (string, error) {
	if err := checkDir(filepath.Dir(path)); err != nil {
		return "", fmt.Errorf("keeping no backup: %w", err)
	}
	finishInterrupted(path)
	if err := shiftBackups(path, keep); err != nil {
		return "", fmt.Errorf("keeping no backup: %w", err)
	}
	staged := stagingName(path)
	if err := copyTo(src, staged); err != nil {
		return "", fmt.Errorf("copy log to %s: %w", staged, err)
	}
	return staged, nil
}

// truncate empties the log through the writer's own descriptor.
//
// Rewind first: a writer without O_APPEND (a shell's `2>file`) shares this
// offset, and left at the old end its next write would recreate the old
// size as a sparse hole. O_APPEND writers ignore the offset. Rewinding
// BEFORE truncating means a write racing in between lands at offset 0 and
// is then cut, rather than landing past the new end of file.
func truncate(f *os.File) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return f.Truncate(0)
}

// backupName is generation gen's name. The ".pilot" infix keeps it apart
// from the names another rotator gives the same log.
func backupName(path string, gen int) string {
	return fmt.Sprintf("%s.pilot.%d.gz", path, gen)
}

// stagingName is the uncompressed copy a rotation gzips into generation 1.
func stagingName(path string) string {
	return path + ".pilot.1"
}

// ownerOf is fileOwner; tests swap it to simulate another user's files.
var ownerOf = fileOwner

// ours reports whether fi is a regular file owned by this process's user,
// the only kind of file logcap reads back, renames or removes.
func ours(fi os.FileInfo) bool {
	if !fi.Mode().IsRegular() {
		return false
	}
	uid, ok := ownerOf(fi)
	return ok && uid == os.Geteuid()
}

// lookup reports whether name exists, and fails when it holds something
// logcap must not touch: a symlink, a directory, another user's file.
func lookup(name string) (bool, error) {
	fi, err := os.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !ours(fi) {
		return true, fmt.Errorf("%s is not a regular file owned by this user; leaving it alone", name)
	}
	return true, nil
}

// openOurs opens name for reading, without following a symlink, and only
// if it is a regular file owned by this user.
func openOurs(name string) (*os.File, error) {
	// #nosec G304 -- name is derived from the daemon's own log path.
	f, err := os.OpenFile(name, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err == nil && !ours(fi) {
		err = fmt.Errorf("%s is not a regular file owned by this user; leaving it alone", name)
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// checkDir refuses a directory where another user could have planted a
// link or a file at one of logcap's names: one writable by group or
// others — a sticky /tmp included, as the sticky bit stops removing
// others' names, not creating new ones — or one owned by another user
// (root excepted).
func checkDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("log directory %s is writable by group or others", dir)
	}
	if uid, ok := ownerOf(fi); !ok || (uid != os.Geteuid() && uid != 0) {
		return fmt.Errorf("log directory %s is owned by another user", dir)
	}
	return nil
}

// shiftBackups frees the <path>.pilot.1.gz slot: the oldest generation is
// dropped and each remaining one moves up by one. Generations beyond keep
// (left from a larger -log-max-backups) are removed too, up to the first
// gap. Every slot up to keep is checked before anything moves, so a name
// holding something that is not ours stops the shift with the
// generations intact.
func shiftBackups(path string, keep int) error {
	for gen := 1; gen <= keep; gen++ {
		if _, err := lookup(backupName(path, gen)); err != nil {
			return err
		}
	}
	for gen := keep + 1; ; gen++ {
		name := backupName(path, gen)
		if exists, err := lookup(name); err != nil || !exists {
			break
		}
		if err := os.Remove(name); err != nil {
			break
		}
	}
	if err := os.Remove(backupName(path, keep)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for gen := keep - 1; gen >= 1; gen-- {
		err := os.Rename(backupName(path, gen), backupName(path, gen+1))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// finishInterrupted compresses a <path>.pilot.1 left by a rotation that
// stopped between the copy and the compress (crash, kill). Its slot is
// free: the shift that preceded the copy already moved the old
// <path>.pilot.1.gz up. When it cannot, the staged copy stays where it is
// and this round keeps no backup (copyTo never replaces a file).
func finishInterrupted(path string) {
	staged := stagingName(path)
	exists, err := lookup(staged)
	if err == nil && !exists {
		return
	}
	if err == nil {
		err = compress(staged, backupName(path, 1))
	}
	if err != nil {
		slog.Warn("log rotation: could not finish interrupted backup", "path", staged, "err", err)
	}
}

// copyTo copies src (from its current offset to EOF) into a new file at
// dst. O_EXCL|O_NOFOLLOW: it never writes into an existing file or
// through a link, and removes only the file it created.
func copyTo(src *os.File, dst string) error {
	// #nosec G304 -- dst is derived from the daemon's own log path.
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL|oNoFollow, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, src)
	if err = errors.Join(err, out.Close()); err != nil {
		_ = os.Remove(dst)
		return err
	}
	return nil
}

// compress gzips src into dst via a temp file, so a partial dst never
// appears, and removes src. src must be a regular file of ours; dst must
// be absent or a generation of ours, which it replaces.
func compress(src, dst string) error {
	in, err := openOurs(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := dst + ".tmp"
	// A temp file of ours is left from an interrupted compress; anything
	// else at that name stops this one.
	if exists, err := lookup(tmp); err != nil {
		return err
	} else if exists {
		if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	// #nosec G304 -- tmp is derived from the daemon's own log path.
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|oNoFollow, 0o600)
	if err != nil {
		return err
	}
	zw := gzip.NewWriter(out)
	_, copyErr := io.Copy(zw, in)
	err = errors.Join(copyErr, zw.Close(), out.Close())
	if err == nil {
		_, err = lookup(dst)
	}
	if err == nil {
		err = os.Rename(tmp, dst)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Remove(src)
}
