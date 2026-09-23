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
// the file exceeds the limit, copy it to <path>.1, truncate the original
// through the daemon's own descriptor, then gzip the copy into
// <path>.1.gz, shifting older generations up to <path>.N.gz. Truncation
// is safe for every writer: launchd (and `pilotctl daemon start`) open
// the log O_APPEND, so each write lands at the new end of file, and
// children share that same open file description. Lines written between
// the copy and the truncate are lost — the usual copy-truncate trade-off,
// a window of milliseconds.
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
	"log/slog"
	"os"
	"time"
)

// Rotator caps one log file, identified by the descriptor the process
// writes it through (os.Stderr in the daemon).
type Rotator struct {
	file       *os.File
	maxBytes   int64
	maxBackups int
}

// New returns a Rotator that rotates f once it exceeds maxBytes, keeping
// maxBackups gzipped generations (0 = truncate without keeping any).
func New(f *os.File, maxBytes int64, maxBackups int) *Rotator {
	if maxBackups < 0 {
		maxBackups = 0
	}
	return &Rotator{file: f, maxBytes: maxBytes, maxBackups: maxBackups}
}

// Watch checks f every interval until ctx is done, rotating it whenever it
// has grown past maxBytes. It returns false, starting nothing, when
// capping is disabled (maxBytes <= 0), f is not a regular file, or the
// platform cannot map a descriptor back to its path.
func Watch(ctx context.Context, f *os.File, maxBytes int64, maxBackups int, interval time.Duration) bool {
	if maxBytes <= 0 || !fdPathSupported {
		return false
	}
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return false
	}
	r := New(f, maxBytes, maxBackups)
	go r.run(ctx, interval)
	return true
}

func (r *Rotator) run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		// Check first so a log already over the limit at startup is
		// rotated right away rather than an interval later.
		if rotated, err := r.Check(); err != nil {
			if rotated {
				slog.Warn("log truncated without keeping a backup", "err", err)
			} else {
				slog.Warn("log rotation failed", "err", err)
			}
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
		// No readable path for the log (deleted, renamed away): still
		// truncate — capping disk use is the point — without a backup.
		backupErr = err
	}

	staged := ""
	if src != nil {
		if r.maxBackups > 0 {
			finishInterrupted(path)
			shiftBackups(path, r.maxBackups)
			staged = path + ".1"
			if err := copyTo(src, staged); err != nil {
				backupErr = fmt.Errorf("copy log to %s: %w", staged, err)
				_ = os.Remove(staged)
				staged = ""
			}
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
		backup = path + ".1.gz"
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
// still names the same file.
func (r *Rotator) openByPath(fi os.FileInfo) (string, *os.File, error) {
	path, err := fdPath(r.file)
	if err != nil {
		return "", nil, fmt.Errorf("resolve log path: %w", err)
	}
	// #nosec G304 -- path is resolved from the daemon's own stderr
	// descriptor, not from any peer or user input.
	src, err := os.Open(path)
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

func backupName(path string, gen int) string {
	return fmt.Sprintf("%s.%d.gz", path, gen)
}

// shiftBackups frees the <path>.1.gz slot: the oldest generation is
// dropped and each remaining one moves up by one. Generations beyond keep
// (left from a larger -log-max-backups) are removed too.
func shiftBackups(path string, keep int) {
	for gen := keep + 1; ; gen++ {
		if err := os.Remove(backupName(path, gen)); err != nil {
			break
		}
	}
	_ = os.Remove(backupName(path, keep))
	for gen := keep - 1; gen >= 1; gen-- {
		_ = os.Rename(backupName(path, gen), backupName(path, gen+1))
	}
}

// finishInterrupted compresses a <path>.1 left by a rotation that stopped
// between the copy and the compress (crash, kill). Its slot is free: the
// shift that preceded the copy already moved the old <path>.1.gz up.
func finishInterrupted(path string) {
	staged := path + ".1"
	if _, err := os.Lstat(staged); err != nil {
		return
	}
	if err := compress(staged, backupName(path, 1)); err != nil {
		slog.Warn("log rotation: could not finish interrupted backup", "path", staged, "err", err)
	}
}

// copyTo copies src (from its current offset to EOF) into a new file at
// dst, replacing any existing one.
func copyTo(src *os.File, dst string) error {
	// #nosec G304 -- dst is derived from the daemon's own log path.
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, src); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// compress gzips src into dst (via a temp file, so a partial dst never
// appears) and removes src.
func compress(src, dst string) (err error) {
	// #nosec G304 -- src is derived from the daemon's own log path.
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := dst + ".tmp"
	// #nosec G304 -- tmp is derived from the daemon's own log path.
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	zw := gzip.NewWriter(out)
	_, copyErr := io.Copy(zw, in)
	if err = errors.Join(copyErr, zw.Close(), out.Close()); err != nil {
		return err
	}
	if err = os.Rename(tmp, dst); err != nil {
		return err
	}
	return os.Remove(src)
}
