// Package engagement manages per-engagement output directories on the control
// plane (reports and audit logs), including layout and retention.
package engagement

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const timeLayout = "20060102-150405"

var unsafeChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// SanitizeTarget converts a target string into a filesystem-safe slug.
func SanitizeTarget(target string) string {
	return unsafeChars.ReplaceAllString(target, "_")
}

// DirName returns the per-engagement directory name "<slug>-<timestamp>".
func DirName(target string, ts time.Time) string {
	return fmt.Sprintf("%s-%s", SanitizeTarget(target), ts.Format(timeLayout))
}

// Create makes the engagement directory under root with 0700 permissions.
func Create(root, target string, ts time.Time) (string, error) {
	dir := filepath.Join(root, DirName(target, ts))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create engagement dir: %w", err)
	}
	// MkdirAll honors umask; enforce 0700 explicitly.
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", fmt.Errorf("chmod engagement dir: %w", err)
	}
	return dir, nil
}

// Purge removes engagement directories whose embedded timestamp is older than
// now-olderThan. It returns the list of removed directory paths.
func Purge(root string, olderThan time.Duration, now time.Time) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	cutoff := now.Add(-olderThan)
	var removed []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if len(name) < 16 { // need at least "-" + 15-char timestamp
			continue
		}
		ts, perr := time.Parse(timeLayout, name[len(name)-15:])
		if perr != nil {
			continue
		}
		if ts.Before(cutoff) {
			p := filepath.Join(root, e.Name())
			if rerr := os.RemoveAll(p); rerr != nil {
				return removed, rerr
			}
			removed = append(removed, p)
		}
	}
	return removed, nil
}

// DefaultRoot returns the default engagements root: ~/.houndoom/engagements.
func DefaultRoot() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".houndoom", "engagements"), nil
}
