package engagement

import (
	"os"
	"testing"
	"time"
)

func TestSanitizeTarget(t *testing.T) {
	cases := map[string]string{
		"scan@10.0.0.5":      "scan_10.0.0.5",
		"user@host:/var/www": "user_host__var_www",
		"WEIRD name/../x":    "WEIRD_name_.._x",
	}
	for in, want := range cases {
		if got := SanitizeTarget(in); got != want {
			t.Errorf("SanitizeTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDirName(t *testing.T) {
	ts := time.Date(2026, 6, 23, 14, 5, 9, 0, time.UTC)
	if got := DirName("scan@10.0.0.5", ts); got != "scan_10.0.0.5-20260623-140509" {
		t.Errorf("DirName = %q", got)
	}
}

func TestCreateMakes0700Dir(t *testing.T) {
	root := t.TempDir()
	ts := time.Date(2026, 6, 23, 14, 5, 9, 0, time.UTC)
	dir, err := Create(root, "scan@10.0.0.5", ts)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatal("expected directory")
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("perm = %o, want 700", perm)
	}
}

func TestPurgeRemovesOldKeepsNew(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 6, 23, 0, 0, 0, 0, time.UTC)
	old, _ := Create(root, "old@h", now.Add(-40*24*time.Hour))
	recent, _ := Create(root, "new@h", now.Add(-1*24*time.Hour))

	removed, err := Purge(root, 30*24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != old {
		t.Fatalf("removed = %v, want [%s]", removed, old)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("old dir should be gone")
	}
	if _, err := os.Stat(recent); err != nil {
		t.Error("recent dir should remain")
	}
}

func TestPurgeHandlesHyphenatedTarget(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 6, 23, 0, 0, 0, 0, time.UTC)
	// Create engagement with hyphenated target 40 days before cutoff
	hyphenated, _ := Create(root, "my-host.com", now.Add(-40*24*time.Hour))

	removed, err := Purge(root, 30*24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != hyphenated {
		t.Fatalf("removed = %v, want [%s]", removed, hyphenated)
	}
	if _, err := os.Stat(hyphenated); !os.IsNotExist(err) {
		t.Error("hyphenated dir should be removed")
	}
}
