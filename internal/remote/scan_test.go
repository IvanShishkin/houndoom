package remote

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// fakeSession records commands and serves canned responses.
type fakeSession struct {
	uploaded    map[string][]byte
	commands    []string
	closed      bool
	failOnCmd   string // if non-empty, fail when cmd contains this substring
	badChecksum bool   // if true, return wrong digest for sha256sum
}

func newFakeSession() *fakeSession { return &fakeSession{uploaded: map[string][]byte{}} }

func (s *fakeSession) Run(ctx context.Context, cmd string) ([]byte, []byte, error) {
	s.commands = append(s.commands, cmd)
	if s.failOnCmd != "" && strings.Contains(cmd, s.failOnCmd) {
		return nil, nil, fmt.Errorf("simulated failure: %s", cmd)
	}
	switch {
	case cmd == "uname -m":
		return []byte("x86_64\n"), nil, nil
	case strings.HasPrefix(cmd, "sha256sum "):
		path := strings.TrimSpace(strings.TrimPrefix(cmd, "sha256sum "))
		if s.badChecksum {
			zeros := strings.Repeat("0", 64)
			return []byte(zeros + "  " + path + "\n"), nil, nil
		}
		sum := sha256.Sum256(s.uploaded[path])
		return []byte(hex.EncodeToString(sum[:]) + "  " + path + "\n"), nil, nil
	default:
		return []byte(""), nil, nil // chmod, scan, rm
	}
}

func (s *fakeSession) Upload(ctx context.Context, data []byte, remotePath string, mode os.FileMode) error {
	s.uploaded[remotePath] = data
	return nil
}

func (s *fakeSession) Download(ctx context.Context, remotePath string) ([]byte, error) {
	return []byte(`{"findings":[]}`), nil
}

func (s *fakeSession) Close() error { s.closed = true; return nil }

func baseDeps(sess *fakeSession, confirm bool) (Deps, *strings.Builder) {
	var audit strings.Builder
	return Deps{
		Connect: func(ctx context.Context, user, host string) (Session, error) { return sess, nil },
		Binaries: fstest.MapFS{
			"dist/houndoom-linux-amd64": {Data: []byte("ELF-amd64-binary")},
		},
		Audit:   NewAuditLog(&audit, "alice", "scan@10.0.0.5"),
		Confirm: func(target string) bool { return confirm },
		Now:     func() time.Time { return time.Date(2026, 6, 23, 14, 0, 0, 0, time.UTC) },
	}, &audit
}

func TestRunHappyPath(t *testing.T) {
	sess := newFakeSession()
	deps, audit := baseDeps(sess, true)
	out := filepath.Join(t.TempDir(), "report.json")
	o := Options{Host: "scan@10.0.0.5", Path: "/var/www", Mode: "paranoid", Output: out, Timeout: 3600 * time.Second}

	reportPath, err := Run(context.Background(), o, deps)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(reportPath)
	if string(data) != `{"findings":[]}` {
		t.Errorf("report content = %q", data)
	}
	// scan command must reference the validated path/mode and request JSON.
	joined := strings.Join(sess.commands, "\n")
	if !strings.Contains(joined, "scan /var/www") || !strings.Contains(joined, "--mode paranoid") || !strings.Contains(joined, "--report=json") {
		t.Errorf("scan command not as expected: %v", sess.commands)
	}
	// Resource limits must be present.
	if !strings.Contains(joined, "nice -n 19") {
		t.Errorf("scan command missing nice: %v", sess.commands)
	}
	if !strings.Contains(joined, "timeout 3600") {
		t.Errorf("scan command missing timeout 3600: %v", sess.commands)
	}
	// Cleanup must have happened and session closed.
	if !strings.Contains(joined, "rm -rf") {
		t.Error("expected cleanup command")
	}
	if !sess.closed {
		t.Error("session not closed")
	}
	// Audit must include all remote actions.
	a := audit.String()
	for _, want := range []string{"uname -m", "mkdir", "upload", "chmod", "sha256sum", "scan", "download", "rm -rf"} {
		if !strings.Contains(a, want) {
			t.Errorf("audit missing %q; full audit:\n%s", want, a)
		}
	}
}

func TestRunAbortsWhenNotConfirmed(t *testing.T) {
	sess := newFakeSession()
	deps, _ := baseDeps(sess, false)
	connectCalled := false
	deps.Connect = func(ctx context.Context, user, host string) (Session, error) {
		connectCalled = true
		return sess, nil
	}
	o := Options{Host: "scan@10.0.0.5", Path: "/var/www", Mode: "normal", Output: filepath.Join(t.TempDir(), "r.json")}
	if _, err := Run(context.Background(), o, deps); err == nil {
		t.Fatal("expected error when not confirmed")
	}
	if connectCalled {
		t.Error("unconfirmed run must not connect")
	}
	if len(sess.commands) != 0 {
		t.Errorf("must not run commands when unconfirmed, got %v", sess.commands)
	}
}

func TestRunPlanDoesNotConnect(t *testing.T) {
	connectCalled := false
	deps, _ := baseDeps(newFakeSession(), true)
	deps.Connect = func(ctx context.Context, user, host string) (Session, error) {
		connectCalled = true
		return nil, nil
	}
	o := Options{Host: "scan@10.0.0.5", Path: "/var/www", Mode: "fast", Plan: true}
	if _, err := Run(context.Background(), o, deps); err != nil {
		t.Fatal(err)
	}
	if connectCalled {
		t.Error("plan mode must not connect")
	}
}

func TestRunRejectsBadInput(t *testing.T) {
	deps, _ := baseDeps(newFakeSession(), true)
	o := Options{Host: "scan@10.0.0.5", Path: "relative", Mode: "fast", Output: "x"}
	if _, err := Run(context.Background(), o, deps); err == nil {
		t.Error("expected validation error for relative path")
	}
}

func TestPlanLines(t *testing.T) {
	lines := PlanLines(Options{Host: "scan@10.0.0.5", Path: "/var/www", Mode: "paranoid"})
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "scan@10.0.0.5") || !strings.Contains(joined, "/var/www") || !strings.Contains(joined, "paranoid") {
		t.Errorf("plan missing target details: %s", joined)
	}
}

func TestRunCleansUpOnScanFailure(t *testing.T) {
	sess := &fakeSession{uploaded: map[string][]byte{}, failOnCmd: "scan"}
	deps, _ := baseDeps(sess, true)
	deps.Connect = func(ctx context.Context, user, host string) (Session, error) { return sess, nil }
	o := Options{Host: "scan@10.0.0.5", Path: "/var/www", Mode: "normal", Output: filepath.Join(t.TempDir(), "r.json")}

	_, err := Run(context.Background(), o, deps)
	if err == nil {
		t.Fatal("expected error when scan fails")
	}
	joined := strings.Join(sess.commands, "\n")
	if !strings.Contains(joined, "rm -rf") {
		t.Errorf("cleanup must run after scan failure; commands:\n%s", joined)
	}
	if !sess.closed {
		t.Error("session must be closed after scan failure")
	}
}

func TestRunChecksumMismatch(t *testing.T) {
	sess := &fakeSession{uploaded: map[string][]byte{}, badChecksum: true}
	deps, _ := baseDeps(sess, true)
	deps.Connect = func(ctx context.Context, user, host string) (Session, error) { return sess, nil }
	o := Options{Host: "scan@10.0.0.5", Path: "/var/www", Mode: "normal", Output: filepath.Join(t.TempDir(), "r.json")}

	_, err := Run(context.Background(), o, deps)
	if err == nil {
		t.Fatal("expected error on checksum mismatch")
	}
	if !strings.Contains(err.Error(), "checksum") {
		t.Errorf("error must mention checksum, got: %v", err)
	}
	joined := strings.Join(sess.commands, "\n")
	if !strings.Contains(joined, "rm -rf") {
		t.Errorf("cleanup must run after checksum mismatch; commands:\n%s", joined)
	}
}

func TestRunRejectsBadMaxSize(t *testing.T) {
	deps, _ := baseDeps(newFakeSession(), true)
	o := Options{
		Host:    "scan@10.0.0.5",
		Path:    "/var/www",
		Mode:    "normal",
		Output:  filepath.Join(t.TempDir(), "r.json"),
		Timeout: time.Hour,
		MaxSize: "100; rm -rf /",
	}
	_, err := Run(context.Background(), o, deps)
	if err == nil {
		t.Fatal("expected validation error for dangerous MaxSize value")
	}
	if !strings.Contains(err.Error(), "max-size") {
		t.Errorf("error must mention max-size, got: %v", err)
	}
}

// errWriter is an io.Writer that always fails.
type errWriter struct{}

func (errWriter) Write(p []byte) (int, error) {
	return 0, fmt.Errorf("disk full (simulated)")
}

func TestRunContinuesOnAuditWriteError(t *testing.T) {
	sess := newFakeSession()
	out := filepath.Join(t.TempDir(), "report.json")
	deps := Deps{
		Connect: func(ctx context.Context, user, host string) (Session, error) { return sess, nil },
		Binaries: fstest.MapFS{
			"dist/houndoom-linux-amd64": {Data: []byte("ELF-amd64-binary")},
		},
		Audit:   NewAuditLog(errWriter{}, "alice", "scan@10.0.0.5"),
		Confirm: func(target string) bool { return true },
		Now:     func() time.Time { return time.Date(2026, 6, 23, 14, 0, 0, 0, time.UTC) },
	}
	o := Options{
		Host:    "scan@10.0.0.5",
		Path:    "/var/www",
		Mode:    "normal",
		Output:  out,
		Timeout: time.Hour,
	}
	reportPath, err := Run(context.Background(), o, deps)
	if err != nil {
		t.Fatalf("scan must succeed despite audit write failures, got: %v", err)
	}
	data, readErr := os.ReadFile(reportPath)
	if readErr != nil {
		t.Fatalf("report not written: %v", readErr)
	}
	if string(data) != `{"findings":[]}` {
		t.Errorf("unexpected report content: %q", data)
	}
}
