package remote

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestAuditLogRecordsJSONLines(t *testing.T) {
	var buf bytes.Buffer
	a := NewAuditLog(&buf, "alice", "scan@10.0.0.5")
	ts := time.Date(2026, 6, 23, 14, 0, 0, 0, time.UTC)
	if err := a.Record(ts, "uname -m"); err != nil {
		t.Fatal(err)
	}
	if err := a.Record(ts.Add(time.Second), "sha256sum /tmp/x"); err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	var e AuditEntry
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil {
		t.Fatal(err)
	}
	if e.Operator != "alice" || e.Target != "scan@10.0.0.5" || e.Action != "uname -m" {
		t.Errorf("unexpected entry: %+v", e)
	}
	if !e.Time.Equal(ts) {
		t.Errorf("time = %v, want %v", e.Time, ts)
	}
}
