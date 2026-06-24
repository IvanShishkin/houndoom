// Package remote implements the recon-only remote scan transport: SSH delivery
// of the scanner to a target, execution, report collection, and auditing.
package remote

import (
	"encoding/json"
	"io"
	"time"
)

// AuditEntry is a single audited action performed against a target.
type AuditEntry struct {
	Time     time.Time `json:"time"`
	Operator string    `json:"operator"`
	Target   string    `json:"target"`
	Action   string    `json:"action"`
}

// AuditLog appends JSON-line audit records to a writer.
type AuditLog struct {
	w        io.Writer
	operator string
	target   string
}

// NewAuditLog creates an audit log bound to an operator and target.
func NewAuditLog(w io.Writer, operator, target string) *AuditLog {
	return &AuditLog{w: w, operator: operator, target: target}
}

// Record writes one audit entry as a JSON line.
func (a *AuditLog) Record(now time.Time, action string) error {
	entry := AuditEntry{Time: now, Operator: a.operator, Target: a.target, Action: action}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = a.w.Write(data)
	return err
}
