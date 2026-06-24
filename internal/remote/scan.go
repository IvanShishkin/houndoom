package remote

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"
)

// Options describes one remote scan request.
type Options struct {
	Host    string        // user@host
	Path    string        // absolute path on target
	Mode    string        // fast|normal|paranoid
	Output  string        // local path to write the collected report
	Plan    bool          // dry-run: print the plan, do not connect
	Timeout time.Duration // wall-clock cap for the remote scan process
	MaxSize string        // optional --max-size passthrough (e.g. "500M")
}

// Deps holds injected collaborators so Run is testable without real SSH.
type Deps struct {
	Connect  Connector
	Binaries fs.FS
	Audit    *AuditLog
	Confirm  func(target string) bool
	Now      func() time.Time
}

func targetString(o Options) string {
	return fmt.Sprintf("%s path=%s mode=%s", o.Host, o.Path, o.Mode)
}

// PlanLines returns the human-readable dry-run plan.
func PlanLines(o Options) []string {
	return []string{
		"Remote scan plan (recon-only, read-only on target):",
		"  Target:  " + o.Host,
		"  Path:    " + o.Path,
		"  Mode:    " + o.Mode,
		fmt.Sprintf("  Timeout: %ds", int(o.Timeout.Seconds())),
		"  Steps:   connect (ssh-agent, host-key pinned) -> uname -m -> upload binary",
		"           -> sha256 verify -> scan -> download report -> rm -rf temp",
	}
}

func validate(o Options) error {
	if _, _, err := ParseUserHost(o.Host); err != nil {
		return err
	}
	if err := ValidateMode(o.Mode); err != nil {
		return err
	}
	if err := ValidateRemotePath(o.Path); err != nil {
		return err
	}
	if o.MaxSize != "" && !safeMaxSize.MatchString(o.MaxSize) {
		return fmt.Errorf("invalid --max-size value %q: must match ^[0-9]+[KkMmGg]?$", o.MaxSize)
	}
	return nil
}

// Run performs a recon-only remote scan and writes the report to o.Output.
func Run(ctx context.Context, o Options, d Deps) (string, error) {
	if err := validate(o); err != nil {
		return "", err
	}

	if o.Plan {
		for _, l := range PlanLines(o) {
			fmt.Println(l)
		}
		return "", nil
	}

	target := targetString(o)
	if !d.Confirm(target) {
		return "", fmt.Errorf("aborted by operator")
	}

	user, host, _ := ParseUserHost(o.Host)
	sess, err := d.Connect(ctx, user, host)
	if err != nil {
		return "", fmt.Errorf("connect: %w", err)
	}
	defer sess.Close()

	record := func(action string) error {
		if err := d.Audit.Record(d.Now(), action); err != nil {
			fmt.Fprintf(os.Stderr, "warning: audit record failed for %q: %v\n", action, err)
			return err
		}
		return nil
	}

	arch, err := detectArchAudited(ctx, sess, record)
	if err != nil {
		return "", fmt.Errorf("detect arch: %w", err)
	}

	bin, binName, err := SelectBinary(d.Binaries, arch)
	if err != nil {
		return "", fmt.Errorf("select binary: %w", err)
	}

	tmpDir := fmt.Sprintf("/tmp/.houndoom-%d", d.Now().UnixNano())
	remoteBin := tmpDir + "/" + binName
	remoteReport := tmpDir + "/report.json"

	// Ensure cleanup runs even on later failure, including context cancellation.
	defer func() {
		cleanup := "rm -rf " + tmpDir
		_ = record(cleanup)
		_, _, _ = sess.Run(context.WithoutCancel(ctx), cleanup)
	}()

	if _, _, err := runAudited(ctx, sess, record, "mkdir -p "+tmpDir); err != nil {
		return "", fmt.Errorf("mkdir temp: %w", err)
	}
	if err := uploadAudited(ctx, sess, record, bin, remoteBin); err != nil {
		return "", fmt.Errorf("upload binary: %w", err)
	}
	if _, _, err := runAudited(ctx, sess, record, "chmod +x "+remoteBin); err != nil {
		return "", fmt.Errorf("chmod: %w", err)
	}
	if err := verifyChecksum(ctx, sess, record, bin, remoteBin); err != nil {
		return "", err
	}

	scanCmd := fmt.Sprintf("nice -n 19 timeout %d %s scan %s --mode %s --report=json --output %s",
		int(o.Timeout.Seconds()), remoteBin, o.Path, o.Mode, remoteReport)
	if o.MaxSize != "" {
		scanCmd += " --max-size " + o.MaxSize
	}
	if _, _, err := runAudited(ctx, sess, record, scanCmd); err != nil {
		return "", fmt.Errorf("remote scan: %w", err)
	}

	_ = record("download " + remoteReport)
	data, err := sess.Download(ctx, remoteReport)
	if err != nil {
		return "", fmt.Errorf("download report: %w", err)
	}

	if err := os.WriteFile(o.Output, data, 0o600); err != nil {
		return "", fmt.Errorf("write report: %w", err)
	}
	return o.Output, nil
}

func runAudited(ctx context.Context, r CommandRunner, record func(string) error, cmd string) ([]byte, []byte, error) {
	_ = record(cmd)
	return r.Run(ctx, cmd)
}

func uploadAudited(ctx context.Context, ft FileTransfer, record func(string) error, data []byte, remotePath string) error {
	_ = record("upload " + remotePath)
	return ft.Upload(ctx, data, remotePath, 0o700)
}

func detectArchAudited(ctx context.Context, r CommandRunner, record func(string) error) (string, error) {
	_ = record("uname -m")
	return DetectArch(ctx, r)
}

// verifyChecksum compares the local binary hash with sha256sum on the target.
// On an untrusted host this is a detection aid, not a guarantee (see spec 4.3).
func verifyChecksum(ctx context.Context, r CommandRunner, record func(string) error, local []byte, remotePath string) error {
	sum := sha256.Sum256(local)
	want := hex.EncodeToString(sum[:])
	out, _, err := runAudited(ctx, r, record, "sha256sum "+remotePath)
	if err != nil {
		return fmt.Errorf("checksum: %w", err)
	}
	got := strings.Fields(string(out))
	if len(got) == 0 || got[0] != want {
		return fmt.Errorf("uploaded binary checksum mismatch (possible host tampering)")
	}
	return nil
}
