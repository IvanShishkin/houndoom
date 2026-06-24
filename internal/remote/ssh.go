package remote

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
)

// execRunner runs an external command and returns its stdout/stderr. It is a
// seam so tests can avoid invoking the real ssh/scp binaries.
type execRunner func(ctx context.Context, name string, args ...string) (stdout []byte, stderr []byte, err error)

// realExec runs the command via os/exec.
func realExec(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

// commonOpts are the ssh/scp options we always pass. We never weaken host-key
// checking; BatchMode makes the client fail instead of prompting. The operator's
// ~/.ssh/config supplies ProxyJump, ports, and per-host IdentityFile.
var commonOpts = []string{"-o", "BatchMode=yes"}

// commonScpUploadOpts are scp options for Upload (OUTBOUND copy). Includes -p
// to preserve local file mode/timestamps on the remote.
var commonScpUploadOpts = []string{"-p", "-o", "BatchMode=yes"}

// sshBaseArgs builds the ssh argv up to (not including) the remote command.
func sshBaseArgs(user, host string) []string {
	args := append([]string{}, commonOpts...)
	return append(args, fmt.Sprintf("%s@%s", user, host))
}

// scpArgs builds the scp argv to copy localPath to user@host:remotePath.
// Uses -p to preserve mode/timestamps.
func scpArgs(user, host, localPath, remotePath string) []string {
	args := append([]string{}, commonScpUploadOpts...)
	return append(args, localPath, fmt.Sprintf("%s@%s:%s", user, host, remotePath))
}

// scpFromArgs builds the scp argv to copy user@host:remotePath to localPath.
func scpFromArgs(user, host, remotePath, localPath string) []string {
	args := append([]string{}, commonOpts...)
	return append(args, fmt.Sprintf("%s@%s:%s", user, host, remotePath), localPath)
}

type sshSession struct {
	user string
	host string
	exec execRunner
}

// NewSSHConnector returns a Connector backed by the system ssh/scp clients.
func NewSSHConnector() Connector {
	return func(ctx context.Context, user, host string) (Session, error) {
		return &sshSession{user: user, host: host, exec: realExec}, nil
	}
}

// Run executes a command on the target. The remote command is passed as a
// single trailing argv element, never concatenated into ssh options.
func (s *sshSession) Run(ctx context.Context, cmd string) ([]byte, []byte, error) {
	args := append(sshBaseArgs(s.user, s.host), cmd)
	out, errOut, err := s.exec(ctx, "ssh", args...)
	if err != nil {
		return out, errOut, fmt.Errorf("ssh %s@%s: %w (stderr: %s)", s.user, s.host, err, string(errOut))
	}
	return out, errOut, nil
}

// Upload copies data to remotePath via scp using a local temp file.
func (s *sshSession) Upload(ctx context.Context, data []byte, remotePath string, mode os.FileMode) error {
	tmp, err := os.CreateTemp("", "houndoom-up-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	args := scpArgs(s.user, s.host, tmp.Name(), remotePath)
	if _, errOut, err := s.exec(ctx, "scp", args...); err != nil {
		return fmt.Errorf("scp upload: %w (stderr: %s)", err, string(errOut))
	}
	return nil
}

// Download copies remotePath to memory via scp using a local temp file.
func (s *sshSession) Download(ctx context.Context, remotePath string) ([]byte, error) {
	tmp, err := os.CreateTemp("", "houndoom-down-*")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpName)
	args := scpFromArgs(s.user, s.host, remotePath, tmpName)
	if _, errOut, err := s.exec(ctx, "scp", args...); err != nil {
		return nil, fmt.Errorf("scp download: %w (stderr: %s)", err, string(errOut))
	}
	return os.ReadFile(tmpName)
}

// Close is a no-op: each Run/Upload/Download is its own short-lived process.
func (s *sshSession) Close() error { return nil }
