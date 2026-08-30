package remote

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestSSHBaseArgsAreHardened(t *testing.T) {
	args := sshBaseArgs("scan", "10.0.0.5", 0)
	joined := strings.Join(args, " ")
	// Must target scan@10.0.0.5 and never weaken host-key checking.
	if !strings.Contains(joined, "scan@10.0.0.5") {
		t.Errorf("missing destination: %v", args)
	}
	if !strings.Contains(joined, "BatchMode=yes") {
		t.Errorf("missing BatchMode: %v", args)
	}
	for _, forbidden := range []string{"StrictHostKeyChecking=no", "UserKnownHostsFile=/dev/null"} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("must not weaken host-key checking: %v", args)
		}
	}
}

func TestScpArgs(t *testing.T) {
	args := scpArgs("scan", "10.0.0.5", "/local/bin", "/tmp/x/bin", 0)
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "/local/bin") || !strings.Contains(joined, "scan@10.0.0.5:/tmp/x/bin") {
		t.Errorf("scp args wrong: %v", args)
	}
	if !strings.Contains(joined, "BatchMode=yes") {
		t.Errorf("scp must use BatchMode: %v", args)
	}
}

// fakeExec records invocations and serves canned ssh output.
type fakeExec struct {
	calls [][]string
}

func (f *fakeExec) run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	// Emulate `ssh ... uname -m`.
	if name == "ssh" && len(args) > 0 && args[len(args)-1] == "uname -m" {
		return []byte("x86_64\n"), nil, nil
	}
	return []byte(""), nil, nil
}

func TestSessionRunInvokesSSH(t *testing.T) {
	fe := &fakeExec{}
	s := &sshSession{user: "scan", host: "10.0.0.5", exec: fe.run}
	out, _, err := s.Run(context.Background(), "uname -m")
	if err != nil || strings.TrimSpace(string(out)) != "x86_64" {
		t.Fatalf("got out=%q err=%v", out, err)
	}
	if len(fe.calls) != 1 || fe.calls[0][0] != "ssh" {
		t.Fatalf("expected one ssh call, got %v", fe.calls)
	}
	// The remote command must be passed as a single trailing argv element,
	// not concatenated into the ssh options.
	last := fe.calls[0][len(fe.calls[0])-1]
	if last != "uname -m" {
		t.Errorf("remote command not passed as single arg: %q", last)
	}
}

func TestUploadUsesSCP(t *testing.T) {
	fe := &fakeExec{}
	s := &sshSession{user: "scan", host: "10.0.0.5", exec: fe.run}
	if err := s.Upload(context.Background(), []byte("ELF"), "/tmp/x/houndoom", 0o700); err != nil {
		t.Fatal(err)
	}
	if len(fe.calls) != 1 || fe.calls[0][0] != "scp" {
		t.Fatalf("expected one scp call, got %v", fe.calls)
	}
	dest := fe.calls[0][len(fe.calls[0])-1]
	if dest != "scan@10.0.0.5:/tmp/x/houndoom" {
		t.Errorf("scp dest wrong: %q", dest)
	}
	// Assert scp argv contains both -p (preserve mode) and BatchMode=yes
	joined := strings.Join(fe.calls[0], " ")
	if !strings.Contains(joined, "-p") {
		t.Errorf("scp upload must include -p to preserve mode: %v", fe.calls[0])
	}
	if !strings.Contains(joined, "BatchMode=yes") {
		t.Errorf("scp upload must include BatchMode=yes: %v", fe.calls[0])
	}
}

func TestScpFromArgs(t *testing.T) {
	args := scpFromArgs("scan", "10.0.0.5", "/tmp/x/report.json", "/local/out", 0)
	joined := strings.Join(args, " ")
	// Assert the source remote path is present
	if !strings.Contains(joined, "scan@10.0.0.5:/tmp/x/report.json") {
		t.Errorf("scpFromArgs missing source: %v", args)
	}
	// Assert the local destination is present
	if !strings.Contains(joined, "/local/out") {
		t.Errorf("scpFromArgs missing destination: %v", args)
	}
	// Assert BatchMode=yes is included
	if !strings.Contains(joined, "BatchMode=yes") {
		t.Errorf("scpFromArgs must include BatchMode=yes: %v", args)
	}
}

func TestDownloadUsesSCP(t *testing.T) {
	fe := &fakeExec{}
	s := &sshSession{user: "scan", host: "10.0.0.5", exec: fe.run}
	got, err := s.Download(context.Background(), "/tmp/x/report.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(fe.calls) != 1 || fe.calls[0][0] != "scp" {
		t.Fatalf("expected one scp call, got %v", fe.calls)
	}
	// Assert the source is in the arguments (should be second to last or earlier arg)
	joined := strings.Join(fe.calls[0], " ")
	if !strings.Contains(joined, "scan@10.0.0.5:/tmp/x/report.json") {
		t.Errorf("scp download missing source: %v", fe.calls[0])
	}
	// The faked scp returns nil, Download reads an empty temp file
	if got == nil {
		t.Errorf("expected empty bytes (not nil)")
	}
}

// TestSSHIntegration exercises the real system ssh/scp against a disposable
// sshd. Guarded by HOUNDOOM_SSH_IT to keep unit runs hermetic.
//
// To run locally, start a throwaway container and trust its host key, e.g.:
//
//	docker run -d --name hd-sshd -p 22:2222 \
//	  -e USER_NAME=scan -e PUBLIC_KEY="$(cat ~/.ssh/id_ed25519.pub)" \
//	  linuxserver/openssh-server
//	ssh-keyscan 127.0.0.1 >> ~/.ssh/known_hosts
//	HOUNDOOM_SSH_IT=1 HD_SSH_HOST=127.0.0.1 HD_SSH_USER=scan \
//	  go test ./internal/remote/ -run TestSSHIntegration -v
//
// Non-standard ports/bastions are configured via the operator's ~/.ssh/config,
// which the system client honors — no code change needed here.
func TestSSHIntegration(t *testing.T) {
	if os.Getenv("HOUNDOOM_SSH_IT") == "" {
		t.Skip("set HOUNDOOM_SSH_IT=1 to run SSH integration test")
	}
	host := os.Getenv("HD_SSH_HOST")
	user := os.Getenv("HD_SSH_USER")
	if host == "" || user == "" {
		t.Fatal("HD_SSH_HOST and HD_SSH_USER required")
	}

	sess, err := NewSSHConnector(0)(context.Background(), user, host)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	out, _, err := sess.Run(context.Background(), "uname -m")
	if err != nil || strings.TrimSpace(string(out)) == "" {
		t.Fatalf("uname failed: out=%q err=%v", out, err)
	}

	remotePath := "/tmp/hd-it-upload.txt"
	if err := sess.Upload(context.Background(), []byte("hello"), remotePath, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := sess.Download(context.Background(), remotePath)
	if err != nil || string(got) != "hello" {
		t.Fatalf("roundtrip failed: got=%q err=%v", got, err)
	}
	_, _, _ = sess.Run(context.Background(), "rm -f "+remotePath)
}

func TestSSHBaseArgsCarriesPort(t *testing.T) {
	args := sshBaseArgs("scan", "10.0.0.5", 2222)
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-p 2222") {
		t.Errorf("ssh must receive -p <port>: %v", args)
	}
	// The port option belongs before the destination, like every other ssh option.
	if args[len(args)-1] != "scan@10.0.0.5" {
		t.Errorf("destination must stay last: %v", args)
	}
}

func TestSSHBaseArgsUnchangedWithoutPort(t *testing.T) {
	// Port 0 means "not set": the operator's ~/.ssh/config keeps deciding, so argv
	// must be byte-for-byte what it was before the flag existed.
	want := []string{"-o", "BatchMode=yes", "scan@10.0.0.5"}
	got := sshBaseArgs("scan", "10.0.0.5", 0)
	if len(got) != len(want) {
		t.Fatalf("argv changed without a port: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("argv changed without a port: got %v, want %v", got, want)
		}
	}
}

func TestScpArgsCarriesPortAndKeepsPreserve(t *testing.T) {
	args := scpArgs("scan", "10.0.0.5", "/local/bin", "/tmp/x/bin", 2222)
	joined := strings.Join(args, " ")
	// scp spells the port -P; lowercase -p is "preserve mode/timestamps" and must survive.
	if !strings.Contains(joined, "-P 2222") {
		t.Errorf("scp must receive -P <port>: %v", args)
	}
	if !hasArg(args, "-p") {
		t.Errorf("scp must keep -p (preserve mode/timestamps): %v", args)
	}
}

func TestScpFromArgsCarriesPort(t *testing.T) {
	args := scpFromArgs("scan", "10.0.0.5", "/tmp/x/report.json", "/local/report.json", 2222)
	if !strings.Contains(strings.Join(args, " "), "-P 2222") {
		t.Errorf("scp download must receive -P <port>: %v", args)
	}
}

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func TestSessionPassesPortToSSHAndSCP(t *testing.T) {
	fe := &fakeExec{}
	s := &sshSession{user: "scan", host: "10.0.0.5", port: 2222, exec: fe.run}

	if _, _, err := s.Run(context.Background(), "uname -m"); err != nil {
		t.Fatal(err)
	}
	if err := s.Upload(context.Background(), []byte("ELF"), "/tmp/x/houndoom", 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Download(context.Background(), "/tmp/x/report.json"); err != nil {
		t.Fatal(err)
	}

	if len(fe.calls) != 3 {
		t.Fatalf("expected ssh + scp up + scp down, got %v", fe.calls)
	}
	if !hasArg(fe.calls[0], "-p") || !hasArg(fe.calls[0], "2222") {
		t.Errorf("ssh call lost the port: %v", fe.calls[0])
	}
	for _, call := range fe.calls[1:] {
		if !hasArg(call, "-P") || !hasArg(call, "2222") {
			t.Errorf("scp call lost the port: %v", call)
		}
	}
}

// failingExec reports a failure the way a refused connection would.
type failingExec struct{}

func (failingExec) run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	return nil, []byte("ssh: connect to host 10.0.0.5 port 2222: Connection refused"), os.ErrDeadlineExceeded
}

func TestRunErrorNamesThePortItDialled(t *testing.T) {
	s := &sshSession{user: "scan", host: "10.0.0.5", port: 2222, exec: failingExec{}.run}
	_, _, err := s.Run(context.Background(), "uname -m")
	if err == nil {
		t.Fatal("expected an error")
	}
	// Without the port the message reads like a plain :22 attempt and misleads the
	// operator who is debugging a port problem.
	if !strings.Contains(err.Error(), "scan@10.0.0.5:2222") {
		t.Errorf("error must name the target including the port, got: %v", err)
	}
}
