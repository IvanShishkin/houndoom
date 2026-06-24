package remote

import (
	"context"
	"errors"
	"testing"
	"testing/fstest"
)

func TestValidateMode(t *testing.T) {
	for _, m := range []string{"fast", "normal", "paranoid"} {
		if err := ValidateMode(m); err != nil {
			t.Errorf("ValidateMode(%q) unexpected error: %v", m, err)
		}
	}
	if err := ValidateMode("evil; rm -rf /"); err == nil {
		t.Error("expected error for invalid mode")
	}
}

func TestValidateRemotePath(t *testing.T) {
	if err := ValidateRemotePath("/var/www"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	for _, bad := range []string{"", "relative/path", "/var/www; rm -rf /", "/a`b`", "/a$(x)", "/var/www /etc/passwd", "/../../etc/shadow", "/var/../etc"} {
		if err := ValidateRemotePath(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestParseUserHost(t *testing.T) {
	u, h, err := ParseUserHost("scan@10.0.0.5")
	if err != nil || u != "scan" || h != "10.0.0.5" {
		t.Fatalf("got (%q,%q,%v)", u, h, err)
	}
	if _, _, err := ParseUserHost("nohost"); err == nil {
		t.Error("expected error when user missing")
	}
	if _, _, err := ParseUserHost("scan@bad host"); err == nil {
		t.Error("expected error for whitespace in host")
	}
}

type fakeRunner struct {
	out    []byte
	err    error
	gotCmd string
}

func (f *fakeRunner) Run(ctx context.Context, cmd string) ([]byte, []byte, error) {
	f.gotCmd = cmd
	return f.out, nil, f.err
}

func TestDetectArch(t *testing.T) {
	cases := map[string]string{"x86_64\n": "amd64", "aarch64\n": "arm64", "arm64\n": "arm64"}
	for unameOut, want := range cases {
		runner := &fakeRunner{out: []byte(unameOut)}
		got, err := DetectArch(context.Background(), runner)
		if err != nil || got != want {
			t.Errorf("uname %q -> (%q,%v), want %q", unameOut, got, err, want)
		}
		if runner.gotCmd != "uname -m" {
			t.Errorf("expected gotCmd to be \"uname -m\", got %q", runner.gotCmd)
		}
	}
	runner := &fakeRunner{out: []byte("mips\n")}
	if _, err := DetectArch(context.Background(), runner); err == nil {
		t.Error("expected error for unsupported arch")
	}
	if runner.gotCmd != "uname -m" {
		t.Errorf("expected gotCmd to be \"uname -m\", got %q", runner.gotCmd)
	}
	if _, err := DetectArch(context.Background(), &fakeRunner{err: errors.New("ssh down")}); err == nil {
		t.Error("expected error when runner fails")
	}
}

func TestSelectBinary(t *testing.T) {
	fsys := fstest.MapFS{
		"dist/houndoom-linux-amd64": {Data: []byte("ELF-amd64")},
	}
	data, name, err := SelectBinary(fsys, "amd64")
	if err != nil || string(data) != "ELF-amd64" || name != "houndoom-linux-amd64" {
		t.Fatalf("got (%q,%q,%v)", data, name, err)
	}
	if _, _, err := SelectBinary(fsys, "arm64"); err == nil {
		t.Error("expected error when binary not bundled")
	}
}
