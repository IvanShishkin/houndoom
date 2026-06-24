package remote

import (
	"context"
	"fmt"
	"io/fs"
	"regexp"
	"strings"
)

// CommandRunner runs a single command on the target and returns its output.
type CommandRunner interface {
	Run(ctx context.Context, cmd string) (stdout []byte, stderr []byte, err error)
}

var validModes = map[string]bool{"fast": true, "normal": true, "paranoid": true}

// safePath allows absolute paths without shell metacharacters.
var safePath = regexp.MustCompile(`^/[A-Za-z0-9._\-/]*$`)

// safeHost allows hostnames/IPs without whitespace or shell metacharacters.
var safeHost = regexp.MustCompile(`^[A-Za-z0-9._\-:]+$`)

// safeUser allows typical unix usernames.
var safeUser = regexp.MustCompile(`^[A-Za-z0-9._\-]+$`)

// safeMaxSize allows size values like "100", "100K", "500M", "2G".
var safeMaxSize = regexp.MustCompile(`^[0-9]+[KkMmGg]?$`)

// ValidateMode rejects any mode outside the fixed set.
func ValidateMode(mode string) error {
	if !validModes[mode] {
		return fmt.Errorf("invalid mode %q: must be fast, normal, or paranoid", mode)
	}
	return nil
}

// ValidateRemotePath requires an absolute path free of shell metacharacters.
func ValidateRemotePath(path string) error {
	if path == "" {
		return fmt.Errorf("path is required")
	}
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("path must be absolute: %q", path)
	}
	if !safePath.MatchString(path) {
		return fmt.Errorf("path contains unsafe characters: %q", path)
	}
	for _, part := range strings.Split(path, "/") {
		if part == ".." {
			return fmt.Errorf("path must not contain '..' components: %q", path)
		}
	}
	return nil
}

// ParseUserHost splits "user@host" and validates both halves.
func ParseUserHost(host string) (string, string, error) {
	idx := strings.Index(host, "@")
	if idx <= 0 || idx == len(host)-1 {
		return "", "", fmt.Errorf("host must be in user@host form: %q", host)
	}
	user, hostname := host[:idx], host[idx+1:]
	if !safeUser.MatchString(user) {
		return "", "", fmt.Errorf("invalid ssh user: %q", user)
	}
	if !safeHost.MatchString(hostname) {
		return "", "", fmt.Errorf("invalid host: %q", hostname)
	}
	return user, hostname, nil
}

// DetectArch runs `uname -m` on the target and maps it to a Go arch.
func DetectArch(ctx context.Context, r CommandRunner) (string, error) {
	out, _, err := r.Run(ctx, "uname -m")
	if err != nil {
		return "", fmt.Errorf("detect arch: %w", err)
	}
	arch := strings.TrimSpace(string(out))
	switch arch {
	case "x86_64", "amd64":
		return "amd64", nil
	case "aarch64", "arm64":
		return "arm64", nil
	default:
		return "", fmt.Errorf("unsupported target arch: %q", arch)
	}
}

// SelectBinary returns the bundled linux binary for the given Go arch.
func SelectBinary(fsys fs.FS, goarch string) ([]byte, string, error) {
	name := fmt.Sprintf("houndoom-linux-%s", goarch)
	data, err := fs.ReadFile(fsys, "dist/"+name)
	if err != nil {
		return nil, "", fmt.Errorf("no bundled binary for linux/%s: %w", goarch, err)
	}
	return data, name, nil
}
