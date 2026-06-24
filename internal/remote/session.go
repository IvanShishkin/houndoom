package remote

import (
	"context"
	"os"
)

// FileTransfer uploads and downloads files over an established connection.
type FileTransfer interface {
	Upload(ctx context.Context, data []byte, remotePath string, mode os.FileMode) error
	Download(ctx context.Context, remotePath string) ([]byte, error)
}

// Session is a connected transport to a target: it can run commands and move files.
type Session interface {
	CommandRunner
	FileTransfer
	Close() error
}

// Connector establishes a Session to user@host. The real implementation uses
// the system SSH client with ssh-agent and known_hosts verification (see ssh.go).
type Connector func(ctx context.Context, user, host string) (Session, error)
