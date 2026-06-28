package models

import (
	"time"
)

// File represents a file to be scanned
type File struct {
	Path         string    // Full file path
	RelativePath string    // Path relative to scan root
	Name         string    // File name
	Extension    string    // File extension (without dot)
	Size         int64     // File size in bytes
	ModTime      time.Time // Modification time
	ChangeTime   time.Time // Change time (inode)
	Content      []byte    `json:"-"` // In-memory file content; never serialized into reports (would bloat JSON with full file bodies).
	Hash         string    // File hash (CRC32 or SHA1)
	IsSymlink    bool      // Is symbolic link
	IsHidden     bool      // Is hidden file
}

// FileInfo contains basic file information without content
type FileInfo struct {
	Path       string
	Size       int64
	ModTime    time.Time
	ChangeTime time.Time
	IsDir      bool
	IsSymlink  bool
	IsHidden   bool
}
