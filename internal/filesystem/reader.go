package filesystem

import (
	"crypto/sha1"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"

	"github.com/IvanShishkin/houndoom/pkg/models"
)

// ReadFile reads a file and returns a File model
func ReadFile(fileInfo *models.FileInfo) (*models.File, error) {
	// Read file content
	content, err := os.ReadFile(fileInfo.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Calculate hash
	hash := calculateHash(content)

	// Get file name and extension
	name := filepath.Base(fileInfo.Path)
	ext := GetExtension(fileInfo.Path)

	return &models.File{
		Path:       fileInfo.Path,
		Name:       name,
		Extension:  ext,
		Size:       fileInfo.Size,
		ModTime:    fileInfo.ModTime,
		ChangeTime: fileInfo.ChangeTime,
		Content:    content,
		Hash:       hash,
		IsSymlink:  fileInfo.IsSymlink,
		IsHidden:   fileInfo.IsHidden,
	}, nil
}

// calculateHash calculates CRC32 hash of content
func calculateHash(content []byte) string {
	crc := crc32.ChecksumIEEE(content)
	return fmt.Sprintf("%08x", crc)
}

// CalculateSHA1 calculates SHA1 hash of content
func CalculateSHA1(content []byte) string {
	hash := sha1.Sum(content)
	return fmt.Sprintf("%x", hash)
}

// ParseSize parses size string (e.g., "650K", "1M") to bytes
func ParseSize(sizeStr string) int64 {
	if len(sizeStr) == 0 {
		return 0
	}

	// Get last character (unit)
	last := sizeStr[len(sizeStr)-1]
	var multiplier int64 = 1

	switch last {
	case 'K', 'k':
		multiplier = 1024
		sizeStr = sizeStr[:len(sizeStr)-1]
	case 'M', 'm':
		multiplier = 1024 * 1024
		sizeStr = sizeStr[:len(sizeStr)-1]
	case 'G', 'g':
		multiplier = 1024 * 1024 * 1024
		sizeStr = sizeStr[:len(sizeStr)-1]
	}

	// Parse number
	var size int64
	fmt.Sscanf(sizeStr, "%d", &size)

	return size * multiplier
}

// CopyFile copies a file from src to dst
func CopyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return err
	}

	return destFile.Sync()
}
