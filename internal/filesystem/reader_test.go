package filesystem

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/IvanShishkin/houndoom/pkg/models"
)

func TestParseSize(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int64
	}{
		{"Bytes", "100", 100},
		{"Kilobytes", "1K", 1024},
		{"Kilobytes lowercase", "1k", 1024},
		{"Megabytes", "1M", 1024 * 1024},
		{"Megabytes lowercase", "1m", 1024 * 1024},
		{"Gigabytes", "1G", 1024 * 1024 * 1024},
		{"Multiple KB", "650K", 650 * 1024},
		{"Multiple MB", "10M", 10 * 1024 * 1024},
		{"Invalid format", "abc", 0},
		{"Empty string", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseSize(tt.input); got != tt.expected {
				t.Errorf("ParseSize(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestGetExtension(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/path/to/file.php", "php"},
		{"/path/to/file.PHP", "PHP"}, // Extension preserves case
		{"/path/to/file.js", "js"},
		{"/path/to/.htaccess", "htaccess"},
		{"/path/to/file", ""},
		{"/path/to/file.tar.gz", "gz"},
		{"file.php", "php"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := GetExtension(tt.path); got != tt.expected {
				t.Errorf("GetExtension(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestReadFile(t *testing.T) {
	// Create temporary test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.php")
	testContent := "<?php echo 'hello'; ?>"

	err := os.WriteFile(testFile, []byte(testContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Get file info
	stat, err := os.Stat(testFile)
	if err != nil {
		t.Fatalf("Failed to stat test file: %v", err)
	}

	fileInfo := &models.FileInfo{
		Path: testFile,
		Size: stat.Size(),
	}

	// Read file
	file, err := ReadFile(fileInfo)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	if file == nil {
		t.Fatal("ReadFile() returned nil file")
	}

	if string(file.Content) != testContent {
		t.Errorf("File content = %q, want %q", string(file.Content), testContent)
	}

	if file.Path != testFile {
		t.Errorf("File path = %q, want %q", file.Path, testFile)
	}

	if file.Extension != "php" {
		t.Errorf("File extension = %q, want %q", file.Extension, "php")
	}
}

func TestReadFile_NonExistent(t *testing.T) {
	fileInfo := &models.FileInfo{
		Path: "/nonexistent/file.php",
		Size: 0,
	}

	_, err := ReadFile(fileInfo)
	if err == nil {
		t.Error("ReadFile() expected error for non-existent file, got nil")
	}
}

func TestReadFile_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "empty.txt")

	err := os.WriteFile(testFile, []byte(""), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	stat, _ := os.Stat(testFile)
	fileInfo := &models.FileInfo{
		Path: testFile,
		Size: stat.Size(),
	}

	file, err := ReadFile(fileInfo)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	if len(file.Content) != 0 {
		t.Errorf("Empty file content length = %d, want 0", len(file.Content))
	}
}
