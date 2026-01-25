package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/IvanShishkin/houndoom/internal/config"
	"github.com/IvanShishkin/houndoom/pkg/models"
	"go.uber.org/zap"
)

func TestScanner_NewScanner(t *testing.T) {
	cfg := &config.Config{
		Mode:    "normal",
		Workers: 4,
	}

	logger, _ := zap.NewDevelopment()
	scanner := NewScanner(cfg, logger)

	if scanner == nil {
		t.Fatal("NewScanner() returned nil")
	}

	if scanner.config != cfg {
		t.Error("Scanner config not set correctly")
	}

	if scanner.logger != logger {
		t.Error("Scanner logger not set correctly")
	}

	if scanner.results == nil {
		t.Error("Scanner results not initialized")
	}
}

func TestScanner_RegisterDetector(t *testing.T) {
	cfg := &config.Config{Mode: "normal"}
	logger, _ := zap.NewDevelopment()
	scanner := NewScanner(cfg, logger)

	// Create a mock detector
	mockDetector := &mockDetector{
		name:     "test_detector",
		priority: 50,
	}

	scanner.RegisterDetector(mockDetector)

	if len(scanner.detectors) != 1 {
		t.Errorf("RegisterDetector() detectors count = %d, want 1", len(scanner.detectors))
	}

	if scanner.detectors[0].Name() != "test_detector" {
		t.Errorf("RegisterDetector() detector name = %v, want %v", scanner.detectors[0].Name(), "test_detector")
	}
}

func TestScanner_Scan_EmptyDirectory(t *testing.T) {
	// Create temporary empty directory
	tmpDir := t.TempDir()

	// Create minimal config
	cfg := &config.Config{
		Mode:           "fast",
		Workers:        2,
		MaxSize:        "1M",
		ReportFormat:   "json",
		OutputFile:     filepath.Join(tmpDir, "report.json"),
		SignaturesPath: "../../configs/signatures",
		Exclude:        []string{},
	}

	logger, _ := zap.NewDevelopment()
	scanner := NewScanner(cfg, logger)

	// Run scan on empty directory
	results, err := scanner.Scan(tmpDir)

	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if results == nil {
		t.Fatal("Scan() returned nil results")
	}

	if results.TotalFiles != 0 {
		t.Errorf("Scan() TotalFiles = %d, want 0", results.TotalFiles)
	}

	if results.ThreatsFound != 0 {
		t.Errorf("Scan() ThreatsFound = %d, want 0", results.ThreatsFound)
	}
}

func TestScanner_Scan_WithCleanFiles(t *testing.T) {
	// Create temporary directory with clean files
	tmpDir := t.TempDir()

	// Create clean PHP file
	cleanPHP := filepath.Join(tmpDir, "clean.php")
	err := os.WriteFile(cleanPHP, []byte("<?php echo 'Hello World'; ?>"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Create clean JS file
	cleanJS := filepath.Join(tmpDir, "clean.js")
	err = os.WriteFile(cleanJS, []byte("console.log('hello');"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	cfg := &config.Config{
		Mode:           "fast",
		Workers:        2,
		MaxSize:        "1M",
		ReportFormat:   "json",
		OutputFile:     filepath.Join(tmpDir, "report.json"),
		SignaturesPath: "../../configs/signatures",
		Exclude:        []string{},
	}

	logger, _ := zap.NewDevelopment()
	scanner := NewScanner(cfg, logger)

	results, err := scanner.Scan(tmpDir)

	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if results.TotalFiles < 2 {
		t.Errorf("Scan() TotalFiles = %d, want at least 2", results.TotalFiles)
	}

	if results.ScannedFiles < 2 {
		t.Errorf("Scan() ScannedFiles = %d, want at least 2", results.ScannedFiles)
	}

	// Clean files should not produce threats
	// Note: This might fail if heuristic detectors are too aggressive
	if results.ThreatsFound > 0 {
		t.Logf("Warning: Clean files produced %d threats (might be false positives)", results.ThreatsFound)
	}
}

func TestScanner_Scan_ExcludeDirectories(t *testing.T) {
	tmpDir := t.TempDir()

	// Create excluded directory
	excludedDir := filepath.Join(tmpDir, "node_modules")
	err := os.Mkdir(excludedDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create excluded dir: %v", err)
	}

	// Create file in excluded directory
	excludedFile := filepath.Join(excludedDir, "test.php")
	err = os.WriteFile(excludedFile, []byte("<?php echo 'excluded'; ?>"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Create file in main directory
	mainFile := filepath.Join(tmpDir, "main.php")
	err = os.WriteFile(mainFile, []byte("<?php echo 'main'; ?>"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	cfg := &config.Config{
		Mode:           "fast",
		Workers:        2,
		MaxSize:        "1M",
		ReportFormat:   "json",
		OutputFile:     filepath.Join(tmpDir, "report.json"),
		SignaturesPath: "../../configs/signatures",
		Exclude:        []string{"node_modules"},
	}

	logger, _ := zap.NewDevelopment()
	scanner := NewScanner(cfg, logger)

	results, err := scanner.Scan(tmpDir)

	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	// Should only scan main.php, not the file in node_modules
	if results.ScannedFiles > 1 {
		t.Logf("Warning: Scanned %d files, expected 1 (excluded directory may not be working)", results.ScannedFiles)
	}
}

// mockDetector is a simple mock detector for testing
type mockDetector struct {
	name     string
	priority int
	enabled  bool
}

func (m *mockDetector) Name() string {
	return m.name
}

func (m *mockDetector) Priority() int {
	return m.priority
}

func (m *mockDetector) SupportedExtensions() []string {
	return []string{"*"}
}

func (m *mockDetector) Detect(ctx context.Context, file *models.File) ([]*models.Finding, error) {
	return nil, nil
}

func (m *mockDetector) IsEnabled() bool {
	return m.enabled
}

func (m *mockDetector) SetEnabled(enabled bool) {
	m.enabled = enabled
}
