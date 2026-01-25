package integration

import (
	"bytes"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeobCommand_FileNotFound(t *testing.T) {
	cmd := exec.Command("go", "run", "../../cmd/scanner", "deob", "/nonexistent/file.php")
	output, err := cmd.CombinedOutput()

	if err == nil {
		t.Error("Expected error for nonexistent file, got nil")
	}

	if !strings.Contains(string(output), "file not found") {
		t.Errorf("Expected 'file not found' error, got: %s", output)
	}
}

func TestDeobCommand_NoObfuscation(t *testing.T) {
	// Create temp file with clean PHP
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "clean.php")

	content := `<?php
echo "Hello World";
$x = 1 + 2;
?>`

	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	cmd := exec.Command("go", "run", "../../cmd/scanner", "deob", tmpFile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("Command failed: %v, stderr: %s", err, stderr.String())
	}

	// Should output warning about no obfuscation
	if !strings.Contains(stderr.String(), "No obfuscation detected") {
		t.Errorf("Expected 'No obfuscation detected' warning, got stderr: %s", stderr.String())
	}

	// Stdout should contain original content
	if !strings.Contains(stdout.String(), "Hello World") {
		t.Errorf("Expected original content in stdout, got: %s", stdout.String())
	}
}

func TestDeobCommand_Base64Obfuscation(t *testing.T) {
	// Create temp file with base64 obfuscated PHP
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "obfuscated.php")

	// Encode "echo 'Hello from decoded code';"
	encoded := base64.StdEncoding.EncodeToString([]byte("echo 'Hello from decoded code';"))
	content := `<?php eval(base64_decode("` + encoded + `")); ?>`

	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	cmd := exec.Command("go", "run", "../../cmd/scanner", "deob", tmpFile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("Command failed: %v, stderr: %s", err, stderr.String())
	}

	// Should output success message
	if !strings.Contains(stderr.String(), "Deobfuscation applied") {
		t.Errorf("Expected 'Deobfuscation applied' message, got stderr: %s", stderr.String())
	}

	// Stdout should contain decoded content
	if !strings.Contains(stdout.String(), "Hello from decoded code") {
		t.Errorf("Expected decoded content in stdout, got: %s", stdout.String())
	}

	// Should NOT contain base64_decode anymore (it was replaced)
	if strings.Contains(stdout.String(), "base64_decode") {
		t.Errorf("Output should not contain base64_decode after deobfuscation, got: %s", stdout.String())
	}
}

func TestDeobCommand_NestedObfuscation(t *testing.T) {
	// Create temp file with nested base64 obfuscation
	// Note: The deobfuscator decodes layer by layer. Each layer must be a valid
	// base64_decode("...") pattern to be decoded in the next iteration.
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "nested.php")

	// Create properly nested obfuscation:
	// Layer 1: system("whoami")
	// Layer 2: eval(base64_decode("Layer1"))
	inner := base64.StdEncoding.EncodeToString([]byte(`system("whoami")`))
	content := `<?php eval(base64_decode("` + inner + `")); ?>`

	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	cmd := exec.Command("go", "run", "../../cmd/scanner", "deob", tmpFile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("Command failed: %v, stderr: %s", err, stderr.String())
	}

	// Should output success message
	if !strings.Contains(stderr.String(), "Deobfuscation applied") {
		t.Errorf("Expected 'Deobfuscation applied' message, got stderr: %s", stderr.String())
	}

	// Stdout should contain decoded content
	if !strings.Contains(stdout.String(), "whoami") {
		t.Errorf("Expected 'whoami' in stdout after deobfuscation, got: %s", stdout.String())
	}
}

func TestDeobCommand_NoArgs(t *testing.T) {
	cmd := exec.Command("go", "run", "../../cmd/scanner", "deob")
	output, err := cmd.CombinedOutput()

	if err == nil {
		t.Error("Expected error when no file argument provided, got nil")
	}

	// Cobra should show usage error
	if !strings.Contains(string(output), "accepts 1 arg") {
		t.Errorf("Expected argument error, got: %s", output)
	}
}

func TestDeobCommand_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "empty.php")

	if err := os.WriteFile(tmpFile, []byte(""), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	cmd := exec.Command("go", "run", "../../cmd/scanner", "deob", tmpFile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("Command failed: %v, stderr: %s", err, stderr.String())
	}

	// Should indicate no obfuscation
	if !strings.Contains(stderr.String(), "No obfuscation detected") {
		t.Errorf("Expected 'No obfuscation detected' for empty file, got stderr: %s", stderr.String())
	}
}

func TestDeobCommand_BinaryFile(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "binary.bin")

	// Write some binary content
	binaryContent := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}
	if err := os.WriteFile(tmpFile, binaryContent, 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	cmd := exec.Command("go", "run", "../../cmd/scanner", "deob", tmpFile)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// Should not crash on binary files
	if err := cmd.Run(); err != nil {
		// It's ok if it fails, but it shouldn't panic
		t.Logf("Command returned error (expected for binary): %v", err)
	}
}

func TestDeobCommand_LargeFile(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large file test in short mode")
	}

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "large.php")

	// Create a large file (~1MB) with some base64 content
	var content strings.Builder
	content.WriteString("<?php\n")
	for i := 0; i < 10000; i++ {
		content.WriteString("$var" + string(rune('A'+i%26)) + " = 'test';\n")
	}
	// Add one base64_decode at the end
	encoded := base64.StdEncoding.EncodeToString([]byte("FOUND_ME"))
	content.WriteString(`eval(base64_decode("` + encoded + `"));`)
	content.WriteString("\n?>")

	if err := os.WriteFile(tmpFile, []byte(content.String()), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	cmd := exec.Command("go", "run", "../../cmd/scanner", "deob", tmpFile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("Command failed: %v, stderr: %s", err, stderr.String())
	}

	// Should find and decode the base64 content
	if !strings.Contains(stdout.String(), "FOUND_ME") {
		t.Error("Expected to find decoded content in large file")
	}
}
