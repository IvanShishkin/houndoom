package php

import (
	"context"
	"testing"

	"github.com/IvanShishkin/houndoom/internal/signatures"
	"github.com/IvanShishkin/houndoom/pkg/models"
)

func TestCriticalDetector_Name(t *testing.T) {
	db := models.NewSignatureDatabase()
	matcher := signatures.NewMatcher(db)
	detector := NewCriticalDetector(matcher, models.LevelBasic)

	if got := detector.Name(); got != "php_critical" {
		t.Errorf("Name() = %v, want %v", got, "php_critical")
	}
}

func TestCriticalDetector_SupportedExtensions(t *testing.T) {
	db := models.NewSignatureDatabase()
	matcher := signatures.NewMatcher(db)
	detector := NewCriticalDetector(matcher, models.LevelBasic)

	exts := detector.SupportedExtensions()
	expectedExts := []string{"php", "php3", "php4", "php5", "php6", "php7", "phtml", "pht", "htaccess"}

	if len(exts) != len(expectedExts) {
		t.Errorf("SupportedExtensions() length = %v, want %v", len(exts), len(expectedExts))
	}
}

func TestCriticalDetector_Detect_NoThreats(t *testing.T) {
	db := models.NewSignatureDatabase()
	db.AddSignature(&models.Signature{
		ID:         "TEST-001",
		Name:       "Test Eval",
		Category:   models.ThreatPHPBackdoor,
		Severity:   models.SeverityCritical,
		Pattern:    `eval\s*\(`,
		Level:      models.LevelBasic,
		IsRegex:    true,
		Enabled:    true,
		Extensions: []string{"php"},
	})

	matcher := signatures.NewMatcher(db)
	detector := NewCriticalDetector(matcher, models.LevelBasic)

	file := &models.File{
		Path:      "/test/clean.php",
		Name:      "clean.php",
		Extension: "php",
		Content:   []byte("<?php echo 'Hello World'; ?>"),
	}

	ctx := context.Background()
	findings, err := detector.Detect(ctx, file)

	if err != nil {
		t.Errorf("Detect() error = %v, want nil", err)
	}

	if len(findings) != 0 {
		t.Errorf("Detect() found %d threats in clean file, want 0", len(findings))
	}
}

func TestCriticalDetector_Detect_WithThreats(t *testing.T) {
	db := models.NewSignatureDatabase()
	db.AddSignature(&models.Signature{
		ID:          "TEST-001",
		Name:        "Test Eval",
		Category:    models.ThreatPHPBackdoor,
		Severity:    models.SeverityCritical,
		Pattern:     `eval\s*\(`,
		Description: "Dangerous eval function",
		Level:       models.LevelBasic,
		IsRegex:     true,
		Enabled:     true,
		Extensions:  []string{"php"},
	})

	matcher := signatures.NewMatcher(db)
	detector := NewCriticalDetector(matcher, models.LevelBasic)

	file := &models.File{
		Path:      "/test/malicious.php",
		Name:      "malicious.php",
		Extension: "php",
		Content:   []byte("<?php eval($_GET['cmd']); ?>"),
	}

	ctx := context.Background()
	findings, err := detector.Detect(ctx, file)

	if err != nil {
		t.Errorf("Detect() error = %v, want nil", err)
	}

	if len(findings) == 0 {
		t.Fatal("Detect() found 0 threats, want at least 1")
	}

	finding := findings[0]
	if finding.SignatureID != "TEST-001" {
		t.Errorf("Finding SignatureID = %v, want %v", finding.SignatureID, "TEST-001")
	}

	if finding.Severity != models.SeverityCritical {
		t.Errorf("Finding Severity = %v, want %v", finding.Severity, models.SeverityCritical)
	}

	if finding.Type != models.ThreatPHPBackdoor {
		t.Errorf("Finding Type = %v, want %v", finding.Type, models.ThreatPHPBackdoor)
	}
}

func TestCriticalDetector_Detect_MultipleThreats(t *testing.T) {
	db := models.NewSignatureDatabase()
	db.AddSignature(&models.Signature{
		ID:         "TEST-001",
		Name:       "Test Eval",
		Category:   models.ThreatPHPBackdoor,
		Severity:   models.SeverityCritical,
		Pattern:    `eval\s*\(`,
		Level:      models.LevelBasic,
		IsRegex:    true,
		Enabled:    true,
		Extensions: []string{"php"},
	})
	db.AddSignature(&models.Signature{
		ID:         "TEST-002",
		Name:       "Test Shell Exec",
		Category:   models.ThreatPHPBackdoor,
		Severity:   models.SeverityCritical,
		Pattern:    `shell_exec\s*\(`,
		Level:      models.LevelBasic,
		IsRegex:    true,
		Enabled:    true,
		Extensions: []string{"php"},
	})

	matcher := signatures.NewMatcher(db)
	detector := NewCriticalDetector(matcher, models.LevelBasic)

	file := &models.File{
		Path:      "/test/backdoor.php",
		Name:      "backdoor.php",
		Extension: "php",
		Content:   []byte("<?php eval($_GET['x']); shell_exec('ls'); ?>"),
	}

	ctx := context.Background()
	findings, err := detector.Detect(ctx, file)

	if err != nil {
		t.Errorf("Detect() error = %v, want nil", err)
	}

	if len(findings) < 2 {
		t.Errorf("Detect() found %d threats, want at least 2", len(findings))
	}
}

func TestCriticalDetector_Priority(t *testing.T) {
	db := models.NewSignatureDatabase()
	matcher := signatures.NewMatcher(db)
	detector := NewCriticalDetector(matcher, models.LevelBasic)

	// Critical detector should have high priority
	if detector.Priority() != 100 {
		t.Errorf("Priority() = %v, want %v", detector.Priority(), 100)
	}
}
