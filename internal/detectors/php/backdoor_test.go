package php

import (
	"context"
	"testing"

	"github.com/IvanShishkin/houndoom/internal/signatures"
	"github.com/IvanShishkin/houndoom/pkg/models"
)

func TestIsMethodCallAtPosition(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		pos      int
		expected bool
	}{
		{
			name:     "arrow method call ->exec",
			content:  "$loader->exec($_REQUEST['mode'])",
			pos:      9, // position of 'e' in exec
			expected: true,
		},
		{
			name:     "static method call ::exec",
			content:  "Loader::exec($_REQUEST['mode'])",
			pos:      8,
			expected: true,
		},
		{
			name:     "standalone exec function",
			content:  "exec($_GET['cmd'])",
			pos:      0,
			expected: false,
		},
		{
			name:     "system function",
			content:  "system($_REQUEST['cmd'])",
			pos:      0,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isMethodCallAtPosition(tt.content, tt.pos)
			if result != tt.expected {
				t.Errorf("isMethodCallAtPosition(%q, %d): expected %v, got %v",
					tt.content, tt.pos, tt.expected, result)
			}
		})
	}
}

func TestBackdoorDetector_MethodCallExclusion(t *testing.T) {
	db := models.NewSignatureDatabase()
	matcher := signatures.NewMatcher(db)
	detector := NewBackdoorDetector(matcher, models.LevelBasic)

	tests := []struct {
		name      string
		content   string
		expectHit bool
		desc      string
	}{
		{
			name:      "method call ->exec should not trigger",
			content:   `<?php $loader->exec($_REQUEST["mode"]);`,
			expectHit: false,
			desc:      "Method calls like ->exec() should be excluded",
		},
		{
			name:      "real exec function should trigger",
			content:   `<?php exec($_GET["cmd"]);`,
			expectHit: true,
			desc:      "Real exec() function with user input should be detected",
		},
		{
			name:      "system function should trigger",
			content:   `<?php system($_REQUEST["cmd"]);`,
			expectHit: true,
			desc:      "system() with user input should be detected",
		},
		{
			name:      "chained method should not trigger",
			content:   `<?php $obj->setValue($_REQUEST["val"])->exec($_REQUEST["mode"]);`,
			expectHit: false,
			desc:      "Chained method calls should be excluded",
		},
		{
			name:      "passthru function should trigger",
			content:   `<?php passthru($_POST["cmd"]);`,
			expectHit: true,
			desc:      "passthru() with user input should be detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := &models.File{
				Path:      "/var/www/test.php",
				Extension: "php",
				Content:   []byte(tt.content),
			}

			findings, err := detector.Detect(context.Background(), file)
			if err != nil {
				t.Fatalf("Detect error: %v", err)
			}

			hasCommandExecution := false
			for _, f := range findings {
				if f.SignatureID == "BACKDOOR-COMBO" &&
					f.SignatureName == "User Input to Command Execution" {
					hasCommandExecution = true
					break
				}
			}

			if hasCommandExecution != tt.expectHit {
				t.Errorf("%s: expected hit=%v, got=%v", tt.desc, tt.expectHit, hasCommandExecution)
				for _, f := range findings {
					t.Logf("  Found: %s - %s", f.SignatureID, f.SignatureName)
				}
			}
		})
	}
}

func TestBackdoorDetector_RealBackdoorsStillDetected(t *testing.T) {
	db := models.NewSignatureDatabase()
	matcher := signatures.NewMatcher(db)
	detector := NewBackdoorDetector(matcher, models.LevelBasic)

	tests := []struct {
		name    string
		content string
		sigID   string
	}{
		{
			name:    "eval with user input",
			content: `<?php eval($_POST["code"]);`,
			sigID:   "BACKDOOR-COMBO",
		},
		{
			name:    "base64 eval",
			content: `<?php eval(base64_decode($encoded));`,
			sigID:   "BACKDOOR-COMBO",
		},
		{
			name:    "known shell signature",
			content: `<?php // c99shell variant`,
			sigID:   "BACKDOOR-SHELL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := &models.File{
				Path:      "/var/www/shell.php",
				Extension: "php",
				Content:   []byte(tt.content),
			}

			findings, err := detector.Detect(context.Background(), file)
			if err != nil {
				t.Fatalf("Detect error: %v", err)
			}

			found := false
			for _, f := range findings {
				if f.SignatureID == tt.sigID {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("Expected to find %s for: %s", tt.sigID, tt.content)
			}
		})
	}
}
