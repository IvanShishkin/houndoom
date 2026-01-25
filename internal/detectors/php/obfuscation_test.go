package php

import (
	"context"
	"strings"
	"testing"

	"github.com/IvanShishkin/houndoom/internal/signatures"
	"github.com/IvanShishkin/houndoom/pkg/models"
)

func TestObfuscationDetector_GotoObfuscation(t *testing.T) {
	db := models.NewSignatureDatabase()
	matcher := signatures.NewMatcher(db)
	detector := NewObfuscationDetector(matcher, models.LevelBasic)

	tests := []struct {
		name      string
		content   string
		expectHit bool
		sigID     string
	}{
		{
			name: "heavy goto obfuscation",
			content: `<?php
				goto label1; label2: echo "b"; goto label3;
				label1: echo "a"; goto label2; label3: echo "c";
				goto label4; label5: echo "e"; goto end;
				label4: echo "d"; goto label5; end: echo "done";
				goto x1; x2: $a=1; goto x3; x1: $b=2; goto x2;
				x3: $c=3; goto x4; x4: $d=4; goto x5; x5: echo $a;
			?>`,
			expectHit: true,
			sigID:     "OBFUSCATION-GOTO",
		},
		{
			name: "normal code without goto",
			content: `<?php
				echo "Hello World";
				$x = 1 + 2;
				function test() { return true; }
			?>`,
			expectHit: false,
			sigID:     "OBFUSCATION-GOTO",
		},
		{
			name: "single goto is fine",
			content: `<?php
				if ($error) goto cleanup;
				// do work
				cleanup: unset($data);
			?>`,
			expectHit: false,
			sigID:     "OBFUSCATION-GOTO",
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

			hasHit := false
			for _, f := range findings {
				if f.SignatureID == tt.sigID {
					hasHit = true
					break
				}
			}

			if hasHit != tt.expectHit {
				t.Errorf("expected %s hit=%v, got=%v", tt.sigID, tt.expectHit, hasHit)
			}
		})
	}
}

func TestObfuscationDetector_HexStringEncoding(t *testing.T) {
	db := models.NewSignatureDatabase()
	matcher := signatures.NewMatcher(db)
	detector := NewObfuscationDetector(matcher, models.LevelBasic)

	tests := []struct {
		name      string
		content   string
		expectHit bool
	}{
		{
			name: "heavy hex encoding",
			content: `<?php
				$a = "\x72\x61\x6e\x67\x65";
				$b = "\x65\x76\x61\x6c";
				$c = "\x62\x61\x73\x65\x36\x34\x5f\x64\x65\x63\x6f\x64\x65";
				$d = "\x73\x79\x73\x74\x65\x6d";
				$e = "\x70\x61\x73\x73\x74\x68\x72\x75";
				$f = "\x65\x78\x65\x63";
			?>`,
			expectHit: true,
		},
		{
			name: "normal code with few escapes",
			content: `<?php
				$newline = "\n";
				$tab = "\t";
				echo "Hello\nWorld";
			?>`,
			expectHit: false,
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

			hasHit := false
			for _, f := range findings {
				if f.SignatureID == "OBFUSCATION-HEXSTRING" {
					hasHit = true
					break
				}
			}

			if hasHit != tt.expectHit {
				t.Errorf("expected HEXSTRING hit=%v, got=%v", tt.expectHit, hasHit)
			}
		})
	}
}

func TestObfuscationDetector_RangeEncoding(t *testing.T) {
	db := models.NewSignatureDatabase()
	matcher := signatures.NewMatcher(db)
	detector := NewObfuscationDetector(matcher, models.LevelBasic)

	// Padding to make files >100 bytes
	padding := "// " + strings.Repeat("x", 100) + "\n"

	tests := []struct {
		name      string
		content   string
		expectHit bool
	}{
		{
			name:      "range tilde to space",
			content:   `<?php ` + padding + `$arr = range('~', ' '); ?>`,
			expectHit: true,
		},
		{
			name:      "range hex encoded",
			content:   `<?php ` + padding + `$arr = range("\176", "\x20"); ?>`,
			expectHit: true,
		},
		{
			name:      "normal range usage",
			content:   `<?php ` + padding + `$arr = range(1, 10); ?>`,
			expectHit: false,
		},
		{
			name:      "range a to z",
			content:   `<?php ` + padding + `$arr = range('a', 'z'); ?>`,
			expectHit: false,
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

			hasHit := false
			for _, f := range findings {
				if f.SignatureID == "OBFUSCATION-RANGE-ENCODING" {
					hasHit = true
					break
				}
			}

			if hasHit != tt.expectHit {
				t.Errorf("expected RANGE-ENCODING hit=%v, got=%v", tt.expectHit, hasHit)
			}
		})
	}
}

func TestObfuscationDetector_EvalViaVariable(t *testing.T) {
	db := models.NewSignatureDatabase()
	matcher := signatures.NewMatcher(db)
	detector := NewObfuscationDetector(matcher, models.LevelBasic)

	padding := "// " + strings.Repeat("x", 100) + "\n"

	tests := []struct {
		name      string
		content   string
		expectHit bool
	}{
		{
			name:      "eval via array",
			content:   `<?php ` + padding + `@eval($funcs[3]($data)); ?>`,
			expectHit: true,
		},
		{
			name:      "eval via variable call",
			content:   `<?php ` + padding + `eval($decoder($encoded)); ?>`,
			expectHit: true,
		},
		{
			name:      "normal eval with string",
			content:   `<?php ` + padding + `eval('echo "test";'); ?>`,
			expectHit: false,
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

			hasHit := false
			for _, f := range findings {
				if f.SignatureID == "OBFUSCATION-EVAL-VAR" {
					hasHit = true
					break
				}
			}

			if hasHit != tt.expectHit {
				t.Errorf("expected EVAL-VAR hit=%v, got=%v", tt.expectHit, hasHit)
			}
		})
	}
}

func TestObfuscationDetector_C2Pattern(t *testing.T) {
	db := models.NewSignatureDatabase()
	matcher := signatures.NewMatcher(db)
	detector := NewObfuscationDetector(matcher, models.LevelBasic)

	padding := "// " + strings.Repeat("x", 100) + "\n"

	tests := []struct {
		name      string
		content   string
		expectHit bool
	}{
		{
			name: "curl + eval C2",
			content: `<?php ` + padding + `
				$ch = curl_init($url);
				$data = curl_exec($ch);
				eval($data);
			?>`,
			expectHit: true,
		},
		{
			name: "curl without eval",
			content: `<?php ` + padding + `
				$ch = curl_init($url);
				$data = curl_exec($ch);
				echo $data;
			?>`,
			expectHit: false,
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

			hasHit := false
			for _, f := range findings {
				if f.SignatureID == "OBFUSCATION-C2-PATTERN" {
					hasHit = true
					break
				}
			}

			if hasHit != tt.expectHit {
				t.Errorf("expected C2-PATTERN hit=%v, got=%v", tt.expectHit, hasHit)
			}
		})
	}
}

func TestObfuscationDetector_Base64Eval(t *testing.T) {
	db := models.NewSignatureDatabase()
	matcher := signatures.NewMatcher(db)
	detector := NewObfuscationDetector(matcher, models.LevelBasic)

	padding := "// " + strings.Repeat("x", 100) + "\n"

	tests := []struct {
		name      string
		content   string
		expectHit bool
	}{
		{
			name:      "eval base64_decode",
			content:   `<?php ` + padding + `eval(base64_decode($encoded)); ?>`,
			expectHit: true,
		},
		{
			name:      "eval gzinflate base64",
			content:   `<?php ` + padding + `eval(gzinflate(base64_decode($data))); ?>`,
			expectHit: true,
		},
		{
			name:      "just base64_decode",
			content:   `<?php ` + padding + `$data = base64_decode($encoded); ?>`,
			expectHit: false,
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

			hasHit := false
			for _, f := range findings {
				if f.SignatureID == "OBFUSCATION-BASE64-EVAL" {
					hasHit = true
					break
				}
			}

			if hasHit != tt.expectHit {
				t.Errorf("expected BASE64-EVAL hit=%v, got=%v", tt.expectHit, hasHit)
			}
		})
	}
}

func TestObfuscationDetector_RealWebshell(t *testing.T) {
	db := models.NewSignatureDatabase()
	matcher := signatures.NewMatcher(db)
	detector := NewObfuscationDetector(matcher, models.LevelBasic)

	// Simulated goto-obfuscated webshell (simplified version)
	webshell := `<?php
		goto S0qiFNaYCc_Wlm; uWE_qW2PD5rrqK: class Q8OMf0gOu9qX64 {
			static function yCkfxEld6ekh1s($HXDIFty21JcP7t) {
				goto tG1NY_BPDBrzfw;
				tG1NY_BPDBrzfw: $SX0ZVrLFe8gqHy = "\x72" . "\x61" . "\x6e" . "\x67" . "\x65";
				goto zHKQSuRmDwBBQK;
				zHKQSuRmDwBBQK: $u2gdJFP3lTIRc_ = $SX0ZVrLFe8gqHy("\176", "\x20");
				goto vAD7Zhz78WYq7r;
				vAD7Zhz78WYq7r: return $u2gdJFP3lTIRc_;
			}
			static function GIw5xESn3G6ATU($url) {
				$ch = curl_init($url);
				$data = curl_exec($ch);
				return $data;
			}
		}
		goto FySsyC0a2qXlOl;
		S0qiFNaYCc_Wlm: $arr = range("\176", "\x20");
		goto t5n2u5q8CVlB8s;
		t5n2u5q8CVlB8s: @eval($arr[3]($data));
		goto UKZymhnoA9gqIY;
		UKZymhnoA9gqIY: echo "done";
		FySsyC0a2qXlOl: Q8OmF0GoU9qX64::yCkfxEld6ekh1s("test");
	?>`

	file := &models.File{
		Path:      "/var/www/login/txets.php",
		Extension: "php",
		Content:   []byte(webshell),
	}

	findings, err := detector.Detect(context.Background(), file)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}

	// Should detect multiple obfuscation techniques
	if len(findings) < 3 {
		t.Errorf("Expected at least 3 findings for webshell, got %d", len(findings))
	}

	// Check for specific signatures
	expectedSigs := []string{
		"OBFUSCATION-GOTO",
		"OBFUSCATION-RANGE-ENCODING",
		"OBFUSCATION-EVAL-VAR",
	}

	for _, expectedSig := range expectedSigs {
		found := false
		for _, f := range findings {
			if f.SignatureID == expectedSig {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected to find %s in webshell detection", expectedSig)
		}
	}

	// Log all findings for visibility
	t.Logf("Found %d obfuscation indicators:", len(findings))
	for _, f := range findings {
		t.Logf("  - %s: %s (severity: %s, confidence: %d%%)",
			f.SignatureID, f.SignatureName, f.Severity, f.Confidence)
	}
}

func TestObfuscationDetector_CleanCode(t *testing.T) {
	db := models.NewSignatureDatabase()
	matcher := signatures.NewMatcher(db)
	detector := NewObfuscationDetector(matcher, models.LevelBasic)

	// Normal PHP code should not trigger
	cleanCode := `<?php
		namespace App\Controllers;

		class UserController {
			private $userService;

			public function __construct(UserService $userService) {
				$this->userService = $userService;
			}

			public function index(): Response {
				$users = $this->userService->getAllUsers();
				return $this->render('users/index', ['users' => $users]);
			}

			public function show(int $id): Response {
				$user = $this->userService->findById($id);
				if (!$user) {
					throw new NotFoundException("User not found");
				}
				return $this->render('users/show', ['user' => $user]);
			}
		}
	?>`

	file := &models.File{
		Path:      "/var/www/app/Controllers/UserController.php",
		Extension: "php",
		Content:   []byte(cleanCode),
	}

	findings, err := detector.Detect(context.Background(), file)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}

	// Should not detect anything in clean code
	if len(findings) > 0 {
		t.Errorf("Expected 0 findings for clean code, got %d:", len(findings))
		for _, f := range findings {
			t.Logf("  - %s: %s", f.SignatureID, f.Description)
		}
	}
}

func TestObfuscationDetector_CharConcatenation(t *testing.T) {
	db := models.NewSignatureDatabase()
	matcher := signatures.NewMatcher(db)
	detector := NewObfuscationDetector(matcher, models.LevelBasic)

	content := `<?php
		$func = "e" . "v" . "a" . "l";
		$decode = "b" . "a" . "s" . "e" . "6" . "4" . "_" . "d" . "e" . "c" . "o" . "d" . "e";
		$sys = "s" . "y" . "s" . "t" . "e" . "m";
	?>`

	file := &models.File{
		Path:      "/var/www/test.php",
		Extension: "php",
		Content:   []byte(content),
	}

	findings, err := detector.Detect(context.Background(), file)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}

	hasCharConcat := false
	for _, f := range findings {
		if strings.Contains(f.SignatureID, "CHAR-CONCAT") {
			hasCharConcat = true
			break
		}
	}

	if !hasCharConcat {
		t.Error("Expected to detect character concatenation obfuscation")
	}
}
