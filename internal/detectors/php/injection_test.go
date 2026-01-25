package php

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/IvanShishkin/houndoom/internal/signatures"
	"github.com/IvanShishkin/houndoom/pkg/models"
)

func TestPregReplaceEModifierPattern(t *testing.T) {
	pattern := regexp.MustCompile(`(?i)\bpreg_replace\s*\(\s*['"]/[^'"]+/[imsxADSUXJu]*e[imsxADSUXJu]*['"]`)

	tests := []struct {
		name   string
		code   string
		expect bool
	}{
		// False positive case from Bitrix - should NOT match
		{
			name:   "bitrix forum component - no /e",
			code:   `preg_replace("/\[user\s*=\s*([^\]]*)\](.+?)\[\/user\]/isu", "<b>\\2</b>", $text)`,
			expect: false,
		},
		// Real /e modifier cases - SHOULD match
		{
			name:   "simple /e modifier",
			code:   `preg_replace("/test/e", $_GET['x'], $text)`,
			expect: true,
		},
		{
			name:   "/ie modifiers",
			code:   `preg_replace('/pattern/ie', 'code', $text)`,
			expect: true,
		},
		{
			name:   "/ei modifiers",
			code:   `preg_replace("/foo/ei", "bar", $x)`,
			expect: true,
		},
		{
			name:   "/e with multiple modifiers",
			code:   `preg_replace("/pattern/imse", "code", $text)`,
			expect: true,
		},
		// No /e modifier - should NOT match
		{
			name:   "only /i modifier",
			code:   `preg_replace("/pattern/i", "repl", $text)`,
			expect: false,
		},
		{
			name:   "/isu modifiers no e",
			code:   `preg_replace('/test/isu', 'x', $y)`,
			expect: false,
		},
		{
			name:   "complex pattern with escaped slashes",
			code:   `preg_replace("/https?:\/\/[^\/]+\//i", "", $url)`,
			expect: false,
		},
		{
			name:   "bitrix SEND pattern with escaped slashes",
			code:   `preg_replace("/\[SEND(?:=(.+?))?\](.+?)?\[\/SEND\]/i", "$2", $quoteMessage['MESSAGE'])`,
			expect: false,
		},
		{
			name:   "bitrix pattern with word containing e after slash",
			code:   `preg_replace("/\[USER=([^\]]+)\](.+?)\[\/USER\]/isu", "<b>$2</b>", $text)`,
			expect: false,
		},
		{
			name:   "bitrix im text.php USER pattern",
			code:   `preg_replace("/\[USER=([0-9]+)( REPLACE)?](.*?)\[\/USER]/i", "$3", $text)`,
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := pattern.MatchString(tt.code)
			if matched != tt.expect {
				t.Errorf("expected %v, got %v for: %s", tt.expect, matched, tt.code)
			}
		})
	}
}

func TestObjectInjectionSafePattern(t *testing.T) {
	// Test the isSafeUnserialize function
	tests := []struct {
		name     string
		code     string
		isSafe   bool
	}{
		// Safe patterns with allowed_classes => false
		{
			name:   "bitrix safe unserialize with allowed_classes false",
			code:   `$arData = unserialize($_REQUEST['MAP_DATA'], ['allowed_classes' => false]);`,
			isSafe: true,
		},
		{
			name:   "allowed_classes with double quotes",
			code:   `$data = unserialize($_POST['data'], ["allowed_classes" => false]);`,
			isSafe: true,
		},
		{
			name:   "allowed_classes without quotes on key",
			code:   `$x = unserialize($_GET['x'], [allowed_classes => false]);`,
			isSafe: true,
		},
		// Unsafe patterns
		{
			name:   "unserialize without second argument",
			code:   `$data = unserialize($_REQUEST['data']);`,
			isSafe: false,
		},
		{
			name:   "unserialize with allowed_classes true",
			code:   `$data = unserialize($_POST['x'], ['allowed_classes' => true]);`,
			isSafe: false,
		},
		{
			name:   "unserialize with empty options",
			code:   `$obj = unserialize($_GET['obj'], []);`,
			isSafe: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSafeUnserialize(tt.code, 0)
			if result != tt.isSafe {
				t.Errorf("isSafeUnserialize: expected %v, got %v for: %s", tt.isSafe, result, tt.code)
			}
		})
	}
}

func TestIsLanguageFile(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		// Should be detected as language files
		{
			name:     "bitrix lang kz",
			path:     "/var/www/bitrix/modules/main/lang/kz/classes/general/vuln_scanner.php",
			expected: true,
		},
		{
			name:     "bitrix lang ru",
			path:     "/bitrix/modules/main/lang/ru/classes/general/vuln_scanner.php",
			expected: true,
		},
		{
			name:     "windows path lang",
			path:     "C:\\bitrix\\modules\\main\\lang\\en\\file.php",
			expected: true,
		},
		// Should NOT be detected as language files
		{
			name:     "regular php file",
			path:     "/var/www/bitrix/modules/main/classes/general/vuln_scanner.php",
			expected: false,
		},
		{
			name:     "upload directory",
			path:     "/var/www/upload/malware.php",
			expected: false,
		},
		{
			name:     "file with lang in name but not directory",
			path:     "/var/www/bitrix/language_file.php",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isLanguageFile(tt.path)
			if result != tt.expected {
				t.Errorf("isLanguageFile(%s): expected %v, got %v", tt.path, tt.expected, result)
			}
		})
	}
}

func TestIsMethodCall(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		pos      int
		expected bool
	}{
		// Method calls - should return true
		{
			name:     "arrow method call ->exec",
			content:  "$loader->exec($_REQUEST['mode'])",
			pos:      9, // position of 'e' in 'exec' (0-indexed: $=0,l=1,o=2,a=3,d=4,e=5,r=6,-=7,>=8,e=9)
			expected: true,
		},
		{
			name:     "static method call ::exec",
			content:  "FileLoader::exec($_REQUEST['mode'])",
			pos:      12, // position of 'exec'
			expected: true,
		},
		{
			name:     "chained method call",
			content:  "$obj->method()->exec($_GET['x'])",
			pos:      16, // position of 'exec'
			expected: true,
		},
		// Function calls - should return false
		{
			name:     "standalone exec function",
			content:  "exec($_GET['cmd'])",
			pos:      0, // position of 'exec'
			expected: false,
		},
		{
			name:     "exec with spaces before",
			content:  "   exec($_GET['cmd'])",
			pos:      3, // position of 'exec'
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
			result := isMethodCall(tt.content, tt.pos)
			if result != tt.expected {
				t.Errorf("isMethodCall(%s, %d): expected %v, got %v",
					tt.content, tt.pos, tt.expected, result)
			}
		})
	}
}

func TestInjectionDetector_LanguageFileExclusion(t *testing.T) {
	// Create detector
	db := models.NewSignatureDatabase()
	matcher := signatures.NewMatcher(db)
	detector := NewInjectionDetector(matcher, models.LevelBasic)

	// Test case: language file with command injection example
	langFile := &models.File{
		Path:      "/bitrix/modules/main/lang/ru/classes/general/vuln_scanner.php",
		Extension: "php",
		Content:   []byte(`<?php $MESS["VULN_DESC"] = "Example: system(\"ping \$_GET['host']\");";`),
	}

	findings, err := detector.Detect(context.Background(), langFile)
	if err != nil {
		t.Fatalf("Detect returned error: %v", err)
	}

	if len(findings) > 0 {
		t.Errorf("Expected no findings for language file, got %d findings", len(findings))
		for _, f := range findings {
			t.Logf("  - %s: %s", f.SignatureID, f.Description)
		}
	}
}

func TestIsSecurityModule(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		// Should be detected as security modules
		{
			path:     "/var/www/bitrix/modules/security/admin/security_file_verifier.php",
			expected: true,
		},
		{
			path:     "/bitrix/modules/security/classes/general/xscan.php",
			expected: true,
		},
		{
			path:     "C:\\bitrix\\modules\\security\\admin\\file.php",
			expected: true,
		},
		// Should NOT be detected as security modules
		{
			path:     "/var/www/bitrix/modules/main/tools/upload.php",
			expected: false,
		},
		{
			path:     "/var/www/upload/security.php",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := isSecurityModule(tt.path)
			if result != tt.expected {
				t.Errorf("isSecurityModule(%s): expected %v, got %v", tt.path, tt.expected, result)
			}
		})
	}
}

func TestInjectionDetector_SecurityModuleExclusion(t *testing.T) {
	db := models.NewSignatureDatabase()
	matcher := signatures.NewMatcher(db)
	detector := NewInjectionDetector(matcher, models.LevelBasic)

	tests := []struct {
		name      string
		path      string
		content   string
		expectHit bool
	}{
		{
			name:      "security module header injection should be excluded",
			path:      "/bitrix/modules/security/admin/security_file_verifier.php",
			content:   `<?php header("Content-Type: " . $_REQUEST["type"]);`,
			expectHit: false,
		},
		{
			name:      "regular file header injection should be detected",
			path:      "/var/www/upload/malicious.php",
			content:   `<?php header("Location: " . $_GET["url"]);`,
			expectHit: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := &models.File{
				Path:      tt.path,
				Extension: "php",
				Content:   []byte(tt.content),
			}

			findings, err := detector.Detect(context.Background(), file)
			if err != nil {
				t.Fatalf("Detect error: %v", err)
			}

			hasHeaderInjection := false
			for _, f := range findings {
				if strings.Contains(f.SignatureID, "Header") {
					hasHeaderInjection = true
					break
				}
			}

			if hasHeaderInjection != tt.expectHit {
				t.Errorf("expected header injection hit=%v, got=%v", tt.expectHit, hasHeaderInjection)
			}
		})
	}
}

func TestInjectionDetector_MethodCallExclusion(t *testing.T) {
	// Create detector
	db := models.NewSignatureDatabase()
	matcher := signatures.NewMatcher(db)
	detector := NewInjectionDetector(matcher, models.LevelBasic)

	tests := []struct {
		name          string
		content       string
		expectHit     bool
		description   string
	}{
		{
			name:        "method call ->exec should not trigger",
			content:     `<?php $loader->exec($_REQUEST["mode"]);`,
			expectHit:   false,
			description: "Method calls like ->exec() should be excluded",
		},
		{
			name:        "real exec function should trigger",
			content:     `<?php exec($_GET["cmd"]);`,
			expectHit:   true,
			description: "Real exec() function with user input should be detected",
		},
		{
			name:        "system function should trigger",
			content:     `<?php system($_REQUEST["cmd"]);`,
			expectHit:   true,
			description: "system() with user input should be detected",
		},
		{
			name:        "chained method ->setValue->exec should not trigger",
			content:     `<?php $obj->setValue($_REQUEST["val"])->exec($_REQUEST["mode"]);`,
			expectHit:   false,
			description: "Chained method calls should be excluded",
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
				t.Fatalf("Detect returned error: %v", err)
			}

			hasCommandInjection := false
			for _, f := range findings {
				if f.SignatureID == "INJECTION-Command-Injection" ||
					f.SignatureID == "INJECTION-User-Input-in-Exec" {
					hasCommandInjection = true
					break
				}
			}

			if hasCommandInjection != tt.expectHit {
				t.Errorf("%s: expected hit=%v, got hit=%v",
					tt.description, tt.expectHit, hasCommandInjection)
				if len(findings) > 0 {
					for _, f := range findings {
						t.Logf("  Found: %s", f.SignatureID)
					}
				}
			}
		})
	}
}
