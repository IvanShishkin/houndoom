package bitrix

import (
	"context"
	"testing"

	"github.com/IvanShishkin/houndoom/internal/signatures"
	"github.com/IvanShishkin/houndoom/pkg/models"
)

func TestBitrixDetector_CacheDirectoryExclusion(t *testing.T) {
	// Create detector
	db := models.NewSignatureDatabase()
	matcher := signatures.NewMatcher(db)
	detector := NewBitrixDetector(matcher, models.LevelBasic)

	tests := []struct {
		name       string
		path       string
		expectHit  bool
		desc       string
	}{
		{
			name:      "cache directory should be excluded",
			path:      "/var/www/bitrix/cache/1a/1a612131b729d2edcb9a582a688af6a3.php",
			expectHit: false,
			desc:      "Bitrix cache files should not trigger BITRIX-STRUCTURE-001",
		},
		{
			name:      "backup index.php should be excluded",
			path:      "/var/www/bitrix/backup/index.php",
			expectHit: false,
			desc:      "Standard backup index.php should not trigger",
		},
		{
			name:      "upload directory should trigger",
			path:      "/var/www/upload/malware.php",
			expectHit: true,
			desc:      "PHP files in upload directory should be detected",
		},
		{
			name:      "nested upload directory should trigger",
			path:      "/var/www/bitrix/upload/suspicious.php",
			expectHit: true,
			desc:      "PHP files in any upload directory should be detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := &models.File{
				Path:      tt.path,
				Extension: "php",
				Content:   []byte("<?php return array('data' => 'cached');"),
			}

			findings, err := detector.Detect(context.Background(), file)
			if err != nil {
				t.Fatalf("Detect returned error: %v", err)
			}

			hasStructureViolation := false
			for _, f := range findings {
				if f.SignatureID == "BITRIX-STRUCTURE-001" {
					hasStructureViolation = true
					break
				}
			}

			if hasStructureViolation != tt.expectHit {
				t.Errorf("%s: expected hit=%v, got hit=%v", tt.desc, tt.expectHit, hasStructureViolation)
			}
		})
	}
}

func TestBitrixDetector_SecurityModuleWhitelist(t *testing.T) {
	// Create detector
	db := models.NewSignatureDatabase()
	matcher := signatures.NewMatcher(db)
	detector := NewBitrixDetector(matcher, models.LevelBasic)

	tests := []struct {
		name       string
		path       string
		content    string
		expectHit  bool
		desc       string
	}{
		{
			name:      "xscan.php should be whitelisted",
			path:      "/var/www/bitrix/modules/security/classes/general/xscan.php",
			content:   `<?php $blacklist = array("/etc/passwd", "/bin/sh", "__halt_compiler");`,
			expectHit: false,
			desc:      "Bitrix security scanner should not trigger on its own signatures",
		},
		{
			name:      "security_file_verifier.php should be whitelisted",
			path:      "/var/www/bitrix/modules/security/admin/security_file_verifier.php",
			content:   `<?php $patterns = array("/etc/hosts", "registerPHPFunctions");`,
			expectHit: false,
			desc:      "Security file verifier should not trigger blacklist",
		},
		{
			name:      "shelladapter.php should be whitelisted",
			path:      "/var/www/bitrix/modules/scale/lib/shelladapter.php",
			content:   `<?php proc_open('/bin/bash', $descriptorspec, $pipes);`,
			expectHit: false,
			desc:      "Scale module shell adapter should not trigger blacklist",
		},
		{
			name:      "random file with blacklist patterns should trigger",
			path:      "/var/www/bitrix/upload/evil.php",
			content:   `<?php $x = "/etc/passwd"; shell("/bin/sh");`,
			expectHit: true,
			desc:      "Non-whitelisted files with blacklist patterns should be detected",
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
				t.Fatalf("Detect returned error: %v", err)
			}

			hasBlacklistHit := false
			for _, f := range findings {
				if f.SignatureID == "BITRIX-BLACKLIST-001" {
					hasBlacklistHit = true
					break
				}
			}

			if hasBlacklistHit != tt.expectHit {
				t.Errorf("%s: expected blacklist hit=%v, got hit=%v",
					tt.desc, tt.expectHit, hasBlacklistHit)
				if len(findings) > 0 {
					for _, f := range findings {
						t.Logf("  Found: %s - %s", f.SignatureID, f.Description)
					}
				}
			}
		})
	}
}

func TestBitrixDetector_IsSecurityModule(t *testing.T) {
	db := models.NewSignatureDatabase()
	matcher := signatures.NewMatcher(db)
	detector := NewBitrixDetector(matcher, models.LevelBasic)

	tests := []struct {
		path     string
		expected bool
	}{
		{"modules/security/classes/general/xscan.php", true},
		{"/var/www/bitrix/modules/security/classes/general/xscan.php", true},
		{"modules/security/admin/security_file_verifier.php", true},
		{"modules/scale/lib/shelladapter.php", true},
		{"/bitrix/modules/scale/lib/shelladapter.php", true},
		// Should NOT be whitelisted
		{"modules/main/tools/upload.php", false},
		{"/var/www/upload/malware.php", false},
		{"modules/security/other_file.php", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := detector.isSecurityModule(tt.path)
			if result != tt.expected {
				t.Errorf("isSecurityModule(%s): expected %v, got %v",
					tt.path, tt.expected, result)
			}
		})
	}
}

func TestIsLegitimateAccessFile(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		content  string
		expected bool
	}{
		{
			name:     "standard bitrix .access.php",
			path:     "/upload/tmp/.access.php",
			content:  `<?$PERM["dabd13924258155e1f6de5ba573a50a3"]["*"]="X";?>`,
			expected: true,
		},
		{
			name:     "bitrix .access.php with php tag",
			path:     "/bitrix/upload/.access.php",
			content:  `<?php $PERM["abc123"]["*"]="R";?>`,
			expected: true,
		},
		{
			name:     "empty .access.php",
			path:     "/upload/.access.php",
			content:  "",
			expected: true,
		},
		{
			name:     "malicious .access.php with eval",
			path:     "/upload/.access.php",
			content:  `<?php eval($_POST['cmd']); ?>`,
			expected: false,
		},
		{
			name:     "not .access.php file",
			path:     "/upload/shell.php",
			content:  `<?$PERM["hash"]["*"]="X";?>`,
			expected: false,
		},
		{
			name:     ".access.php with extra code",
			path:     "/upload/.access.php",
			content:  `<?$PERM["hash"]["*"]="X";?><?php system($_GET['x']);`,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := &models.File{
				Path:      tt.path,
				Extension: "php",
				Content:   []byte(tt.content),
			}
			result := isLegitimateAccessFile(file)
			if result != tt.expected {
				t.Errorf("isLegitimateAccessFile: expected %v, got %v for content: %s",
					tt.expected, result, tt.content)
			}
		})
	}
}

func TestBitrixDetector_AccessFileExclusion(t *testing.T) {
	db := models.NewSignatureDatabase()
	matcher := signatures.NewMatcher(db)
	detector := NewBitrixDetector(matcher, models.LevelBasic)

	tests := []struct {
		name      string
		path      string
		content   string
		expectHit bool
	}{
		{
			name:      "legitimate .access.php should be excluded",
			path:      "/var/www/upload/tmp/.access.php",
			content:   `<?$PERM["dabd13924258155e1f6de5ba573a50a3"]["*"]="X";?>`,
			expectHit: false,
		},
		{
			name:      "malicious .access.php should be detected",
			path:      "/var/www/upload/.access.php",
			content:   `<?php eval($_POST['cmd']); ?>`,
			expectHit: true,
		},
		{
			name:      "regular PHP in upload should be detected",
			path:      "/var/www/upload/shell.php",
			content:   `<?php echo "hello"; ?>`,
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

			hasStructureViolation := false
			for _, f := range findings {
				if f.SignatureID == "BITRIX-STRUCTURE-001" {
					hasStructureViolation = true
					break
				}
			}

			if hasStructureViolation != tt.expectHit {
				t.Errorf("expected structure violation=%v, got=%v", tt.expectHit, hasStructureViolation)
			}
		})
	}
}

func TestBitrixDetector_RealMalwareStillDetected(t *testing.T) {
	// Verify that real malware patterns are still detected
	db := models.NewSignatureDatabase()
	matcher := signatures.NewMatcher(db)
	detector := NewBitrixDetector(matcher, models.LevelBasic)

	// Real webshell in upload directory
	maliciousFile := &models.File{
		Path:      "/var/www/upload/shell.php",
		Extension: "php",
		Content:   []byte(`<?php eval($_POST['cmd']); system($_GET['x']); /bin/bash;`),
	}

	findings, err := detector.Detect(context.Background(), maliciousFile)
	if err != nil {
		t.Fatalf("Detect returned error: %v", err)
	}

	// Should detect at least structure violation for /upload/
	hasStructureViolation := false
	hasBlacklistHit := false
	for _, f := range findings {
		if f.SignatureID == "BITRIX-STRUCTURE-001" {
			hasStructureViolation = true
		}
		if f.SignatureID == "BITRIX-BLACKLIST-001" {
			hasBlacklistHit = true
		}
	}

	if !hasStructureViolation {
		t.Error("Expected BITRIX-STRUCTURE-001 for PHP in upload directory")
	}
	if !hasBlacklistHit {
		t.Error("Expected BITRIX-BLACKLIST-001 for /bin/bash pattern")
	}
}
