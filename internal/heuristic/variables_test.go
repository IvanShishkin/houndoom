package heuristic

import (
	"strings"
	"testing"
)

func TestNewVariableAnalyzer(t *testing.T) {
	va := NewVariableAnalyzer()

	if va == nil {
		t.Fatal("NewVariableAnalyzer returned nil")
	}

	if va.varRegex == nil {
		t.Fatal("varRegex should be initialized")
	}

	if len(va.patterns) == 0 {
		t.Fatal("patterns should be initialized")
	}

	if va.phpSuperglobals == nil {
		t.Fatal("phpSuperglobals should be initialized")
	}
}

func TestVariableAnalyzer_Analyze(t *testing.T) {
	va := NewVariableAnalyzer()

	tests := []struct {
		name               string
		input              string
		wantSuspicious     bool
		minSuspiciousCount int
		maxSuspiciousCount int
	}{
		{
			name: "normal code - no suspicious vars",
			input: `<?php
				$name = "John";
				$age = 25;
				$userEmail = "john@example.com";
			?>`,
			wantSuspicious:     false,
			minSuspiciousCount: 0,
			maxSuspiciousCount: 0,
		},
		{
			name: "camelCase variables - legitimate",
			input: `<?php
				$userName = "test";
				$userAddress = "123 Main St";
				$totalCount = 100;
			?>`,
			wantSuspicious:     false,
			minSuspiciousCount: 0,
			maxSuspiciousCount: 0,
		},
		{
			name: "snake_case variables - legitimate",
			input: `<?php
				$user_name = "test";
				$user_address = "123 Main St";
				$total_count = 100;
			?>`,
			wantSuspicious:     false,
			minSuspiciousCount: 0,
			maxSuspiciousCount: 0,
		},
		{
			name: "O0 obfuscation pattern",
			input: `<?php
				$O0O0O0 = "payload";
				$O00O0O = "data";
				$OO0O00 = "exec";
			?>`,
			wantSuspicious:     true,
			minSuspiciousCount: 2,
			maxSuspiciousCount: 3,
		},
		{
			name: "hex variable pattern",
			input: `<?php
				$_0x4a3b = "encoded";
				$_0xDEADBEEF = "data";
			?>`,
			wantSuspicious:     true,
			minSuspiciousCount: 2,
			maxSuspiciousCount: 2,
		},
		{
			name: "underscore obfuscation",
			input: `<?php
				$___data___ = "secret";
				$__code__ = "payload";
			?>`,
			wantSuspicious:     true,
			minSuspiciousCount: 1,
			maxSuspiciousCount: 2,
		},
		{
			name: "PHP superglobals - not suspicious",
			input: `<?php
				$name = $_GET['name'];
				$data = $_POST['data'];
				$session = $_SESSION['user'];
			?>`,
			wantSuspicious:     false,
			minSuspiciousCount: 0,
			maxSuspiciousCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := va.Analyze(tt.input)

			if tt.wantSuspicious && result.SuspiciousCount < tt.minSuspiciousCount {
				t.Errorf("Expected at least %d suspicious vars, got %d",
					tt.minSuspiciousCount, result.SuspiciousCount)
			}

			if result.SuspiciousCount > tt.maxSuspiciousCount {
				t.Errorf("Expected at most %d suspicious vars, got %d",
					tt.maxSuspiciousCount, result.SuspiciousCount)
				for _, v := range result.SuspiciousVars {
					t.Logf("  Found: $%s (pattern: %s)", v.Name, v.PatternName)
				}
			}
		})
	}
}

func TestVariableAnalyzer_ObfuscationScore(t *testing.T) {
	va := NewVariableAnalyzer()

	tests := []struct {
		name     string
		input    string
		minScore int
		maxScore int
	}{
		{
			name: "clean code - low score",
			input: `<?php
				$name = "test";
				$count = 0;
			?>`,
			minScore: 0,
			maxScore: 20,
		},
		{
			name: "heavily obfuscated - high score",
			input: `<?php
				$O0O0O0 = "a";
				$O00O0O = "b";
				$OO0O00 = "c";
				$_0x4a3b = "d";
				$_0xDEAD = "e";
				$___x___ = "f";
			?>`,
			minScore: 50,
			maxScore: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := va.Analyze(tt.input)

			if result.ObfuscationScore < tt.minScore {
				t.Errorf("ObfuscationScore = %d, want >= %d",
					result.ObfuscationScore, tt.minScore)
			}

			if result.ObfuscationScore > tt.maxScore {
				t.Errorf("ObfuscationScore = %d, want <= %d",
					result.ObfuscationScore, tt.maxScore)
			}
		})
	}
}

func TestVariableAnalyzer_LongStrings(t *testing.T) {
	va := NewVariableAnalyzer()

	// Create a long string (500+ chars)
	longString := strings.Repeat("A", 600)

	tests := []struct {
		name            string
		input           string
		wantLongStrings int
	}{
		{
			name:            "no long strings",
			input:           `<?php $x = "short"; ?>`,
			wantLongStrings: 0,
		},
		{
			name:            "one long string",
			input:           `<?php $x = "` + longString + `"; ?>`,
			wantLongStrings: 1,
		},
		{
			name:            "multiple long strings",
			input:           `<?php $x = "` + longString + `"; $y = '` + longString + `'; ?>`,
			wantLongStrings: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := va.Analyze(tt.input)

			if result.LongStrings != tt.wantLongStrings {
				t.Errorf("LongStrings = %d, want %d",
					result.LongStrings, tt.wantLongStrings)
			}
		})
	}
}

func TestVariableAnalyzer_UniquePatterns(t *testing.T) {
	va := NewVariableAnalyzer()

	input := `<?php
		$O0O0O0 = "a";  // O0 pattern
		$_0x4a3b = "b"; // Hex pattern
		$___x___ = "c"; // Underscore pattern
	?>`

	result := va.Analyze(input)

	if len(result.UniquePatterns) < 2 {
		t.Errorf("Expected at least 2 unique patterns, got %d", len(result.UniquePatterns))
	}
}

func TestIsLegitimateNaming(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		// Legitimate patterns
		{"userName", true},      // camelCase
		{"getUserName", true},   // camelCase
		{"UserName", true},      // PascalCase
		{"user_name", true},     // snake_case
		{"total_count", true},   // snake_case
		{"arItems", true},       // Hungarian (ar)
		{"strValue", true},      // Hungarian (str)
		{"isActive", true},      // Hungarian (is)
		{"hasPermission", true}, // Hungarian (has)
		{"tmpFile", true},       // Common prefix (tmp)
		{"dataResult", true},    // Common prefix (data)

		// Non-legitimate patterns
		{"x", false},            // Too short for detection
		{"O0O0O0", false},       // Obfuscated
		{"aaaaaaaaaa", false},   // Random-like
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isLegitimateNaming(tt.name)
			if result != tt.want {
				t.Errorf("isLegitimateNaming(%q) = %v, want %v", tt.name, result, tt.want)
			}
		})
	}
}

func TestAnalyzeCodeStructure(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		wantMinified  bool
		wantMaxLine   int
		minTotalLines int
	}{
		{
			name: "normal formatted code",
			input: `<?php
function test() {
    echo "Hello";
}
?>`,
			wantMinified:  false,
			wantMaxLine:   20,
			minTotalLines: 4,
		},
		{
			name:          "single line code",
			input:         `<?php echo "Hello"; function test() { return 1; } ?>`,
			wantMinified:  false, // Not long enough
			wantMaxLine:   60,
			minTotalLines: 1,
		},
		{
			name:          "minified code - very long line",
			input:         `<?php ` + strings.Repeat("$x=1;", 300) + ` ?>`,
			wantMinified:  true,
			wantMaxLine:   1000,
			minTotalLines: 1,
		},
		{
			name:          "empty string",
			input:         "",
			wantMinified:  false,
			wantMaxLine:   0,
			minTotalLines: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeCodeStructure(tt.input)

			if result.IsMinified != tt.wantMinified {
				t.Errorf("IsMinified = %v, want %v (MaxLine: %d)",
					result.IsMinified, tt.wantMinified, result.MaxLineLength)
			}

			if tt.wantMaxLine > 0 && result.MaxLineLength > tt.wantMaxLine*2 {
				t.Errorf("MaxLineLength = %d, want around %d",
					result.MaxLineLength, tt.wantMaxLine)
			}

			if result.TotalLines < tt.minTotalLines {
				t.Errorf("TotalLines = %d, want >= %d",
					result.TotalLines, tt.minTotalLines)
			}
		})
	}
}

func TestAnalyzeCodeStructure_EmptyLines(t *testing.T) {
	input := `<?php

function test() {

    echo "Hello";

}

?>`

	result := AnalyzeCodeStructure(input)

	if result.EmptyLines < 4 {
		t.Errorf("EmptyLines = %d, expected at least 4", result.EmptyLines)
	}
}

func TestAnalyzeCodeStructure_AverageLineLength(t *testing.T) {
	input := `<?php
echo "a";
echo "ab";
echo "abc";
?>`

	result := AnalyzeCodeStructure(input)

	if result.AverageLineLength < 1 {
		t.Error("AverageLineLength should be greater than 0")
	}

	if result.AverageLineLength > float64(result.MaxLineLength) {
		t.Error("AverageLineLength should not exceed MaxLineLength")
	}
}

func TestVariablePatterns(t *testing.T) {
	va := NewVariableAnalyzer()

	// Test each pattern individually
	patternTests := []struct {
		patternName string
		varNames    []string
		shouldMatch bool
	}{
		{
			patternName: "O0_Pattern",
			varNames:    []string{"O0O0O0", "OOOO", "OO00OO"},
			shouldMatch: true,
		},
		{
			patternName: "Hex_Pattern",
			varNames:    []string{"_0x4a3b", "_0xDEADBEEF", "_0x123"},
			shouldMatch: true,
		},
		{
			patternName: "Underscore_Pattern",
			varNames:    []string{"___data___", "__x__"},
			shouldMatch: true,
		},
	}

	for _, tt := range patternTests {
		t.Run(tt.patternName, func(t *testing.T) {
			for _, varName := range tt.varNames {
				input := `<?php $` + varName + ` = "test"; ?>`
				result := va.Analyze(input)

				hasMatch := result.SuspiciousCount > 0
				if hasMatch != tt.shouldMatch {
					t.Errorf("Variable $%s: expected match=%v, got %v",
						varName, tt.shouldMatch, hasMatch)
				}
			}
		})
	}
}

// Benchmarks

func BenchmarkVariableAnalyzer_Analyze(b *testing.B) {
	va := NewVariableAnalyzer()
	input := `<?php
		$O0O0O0 = "a";
		$userName = "test";
		$_0x4a3b = "data";
		$config = array();
	?>`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		va.Analyze(input)
	}
}

func BenchmarkAnalyzeCodeStructure(b *testing.B) {
	input := strings.Repeat("$x = 1;\n", 1000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AnalyzeCodeStructure(input)
	}
}
