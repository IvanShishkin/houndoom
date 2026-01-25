package heuristic

import (
	"testing"

	"github.com/IvanShishkin/houndoom/pkg/models"
)

func TestNewDataFlowAnalyzer(t *testing.T) {
	dfa := NewDataFlowAnalyzer()

	if dfa == nil {
		t.Fatal("NewDataFlowAnalyzer returned nil")
	}

	if dfa.contextDetector == nil {
		t.Error("contextDetector should be initialized")
	}

	if dfa.scoringRules == nil {
		t.Error("scoringRules should be initialized")
	}
}

func TestDataFlowAnalyzer_Analyze(t *testing.T) {
	dfa := NewDataFlowAnalyzer()

	tests := []struct {
		name         string
		input        string
		wantFindings int
		wantTargets  []string // Expected target functions
	}{
		{
			name:         "clean code - no flows",
			input:        `<?php echo "Hello World"; ?>`,
			wantFindings: 0,
			wantTargets:  nil,
		},
		{
			name: "direct user input to eval",
			input: `<?php
				eval($_GET['code']);
			?>`,
			wantFindings: 1,
			wantTargets:  []string{"eval"},
		},
		{
			name: "indirect flow - GET to eval",
			input: `<?php
				$code = $_GET['code'];
				eval($code);
			?>`,
			wantFindings: 1,
			wantTargets:  []string{"eval"},
		},
		{
			name: "indirect flow - POST to system",
			input: `<?php
				$cmd = $_POST['cmd'];
				system($cmd);
			?>`,
			wantFindings: 1,
			wantTargets:  []string{"system"},
		},
		{
			name: "indirect flow - REQUEST to exec",
			input: `<?php
				$command = $_REQUEST['command'];
				exec($command);
			?>`,
			wantFindings: 1,
			wantTargets:  []string{"exec"},
		},
		{
			name: "multiple flows - same variable",
			input: `<?php
				$cmd = $_GET['cmd'];
				eval($cmd);
				system($cmd);
			?>`,
			wantFindings: 2,
			wantTargets:  []string{"eval", "system"},
		},
		{
			name: "multiple flows - different variables",
			input: `<?php
				$code = $_GET['code'];
				$cmd = $_POST['cmd'];
				eval($code);
				exec($cmd);
			?>`,
			wantFindings: 2,
			wantTargets:  []string{"eval", "exec"},
		},
		{
			name: "flow to file_put_contents",
			input: `<?php
				$content = $_POST['content'];
				file_put_contents('shell.php', $content);
			?>`,
			wantFindings: 1,
			wantTargets:  []string{"file_put_contents"},
		},
		{
			name: "flow to include",
			input: `<?php
				$file = $_GET['file'];
				include($file);
			?>`,
			wantFindings: 1,
			wantTargets:  []string{"include"},
		},
		{
			name: "flow to mysql_query - SQL injection",
			input: `<?php
				$id = $_GET['id'];
				mysql_query("SELECT * FROM users WHERE id = $id");
			?>`,
			wantFindings: 1,
			wantTargets:  []string{"mysql_query"},
		},
		{
			name: "flow to unserialize",
			input: `<?php
				$data = $_COOKIE['data'];
				unserialize($data);
			?>`,
			wantFindings: 1,
			wantTargets:  []string{"unserialize"},
		},
		{
			name: "direct flow to shell_exec",
			input: `<?php
				shell_exec($_GET['cmd']);
			?>`,
			wantFindings: 1,
			wantTargets:  []string{"shell_exec"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := dfa.Analyze(tt.input)

			if len(findings) != tt.wantFindings {
				t.Errorf("Analyze() returned %d findings, want %d", len(findings), tt.wantFindings)
				for _, f := range findings {
					t.Logf("  Found: %s -> %s", f.SourceType, f.TargetFunction)
				}
			}

			if tt.wantTargets != nil {
				for _, target := range tt.wantTargets {
					found := false
					for _, f := range findings {
						if f.TargetFunction == target {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected to find flow to %q", target)
					}
				}
			}
		})
	}
}

func TestDataFlowAnalyzer_TrackUserInputVars(t *testing.T) {
	dfa := NewDataFlowAnalyzer()

	tests := []struct {
		name     string
		input    string
		wantVars int
		wantType string
	}{
		{
			name:     "no user input",
			input:    `<?php $x = 1; ?>`,
			wantVars: 0,
		},
		{
			name: "GET variable",
			input: `<?php
				$name = $_GET['name'];
			?>`,
			wantVars: 1,
			wantType: "GET",
		},
		{
			name: "POST variable",
			input: `<?php
				$data = $_POST['data'];
			?>`,
			wantVars: 1,
			wantType: "POST",
		},
		{
			name: "multiple user inputs",
			input: `<?php
				$a = $_GET['a'];
				$b = $_POST['b'];
				$c = $_REQUEST['c'];
			?>`,
			wantVars: 3,
		},
		{
			name: "FILES variable",
			input: `<?php
				$file = $_FILES['upload'];
			?>`,
			wantVars: 1,
			wantType: "FILES",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vars := dfa.trackUserInputVars(tt.input)

			if len(vars) != tt.wantVars {
				t.Errorf("trackUserInputVars() returned %d vars, want %d", len(vars), tt.wantVars)
			}

			if tt.wantType != "" && len(vars) > 0 {
				if vars[0].SourceType != tt.wantType {
					t.Errorf("SourceType = %q, want %q", vars[0].SourceType, tt.wantType)
				}
			}
		})
	}
}

func TestDataFlowAnalyzer_TrackDangerousCalls(t *testing.T) {
	dfa := NewDataFlowAnalyzer()

	tests := []struct {
		name      string
		input     string
		wantCalls int
		wantFuncs []string
	}{
		{
			name:      "no dangerous calls",
			input:     `<?php echo "Hello"; ?>`,
			wantCalls: 0,
		},
		{
			name: "eval call",
			input: `<?php
				eval($code);
			?>`,
			wantCalls: 1,
			wantFuncs: []string{"eval"},
		},
		{
			name: "multiple dangerous calls",
			input: `<?php
				eval($a);
				exec($b);
				system($c);
			?>`,
			wantCalls: 3,
			wantFuncs: []string{"eval", "exec", "system"},
		},
		{
			name: "case insensitive",
			input: `<?php
				EVAL($code);
				Exec($cmd);
			?>`,
			wantCalls: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := dfa.trackDangerousCalls(tt.input)

			if len(calls) != tt.wantCalls {
				t.Errorf("trackDangerousCalls() returned %d calls, want %d", len(calls), tt.wantCalls)
			}

			if tt.wantFuncs != nil {
				for _, fn := range tt.wantFuncs {
					found := false
					for _, c := range calls {
						if c.Function == fn {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected to find call to %q", fn)
					}
				}
			}
		})
	}
}

func TestDataFlowAnalyzer_RiskScore(t *testing.T) {
	dfa := NewDataFlowAnalyzer()

	tests := []struct {
		name           string
		input          string
		minScore       int
		wantContext    models.ScoringContext
	}{
		{
			name: "eval with user input - critical",
			input: `<?php
				$code = $_GET['code'];
				eval($code);
			?>`,
			minScore:    50, // Actual score depends on scoring rules
			wantContext: models.ContextUserInput,
		},
		{
			name: "system call with user input - critical",
			input: `<?php
				$cmd = $_POST['cmd'];
				system($cmd);
			?>`,
			minScore:    50,
			wantContext: models.ContextUserInput,
		},
		{
			name: "SQL query with user input - high",
			input: `<?php
				$id = $_GET['id'];
				mysql_query("SELECT * FROM users WHERE id = $id");
			?>`,
			minScore:    40,
			wantContext: models.ContextUserInput,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := dfa.Analyze(tt.input)

			if len(findings) == 0 {
				t.Fatal("Expected at least one finding")
			}

			finding := findings[0]

			if finding.RiskScore == nil {
				t.Fatal("RiskScore should not be nil")
			}

			if finding.RiskScore.NormalizedScore < tt.minScore {
				t.Errorf("NormalizedScore = %d, want >= %d",
					finding.RiskScore.NormalizedScore, tt.minScore)
			}

			if !finding.RiskScore.Contexts[tt.wantContext] {
				t.Errorf("Expected context %v to be present", tt.wantContext)
			}
		})
	}
}

func TestDataFlowAnalyzer_FlowPath(t *testing.T) {
	dfa := NewDataFlowAnalyzer()

	tests := []struct {
		name         string
		input        string
		wantDirect   bool
		wantPathLen  int
	}{
		{
			name: "direct flow",
			input: `<?php
				eval($_GET['code']);
			?>`,
			wantDirect:  true,
			wantPathLen: 1,
		},
		{
			name: "indirect flow",
			input: `<?php
				$code = $_GET['code'];
				eval($code);
			?>`,
			wantDirect:  false,
			wantPathLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := dfa.Analyze(tt.input)

			if len(findings) == 0 {
				t.Fatal("Expected at least one finding")
			}

			finding := findings[0]

			if len(finding.FlowPath) != tt.wantPathLen {
				t.Errorf("FlowPath length = %d, want %d", len(finding.FlowPath), tt.wantPathLen)
			}

			isDirect := len(finding.FlowPath) == 1 && containsSubstring(finding.FlowPath[0], "DIRECT")
			if isDirect != tt.wantDirect {
				t.Errorf("Direct flow = %v, want %v", isDirect, tt.wantDirect)
			}
		})
	}
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestGetFlowDescription(t *testing.T) {
	tests := []struct {
		name    string
		finding *DataFlowFinding
		want    string
	}{
		{
			name: "direct flow",
			finding: &DataFlowFinding{
				SourceType:     "GET",
				SourceVar:      "_GET",
				TargetFunction: "eval",
				FlowPath:       []string{"$_GET -> eval() [DIRECT]"},
			},
			want: "Direct user input",
		},
		{
			name: "indirect flow",
			finding: &DataFlowFinding{
				SourceType:     "POST",
				SourceVar:      "data",
				TargetFunction: "system",
				FlowPath:       []string{"$_POST -> $data", "$data -> system()"},
			},
			want: "flows through",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetFlowDescription(tt.finding)

			if !containsSubstring(result, tt.want) {
				t.Errorf("GetFlowDescription() = %q, should contain %q", result, tt.want)
			}
		})
	}
}

func TestDataFlowAnalyzer_CodeSnippet(t *testing.T) {
	dfa := NewDataFlowAnalyzer()

	input := `<?php
		$cmd = $_GET['cmd'];
		system($cmd);
	?>`

	findings := dfa.Analyze(input)

	if len(findings) == 0 {
		t.Fatal("Expected at least one finding")
	}

	finding := findings[0]

	if finding.CodeSnippet == "" {
		t.Error("CodeSnippet should not be empty")
	}

	if !containsSubstring(finding.CodeSnippet, "system") {
		t.Errorf("CodeSnippet should contain the dangerous function call")
	}
}

func TestDataFlowAnalyzer_Position(t *testing.T) {
	dfa := NewDataFlowAnalyzer()

	input := `<?php
		$cmd = $_GET['cmd'];
		system($cmd);
	?>`

	findings := dfa.Analyze(input)

	if len(findings) == 0 {
		t.Fatal("Expected at least one finding")
	}

	finding := findings[0]

	// Position should be > 0 (not at the very beginning)
	if finding.Position <= 0 {
		t.Errorf("Position = %d, expected > 0", finding.Position)
	}
}

// Benchmarks

func BenchmarkDataFlowAnalyzer_Analyze(b *testing.B) {
	dfa := NewDataFlowAnalyzer()
	input := `<?php
		$cmd = $_GET['cmd'];
		$data = $_POST['data'];
		eval($cmd);
		system($data);
		file_put_contents('log.txt', $cmd);
	?>`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dfa.Analyze(input)
	}
}

func BenchmarkDataFlowAnalyzer_CleanCode(b *testing.B) {
	dfa := NewDataFlowAnalyzer()
	input := `<?php
		function greet($name) {
			return "Hello, " . htmlspecialchars($name);
		}
		$name = "World";
		echo greet($name);
	?>`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dfa.Analyze(input)
	}
}
