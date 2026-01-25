package heuristic

import (
	"testing"

	"github.com/IvanShishkin/houndoom/pkg/models"
)

func TestNewContextDetector(t *testing.T) {
	cd := NewContextDetector()

	if cd == nil {
		t.Fatal("NewContextDetector returned nil")
	}

	if cd.userInputPattern == nil {
		t.Error("userInputPattern should be initialized")
	}
	if cd.evalPattern == nil {
		t.Error("evalPattern should be initialized")
	}
	if cd.fileOpPattern == nil {
		t.Error("fileOpPattern should be initialized")
	}
	if cd.networkOpPattern == nil {
		t.Error("networkOpPattern should be initialized")
	}
	if cd.dbOpPattern == nil {
		t.Error("dbOpPattern should be initialized")
	}
	if cd.systemCallPattern == nil {
		t.Error("systemCallPattern should be initialized")
	}
	if len(cd.obfuscatedPatterns) == 0 {
		t.Error("obfuscatedPatterns should be initialized")
	}
	if len(cd.encodedPatterns) == 0 {
		t.Error("encodedPatterns should be initialized")
	}
}

func TestContextDetector_DetectContexts(t *testing.T) {
	cd := NewContextDetector()

	tests := []struct {
		name            string
		input           string
		expectedContext []models.ScoringContext
		notExpected     []models.ScoringContext
	}{
		{
			name:            "empty content - default only",
			input:           "",
			expectedContext: []models.ScoringContext{models.ContextDefault},
			notExpected:     []models.ScoringContext{models.ContextUserInput, models.ContextEval},
		},
		{
			name: "user input detection - GET",
			input: `<?php
				$name = $_GET['name'];
			?>`,
			expectedContext: []models.ScoringContext{models.ContextDefault, models.ContextUserInput},
		},
		{
			name: "user input detection - POST",
			input: `<?php
				$data = $_POST['data'];
			?>`,
			expectedContext: []models.ScoringContext{models.ContextDefault, models.ContextUserInput},
		},
		{
			name: "user input detection - REQUEST",
			input: `<?php
				$value = $_REQUEST['value'];
			?>`,
			expectedContext: []models.ScoringContext{models.ContextDefault, models.ContextUserInput},
		},
		{
			name: "user input detection - COOKIE",
			input: `<?php
				$session = $_COOKIE['session'];
			?>`,
			expectedContext: []models.ScoringContext{models.ContextDefault, models.ContextUserInput},
		},
		{
			name: "eval detection",
			input: `<?php
				eval($code);
			?>`,
			expectedContext: []models.ScoringContext{models.ContextDefault, models.ContextEval},
		},
		{
			name: "assert detection",
			input: `<?php
				assert($condition);
			?>`,
			expectedContext: []models.ScoringContext{models.ContextDefault, models.ContextEval},
		},
		{
			name: "create_function detection",
			input: `<?php
				$func = create_function('$x', 'return $x * 2;');
			?>`,
			expectedContext: []models.ScoringContext{models.ContextDefault, models.ContextEval},
		},
		{
			name: "file operation - file_get_contents",
			input: `<?php
				$content = file_get_contents('file.txt');
			?>`,
			expectedContext: []models.ScoringContext{models.ContextDefault, models.ContextFileOperation},
		},
		{
			name: "file operation - include with parens",
			input: `<?php
				include('header.php');
			?>`,
			expectedContext: []models.ScoringContext{models.ContextDefault, models.ContextFileOperation},
		},
		{
			name: "database operation - mysql_query",
			input: `<?php
				$result = mysql_query("SELECT * FROM users");
			?>`,
			expectedContext: []models.ScoringContext{models.ContextDefault, models.ContextDatabaseOperation},
		},
		{
			name: "database operation - mysqli_query",
			input: `<?php
				$result = mysqli_query($conn, "SELECT * FROM users");
			?>`,
			expectedContext: []models.ScoringContext{models.ContextDefault, models.ContextDatabaseOperation},
		},
		{
			name: "system call - exec",
			input: `<?php
				exec('ls -la');
			?>`,
			expectedContext: []models.ScoringContext{models.ContextDefault, models.ContextSystemCall},
		},
		{
			name: "system call - system",
			input: `<?php
				system('whoami');
			?>`,
			expectedContext: []models.ScoringContext{models.ContextDefault, models.ContextSystemCall},
		},
		{
			name: "system call - backticks",
			input: "<?php $out = `ls -la`; ?>",
			expectedContext: []models.ScoringContext{models.ContextDefault, models.ContextSystemCall},
		},
		{
			name: "encoded content - base64_decode",
			input: `<?php
				$data = base64_decode($encoded);
			?>`,
			expectedContext: []models.ScoringContext{models.ContextDefault, models.ContextEncoded},
		},
		{
			name: "encoded content - gzinflate",
			input: `<?php
				$data = gzinflate($compressed);
			?>`,
			expectedContext: []models.ScoringContext{models.ContextDefault, models.ContextEncoded},
		},
		{
			name: "multiple contexts",
			input: `<?php
				$cmd = $_GET['cmd'];
				eval($cmd);
				file_put_contents('log.txt', $cmd);
			?>`,
			expectedContext: []models.ScoringContext{
				models.ContextDefault,
				models.ContextUserInput,
				models.ContextEval,
				models.ContextFileOperation,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contexts := cd.DetectContexts(tt.input)

			for _, expected := range tt.expectedContext {
				if !contexts[expected] {
					t.Errorf("Expected context %v to be detected", expected)
				}
			}

			for _, notExpected := range tt.notExpected {
				if contexts[notExpected] {
					t.Errorf("Context %v should not be detected", notExpected)
				}
			}
		})
	}
}

func TestContextDetector_DetectObfuscation(t *testing.T) {
	cd := NewContextDetector()

	tests := []struct {
		name           string
		input          string
		wantObfuscated bool
	}{
		{
			name:           "clean code",
			input:          `<?php $name = "John"; echo $name; ?>`,
			wantObfuscated: false,
		},
		{
			name: "obfuscated variables - multiple indicators",
			input: `<?php
				$a1b2c3 = "test";
				$O0O0l1l = "data";
				$_ABC123DEF456GHI789JKL012MNO345PQR = "value";
			?>`,
			wantObfuscated: true,
		},
		{
			name: "variable variables - obfuscation indicator",
			input: `<?php
				$$var = "value";
				$$$nested = "deep";
			?>`,
			wantObfuscated: false, // Need 2+ indicators
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contexts := cd.DetectContexts(tt.input)
			isObfuscated := contexts[models.ContextObfuscated]

			if isObfuscated != tt.wantObfuscated {
				t.Errorf("Obfuscation detection = %v, want %v", isObfuscated, tt.wantObfuscated)
			}
		})
	}
}

func TestContextDetector_GetPrimaryContext(t *testing.T) {
	cd := NewContextDetector()

	tests := []struct {
		name     string
		contexts map[models.ScoringContext]bool
		want     models.ScoringContext
	}{
		{
			name:     "empty contexts - default",
			contexts: map[models.ScoringContext]bool{},
			want:     models.ContextDefault,
		},
		{
			name: "only default",
			contexts: map[models.ScoringContext]bool{
				models.ContextDefault: true,
			},
			want: models.ContextDefault,
		},
		{
			name: "eval takes priority",
			contexts: map[models.ScoringContext]bool{
				models.ContextDefault:       true,
				models.ContextUserInput:     true,
				models.ContextEval:          true,
				models.ContextFileOperation: true,
			},
			want: models.ContextEval,
		},
		{
			name: "user input priority over file op",
			contexts: map[models.ScoringContext]bool{
				models.ContextDefault:       true,
				models.ContextUserInput:     true,
				models.ContextFileOperation: true,
			},
			want: models.ContextUserInput,
		},
		{
			name: "system call priority",
			contexts: map[models.ScoringContext]bool{
				models.ContextDefault:           true,
				models.ContextSystemCall:        true,
				models.ContextDatabaseOperation: true,
			},
			want: models.ContextSystemCall,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cd.GetPrimaryContext(tt.contexts)
			if result != tt.want {
				t.Errorf("GetPrimaryContext() = %v, want %v", result, tt.want)
			}
		})
	}
}

func TestContextDetector_DetectDataFlow(t *testing.T) {
	cd := NewContextDetector()

	tests := []struct {
		name      string
		input     string
		wantFlow  bool
		wantCount int
	}{
		{
			name:      "no data flow",
			input:     `<?php echo "Hello"; ?>`,
			wantFlow:  false,
			wantCount: 0,
		},
		{
			name: "direct user input to eval",
			input: `<?php
				eval($_GET['code']);
			?>`,
			wantFlow:  true,
			wantCount: 1,
		},
		{
			name: "indirect user input to eval",
			input: `<?php
				$code = $_GET['code'];
				eval($code);
			?>`,
			wantFlow:  true,
			wantCount: 1,
		},
		{
			name: "user input to system",
			input: `<?php
				$cmd = $_POST['cmd'];
				system($cmd);
			?>`,
			wantFlow:  true,
			wantCount: 1,
		},
		{
			name: "multiple dangerous flows",
			input: `<?php
				$cmd = $_GET['cmd'];
				eval($cmd);
				exec($cmd);
			?>`,
			wantFlow:  true,
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasFlow, flows := cd.DetectDataFlow(tt.input)

			if hasFlow != tt.wantFlow {
				t.Errorf("DetectDataFlow() hasFlow = %v, want %v", hasFlow, tt.wantFlow)
			}

			if len(flows) != tt.wantCount {
				t.Errorf("DetectDataFlow() returned %d flows, want %d", len(flows), tt.wantCount)
				for _, f := range flows {
					t.Logf("  Flow: %s", f)
				}
			}
		})
	}
}

func TestContextDetector_AnalyzeLocalContext(t *testing.T) {
	cd := NewContextDetector()

	tests := []struct {
		name             string
		snippet          string
		surroundingLines string
		want             models.ScoringContext
	}{
		{
			name:             "eval in snippet",
			snippet:          "eval($code);",
			surroundingLines: "$code = 'test';",
			want:             models.ContextEval,
		},
		{
			name:             "user input in surrounding",
			snippet:          "echo $name;",
			surroundingLines: "$name = $_GET['name'];",
			want:             models.ContextUserInput,
		},
		{
			name:             "clean snippet",
			snippet:          "echo 'hello';",
			surroundingLines: "$x = 1;",
			want:             models.ContextDefault,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cd.AnalyzeLocalContext(tt.snippet, tt.surroundingLines)
			if result != tt.want {
				t.Errorf("AnalyzeLocalContext() = %v, want %v", result, tt.want)
			}
		})
	}
}

func TestGetContextDescription(t *testing.T) {
	tests := []struct {
		name     string
		contexts map[models.ScoringContext]bool
		contains []string
	}{
		{
			name:     "empty contexts",
			contexts: map[models.ScoringContext]bool{},
			contains: []string{"default context"},
		},
		{
			name: "user input context",
			contexts: map[models.ScoringContext]bool{
				models.ContextUserInput: true,
			},
			contains: []string{"user input"},
		},
		{
			name: "eval context",
			contexts: map[models.ScoringContext]bool{
				models.ContextEval: true,
			},
			contains: []string{"dynamic code evaluation"},
		},
		{
			name: "multiple contexts",
			contexts: map[models.ScoringContext]bool{
				models.ContextUserInput:     true,
				models.ContextFileOperation: true,
				models.ContextSystemCall:    true,
			},
			contains: []string{"user input", "file operations", "system calls"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetContextDescription(tt.contexts)

			for _, expected := range tt.contains {
				if !containsString(result, expected) {
					t.Errorf("GetContextDescription() = %q, should contain %q", result, expected)
				}
			}
		})
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && stringContains(s, substr)))
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Benchmarks

func BenchmarkContextDetector_DetectContexts(b *testing.B) {
	cd := NewContextDetector()
	input := `<?php
		$cmd = $_GET['cmd'];
		$data = base64_decode($encoded);
		eval($data);
		file_put_contents('log.txt', $cmd);
		mysql_query("SELECT * FROM users WHERE id = " . $id);
	?>`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cd.DetectContexts(input)
	}
}

func BenchmarkContextDetector_DetectDataFlow(b *testing.B) {
	cd := NewContextDetector()
	input := `<?php
		$cmd = $_GET['cmd'];
		$data = $_POST['data'];
		eval($cmd);
		system($data);
	?>`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cd.DetectDataFlow(input)
	}
}
