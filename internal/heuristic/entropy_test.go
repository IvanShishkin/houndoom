package heuristic

import (
	"math"
	"strings"
	"testing"
)

func TestCalculateEntropy(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		minValue float64
		maxValue float64
	}{
		{
			name:     "empty string",
			input:    "",
			minValue: 0,
			maxValue: 0,
		},
		{
			name:     "single character",
			input:    "a",
			minValue: 0,
			maxValue: 0,
		},
		{
			name:     "repeated characters - zero entropy",
			input:    "aaaaaaaaaa",
			minValue: 0,
			maxValue: 0.01,
		},
		{
			name:     "two different characters - entropy ~1",
			input:    "ababababab",
			minValue: 0.9,
			maxValue: 1.1,
		},
		{
			name:     "normal PHP code - moderate entropy",
			input:    `<?php function hello() { echo "Hello World"; } ?>`,
			minValue: 3.5,
			maxValue: 5.0,
		},
		{
			name:     "base64-like string - high entropy",
			input:    "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=",
			minValue: 5.0,
			maxValue: 6.5,
		},
		{
			name:     "random-looking obfuscated code",
			input:    `$a1b2c3d4e5="\x62\x61\x73\x65\x36\x34\x5f\x64\x65\x63\x6f\x64\x65";`,
			minValue: 3.0,
			maxValue: 4.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateEntropy(tt.input)
			if result < tt.minValue || result > tt.maxValue {
				t.Errorf("CalculateEntropy(%q) = %v, want between %v and %v",
					tt.input, result, tt.minValue, tt.maxValue)
			}
		})
	}
}

func TestCalculateEntropy_MaxValue(t *testing.T) {
	// Maximum entropy for bytes is 8 (log2(256))
	// Create string with all 256 byte values
	var allBytes []byte
	for i := 0; i < 256; i++ {
		allBytes = append(allBytes, byte(i))
	}
	// Repeat to have enough data
	data := string(allBytes)
	for i := 0; i < 10; i++ {
		data += string(allBytes)
	}

	result := CalculateEntropy(data)
	if result < 7.9 || result > 8.0 {
		t.Errorf("Maximum entropy should be close to 8, got %v", result)
	}
}

func TestCalculateEntropyForChunks(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		chunkSize  int
		wantChunks int
	}{
		{
			name:       "empty string",
			input:      "",
			chunkSize:  100,
			wantChunks: 0,
		},
		{
			name:       "zero chunk size",
			input:      "test data",
			chunkSize:  0,
			wantChunks: 0,
		},
		{
			name:       "negative chunk size",
			input:      "test data",
			chunkSize:  -1,
			wantChunks: 0,
		},
		{
			name:       "single chunk",
			input:      "short",
			chunkSize:  100,
			wantChunks: 1,
		},
		{
			name:       "multiple chunks",
			input:      strings.Repeat("a", 1000),
			chunkSize:  100,
			wantChunks: 10,
		},
		{
			name:       "uneven chunks",
			input:      strings.Repeat("a", 350),
			chunkSize:  100,
			wantChunks: 4, // 100 + 100 + 100 + 50
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateEntropyForChunks(tt.input, tt.chunkSize)
			if len(result) != tt.wantChunks {
				t.Errorf("CalculateEntropyForChunks() returned %d chunks, want %d",
					len(result), tt.wantChunks)
			}
		})
	}
}

func TestGetMaxChunkEntropy(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		chunkSize int
		wantMax   float64
		tolerance float64
	}{
		{
			name:      "empty string",
			input:     "",
			chunkSize: 100,
			wantMax:   0,
			tolerance: 0.01,
		},
		{
			name:      "uniform content",
			input:     strings.Repeat("a", 500),
			chunkSize: 100,
			wantMax:   0,
			tolerance: 0.01,
		},
		{
			name:      "mixed content - low then high entropy",
			input:     strings.Repeat("a", 100) + "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=",
			chunkSize: 100,
			wantMax:   5.5,
			tolerance: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetMaxChunkEntropy(tt.input, tt.chunkSize)
			if math.Abs(result-tt.wantMax) > tt.tolerance {
				t.Errorf("GetMaxChunkEntropy() = %v, want %v (±%v)",
					result, tt.wantMax, tt.tolerance)
			}
		})
	}
}

func TestIsLikelyObfuscated(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "normal PHP code",
			input: `<?php echo "Hello World"; ?>`,
			want:  false,
		},
		{
			name:  "simple variable assignment",
			input: `$name = "John"; $age = 25;`,
			want:  false,
		},
		{
			name:  "short base64 - not enough entropy",
			input: "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=",
			want:  false, // Short strings don't have enough entropy
		},
		{
			name:  "repeated pattern - low entropy",
			input: strings.Repeat("\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff", 50),
			want:  false, // Repeated pattern has lower entropy than threshold
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsLikelyObfuscated(tt.input)
			if result != tt.want {
				t.Errorf("IsLikelyObfuscated(%q) = %v, want %v", tt.input, result, tt.want)
			}
		})
	}
}

func TestAnalyzeEntropy(t *testing.T) {
	// Create high entropy data (all 256 byte values repeated)
	var highEntropyBytes []byte
	for i := 0; i < 256; i++ {
		highEntropyBytes = append(highEntropyBytes, byte(i))
	}
	highEntropyData := string(highEntropyBytes)
	for i := 0; i < 10; i++ {
		highEntropyData += string(highEntropyBytes)
	}

	tests := []struct {
		name           string
		input          string
		wantObfuscated bool
		minConfidence  int
		maxConfidence  int
	}{
		{
			name:           "empty string",
			input:          "",
			wantObfuscated: false,
			minConfidence:  0,
			maxConfidence:  0,
		},
		{
			name: "normal PHP code",
			input: `<?php
function greet($name) {
    echo "Hello, " . $name;
}
greet("World");
?>`,
			wantObfuscated: false,
			minConfidence:  0,
			maxConfidence:  50,
		},
		{
			name:           "high entropy data - all 256 bytes",
			input:          highEntropyData,
			wantObfuscated: true,
			minConfidence:  75,
			maxConfidence:  100,
		},
		{
			name: "mixed content with obfuscated section",
			input: `<?php
// Normal code here
$x = 1;
` + strings.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 50),
			wantObfuscated: true,
			minConfidence:  50,
			maxConfidence:  100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeEntropy(tt.input)

			if result.IsObfuscated != tt.wantObfuscated {
				t.Errorf("AnalyzeEntropy().IsObfuscated = %v, want %v (entropy: %.2f)",
					result.IsObfuscated, tt.wantObfuscated, result.Overall)
			}

			if result.Confidence < tt.minConfidence || result.Confidence > tt.maxConfidence {
				t.Errorf("AnalyzeEntropy().Confidence = %d, want between %d and %d",
					result.Confidence, tt.minConfidence, tt.maxConfidence)
			}
		})
	}
}

func TestAnalyzeEntropy_ChunkAnalysis(t *testing.T) {
	// Test that chunk analysis works correctly
	input := strings.Repeat("a", 1000) // Low entropy
	result := AnalyzeEntropy(input)

	if len(result.ChunkResults) == 0 {
		t.Error("Expected chunk results to be populated")
	}

	if result.Min > result.Max {
		t.Error("Min entropy should not be greater than Max")
	}

	if result.Average < result.Min || result.Average > result.Max {
		t.Error("Average entropy should be between Min and Max")
	}
}

func TestEntropyConstants(t *testing.T) {
	// Verify threshold ordering makes sense
	if EntropyNormalPHP >= EntropyObfuscated {
		t.Error("EntropyNormalPHP should be less than EntropyObfuscated")
	}

	if EntropyObfuscated >= EntropyHighlyEncoded {
		t.Error("EntropyObfuscated should be less than EntropyHighlyEncoded")
	}

	// Verify values are reasonable for byte entropy (0-8)
	if EntropyHighlyEncoded > 8 {
		t.Error("EntropyHighlyEncoded should not exceed maximum byte entropy (8)")
	}
}

// Benchmarks

func BenchmarkCalculateEntropy(b *testing.B) {
	data := strings.Repeat("test data with some variation 12345", 100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CalculateEntropy(data)
	}
}

func BenchmarkAnalyzeEntropy(b *testing.B) {
	data := strings.Repeat("test data with some variation 12345", 100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AnalyzeEntropy(data)
	}
}
