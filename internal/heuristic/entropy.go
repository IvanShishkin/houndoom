package heuristic

import (
	"math"
)

// EntropyThresholds for different content types
const (
	EntropyNormalPHP     = 4.5 // Normal PHP code
	EntropyObfuscated    = 5.5 // Likely obfuscated
	EntropyHighlyEncoded = 6.0 // Highly encoded/encrypted
)

// CalculateEntropy calculates Shannon entropy of a string
// Returns value between 0 (uniform) and 8 (maximum randomness for bytes)
func CalculateEntropy(data string) float64 {
	if len(data) == 0 {
		return 0
	}

	// Count byte frequencies
	freq := make(map[byte]int)
	for i := 0; i < len(data); i++ {
		freq[data[i]]++
	}

	// Calculate entropy
	length := float64(len(data))
	var entropy float64

	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// CalculateEntropyForChunks calculates entropy for chunks of data
// Useful for detecting localized obfuscation
func CalculateEntropyForChunks(data string, chunkSize int) []float64 {
	if len(data) == 0 || chunkSize <= 0 {
		return nil
	}

	var results []float64
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]
		if len(chunk) > 0 {
			results = append(results, CalculateEntropy(chunk))
		}
	}

	return results
}

// GetMaxChunkEntropy returns maximum entropy among all chunks
func GetMaxChunkEntropy(data string, chunkSize int) float64 {
	chunks := CalculateEntropyForChunks(data, chunkSize)
	if len(chunks) == 0 {
		return 0
	}

	maxEntropy := chunks[0]
	for _, e := range chunks[1:] {
		if e > maxEntropy {
			maxEntropy = e
		}
	}
	return maxEntropy
}

// IsLikelyObfuscated checks if content is likely obfuscated based on entropy
func IsLikelyObfuscated(data string) bool {
	entropy := CalculateEntropy(data)
	return entropy > EntropyObfuscated
}

// EntropyAnalysis contains detailed entropy analysis results
type EntropyAnalysis struct {
	Overall      float64   // Overall entropy
	Max          float64   // Maximum chunk entropy
	Min          float64   // Minimum chunk entropy
	Average      float64   // Average chunk entropy
	ChunkResults []float64 // Per-chunk results
	IsObfuscated bool      // Likely obfuscated flag
	Confidence   int       // Confidence level 0-100
}

// AnalyzeEntropy performs detailed entropy analysis
func AnalyzeEntropy(data string) *EntropyAnalysis {
	if len(data) == 0 {
		return &EntropyAnalysis{}
	}

	analysis := &EntropyAnalysis{
		Overall: CalculateEntropy(data),
	}

	// Analyze in 512-byte chunks
	chunkSize := 512
	if len(data) < chunkSize {
		chunkSize = len(data)
	}

	analysis.ChunkResults = CalculateEntropyForChunks(data, chunkSize)

	if len(analysis.ChunkResults) > 0 {
		analysis.Min = analysis.ChunkResults[0]
		analysis.Max = analysis.ChunkResults[0]
		var sum float64

		for _, e := range analysis.ChunkResults {
			sum += e
			if e < analysis.Min {
				analysis.Min = e
			}
			if e > analysis.Max {
				analysis.Max = e
			}
		}
		analysis.Average = sum / float64(len(analysis.ChunkResults))
	}

	// Determine if obfuscated
	if analysis.Overall > EntropyHighlyEncoded {
		analysis.IsObfuscated = true
		analysis.Confidence = 95
	} else if analysis.Overall > EntropyObfuscated {
		analysis.IsObfuscated = true
		analysis.Confidence = 75
	} else if analysis.Max > EntropyHighlyEncoded {
		// Localized obfuscation
		analysis.IsObfuscated = true
		analysis.Confidence = 60
	}

	return analysis
}
