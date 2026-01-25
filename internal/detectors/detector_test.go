package detectors

import (
	"testing"
)

func TestBaseDetector_Name(t *testing.T) {
	detector := NewBaseDetector("test_detector", 10, []string{"php", "js"})

	if got := detector.Name(); got != "test_detector" {
		t.Errorf("Name() = %v, want %v", got, "test_detector")
	}
}

func TestBaseDetector_Priority(t *testing.T) {
	detector := NewBaseDetector("test_detector", 10, []string{"php"})

	if got := detector.Priority(); got != 10 {
		t.Errorf("Priority() = %v, want %v", got, 10)
	}
}

func TestBaseDetector_SupportedExtensions(t *testing.T) {
	extensions := []string{"php", "js", "html"}
	detector := NewBaseDetector("test_detector", 10, extensions)

	got := detector.SupportedExtensions()
	if len(got) != len(extensions) {
		t.Errorf("SupportedExtensions() length = %v, want %v", len(got), len(extensions))
	}

	for i, ext := range extensions {
		if got[i] != ext {
			t.Errorf("SupportedExtensions()[%d] = %v, want %v", i, got[i], ext)
		}
	}
}

func TestBaseDetector_IsEnabled(t *testing.T) {
	detector := NewBaseDetector("test_detector", 10, []string{"php"})

	// Should be enabled by default
	if !detector.IsEnabled() {
		t.Error("IsEnabled() = false, want true (default)")
	}
}

func TestBaseDetector_SetEnabled(t *testing.T) {
	detector := NewBaseDetector("test_detector", 10, []string{"php"})

	// Test disabling
	detector.SetEnabled(false)
	if detector.IsEnabled() {
		t.Error("After SetEnabled(false), IsEnabled() = true, want false")
	}

	// Test enabling
	detector.SetEnabled(true)
	if !detector.IsEnabled() {
		t.Error("After SetEnabled(true), IsEnabled() = false, want true")
	}
}

func TestBaseDetector_SupportsFile(t *testing.T) {
	detector := NewBaseDetector("test_detector", 10, []string{"php", "js", "html"})

	tests := []struct {
		name      string
		extension string
		expected  bool
	}{
		{"Supported PHP", "php", true},
		{"Supported JS", "js", true},
		{"Supported HTML", "html", true},
		{"Not supported TXT", "txt", false},
		{"Not supported CSS", "css", false},
		{"Empty extension", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detector.SupportsFile(tt.extension); got != tt.expected {
				t.Errorf("SupportsFile(%q) = %v, want %v", tt.extension, got, tt.expected)
			}
		})
	}
}

func TestBaseDetector_SupportsFile_Wildcard(t *testing.T) {
	// Detector that supports all files
	detector := NewBaseDetector("universal_detector", 10, []string{"*"})

	tests := []string{"php", "js", "html", "txt", "css", "unknown", ""}

	for _, ext := range tests {
		t.Run(ext, func(t *testing.T) {
			if !detector.SupportsFile(ext) {
				t.Errorf("SupportsFile(%q) with wildcard = false, want true", ext)
			}
		})
	}
}
