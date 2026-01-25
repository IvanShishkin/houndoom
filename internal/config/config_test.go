package config

import (
	"testing"
)

func TestGetScanMode(t *testing.T) {
	tests := []struct {
		name     string
		mode     string
		expected ScanMode
	}{
		{"Fast mode", "fast", ModeFast},
		{"Normal mode", "normal", ModeNormal},
		{"Paranoid mode", "paranoid", ModeParanoid},
		{"Default mode", "", ModeNormal},
		{"Invalid mode", "invalid", ModeNormal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Mode: tt.mode}
			if got := cfg.GetScanMode(); got != tt.expected {
				t.Errorf("GetScanMode() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestShouldScanFile(t *testing.T) {
	tests := []struct {
		name       string
		mode       string
		extension  string
		scanAll    bool
		extensions []string
		expected   bool
	}{
		{"PHP in fast mode", "fast", "php", false, nil, true},
		{"JS in fast mode", "fast", "js", false, nil, true},
		{"TXT in fast mode", "fast", "txt", false, nil, false},
		{"TXT in normal mode", "normal", "txt", false, nil, true},
		{"TXT in paranoid mode", "paranoid", "txt", false, nil, true},
		{"Any file with scanAll", "normal", "unknown", true, nil, true},
		{"Custom extensions", "normal", "custom", false, []string{"custom", "test"}, true},
		{"Non-matching custom ext", "normal", "php", false, []string{"custom", "test"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Mode:         tt.mode,
				ScanAllFiles: tt.scanAll,
				Extensions:   tt.extensions,
			}
			if got := cfg.ShouldScanFile(tt.extension); got != tt.expected {
				t.Errorf("ShouldScanFile(%q) = %v, want %v", tt.extension, got, tt.expected)
			}
		})
	}
}

func TestIsCriticalExtension(t *testing.T) {
	tests := []struct {
		extension string
		expected  bool
	}{
		{"php", true},
		{"js", true},
		{"html", true},
		{"htm", true},
		{"htaccess", true},
		{"txt", false},
		{"css", false},
		{"jpg", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.extension, func(t *testing.T) {
			if got := isCriticalExtension(tt.extension); got != tt.expected {
				t.Errorf("isCriticalExtension(%q) = %v, want %v", tt.extension, got, tt.expected)
			}
		})
	}
}

func TestIsSensitiveExtension(t *testing.T) {
	tests := []struct {
		extension string
		expected  bool
	}{
		{"php", true},
		{"php3", true},
		{"php5", true},
		{"phtml", true},
		{"js", true},
		{"html", true},
		{"cgi", true},
		{"pl", true},
		{"py", true},
		{"sh", true},
		{"jpg", false},
		{"png", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.extension, func(t *testing.T) {
			if got := isSensitiveExtension(tt.extension); got != tt.expected {
				t.Errorf("isSensitiveExtension(%q) = %v, want %v", tt.extension, got, tt.expected)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	// Test default config loading (without config file)
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	// Check defaults
	if cfg.Mode != "normal" {
		t.Errorf("Default mode = %v, want %v", cfg.Mode, "normal")
	}

	if cfg.MaxSize != "650K" {
		t.Errorf("Default max_size = %v, want %v", cfg.MaxSize, "650K")
	}

	if cfg.ReportFormat != "" {
		t.Errorf("Default report_format = %v, want %v", cfg.ReportFormat, "")
	}

	if cfg.EnableDeobfuscation != true {
		t.Errorf("Default enable_deobfuscation = %v, want %v", cfg.EnableDeobfuscation, true)
	}

	if cfg.MaxDeobfuscateDepth != 100 {
		t.Errorf("Default max_deobfuscate_depth = %v, want %v", cfg.MaxDeobfuscateDepth, 100)
	}

	if cfg.EnableExperimental != false {
		t.Errorf("Default enable_experimental = %v, want %v", cfg.EnableExperimental, false)
	}

	// Check default exclude list
	expectedExclude := []string{".git", "node_modules", "vendor", ".svn", ".hg"}
	if len(cfg.Exclude) != len(expectedExclude) {
		t.Errorf("Default exclude count = %v, want %v", len(cfg.Exclude), len(expectedExclude))
	}
}
