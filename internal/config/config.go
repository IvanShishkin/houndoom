package config

import (
	"runtime"

	"github.com/spf13/viper"
)

// Config represents the scanner configuration
type Config struct {
	// Scan settings
	Mode         string   `mapstructure:"mode"`          // fast, normal, paranoid
	Path         string   `mapstructure:"path"`          // path to scan
	Workers      int      `mapstructure:"workers"`       // number of worker goroutines
	MaxSize      string   `mapstructure:"max_size"`      // maximum file size to scan
	Extensions   []string `mapstructure:"extensions"`    // file extensions to scan
	Exclude      []string `mapstructure:"exclude"`       // directories to exclude
	ScanAllFiles bool     `mapstructure:"scan_all_files"` // scan all files regardless of extension
	ScanDelay    int      `mapstructure:"scan_delay"`    // delay between file scans (ms)
	SkipCache    bool     `mapstructure:"skip_cache"`    // skip cache files

	// Report settings
	ReportFormat string `mapstructure:"report_format"` // html, json, text, xml
	OutputFile   string `mapstructure:"output_file"`   // output file path
	NoHTML       bool   `mapstructure:"no_html"`       // disable HTML report

	// Detector settings
	Detectors          []string `mapstructure:"detectors"`          // enabled detectors
	Disable            []string `mapstructure:"disable"`            // disabled detectors
	EnableExperimental bool     `mapstructure:"enable_experimental"` // enable experimental detectors (heuristic, adware, phishing, doorway)
	ForceCMS           string   `mapstructure:"force_cms"`          // force specific CMS detector (bitrix, wordpress, etc) - auto-detect if empty

	// Whitelist settings
	WhitelistDB string `mapstructure:"whitelist_db"` // whitelist database path
	UseWhitelist bool  `mapstructure:"use_whitelist"` // enable whitelist checking

	// Deobfuscation settings
	EnableDeobfuscation bool `mapstructure:"enable_deobfuscation"` // enable code deobfuscation
	MaxDeobfuscateDepth int  `mapstructure:"max_deobfuscate_depth"` // maximum deobfuscation recursion depth

	// Signature settings
	SignaturesPath string `mapstructure:"signatures_path"` // path to signatures directory

	// AI settings
	AI AIConfig `mapstructure:"ai"` // AI-powered analysis configuration
}

// AIConfig holds AI analysis configuration
type AIConfig struct {
	Enabled     bool   `mapstructure:"ai_enabled"`      // Enable AI-powered analysis
	Model       string `mapstructure:"ai_model"`        // Model: haiku, sonnet, opus
	APIToken    string `mapstructure:"ai_token"`        // Anthropic API token
	MaxFindings int    `mapstructure:"ai_max_findings"` // Cost control limit
	Timeout     int    `mapstructure:"ai_timeout"`      // Seconds per request
	QuickFilter bool   `mapstructure:"ai_quick_filter"` // Use Haiku for pre-filtering
	Language    string `mapstructure:"ai_language"`     // Report language: en, ru, es
	SmartMode   bool   `mapstructure:"ai_smart"`        // Smart mode: dedupe + sampling + severity priority
}

// ScanMode represents the scanning mode
type ScanMode int

const (
	ModeFast ScanMode = iota
	ModeNormal
	ModeParanoid
)

// LoadConfig loads configuration from environment variables and defaults
func LoadConfig() (*Config, error) {
	v := viper.New()

	// Set defaults
	v.SetDefault("mode", "normal")
	v.SetDefault("workers", runtime.NumCPU()*2)
	v.SetDefault("max_size", "650K")
	v.SetDefault("scan_all_files", false)
	v.SetDefault("scan_delay", 0)
	v.SetDefault("skip_cache", false)
	v.SetDefault("report_format", "")
	v.SetDefault("no_html", false)
	v.SetDefault("use_whitelist", true)
	v.SetDefault("enable_deobfuscation", true)
	v.SetDefault("max_deobfuscate_depth", 100)
	v.SetDefault("signatures_path", "configs/signatures")
	v.SetDefault("exclude", []string{".git", "node_modules", "vendor", ".svn", ".hg"})
	v.SetDefault("enable_experimental", false) // By default, use only critical detectors

	// AI defaults
	v.SetDefault("ai.ai_enabled", false)
	v.SetDefault("ai.ai_model", "sonnet")
	v.SetDefault("ai.ai_max_findings", 50)
	v.SetDefault("ai.ai_timeout", 30)
	v.SetDefault("ai.ai_quick_filter", true)
	v.SetDefault("ai.ai_language", "en")
	v.SetDefault("ai.ai_smart", false)

	// Read environment variables
	v.SetEnvPrefix("HOUNDOOM")
	v.AutomaticEnv()

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// GetScanMode returns the scan mode enum value
func (c *Config) GetScanMode() ScanMode {
	switch c.Mode {
	case "fast":
		return ModeFast
	case "paranoid":
		return ModeParanoid
	default:
		return ModeNormal
	}
}

// ShouldScanFile determines if a file should be scanned based on extension
func (c *Config) ShouldScanFile(extension string) bool {
	if c.ScanAllFiles {
		return true
	}

	if len(c.Extensions) > 0 {
		// Custom extensions specified
		for _, ext := range c.Extensions {
			if ext == extension {
				return true
			}
		}
		return false
	}

	// Default extensions based on mode
	mode := c.GetScanMode()
	switch mode {
	case ModeFast:
		// Only critical files
		return isCriticalExtension(extension)
	case ModeParanoid:
		// All files
		return true
	default:
		// Normal mode - sensitive files
		return isSensitiveExtension(extension)
	}
}

// isCriticalExtension checks if extension is critical
func isCriticalExtension(ext string) bool {
	critical := []string{"php", "htaccess", "js", "html", "htm"}
	for _, e := range critical {
		if e == ext {
			return true
		}
	}
	return false
}

// isSensitiveExtension checks if extension is sensitive
func isSensitiveExtension(ext string) bool {
	sensitive := []string{
		"php", "php3", "php4", "php5", "php6", "php7", "pht", "phtml",
		"js", "json", "html", "htm", "shtml", "htaccess",
		"cgi", "pl", "py", "sh", "o", "so",
		"tpl", "inc", "css", "txt", "sql",
	}
	for _, e := range sensitive {
		if e == ext {
			return true
		}
	}
	return false
}
