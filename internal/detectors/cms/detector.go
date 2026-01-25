package cms

import (
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
)

// CMSType represents the detected CMS type
type CMSType string

const (
	CMSUnknown   CMSType = "unknown"
	CMSBitrix    CMSType = "bitrix"
	CMSWordPress CMSType = "wordpress"
	CMSDrupal    CMSType = "drupal"
	CMSLaravel   CMSType = "laravel"
	CMSSymfony   CMSType = "symfony"
	CMSJoomla    CMSType = "joomla"
)

// Detector detects the CMS type of a project
type Detector struct {
	logger *zap.Logger
}

// NewDetector creates a new CMS detector
func NewDetector(logger *zap.Logger) *Detector {
	return &Detector{
		logger: logger,
	}
}

// DetectionResult contains CMS detection results
type DetectionResult struct {
	Type       CMSType
	Confidence int      // 0-100
	Indicators []string // What indicators were found
	Version    string   // CMS version if detected
}

// Detect automatically detects the CMS type from project structure
func (d *Detector) Detect(projectPath string) *DetectionResult {
	result := &DetectionResult{
		Type:       CMSUnknown,
		Confidence: 0,
		Indicators: make([]string, 0),
	}

	// Check for Bitrix
	if d.isBitrix(projectPath, result) {
		result.Type = CMSBitrix
		return result
	}

	// Check for WordPress
	if d.isWordPress(projectPath, result) {
		result.Type = CMSWordPress
		return result
	}

	// Check for Laravel
	if d.isLaravel(projectPath, result) {
		result.Type = CMSLaravel
		return result
	}

	// Check for Symfony
	if d.isSymfony(projectPath, result) {
		result.Type = CMSSymfony
		return result
	}

	// Check for Drupal
	if d.isDrupal(projectPath, result) {
		result.Type = CMSDrupal
		return result
	}

	// Check for Joomla
	if d.isJoomla(projectPath, result) {
		result.Type = CMSJoomla
		return result
	}

	return result
}

// isBitrix checks if project is Bitrix CMS
func (d *Detector) isBitrix(projectPath string, result *DetectionResult) bool {
	indicators := []struct {
		path   string
		weight int
	}{
		{"/bitrix/modules/", 50},                      // Core directory
		{"/bitrix/components/", 40},                   // Components
		{"/bitrix/templates/", 30},                    // Templates
		{"/bitrix/php_interface/", 30},                // PHP interface
		{"/bitrix/.settings.php", 30},                 // Settings file
		{"/bitrix/admin/", 20},                        // Admin panel
		{"/upload/", 10},                              // Upload directory
		{"/local/", 10},                               // Local customizations
		{"/bitrix/cache/", 10},                        // Cache
		{"/bitrix/managed_cache/", 10},                // Managed cache
	}

	confidence := 0
	for _, indicator := range indicators {
		fullPath := filepath.Join(projectPath, filepath.FromSlash(indicator.path))
		if _, err := os.Stat(fullPath); err == nil {
			confidence += indicator.weight
			result.Indicators = append(result.Indicators, indicator.path)
		}
	}

	// Additional check: look for bitrix in any subdirectory
	if confidence < 50 {
		err := filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // Continue on error
			}
			if info.IsDir() && strings.Contains(strings.ToLower(info.Name()), "bitrix") {
				confidence += 20
				result.Indicators = append(result.Indicators, "Found directory: "+info.Name())
				return filepath.SkipDir
			}
			return nil
		})
		if err != nil {
			d.logger.Debug("Error walking directory", zap.Error(err))
		}
	}

	// Try to detect version from bitrix/.settings.php
	if confidence >= 50 {
		version := d.detectBitrixVersion(projectPath)
		if version != "" {
			result.Version = version
			confidence += 10
		}
	}

	result.Confidence = confidence
	return confidence >= 50 // Requires at least 50 points
}

// isWordPress checks if project is WordPress
func (d *Detector) isWordPress(projectPath string, result *DetectionResult) bool {
	indicators := []struct {
		path   string
		weight int
	}{
		{"/wp-config.php", 60},                        // Main config
		{"/wp-content/", 40},                          // Content directory
		{"/wp-admin/", 40},                            // Admin panel
		{"/wp-includes/", 40},                         // Core includes
		{"/wp-login.php", 30},                         // Login file
		{"/wp-content/plugins/", 20},                  // Plugins
		{"/wp-content/themes/", 20},                   // Themes
	}

	confidence := 0
	for _, indicator := range indicators {
		fullPath := filepath.Join(projectPath, filepath.FromSlash(indicator.path))
		if _, err := os.Stat(fullPath); err == nil {
			confidence += indicator.weight
			result.Indicators = append(result.Indicators, indicator.path)
		}
	}

	result.Confidence = confidence
	return confidence >= 50
}

// isLaravel checks if project is Laravel
func (d *Detector) isLaravel(projectPath string, result *DetectionResult) bool {
	indicators := []struct {
		path   string
		weight int
	}{
		{"/artisan", 60},                              // Laravel CLI
		{"/app/Http/Kernel.php", 50},                  // HTTP Kernel
		{"/bootstrap/app.php", 40},                    // Bootstrap
		{"/config/app.php", 30},                       // App config
		{"/routes/web.php", 30},                       // Routes
		{"/composer.json", 10},                        // Composer
	}

	confidence := 0
	for _, indicator := range indicators {
		fullPath := filepath.Join(projectPath, filepath.FromSlash(indicator.path))
		if _, err := os.Stat(fullPath); err == nil {
			confidence += indicator.weight

			// Check composer.json for laravel/framework
			if indicator.path == "/composer.json" {
				if d.checkFileContains(fullPath, "laravel/framework") {
					confidence += 40
					result.Indicators = append(result.Indicators, "composer.json contains laravel/framework")
				}
			} else {
				result.Indicators = append(result.Indicators, indicator.path)
			}
		}
	}

	result.Confidence = confidence
	return confidence >= 50
}

// isSymfony checks if project is Symfony
func (d *Detector) isSymfony(projectPath string, result *DetectionResult) bool {
	indicators := []struct {
		path   string
		weight int
	}{
		{"/symfony.lock", 60},                         // Symfony lock file
		{"/bin/console", 50},                          // Console
		{"/config/services.yaml", 40},                 // Services config
		{"/src/Kernel.php", 40},                       // Kernel
		{"/public/index.php", 20},                     // Entry point
		{"/composer.json", 10},                        // Composer
	}

	confidence := 0
	for _, indicator := range indicators {
		fullPath := filepath.Join(projectPath, filepath.FromSlash(indicator.path))
		if _, err := os.Stat(fullPath); err == nil {
			confidence += indicator.weight

			if indicator.path == "/composer.json" {
				if d.checkFileContains(fullPath, "symfony/framework-bundle") {
					confidence += 40
					result.Indicators = append(result.Indicators, "composer.json contains symfony/framework-bundle")
				}
			} else {
				result.Indicators = append(result.Indicators, indicator.path)
			}
		}
	}

	result.Confidence = confidence
	return confidence >= 50
}

// isDrupal checks if project is Drupal
func (d *Detector) isDrupal(projectPath string, result *DetectionResult) bool {
	indicators := []struct {
		path   string
		weight int
	}{
		{"/core/", 50},                                // Core directory
		{"/sites/default/", 40},                       // Sites directory
		{"/modules/", 30},                             // Modules
		{"/themes/", 30},                              // Themes
		{"/index.php", 10},                            // Entry point
	}

	confidence := 0
	for _, indicator := range indicators {
		fullPath := filepath.Join(projectPath, filepath.FromSlash(indicator.path))
		if _, err := os.Stat(fullPath); err == nil {
			// Check index.php for Drupal
			if indicator.path == "/index.php" {
				if d.checkFileContains(fullPath, "DRUPAL_ROOT") {
					confidence += 50
					result.Indicators = append(result.Indicators, "index.php contains DRUPAL_ROOT")
				}
			} else {
				confidence += indicator.weight
				result.Indicators = append(result.Indicators, indicator.path)
			}
		}
	}

	result.Confidence = confidence
	return confidence >= 50
}

// isJoomla checks if project is Joomla
func (d *Detector) isJoomla(projectPath string, result *DetectionResult) bool {
	indicators := []struct {
		path   string
		weight int
	}{
		{"/configuration.php", 60},                    // Main config
		{"/administrator/", 40},                       // Admin panel
		{"/libraries/", 30},                           // Libraries
		{"/components/", 30},                          // Components
		{"/modules/", 20},                             // Modules
		{"/plugins/", 20},                             // Plugins
		{"/templates/", 20},                           // Templates
	}

	confidence := 0
	for _, indicator := range indicators {
		fullPath := filepath.Join(projectPath, filepath.FromSlash(indicator.path))
		if _, err := os.Stat(fullPath); err == nil {
			confidence += indicator.weight
			result.Indicators = append(result.Indicators, indicator.path)
		}
	}

	result.Confidence = confidence
	return confidence >= 50
}

// detectBitrixVersion tries to detect Bitrix version
func (d *Detector) detectBitrixVersion(projectPath string) string {
	// Try to read version from bitrix/.settings.php or other files
	// This is simplified - in real implementation would parse the file
	return "" // TODO: Implement version detection
}

// checkFileContains checks if file contains a string
func (d *Detector) checkFileContains(filePath, searchString string) bool {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), searchString)
}

// String returns string representation of CMS type
func (c CMSType) String() string {
	return string(c)
}

// IsBitrix returns true if detected CMS is Bitrix
func (r *DetectionResult) IsBitrix() bool {
	return r.Type == CMSBitrix && r.Confidence >= 50
}

// IsWordPress returns true if detected CMS is WordPress
func (r *DetectionResult) IsWordPress() bool {
	return r.Type == CMSWordPress && r.Confidence >= 50
}

// IsLaravel returns true if detected CMS is Laravel
func (r *DetectionResult) IsLaravel() bool {
	return r.Type == CMSLaravel && r.Confidence >= 50
}
