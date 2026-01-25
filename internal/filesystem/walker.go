package filesystem

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/IvanShishkin/houndoom/internal/config"
	"github.com/IvanShishkin/houndoom/pkg/models"
	"go.uber.org/zap"
)

// Walker walks the filesystem and finds files to scan
type Walker struct {
	config  *config.Config
	logger  *zap.Logger
	exclude map[string]bool
}

// NewWalker creates a new filesystem walker
func NewWalker(cfg *config.Config, logger *zap.Logger) *Walker {
	// Build exclude map for fast lookup
	exclude := make(map[string]bool)
	for _, dir := range cfg.Exclude {
		exclude[dir] = true
	}

	return &Walker{
		config:  cfg,
		logger:  logger,
		exclude: exclude,
	}
}

// Walk recursively walks the directory tree
func (w *Walker) Walk(root string, callback func(*models.FileInfo) error) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			w.logger.Warn("Error accessing path", zap.String("path", path), zap.Error(err))
			return nil // Continue walking
		}

		// Get relative path
		relPath, err := filepath.Rel(root, path)
		if err != nil {
			relPath = path
		}

		// Skip excluded directories
		if info.IsDir() {
			if w.shouldExclude(info.Name(), relPath) {
				w.logger.Debug("Skipping excluded directory", zap.String("path", relPath))
				return filepath.SkipDir
			}
		}

		// Create FileInfo
		fileInfo := &models.FileInfo{
			Path:      path,
			Size:      info.Size(),
			ModTime:   info.ModTime(),
			IsDir:     info.IsDir(),
			IsSymlink: info.Mode()&os.ModeSymlink != 0,
			IsHidden:  isHidden(info.Name()),
		}

		// Get change time (platform-dependent)
		fileInfo.ChangeTime = getChangeTime(info)

		// Call callback
		return callback(fileInfo)
	})
}

// shouldExclude checks if a directory should be excluded
func (w *Walker) shouldExclude(name, path string) bool {
	// Check exact match
	if w.exclude[name] {
		return true
	}

	// Check if path contains excluded directory
	parts := strings.Split(path, string(os.PathSeparator))
	for _, part := range parts {
		if w.exclude[part] {
			return true
		}
	}

	return false
}

// isHidden checks if a file is hidden
func isHidden(name string) bool {
	// Unix-like systems: files starting with dot
	if len(name) > 0 && name[0] == '.' {
		return true
	}
	// TODO: Windows hidden attribute check
	return false
}

// GetExtension returns the file extension without dot
func GetExtension(path string) string {
	ext := filepath.Ext(path)
	if len(ext) > 0 && ext[0] == '.' {
		return ext[1:]
	}
	return ext
}
