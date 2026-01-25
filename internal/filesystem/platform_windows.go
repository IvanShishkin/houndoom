// +build windows

package filesystem

import (
	"os"
	"syscall"
	"time"
)

// getChangeTime gets the change time from FileInfo (Windows)
func getChangeTime(info os.FileInfo) time.Time {
	stat := info.Sys().(*syscall.Win32FileAttributeData)
	// On Windows, use creation time as change time
	return time.Unix(0, stat.CreationTime.Nanoseconds())
}
