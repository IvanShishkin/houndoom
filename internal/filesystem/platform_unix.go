// +build !windows

package filesystem

import (
	"os"
	"syscall"
	"time"
)

// getChangeTime gets the change time from FileInfo (Unix)
func getChangeTime(info os.FileInfo) time.Time {
	stat := info.Sys().(*syscall.Stat_t)
	// Use ctime (change time)
	return time.Unix(stat.Ctim.Sec, stat.Ctim.Nsec)
}
