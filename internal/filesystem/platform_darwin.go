//go:build darwin || freebsd

package filesystem

import (
	"os"
	"syscall"
	"time"
)

// getChangeTime gets the change time from FileInfo (BSD/Darwin)
func getChangeTime(info os.FileInfo) time.Time {
	stat := info.Sys().(*syscall.Stat_t)
	return time.Unix(stat.Ctimespec.Sec, stat.Ctimespec.Nsec)
}
