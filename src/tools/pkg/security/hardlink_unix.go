//go:build unix

package security

import (
	"os"
	"syscall"
)

// isHardlink reports whether info describes a file with more than one link.
func isHardlink(_ string, info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink > 1
}
