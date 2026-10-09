//go:build windows

package security

import (
	"os"
	"syscall"
)

// isHardlink reports whether path has more than one hard link.
func isHardlink(path string, _ os.FileInfo) bool {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return false
	}

	handle, err := syscall.CreateFile(
		name,
		0,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(handle)

	var data syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &data); err != nil {
		return false
	}
	return data.NumberOfLinks > 1
}
