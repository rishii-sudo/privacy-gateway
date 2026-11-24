//go:build windows

package tor

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var (
	modadvapi32          = syscall.NewLazyDLL("advapi32.dll")
	procGetSecurityInfo  = modadvapi32.NewProc("GetSecurityInfo")
	procIsValidSid       = modadvapi32.NewProc("IsValidSid")
	procEqualSid         = modadvapi32.NewProc("EqualSid")
	procConvertStringSid = modadvapi32.NewProc("ConvertStringSidToSidW")

	modkernel32          = syscall.NewLazyDLL("kernel32.dll")
	procLocalFree        = modkernel32.NewProc("LocalFree")
	procGetFinalPathName = modkernel32.NewProc("GetFinalPathNameByHandleW")
)

const (
	ownerSecurityInformation = 0x00000001
	seFileObject             = 1

	// maxFinalPathBufSize is the strict upper bound for GetFinalPathNameByHandleW buffers (32 KB / MAX_LONG_PATH).
	maxFinalPathBufSize = 32768
	// initialFinalPathBufSize is the initial buffer size (1024 UTF-16 characters).
	initialFinalPathBufSize = 1024
)

// finalPathNameCaller abstracts the low-level Win32 GetFinalPathNameByHandleW invocation for testability.
type finalPathNameCaller func(handle syscall.Handle, buf []uint16) (uint32, error)

// defaultGetFinalPathNameCaller invokes kernel32.dll GetFinalPathNameByHandleW.
func defaultGetFinalPathNameCaller(handle syscall.Handle, buf []uint16) (uint32, error) {
	if err := procGetFinalPathName.Find(); err != nil {
		return 0, fmt.Errorf("kernel32.dll GetFinalPathNameByHandleW procedure could not be resolved: %w", err)
	}

	ret, _, callErr := procGetFinalPathName.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0, // FILE_NAME_NORMALIZED | VOLUME_NAME_DOS
	)

	if ret == 0 {
		return 0, fmt.Errorf("GetFinalPathNameByHandleW returned 0: %w", callErr)
	}

	return uint32(ret), nil
}

// resolveFinalCanonicalPath executes GetFinalPathNameByHandleW with fail-closed semantics,
// dynamic bounded resizing, and canonical path normalization.
func resolveFinalCanonicalPath(handle syscall.Handle, caller finalPathNameCaller) (string, error) {
	if caller == nil {
		caller = defaultGetFinalPathNameCaller
	}

	bufSize := initialFinalPathBufSize
	for {
		buf := make([]uint16, bufSize)
		ret, err := caller(handle, buf)
		if err != nil {
			return "", fmt.Errorf("canonical path query failed: %w", err)
		}

		if ret == 0 {
			return "", fmt.Errorf("canonical path query returned 0 characters (API failure)")
		}

		// Win32 GetFinalPathNameByHandleW:
		// If ret < len(buf), the function succeeded and ret is the string length without null terminator.
		if ret < uint32(len(buf)) {
			rawPath := syscall.UTF16ToString(buf[:ret])
			return normalizeWindowsPath(rawPath), nil
		}

		// Buffer was insufficient. Win32 specifies ret is the required size including terminating null.
		if ret > maxFinalPathBufSize {
			return "", fmt.Errorf("required canonical path buffer size %d exceeds strict security limit %d", ret, maxFinalPathBufSize)
		}

		if ret <= uint32(bufSize) {
			return "", fmt.Errorf("insufficient buffer retry failed: requested size %d not greater than current %d", ret, bufSize)
		}

		bufSize = int(ret)
	}
}

// normalizeWindowsPath normalizes drive letters, UNC paths, and extended-length prefixes.
func normalizeWindowsPath(p string) string {
	p = strings.TrimSpace(p)

	// Strip Win32 extended-length prefixes:
	// 1. \\?\UNC\server\share -> \\server\share
	// 2. \\?\C:\path -> C:\path
	// 3. \??\C:\path -> C:\path (NT device namespace)
	if strings.HasPrefix(p, `\\?\UNC\`) {
		p = `\\` + strings.TrimPrefix(p, `\\?\UNC\`)
	} else if strings.HasPrefix(p, `\\?\`) {
		p = strings.TrimPrefix(p, `\\?\`)
	} else if strings.HasPrefix(p, `\??\`) {
		p = strings.TrimPrefix(p, `\??\`)
	}

	return filepath.Clean(p)
}

// openCookieFile opens the cookie file on Windows.
// It explicitly passes FILE_FLAG_OPEN_REPARSE_POINT to CreateFileW to prevent Windows
// from following any symbolic links or junctions before validation checks occur.
func openCookieFile(path string) (*os.File, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("invalid path string %q: %w", path, err)
	}

	// 1. Open with FILE_FLAG_OPEN_REPARSE_POINT:
	// Instructs Windows NOT to follow any symbolic link or junction for the terminal file.
	handle, err := syscall.CreateFile(
		pathPtr,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_OPEN_REPARSE_POINT|syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to open cookie file %q: %w", path, err)
	}

	// 2. Immediately inspect file information on the open handle to reject reparse points
	var fileInfo syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &fileInfo); err != nil {
		_ = syscall.CloseHandle(handle)
		return nil, fmt.Errorf("failed to query file information for %q: %w", path, err)
	}

	if fileInfo.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = syscall.CloseHandle(handle)
		return nil, fmt.Errorf("cookie file %q is a Windows reparse point (junction/symlink): rejected", path)
	}

	// 3. Fail-closed inspection of the final canonical path to ensure no parent directory was a junction or symlink
	cleanFinal, err := resolveFinalCanonicalPath(handle, defaultGetFinalPathNameCaller)
	if err != nil {
		_ = syscall.CloseHandle(handle)
		return nil, fmt.Errorf("cookie file %q path verification failed: %w", path, err)
	}

	absInput, err := filepath.Abs(path)
	if err != nil {
		_ = syscall.CloseHandle(handle)
		return nil, fmt.Errorf("failed to determine absolute path for %q: %w", path, err)
	}
	cleanInput := normalizeWindowsPath(absInput)

	if !strings.EqualFold(cleanFinal, cleanInput) {
		_ = syscall.CloseHandle(handle)
		return nil, fmt.Errorf("cookie file %q path traverses a symbolic link or junction (resolved to %q): rejected", path, cleanFinal)
	}

	// Wrap the validated non-reparse point Windows handle into an *os.File
	return os.NewFile(uintptr(handle), path), nil
}

// validateCookiePermissions validates file permissions, attributes, and ownership directly on the opened file handle.
func validateCookiePermissions(file *os.File, path string, info os.FileInfo) error {
	handle := syscall.Handle(file.Fd())

	// 1. Double-check file information by handle to reject reparse points
	var fileInfo syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &fileInfo); err != nil {
		return fmt.Errorf("failed to query file information for %q: %w", path, err)
	}

	if fileInfo.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("cookie file %q is a Windows reparse point (junction/symlink): rejected", path)
	}

	// 2. Validate Ownership using GetSecurityInfo directly on the open handle
	var pSidOwner uintptr
	var pSecDesc uintptr

	ret, _, callErr := procGetSecurityInfo.Call(
		uintptr(handle),
		uintptr(seFileObject),
		uintptr(ownerSecurityInformation),
		uintptr(unsafe.Pointer(&pSidOwner)),
		0, // ppsidGroup
		0, // ppDacl
		0, // ppSacl
		uintptr(unsafe.Pointer(&pSecDesc)),
	)

	if ret != 0 {
		return fmt.Errorf("failed to inspect Windows security descriptor for %q: error code %d (%v)", path, ret, callErr)
	}
	defer procLocalFree.Call(pSecDesc)

	if pSidOwner == 0 {
		return fmt.Errorf("cookie file %q has no owner SID", path)
	}

	res, _, _ := procIsValidSid.Call(pSidOwner)
	if res == 0 {
		return fmt.Errorf("cookie file %q has invalid owner SID", path)
	}

	// Compare with current user SID
	currUser, err := user.Current()
	if err == nil && currUser.Uid != "" {
		currUserSidPtr, err := syscall.UTF16PtrFromString(currUser.Uid)
		if err == nil {
			var pUserSid uintptr
			convRet, _, _ := procConvertStringSid.Call(
				uintptr(unsafe.Pointer(currUserSidPtr)),
				uintptr(unsafe.Pointer(&pUserSid)),
			)
			if convRet != 0 && pUserSid != 0 {
				defer procLocalFree.Call(pUserSid)

				eq, _, _ := procEqualSid.Call(pSidOwner, pUserSid)
				if eq != 0 {
					return nil
				}
			}
		}
	}

	// Check if owner is Builtin Administrators (S-1-5-32-544) or Local SYSTEM (S-1-5-18)
	trustedSids := []string{
		"S-1-5-32-544", // BUILTIN\Administrators
		"S-1-5-18",     // NT AUTHORITY\SYSTEM
	}

	for _, sidStr := range trustedSids {
		sidPtr, err := syscall.UTF16PtrFromString(sidStr)
		if err != nil {
			continue
		}
		var pTrustedSid uintptr
		convRet, _, _ := procConvertStringSid.Call(
			uintptr(unsafe.Pointer(sidPtr)),
			uintptr(unsafe.Pointer(&pTrustedSid)),
		)
		if convRet != 0 && pTrustedSid != 0 {
			defer procLocalFree.Call(pTrustedSid)
			eq, _, _ := procEqualSid.Call(pSidOwner, pTrustedSid)
			if eq != 0 {
				return nil
			}
		}
	}

	return fmt.Errorf("cookie file %q owner SID does not match current user, Administrators, or SYSTEM", path)
}

func validateUnixAncestorDirPlatform(fi os.FileInfo, path string) error {
	return nil
}

func isSystemSymlinkAllowed(fi os.FileInfo, path string) bool {
	return false
}

func validateUnixSocketPlatform(fi os.FileInfo, path string) error {
	return nil
}
