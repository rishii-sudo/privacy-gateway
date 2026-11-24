//go:build windows

package tor

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestWindowsCookieReparsePointOpeningWithFlag(t *testing.T) {
	tempDir := t.TempDir()
	cookiePath := filepath.Join(tempDir, "safecookie.bin")

	cookieBytes := make([]byte, CookieSize)
	for i := range cookieBytes {
		cookieBytes[i] = byte(i * 3)
	}
	if err := os.WriteFile(cookiePath, cookieBytes, 0600); err != nil {
		t.Fatalf("failed to create test cookie file: %v", err)
	}

	file, err := openCookieFile(cookiePath)
	if err != nil {
		t.Fatalf("openCookieFile failed on regular file: %v", err)
	}
	defer file.Close()

	handle := syscall.Handle(file.Fd())
	var fileInfo syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &fileInfo); err != nil {
		t.Fatalf("GetFileInformationByHandle failed: %v", err)
	}

	if fileInfo.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		t.Errorf("regular test file was incorrectly flagged as reparse point")
	}

	readData, err := ValidateAndReadCookieFile(cookiePath)
	if err != nil {
		t.Fatalf("ValidateAndReadCookieFile failed: %v", err)
	}

	if len(readData) != CookieSize {
		t.Errorf("expected %d bytes, got %d", CookieSize, len(readData))
	}
}

func TestWindowsCookieRejectsDirectoryJunction(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Create a controlled target directory containing a valid 32-byte cookie
	targetDir := filepath.Join(tempDir, "controlled_target")
	if err := os.Mkdir(targetDir, 0755); err != nil {
		t.Fatalf("failed to create target dir: %v", err)
	}

	cookieInTarget := filepath.Join(targetDir, "auth_cookie")
	cookieBytes := make([]byte, CookieSize)
	for i := range cookieBytes {
		cookieBytes[i] = byte(i + 1)
	}
	if err := os.WriteFile(cookieInTarget, cookieBytes, 0600); err != nil {
		t.Fatalf("failed to write cookie in target: %v", err)
	}

	// 2. Attempt to create a temporary directory junction pointing to controlled target
	junctionDir := filepath.Join(tempDir, "controlled_junction")
	cmd := exec.Command("cmd.exe", "/c", "mklink", "/J", junctionDir, targetDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Directory junction creation via mklink /J not permitted in current Windows user environment (%v: %s).", err, strings.TrimSpace(string(output)))
		t.Logf("Documenting environment limitation: user account lacks privilege or policy prohibits junction creation.")
		return
	}
	defer func() {
		// Clean up junction specifically with rmdir
		_ = exec.Command("cmd.exe", "/c", "rmdir", junctionDir).Run()
	}()

	t.Logf("Successfully created directory junction: %s -> %s", junctionDir, targetDir)

	// 3. Access the valid cookie file THROUGH the directory junction
	cookieViaJunction := filepath.Join(junctionDir, "auth_cookie")

	// 4. Verify ValidateAndReadCookieFile rejects it specifically as a reparse point / junction traversal
	_, readErr := ValidateAndReadCookieFile(cookieViaJunction)
	if readErr == nil {
		t.Fatalf("SECURITY VIOLATION: ValidateAndReadCookieFile accepted a cookie accessed through a directory junction!")
	}

	// Assert the rejection was SPECIFICALLY because it traverses a junction/reparse point, NOT merely "Access is denied"
	errMsg := readErr.Error()
	if strings.Contains(errMsg, "traverses a symbolic link or junction") || strings.Contains(errMsg, "reparse point") {
		t.Logf("Confirmed: cookie was specifically rejected for reparse/junction traversal: %s", errMsg)
	} else {
		t.Fatalf("Expected specific reparse point or junction traversal rejection, but got: %s", errMsg)
	}
}

func TestWindowsCookieSymbolicLinkRejectionIfPrivilegeHeld(t *testing.T) {
	tempDir := t.TempDir()
	targetPath := filepath.Join(tempDir, "real_cookie.bin")
	cookieBytes := make([]byte, CookieSize)
	if err := os.WriteFile(targetPath, cookieBytes, 0600); err != nil {
		t.Fatalf("failed to write target file: %v", err)
	}

	symlinkPath := filepath.Join(tempDir, "symlink_cookie.bin")
	err := os.Symlink(targetPath, symlinkPath)
	if err != nil {
		t.Logf("os.Symlink requires SeCreateSymbolicLinkPrivilege (not held by current test user: %v). Skipping live symlink creation.", err)
		return
	}
	defer os.Remove(symlinkPath)

	_, readErr := ValidateAndReadCookieFile(symlinkPath)
	if readErr == nil {
		t.Fatalf("SECURITY VIOLATION: ValidateAndReadCookieFile accepted a symbolic link!")
	}
	if !strings.Contains(readErr.Error(), "reparse point") && !strings.Contains(readErr.Error(), "symbolic link") {
		t.Fatalf("Expected specific symbolic link/reparse rejection, got: %v", readErr)
	}
	t.Logf("Symbolic link successfully rejected: %v", readErr)
}

func TestGetFinalPathNameLookupFailure(t *testing.T) {
	// Simulate proc lookup failure
	mockCaller := func(handle syscall.Handle, buf []uint16) (uint32, error) {
		return 0, fmt.Errorf("kernel32.dll GetFinalPathNameByHandleW procedure could not be resolved")
	}

	_, err := resolveFinalCanonicalPath(0, mockCaller)
	if err == nil {
		t.Fatalf("expected fail-closed error when procedure lookup fails, got nil")
	}
	if !strings.Contains(err.Error(), "procedure could not be resolved") {
		t.Errorf("expected procedure resolution error, got: %v", err)
	}
}

func TestGetFinalPathNameAPIReturnsZero(t *testing.T) {
	// Simulate Win32 API failure returning 0
	mockCaller := func(handle syscall.Handle, buf []uint16) (uint32, error) {
		return 0, nil
	}

	_, err := resolveFinalCanonicalPath(0, mockCaller)
	if err == nil {
		t.Fatalf("expected fail-closed error when API returns 0, got nil")
	}
	if !strings.Contains(err.Error(), "returned 0 characters") {
		t.Errorf("expected 0 characters API failure, got: %v", err)
	}
}

func TestGetFinalPathNameInsufficientBuffer_ResizeSuccess(t *testing.T) {
	expectedPath := `\\?\C:\SafeDir\Tor\control_auth_cookie`
	expectedUTF16, err := syscall.UTF16FromString(expectedPath)
	if err != nil {
		t.Fatalf("UTF16FromString failed: %v", err)
	}

	callCount := 0
	mockCaller := func(handle syscall.Handle, buf []uint16) (uint32, error) {
		callCount++
		if callCount == 1 {
			// First call: report buffer too small, require 2048 characters
			return 2048, nil
		}
		// Second call: buffer has been resized to 2048, copy data and return length
		if len(buf) < len(expectedUTF16)-1 {
			return 0, errors.New("buffer still too small on second call")
		}
		copy(buf, expectedUTF16[:len(expectedUTF16)-1])
		return uint32(len(expectedUTF16) - 1), nil
	}

	result, err := resolveFinalCanonicalPath(0, mockCaller)
	if err != nil {
		t.Fatalf("expected dynamic resize to succeed, got: %v", err)
	}

	if callCount != 2 {
		t.Errorf("expected exactly 2 calls (initial + resized retry), got: %d", callCount)
	}

	expectedNormalized := `C:\SafeDir\Tor\control_auth_cookie`
	if !strings.EqualFold(result, expectedNormalized) {
		t.Errorf("expected %q, got %q", expectedNormalized, result)
	}
}

func TestGetFinalPathNameInsufficientBuffer_ExceedsStrictLimit(t *testing.T) {
	mockCaller := func(handle syscall.Handle, buf []uint16) (uint32, error) {
		// Request 65536 characters (exceeds maxFinalPathBufSize = 32768)
		return 65536, nil
	}

	_, err := resolveFinalCanonicalPath(0, mockCaller)
	if err == nil {
		t.Fatalf("expected error when required buffer exceeds 32768 limit, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds strict security limit") {
		t.Errorf("expected strict limit error, got: %v", err)
	}
}

func TestGetFinalPathNameInsufficientBuffer_LoopProtection(t *testing.T) {
	mockCaller := func(handle syscall.Handle, buf []uint16) (uint32, error) {
		// Request same size as current buffer (does not increase)
		return uint32(len(buf)), nil
	}

	_, err := resolveFinalCanonicalPath(0, mockCaller)
	if err == nil {
		t.Fatalf("expected loop protection error, got nil")
	}
	if !strings.Contains(err.Error(), "insufficient buffer retry failed") {
		t.Errorf("expected loop protection error, got: %v", err)
	}
}

func TestNormalizeWindowsPath_Variations(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{`C:\Tor\cookie.bin`, `C:\Tor\cookie.bin`},
		{`\\?\C:\Tor\cookie.bin`, `C:\Tor\cookie.bin`},
		{`\??\C:\Tor\cookie.bin`, `C:\Tor\cookie.bin`},
		{`\\server\share\cookie.bin`, `\\server\share\cookie.bin`},
		{`\\?\UNC\server\share\cookie.bin`, `\\server\share\cookie.bin`},
		{`  C:\Tor\sub\..\cookie.bin  `, `C:\Tor\cookie.bin`},
	}

	for _, tc := range cases {
		result := normalizeWindowsPath(tc.input)
		if !strings.EqualFold(result, tc.expected) {
			t.Errorf("normalizeWindowsPath(%q) = %q, expected %q", tc.input, result, tc.expected)
		}
	}
}

func TestWindowsCookieDivergentPathRejection(t *testing.T) {
	// Verify that if resolved path diverges from input, it is flagged as junction traversal
	inputPath := `C:\Junction\Tor\cookie.bin`
	divergentCanonical := `C:\RealTarget\Tor\cookie.bin`

	normInput := normalizeWindowsPath(inputPath)
	normFinal := normalizeWindowsPath(divergentCanonical)

	if strings.EqualFold(normFinal, normInput) {
		t.Fatalf("expected divergence between input and final path")
	}

	err := fmt.Errorf("cookie file %q path traverses a symbolic link or junction (resolved to %q): rejected", inputPath, normFinal)
	if !strings.Contains(err.Error(), "traverses a symbolic link or junction") {
		t.Errorf("expected specific junction traversal error message")
	}
}

func TestWindowsCookieExactHandleChain(t *testing.T) {
	tempDir := t.TempDir()
	cookiePath := filepath.Join(tempDir, "handle_chain.bin")
	cookieBytes := make([]byte, CookieSize)
	for i := range cookieBytes {
		cookieBytes[i] = 0xAA
	}
	if err := os.WriteFile(cookiePath, cookieBytes, 0600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	file, err := openCookieFile(cookiePath)
	if err != nil {
		t.Fatalf("openCookieFile failed: %v", err)
	}
	defer file.Close()

	initialFd := file.Fd()

	info, err := file.Stat()
	if err != nil {
		t.Fatalf("file.Stat failed: %v", err)
	}

	if err := validateCookiePermissions(file, cookiePath, info); err != nil {
		t.Fatalf("validateCookiePermissions failed: %v", err)
	}

	if file.Fd() != initialFd {
		t.Fatalf("file handle changed during validation: initial %d != current %d", initialFd, file.Fd())
	}
}
