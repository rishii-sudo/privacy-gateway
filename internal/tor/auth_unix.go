//go:build !windows

package tor

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// openCookieFile opens the cookie file on Unix with O_NOFOLLOW to prevent following symlinks.
func openCookieFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}

// validateCookiePermissions validates file permissions, attributes, and ownership directly on the opened file.
func validateCookiePermissions(file *os.File, path string, info os.FileInfo) error {
	perm := info.Mode().Perm()

	// 1. Tor Control Port spec / security rules:
	// Cookie file must NOT have world access (r/w/x)
	if perm&0007 != 0 {
		return fmt.Errorf("insecure cookie file permissions %04o: world access is strictly prohibited", perm)
	}

	// Cookie file must NOT have group write access
	if perm&0020 != 0 {
		return fmt.Errorf("insecure cookie file permissions %04o: group write access is prohibited", perm)
	}

	// Cookie file must NOT have group execute access
	if perm&0010 != 0 {
		return fmt.Errorf("insecure cookie file permissions %04o: group execute access is prohibited", perm)
	}

	// 2. Ownership validation directly on open file descriptor
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("unable to retrieve Unix file stat for cookie file %q", path)
	}

	currentUID := uint32(os.Getuid())

	// UID must ONLY be compared with valid owner UIDs (never supplementary GIDs)
	if !isTrustedTorUID(stat.Uid, currentUID) {
		return fmt.Errorf("cookie file %q ownership violation: owned by unauthorized UID %d (current UID: %d)", path, stat.Uid, currentUID)
	}

	// 3. Evaluate group-read permission:
	// If current user is not the owner (relying on group access to read a daemon-owned cookie),
	// the file MUST have group-read permission (0040) AND the running user must belong to stat.Gid.
	hasGroupRead := perm&0040 != 0
	if stat.Uid != currentUID {
		if !hasGroupRead {
			return fmt.Errorf("cookie file %q owned by UID %d does not have group-read permission (mode: %04o)", path, stat.Uid, perm)
		}
	}

	if hasGroupRead {
		currentGID := uint32(os.Getgid())
		isUserInGroup := (stat.Gid == currentGID)

		if !isUserInGroup {
			userGids, err := os.Getgroups()
			if err == nil {
				for _, gid := range userGids {
					if uint32(gid) == stat.Gid {
						isUserInGroup = true
						break
					}
				}
			}
		}

		if !isUserInGroup {
			return fmt.Errorf("cookie file %q has group-read permission (%04o) for GID %d, but running user (GID %d) is not a member of that group", path, perm, stat.Gid, currentGID)
		}
	}

	return nil
}

// isTrustedTorUID checks if a UID matches the current process UID, root (0), or a recognized system Tor account.
func isTrustedTorUID(uid uint32, currentUID uint32) bool {
	if uid == currentUID || uid == 0 {
		return true
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return false
	}
	validTorUsers := map[string]bool{
		"debian-tor": true,
		"tor":        true,
		"_tor":       true,
		"torproject": true,
	}
	return validTorUsers[u.Username]
}

// validateUnixAncestorDirPlatform validates ancestor directory ownership on Unix systems.
func validateUnixAncestorDirPlatform(fi os.FileInfo, path string) error {
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	currentUID := uint32(os.Getuid())
	if !isTrustedTorUID(stat.Uid, currentUID) {
		return fmt.Errorf("security violation: unix control socket ancestor directory %q owned by untrusted UID %d", path, stat.Uid)
	}
	return nil
}

// isSystemSymlinkAllowed checks if a symlink in an ancestor directory is an approved
// OS-level distribution symlink (specifically /var/run -> /run or /var/lock -> /run/lock on Linux).
func isSystemSymlinkAllowed(fi os.FileInfo, path string) bool {
	clean := filepath.Clean(path)
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	// The symlink itself must be owned by root (UID 0)
	if stat.Uid != 0 {
		return false
	}

	// Read raw link destination
	target, err := os.Readlink(clean)
	if err != nil {
		return false
	}
	targetClean := filepath.Clean(target)

	// Validate target against exact expected destination per path
	switch clean {
	case "/var/run":
		// Must point specifically to /run or relative ../run
		if targetClean != "/run" && targetClean != "../run" {
			return false
		}
	case "/var/lock":
		// Must point specifically to /run/lock or relative ../run/lock
		if targetClean != "/run/lock" && targetClean != "../run/lock" {
			return false
		}
	default:
		return false
	}

	// Verify the resolved destination exists, is a directory, and is owned by root (UID 0)
	destFi, err := os.Stat(clean)
	if err != nil || !destFi.IsDir() {
		return false
	}
	destStat, ok := destFi.Sys().(*syscall.Stat_t)
	if !ok || destStat.Uid != 0 {
		return false
	}

	return true
}

// validateUnixSocketPlatform validates socket ownership on Unix systems.
func validateUnixSocketPlatform(fi os.FileInfo, path string) error {
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	currentUID := uint32(os.Getuid())
	if !isTrustedTorUID(stat.Uid, currentUID) {
		return fmt.Errorf("security violation: unix control socket %q owned by untrusted UID %d", path, stat.Uid)
	}
	return nil
}
