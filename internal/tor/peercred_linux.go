//go:build linux

package tor

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

// verifyUnixPeer inspects the peer process credentials on Linux via SO_PEERCRED.
// This mitigates residual TOCTOU races between pre-dial Lstat validation and connect().
func verifyUnixPeer(conn net.Conn) (PeerVerificationStatus, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return PeerVerificationUnsupported, nil
	}
	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return PeerVerificationFailed, fmt.Errorf("failed to obtain raw connection for peer verification: %w", err)
	}
	var peerErr error
	ctrlErr := rawConn.Control(func(fd uintptr) {
		ucred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			peerErr = fmt.Errorf("security violation: failed to retrieve SO_PEERCRED on unix control socket: %w", err)
			return
		}
		currentUID := uint32(os.Getuid())
		if !isTrustedTorUID(ucred.Uid, currentUID) {
			peerErr = fmt.Errorf("security violation: unix control peer process owned by untrusted UID %d (pid %d)", ucred.Uid, ucred.Pid)
		}
	})
	if ctrlErr != nil {
		return PeerVerificationFailed, fmt.Errorf("failed to check peer credentials: %w", ctrlErr)
	}
	if peerErr != nil {
		return PeerVerificationFailed, peerErr
	}
	return PeerVerificationVerified, nil
}
