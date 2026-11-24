//go:build !linux

package tor

import "net"

// verifyUnixPeer is invoked on non-Linux platforms (Windows, Darwin, FreeBSD) where
// standard POSIX SO_PEERCRED is unsupported. It explicitly returns PeerVerificationUnsupported
// so unsupported operating systems never silently claim equivalent verification.
func verifyUnixPeer(conn net.Conn) (PeerVerificationStatus, error) {
	return PeerVerificationUnsupported, nil
}
