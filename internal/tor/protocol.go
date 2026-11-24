package tor

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	// MaxLineLength is the maximum accepted length of a single response line (64 KB).
	MaxLineLength = 65536

	// MaxResponseLines is the maximum number of lines permitted in a multi-line response.
	MaxResponseLines = 2048

	// MaxAggregateResponseBytes is the maximum aggregate bytes permitted across all lines of a response (1 MB).
	MaxAggregateResponseBytes = 1048576
)

// readSingleLineResponse reads one CRLF-terminated line from the connection.
func readSingleLineResponse(conn net.Conn, timeout time.Duration) (string, error) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}
	defer func() {
		_ = conn.SetDeadline(time.Time{})
	}()

	reader := bufio.NewReaderSize(conn, MaxLineLength)
	line, err := readBoundedLine(reader, MaxLineLength)
	if err != nil {
		return "", err
	}
	return line, nil
}

// readMultilineResponse reads a multi-line reply until the final "250 " or "5xx " line.
func readMultilineResponse(conn net.Conn, timeout time.Duration) ([]string, error) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	defer func() {
		_ = conn.SetDeadline(time.Time{})
	}()

	reader := bufio.NewReaderSize(conn, MaxLineLength)
	var lines []string
	totalBytes := 0

	for {
		line, err := readBoundedLine(reader, MaxLineLength)
		if err != nil {
			return lines, err
		}

		totalBytes += len(line)
		if totalBytes > MaxAggregateResponseBytes {
			return nil, fmt.Errorf("%w: aggregate response size %d bytes exceeds maximum limit of %d bytes", ErrProtocolViolation, totalBytes, MaxAggregateResponseBytes)
		}

		if len(lines) >= MaxResponseLines {
			return nil, fmt.Errorf("%w: response exceeds maximum permitted line count of %d", ErrProtocolViolation, MaxResponseLines)
		}

		lines = append(lines, line)

		// End of reply condition:
		// Line starts with 3 digits followed by a space, e.g. "250 OK" or "515 Error"
		// If line starts with "250-" or "250+", more lines follow.
		if len(line) >= 4 && (line[3] == ' ') {
			break
		}
	}

	return lines, nil
}

// readBoundedLine reads bytes until \n or until maxLen is reached.
func readBoundedLine(reader *bufio.Reader, maxLen int) (string, error) {
	var buf strings.Builder
	for {
		b, err := reader.ReadByte()
		if err != nil {
			if buf.Len() > 0 && err == io.EOF {
				return buf.String(), nil
			}
			return "", err
		}

		if b == '\n' {
			res := strings.TrimRight(buf.String(), "\r")
			return res, nil
		}

		if buf.Len() >= maxLen {
			return "", fmt.Errorf("%w: line exceeds maximum permitted length of %d bytes", ErrProtocolViolation, maxLen)
		}

		buf.WriteByte(b)
	}
}

// isAsyncEventLine returns true if the line starts with an asynchronous 650 code.
func isAsyncEventLine(line string) bool {
	return strings.HasPrefix(line, "650 ") || strings.HasPrefix(line, "650-") || strings.HasPrefix(line, "650+")
}
