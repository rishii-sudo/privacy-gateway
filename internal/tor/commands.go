package tor

import (
	"context"
	"fmt"
	"strings"
)

// GetVersion queries GETINFO version and returns the running Tor version.
func (c *Client) GetVersion(ctx context.Context) (string, error) {
	lines, err := c.SendCommand(ctx, "GETINFO version")
	if err != nil {
		return "", err
	}

	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "250-version=") || strings.HasPrefix(trimmed, "250 version=") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				return parts[1], nil
			}
		}
	}

	return "", fmt.Errorf("%w: missing version in GETINFO reply", ErrProtocolViolation)
}

// GetBootstrapStatus queries GETINFO status/bootstrap-phase and parses progress.
func (c *Client) GetBootstrapStatus(ctx context.Context) (*BootstrapStatus, error) {
	lines, err := c.SendCommand(ctx, "GETINFO status/bootstrap-phase")
	if err != nil {
		return nil, err
	}

	payload := strings.Join(lines, "\n")
	return c.inspector.ParseBootstrap(payload)
}

// GetCircuitEstablished queries GETINFO status/circuit-established.
func (c *Client) GetCircuitEstablished(ctx context.Context) (bool, error) {
	lines, err := c.SendCommand(ctx, "GETINFO status/circuit-established")
	if err != nil {
		return false, err
	}

	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.Contains(trimmed, "circuit-established=1") {
			return true, nil
		}
		if strings.Contains(trimmed, "circuit-established=0") {
			return false, nil
		}
	}

	return false, nil
}

// GetActiveCircuits queries GETINFO circuit-status and parses active circuits.
func (c *Client) GetActiveCircuits(ctx context.Context) ([]Circuit, error) {
	lines, err := c.SendCommand(ctx, "GETINFO circuit-status")
	if err != nil {
		return nil, err
	}

	payload := strings.Join(lines, "\n")
	return c.inspector.ParseCircuits(payload)
}

// GetSocksListeners queries GETINFO net/listeners/socks.
func (c *Client) GetSocksListeners(ctx context.Context) ([]string, error) {
	lines, err := c.SendCommand(ctx, "GETINFO net/listeners/socks")
	if err != nil {
		return nil, err
	}

	var listeners []string
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "250-net/listeners/socks=") || strings.HasPrefix(trimmed, "250 net/listeners/socks=") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				raw := strings.Trim(parts[1], "\"")
				for _, addr := range strings.Fields(raw) {
					listeners = append(listeners, strings.Trim(addr, "\""))
				}
			}
		}
	}
	return listeners, nil
}

// SetEvents configures asynchronous event subscriptions on the Tor daemon.
func (c *Client) SetEvents(ctx context.Context, events ...string) error {
	if len(events) == 0 {
		events = []string{"STATUS_CLIENT", "CIRC", "STREAM"}
	}

	cmd := fmt.Sprintf("SETEVENTS %s", strings.Join(events, " "))
	lines, err := c.SendCommand(ctx, cmd)
	if err != nil {
		return err
	}

	if len(lines) == 0 || !strings.HasPrefix(lines[0], "250") {
		return fmt.Errorf("%w: SETEVENTS rejected: %v", ErrProtocolViolation, lines)
	}

	return nil
}
