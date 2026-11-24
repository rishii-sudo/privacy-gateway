package tor

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rishii-sudo/privacy-gateway/internal/logging"
)

// SubscribeEvents registers a bounded listener channel for Tor async events.
// The listener is automatically closed and deregistered when the context expires.
func (c *Client) SubscribeEvents(ctx context.Context, eventTypes ...string) (<-chan Event, error) {
	if c.State() != StateAuthenticated {
		return nil, ErrInvalidState
	}

	queueLimit := c.cfg.Tor.EventQueueLimit
	if queueLimit <= 0 {
		queueLimit = 1000
	} else if queueLimit > 10000 {
		queueLimit = 10000
	}

	filterMap := make(map[string]bool)
	for _, et := range eventTypes {
		filterMap[strings.ToUpper(et)] = true
	}

	filteredCh := make(chan Event, queueLimit)
	rawCh := make(chan Event, queueLimit)

	c.subMu.Lock()
	c.subscribers[rawCh] = struct{}{}
	c.subMu.Unlock()

	// Goroutine to filter and deliver to caller
	go func() {
		defer func() {
			c.subMu.Lock()
			delete(c.subscribers, rawCh)
			c.subMu.Unlock()
			close(filteredCh)
		}()

		for {
			select {
			case <-ctx.Done():
				return
			case <-c.closeChan:
				return
			case evt, ok := <-rawCh:
				if !ok {
					return
				}
				// If filters defined, check match
				if len(filterMap) > 0 && !filterMap[evt.Type] {
					continue
				}
				select {
				case filteredCh <- evt:
				default:
					// Filtered channel buffer is full: drop event and transition monitoring state to DEGRADED
					c.monMu.Lock()
					c.droppedEvents++
					c.lastDropTime = time.Now().UTC()
					c.isDegraded = true
					c.degradedReason = fmt.Sprintf("subscriber filter queue overflow: %d events dropped due to buffer saturation", c.droppedEvents)
					c.monMu.Unlock()

					if c.logger != nil {
						c.logger.Warn(logging.CategoryTor, "EventDispatcher", "subscriber filter queue full: dropped event")
					}
				}
			}
		}
	}()

	return filteredCh, nil
}
