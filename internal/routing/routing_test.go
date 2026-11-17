package routing

import (
	"errors"
	"testing"
)

func TestUnimplementedRouter(t *testing.T) {
	r := &UnimplementedRouter{}
	if _, err := r.VerifyRouteChain(RouteChain{}); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got %v", err)
	}
	if _, err := r.GetExitNodeStatus(); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got %v", err)
	}
}
