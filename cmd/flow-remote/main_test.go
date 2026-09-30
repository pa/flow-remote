package main

import (
	"strings"
	"testing"
	"time"

	"github.com/pa/flow-remote/internal/client"
	"github.com/pa/flow-remote/internal/identity"
)

func TestDeviceState(t *testing.T) {
	now := time.Now()
	seen := map[string]client.DeviceStatus{
		"seen":    {ID: "seen", LastSeen: &now},
		"never":   {ID: "never"},
		"expired": {ID: "expired", LastSeen: &now, Expired: true},
	}
	for _, tc := range []struct {
		dev         identity.Device
		last, state string
	}{
		{identity.Device{ID: "seen"}, "last seen just now", "active"},
		{identity.Device{ID: "never"}, "never seen", "active"},
		{identity.Device{ID: "expired"}, "last seen just now", "expired (unused 90+ days; pair again)"},
		{identity.Device{ID: "offline"}, "last seen unknown", "active"},
		{identity.Device{ID: "seen", RevokedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}, "", "revoked 2026-09-01"},
	} {
		last, state := deviceState(tc.dev, seen, 90)
		if !strings.HasPrefix(last, tc.last) || state != tc.state {
			t.Errorf("%s: got %q, %q; want %q, %q", tc.dev.ID, last, state, tc.last, tc.state)
		}
	}
}
