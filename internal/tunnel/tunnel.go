// Package tunnel is how phones reach `flow-remote serve`. A tunnel only
// carries bytes: pairing, signed requests and sealed envelopes keep it
// from reading or changing messages, so every kind is treated as
// untrusted.
package tunnel

import (
	"context"
	"net"
	"strings"
)

type Tunnel interface {
	// Listen returns where phones' requests arrive and the URL they use.
	Listen(ctx context.Context) (net.Listener, string, error)
}

// Local listens on a plain TCP address. It's for tests and for a machine
// that's reached some other way the user sets up; URL is what phones use.
// Empty URL means http://<the address it got>.
type Local struct {
	Addr string
	URL  string
}

func (l Local) Listen(context.Context) (net.Listener, string, error) {
	ln, err := net.Listen("tcp", l.Addr)
	if err != nil {
		return nil, "", err
	}
	url := strings.TrimRight(l.URL, "/")
	if url == "" {
		url = "http://" + ln.Addr().String()
	}
	return ln, url, nil
}
