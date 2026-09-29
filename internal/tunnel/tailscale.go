package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"tailscale.com/tsnet"
)

// Tailscale joins the tailnet as its own device, inside this process.
// tsnet runs its own network stack in software: no VPN interface on the
// machine, no routes, and nothing else on the machine becomes reachable.
// The only thing this device answers is the HTTPS listener serve opens.
//
// It joins once, with a single-use auth key for tag:flow-remote (tagged
// devices don't expire); after that its identity lives in Dir, and the
// key isn't needed or kept.
type Tailscale struct {
	Dir      string // tsnet's state, 0700; this is the device's identity
	Hostname string
	AuthKey  string // only for the first join
	// Logf gets messages meant for a person, such as a login problem.
	Logf func(format string, args ...any)

	srv *tsnet.Server
}

// Joined reports whether dir holds a device that already joined, so a
// run under launchd can refuse to start instead of waiting for a login
// nobody will do.
func Joined(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "tailscaled.state"))
	return err == nil
}

var notHost = regexp.MustCompile(`[^a-z0-9-]+`)

// Hostname turns a Mac's name into a tailnet device name like
// "flow-remote-my-mac". It becomes part of the app's address, which the
// phone's storage is tied to, so it's chosen once at setup.
func Hostname(name string) string {
	h := strings.Trim(notHost.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if h == "" {
		return "flow-remote"
	}
	h = "flow-remote-" + h
	if len(h) > 63 {
		h = strings.TrimRight(h[:63], "-")
	}
	return h
}

func (t *Tailscale) start(ctx context.Context) (*tsnet.Server, []string, error) {
	if err := os.MkdirAll(t.Dir, 0o700); err != nil {
		return nil, nil, err
	}
	if err := os.Chmod(t.Dir, 0o700); err != nil {
		return nil, nil, err
	}
	if t.AuthKey == "" && !Joined(t.Dir) {
		return nil, nil, errors.New("this machine hasn't joined the tailnet yet; run `flow-remote setup --tunnel tailscale`")
	}
	logf := t.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	s := &tsnet.Server{
		Dir: t.Dir, Hostname: t.Hostname, AuthKey: t.AuthKey,
		UserLogf: logf,
		Logf:     func(string, ...any) {}, // the backend's debug logging
	}
	upCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if _, err := s.Up(upCtx); err != nil {
		s.Close()
		if upCtx.Err() != nil && ctx.Err() == nil {
			return nil, nil, errors.New("couldn't join the tailnet within 2 minutes; check the auth key (single-use, not expired, tagged tag:flow-remote) and that this machine is online")
		}
		return nil, nil, err
	}
	domains := s.CertDomains()
	if len(domains) == 0 {
		s.Close()
		return nil, nil, errors.New("the tailnet has no HTTPS certificates; turn on MagicDNS and HTTPS Certificates in the Tailscale admin console (DNS page)")
	}
	return s, domains, nil
}

func (t *Tailscale) Listen(ctx context.Context) (net.Listener, string, error) {
	s, domains, err := t.start(ctx)
	if err != nil {
		return nil, "", err
	}
	ln, err := s.ListenTLS("tcp", ":443")
	if err != nil {
		s.Close()
		return nil, "", err
	}
	t.srv = s
	return ln, "https://" + domains[0], nil
}

func (t *Tailscale) Close() error {
	if t.srv == nil {
		return nil
	}
	return t.srv.Close()
}

// Join brings the device onto the tailnet with t.AuthKey, fetches its
// HTTPS certificate once so the first page load isn't slow, and stops.
// It returns the URL phones will use.
func (t *Tailscale) Join(ctx context.Context) (string, error) {
	s, domains, err := t.start(ctx)
	if err != nil {
		return "", err
	}
	defer s.Close()
	lc, err := s.LocalClient()
	if err != nil {
		return "", err
	}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if _, _, err := lc.CertPair(cctx, domains[0]); err != nil {
		return "", fmt.Errorf("joined, but getting the HTTPS certificate failed: %w", err)
	}
	return "https://" + domains[0], nil
}
