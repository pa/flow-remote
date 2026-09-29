// Package serve runs flow-remote on the machine where flow runs: the
// mailbox phones reach through a tunnel, and the relay that hands their
// messages to flow sessions, in one process.
//
//	phones ──tunnel──► public listener: the app, and the phone routes only
//	relay, CLI ──────► unix socket (0600): every route, signed by this Mac
//
// The relay talks to the mailbox over the socket with the same signed API
// it uses for a hosted mailbox, so internal/relay doesn't know which mode
// it's in.
package serve

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pa/flow-remote/internal/client"
	"github.com/pa/flow-remote/internal/identity"
	"github.com/pa/flow-remote/internal/mailbox"
	"github.com/pa/flow-remote/internal/relay"
	"github.com/pa/flow-remote/internal/tunnel"
	"github.com/pa/flow-remote/internal/webapp"
	"github.com/pa/flow-remote/web"
)

type Options struct {
	Home  string // holds mailbox.db and mailbox.sock
	Mac   *identity.Mac
	Relay *relay.Relay // Run sets its Mailbox
	// Tunnel is how phones reach this machine.
	Tunnel tunnel.Tunnel
	// Origins are other app addresses allowed to call the API, such as the
	// app installed from another of your machines.
	Origins    []string
	DeviceIdle time.Duration
	Log        *slog.Logger
	// Listening, if set, is called with the public URL once phones can
	// connect and the relay is starting.
	Listening func(url string)
}

func SocketPath(home string) string { return filepath.Join(home, "mailbox.sock") }

// Client reaches the running serve's mailbox, signing as mac. The host in
// the URL is ignored: every request goes to the socket.
func Client(home string, mac *identity.Mac) *client.Client {
	return &client.Client{BaseURL: "http://flow-remote", Mac: mac, HTTP: client.Unix(SocketPath(home))}
}

// ErrNotRunning means nothing is listening on the socket.
var ErrNotRunning = errors.New("flow-remote isn't running here; start it with `flow-remote start`")

// NotRunning reports whether err came from dialing a socket nobody listens on.
func NotRunning(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "dial"
}

func Run(ctx context.Context, o Options) error {
	if err := os.MkdirAll(o.Home, 0o700); err != nil {
		return err
	}
	db, err := mailbox.OpenBolt(filepath.Join(o.Home, "mailbox.db"), time.Second)
	if err != nil {
		return fmt.Errorf("opening the mailbox database (is flow-remote already running?): %w", err)
	}
	defer db.Close()

	// This machine is the only tenant, registered directly: no setup
	// token, no invites.
	err = db.RegisterMac(ctx, mailbox.Mac{ID: o.Mac.ID, SignPub: o.Mac.SignPub(), Admin: true, Created: time.Now()})
	if errors.Is(err, mailbox.ErrConflict) {
		return errors.New("mailbox.db belongs to a different identity for this computer; move it aside to start fresh")
	}
	if err != nil && !errors.Is(err, mailbox.ErrExists) {
		return err
	}
	// The Keychain's device list is the source of truth; bring the store
	// in line before loading keys, in case an enrollment or revocation
	// happened while this wasn't running.
	for _, d := range o.Relay.Devices.List() {
		if d.Revoked() {
			err = db.RevokeDevice(ctx, o.Mac.ID, d.ID)
			if errors.Is(err, mailbox.ErrNotFound) {
				err = nil
			}
		} else {
			err = db.PutDevice(ctx, o.Mac.ID, d.ID, d.SignPub)
		}
		if err != nil && o.Log != nil {
			o.Log.Warn("device sync", "device", d.ID, "err", err)
		}
	}

	wake := make(chan struct{}, 1)
	srv := &mailbox.Server{
		Store: db, DeviceIdle: o.DeviceIdle, Log: o.Log,
		Proxies: []*net.IPNet{}, // nothing in front is trusted; forwarded headers are dropped below
		Notify: func(to string) {
			if to == o.Mac.ID {
				select {
				case wake <- struct{}{}:
				default:
				}
			}
		},
	}
	if err := srv.Warm(ctx); err != nil {
		return err
	}

	sock := SocketPath(o.Home)
	os.Remove(sock) // left by a crash; the database lock says no other serve is running
	sl, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	if err := os.Chmod(sock, 0o600); err != nil {
		sl.Close()
		return err
	}
	defer os.Remove(sock)
	pl, publicURL, err := o.Tunnel.Listen(ctx)
	if err != nil {
		sl.Close()
		return fmt.Errorf("starting the tunnel: %w", err)
	}
	if c, ok := o.Tunnel.(io.Closer); ok {
		defer c.Close() // after the servers stop, below
	}

	public := newServer(cors(dropForwarded(webapp.Handler(srv.PublicHandler(), web.Files)), allowedOrigins(publicURL, o.Origins)))
	local := newServer(srv.Handler())
	errc := make(chan error, 3)
	go func() { errc <- public.Serve(pl) }()
	go func() { errc <- local.Serve(sl) }()

	o.Relay.Mailbox = Client(o.Home, o.Mac)
	if o.Listening != nil {
		o.Listening(publicURL)
	}
	go func() { errc <- o.Relay.Loop(ctx, wake) }()

	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-errc:
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	public.Shutdown(sctx)
	local.Shutdown(sctx)
	return err
}

// Timeouts so slow clients can't hold connections open.
func newServer(h http.Handler) *http.Server {
	return &http.Server{Handler: h,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute}
}

// dropForwarded removes X-Forwarded-For. Phones connect to this process
// directly (or through a tunnel that isn't trusted), so the header is
// whatever the client chose, and honouring it would let one client dodge
// the per-address limit.
func dropForwarded(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Del("X-Forwarded-For")
		h.ServeHTTP(w, r)
	})
}

func origin(u string) string {
	p, err := url.Parse(u)
	if err != nil || p.Scheme == "" || p.Host == "" {
		return ""
	}
	return strings.ToLower(p.Scheme + "://" + p.Host)
}

// allowedOrigins is every extra app address, minus this server's own:
// the same origin needs no CORS.
func allowedOrigins(self string, extra []string) map[string]bool {
	out := map[string]bool{}
	for _, u := range extra {
		if o := origin(u); o != "" && o != origin(self) {
			out[o] = true
		}
	}
	return out
}

// cors lets an app served from another of your machines call this one's
// API. Signatures, not the origin, are what authenticate a request; this
// only stops the browser from blocking the call.
func cors(h http.Handler, allowed map[string]bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o := r.Header.Get("Origin")
		if o != "" && allowed[strings.ToLower(o)] && strings.HasPrefix(r.URL.Path, "/v1/") {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Add("Vary", "Origin")
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-FR-Key, X-FR-TS, X-FR-Sig")
				w.Header().Set("Access-Control-Max-Age", "600")
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}
