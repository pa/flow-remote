package mailbox

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pa/flow-remote/internal/envelope"
	"github.com/pa/flow-remote/internal/reqsig"
)

const (
	maxBody = 64 << 10

	// The relay polls fast only while one of its phones is in use.
	PollActive   = 3 * time.Second
	PollIdle     = 60 * time.Second
	ActiveWindow = 10 * time.Minute

	phonePerHour = 30  // from the plan's threat model
	relayPerHour = 600 // caps a runaway session, well above normal use

	// Expired data is deleted in passing, at most this often. Relays call
	// in at least once a minute, so no scheduled job is needed.
	cleanupEvery = time.Hour

	HeaderSetup  = "X-FR-Setup"
	HeaderInvite = "X-FR-Invite"
)

// Server is the mailbox API. Nobody signs in: a Mac signs requests with
// its key and a phone with its device key, and the mailbox only knows the
// public halves.
//
// Each Mac is a tenant. The first Mac registers with the setup token and
// becomes an admin; others join with single-use invites that an admin
// creates. A phone belongs to the Mac that enrolled it: it can only send to
// that Mac and read its own queue, and a Mac can only manage, message or
// pair its own phones.
type Server struct {
	Store Store
	// SetupToken registers the first (admin) Mac. Clear it once that's
	// done; invites cover every Mac after that. Empty disables it.
	SetupToken string
	// DeviceIdle expires a phone key unused for this long; 0 never does.
	// Like Remote Control's trusted devices and Tailscale's node keys, a
	// forgotten phone then stops working on its own.
	DeviceIdle time.Duration
	// Ready, if set, gates the API: until it returns nil every call gets
	// 503, and /v1/health says why.
	Ready func() error
	Now   func() time.Time
	Log   *slog.Logger

	limits      limiter
	cleanupMu   sync.Mutex
	lastCleanup time.Time
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Not /healthz: Google's front end reserves paths like it, so on Cloud
	// Run the request never reaches the container.
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, _ *http.Request) {
		if err := s.ready(); err != nil {
			s.fail(w, http.StatusServiceUnavailable, "store not ready: "+err.Error())
			return
		}
		w.Write([]byte("ok"))
	})

	mux.HandleFunc("POST /v1/macs", s.registerMac)

	// Phone. Pairing is the one unsigned call: the device key isn't
	// registered yet, and the slot must have been opened by that Mac.
	mux.HandleFunc("POST /v1/pair/{pair}", s.postPair)
	mux.HandleFunc("POST /v1/envelopes", s.device(s.phonePost))
	mux.HandleFunc("GET /v1/envelopes", s.device(s.phoneList))
	mux.HandleFunc("POST /v1/ack", s.device(s.phoneAck))
	mux.HandleFunc("GET /v1/status", s.device(s.status))

	// Relay.
	mux.HandleFunc("POST /v1/relay/pairs", s.mac(s.openPair))
	mux.HandleFunc("GET /v1/relay/pairs/{pair}", s.mac(s.takePair))
	mux.HandleFunc("POST /v1/relay/devices", s.mac(s.putDevice))
	mux.HandleFunc("POST /v1/relay/devices/{id}/revoke", s.mac(s.revokeDevice))
	mux.HandleFunc("GET /v1/relay/devices", s.mac(s.listDevices))
	mux.HandleFunc("GET /v1/relay/envelopes", s.mac(s.relayList))
	mux.HandleFunc("POST /v1/relay/envelopes", s.mac(s.relayPost))
	mux.HandleFunc("POST /v1/relay/ack", s.mac(s.relayAck))

	// Admin Macs only.
	mux.HandleFunc("POST /v1/relay/invites", s.admin(s.createInvite))
	mux.HandleFunc("GET /v1/relay/tenants", s.admin(s.listTenants))
	mux.HandleFunc("POST /v1/relay/tenants/{id}/remove", s.admin(s.removeTenant))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/health" && s.ready() != nil {
			s.fail(w, http.StatusServiceUnavailable, "the mailbox is starting; try again shortly")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) ready() error {
	if s.Ready == nil {
		return nil
	}
	return s.Ready()
}

// ---- auth ----

// caller is who signed the request. For a device, Mac is its owner.
type caller struct {
	ID    string
	Mac   string
	Admin bool
}

type handler func(http.ResponseWriter, *http.Request, caller)

func (s *Server) device(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		var dev Device
		id, err := reqsig.Verify(r, func(id string) (*ecdsa.PublicKey, error) {
			if !strings.HasPrefix(id, "dev-") {
				return nil, reqsig.ErrUnsigned
			}
			d, err := s.Store.GetDevice(r.Context(), id)
			if err != nil {
				return nil, err
			}
			dev = d
			return envelope.ParseSignPub(d.SignPub)
		}, s.now())
		if err != nil {
			s.fail(w, http.StatusUnauthorized, "unsigned, or signed by an unknown or revoked device")
			return
		}
		if s.expired(r.Context(), id) {
			s.fail(w, http.StatusUnauthorized, "this device's key expired after going unused; pair again")
			return
		}
		s.Store.Touch(r.Context(), "dev:"+id, s.now())
		s.Store.Touch(r.Context(), "phone:"+dev.Owner, s.now())
		s.maybeCleanup(r.Context())
		h(w, r, caller{ID: id, Mac: dev.Owner})
	}
}

func (s *Server) mac(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		var mac Mac
		id, err := reqsig.Verify(r, func(id string) (*ecdsa.PublicKey, error) {
			if !strings.HasPrefix(id, "mac-") {
				return nil, reqsig.ErrUnsigned
			}
			m, err := s.Store.GetMac(r.Context(), id)
			if err != nil {
				return nil, err
			}
			mac = m
			return envelope.ParseSignPub(m.SignPub)
		}, s.now())
		if err != nil {
			s.fail(w, http.StatusUnauthorized, "unsigned, or signed by an unknown Mac")
			return
		}
		s.Store.Touch(r.Context(), "mac:"+id, s.now())
		s.maybeCleanup(r.Context())
		h(w, r, caller{ID: id, Mac: id, Admin: mac.Admin})
	}
}

// expired reports whether a device has gone unused past DeviceIdle. A
// device with no recorded use yet (registered before this existed) isn't
// expired; its first request starts the clock.
func (s *Server) expired(ctx context.Context, deviceID string) bool {
	if s.DeviceIdle <= 0 {
		return false
	}
	last, err := s.Store.LastSeen(ctx, "dev:"+deviceID)
	return err == nil && !last.IsZero() && s.now().Sub(last) > s.DeviceIdle
}

func (s *Server) admin(h handler) http.HandlerFunc {
	return s.mac(func(w http.ResponseWriter, r *http.Request, c caller) {
		if !c.Admin {
			s.fail(w, http.StatusForbidden, "only an admin Mac can do that")
			return
		}
		h(w, r, c)
	})
}

func hashCode(code string) string {
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}

// registerMac adds a tenant. It needs either the setup token (the first,
// admin Mac) or an unused invite, and the request must be signed by the key
// being registered, so a token or invite alone can't register someone
// else's key. An invite is spent only once the rest of the request checks
// out.
func (s *Server) registerMac(w http.ResponseWriter, r *http.Request) {
	setup, invite := r.Header.Get(HeaderSetup), r.Header.Get(HeaderInvite)
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		s.fail(w, http.StatusBadRequest, "body too large")
		return
	}
	var req struct {
		MacID   string `json:"mac_id"`
		SignPub string `json:"sign_pub"`
	}
	if err := json.Unmarshal(body, &req); err != nil || !strings.HasPrefix(req.MacID, "mac-") {
		s.fail(w, http.StatusBadRequest, "bad registration")
		return
	}
	key, err := envelope.ParseSignPub(req.SignPub)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "bad mac key")
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if _, err := reqsig.Verify(r, func(id string) (*ecdsa.PublicKey, error) {
		if id != req.MacID {
			return nil, reqsig.ErrUnsigned
		}
		return key, nil
	}, s.now()); err != nil {
		s.fail(w, http.StatusUnauthorized, "registration must be signed by the key it registers")
		return
	}
	ctx := r.Context()
	// A Mac that's already registered with this key needs nothing more:
	// the signature just proved it holds the key.
	if cur, err := s.Store.GetMac(ctx, req.MacID); err == nil {
		if cur.SignPub != req.SignPub {
			s.storeErr(w, ErrConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	admin := false
	switch {
	case setup != "":
		if s.SetupToken == "" || subtle.ConstantTimeCompare([]byte(setup), []byte(s.SetupToken)) != 1 {
			s.fail(w, http.StatusForbidden, "wrong setup token, or setup is switched off")
			return
		}
		admin = true
	case invite == "":
		s.fail(w, http.StatusForbidden, "registering needs an invite from an admin Mac (`flow-remote invite`)")
		return
	}
	if invite != "" && setup == "" {
		if err := s.Store.UseInvite(ctx, hashCode(invite), s.now()); err != nil {
			s.fail(w, http.StatusForbidden, "that invite is unknown, used or expired")
			return
		}
	}
	err = s.Store.RegisterMac(ctx, Mac{ID: req.MacID, SignPub: req.SignPub, Admin: admin, Created: s.now()})
	if err != nil && !errors.Is(err, ErrExists) {
		s.storeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- phone ----

func (s *Server) postPair(w http.ResponseWriter, r *http.Request) {
	var e envelope.Envelope
	if !s.decode(w, r, &e) {
		return
	}
	if !strings.HasPrefix(e.From, "dev-") || !strings.HasPrefix(e.To, "mac-") {
		s.fail(w, http.StatusBadRequest, "bad pairing envelope")
		return
	}
	if err := s.Store.PutPair(r.Context(), r.PathValue("pair"), e, s.now()); err != nil {
		if errors.Is(err, ErrNotFound) {
			s.fail(w, http.StatusNotFound, "no open pairing with that code; run `flow-remote pair` again")
			return
		}
		s.storeErrPublic(w, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) phonePost(w http.ResponseWriter, r *http.Request, c caller) {
	var e envelope.Envelope
	if !s.decode(w, r, &e) {
		return
	}
	if e.From != c.ID || e.To != c.Mac {
		s.fail(w, http.StatusBadRequest, "a phone sends as itself, to the Mac that enrolled it")
		return
	}
	if !s.limits.allow(c.ID, phonePerHour, s.now()) {
		s.fail(w, http.StatusTooManyRequests, "limit is 30 messages an hour per device")
		return
	}
	s.put(w, r.Context(), e)
}

func (s *Server) phoneList(w http.ResponseWriter, r *http.Request, c caller) {
	s.list(w, r.Context(), c.ID, nil)
}

func (s *Server) phoneAck(w http.ResponseWriter, r *http.Request, c caller) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	s.ack(w, r.Context(), c.ID, req.IDs)
}

// status tells a phone when its own Mac last checked in, and nothing about
// any other tenant.
func (s *Server) status(w http.ResponseWriter, r *http.Request, c caller) {
	t, _ := s.Store.LastSeen(r.Context(), "mac:"+c.Mac)
	s.json(w, http.StatusOK, map[string]any{
		"macs": map[string]any{c.Mac: map[string]any{"last_seen": nullTime(t)}},
		"now":  s.now(),
	})
}

// ---- relay ----

func (s *Server) openPair(w http.ResponseWriter, r *http.Request, c caller) {
	var req struct {
		PairID string `json:"pair_id"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	if len(req.PairID) < 16 {
		s.fail(w, http.StatusBadRequest, "pair id too short")
		return
	}
	if err := s.Store.OpenPair(r.Context(), req.PairID, c.Mac, s.now()); err != nil {
		s.storeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) takePair(w http.ResponseWriter, r *http.Request, c caller) {
	e, err := s.Store.TakePair(r.Context(), r.PathValue("pair"), c.Mac, s.now())
	if err != nil {
		s.storeErr(w, err)
		return
	}
	s.json(w, http.StatusOK, e)
}

func (s *Server) putDevice(w http.ResponseWriter, r *http.Request, c caller) {
	var req struct {
		DeviceID string `json:"device_id"`
		SignPub  string `json:"sign_pub"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	if !strings.HasPrefix(req.DeviceID, "dev-") {
		s.fail(w, http.StatusBadRequest, "bad device id")
		return
	}
	if _, err := envelope.ParseSignPub(req.SignPub); err != nil {
		s.fail(w, http.StatusBadRequest, "bad device key")
		return
	}
	if err := s.Store.PutDevice(r.Context(), c.Mac, req.DeviceID, req.SignPub); err != nil {
		s.storeErr(w, err)
		return
	}
	// Enrollment counts as use, so the idle clock starts now. Only for a
	// device never seen, so a re-sync on relay start can't revive an
	// expired one.
	if t, _ := s.Store.LastSeen(r.Context(), "dev:"+req.DeviceID); t.IsZero() {
		s.Store.Touch(r.Context(), "dev:"+req.DeviceID, s.now())
	}
	w.WriteHeader(http.StatusNoContent)
}

// listDevices reports a Mac's phones with when each last checked in.
func (s *Server) listDevices(w http.ResponseWriter, r *http.Request, c caller) {
	ids, err := s.Store.ListDevices(r.Context(), c.Mac)
	if err != nil {
		s.storeErr(w, err)
		return
	}
	out := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		t, _ := s.Store.LastSeen(r.Context(), "dev:"+id)
		out = append(out, map[string]any{"id": id, "last_seen": nullTime(t), "expired": s.expired(r.Context(), id)})
	}
	s.json(w, http.StatusOK, map[string]any{"devices": out, "idle_days": int(s.DeviceIdle.Hours() / 24)})
}

func (s *Server) revokeDevice(w http.ResponseWriter, r *http.Request, c caller) {
	if err := s.Store.RevokeDevice(r.Context(), c.Mac, r.PathValue("id")); err != nil {
		s.storeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) relayList(w http.ResponseWriter, r *http.Request, c caller) {
	poll := PollIdle
	if t, _ := s.Store.LastSeen(r.Context(), "phone:"+c.Mac); s.now().Sub(t) < ActiveWindow {
		poll = PollActive
	}
	s.list(w, r.Context(), c.Mac, map[string]any{"poll_ms": poll.Milliseconds()})
}

func (s *Server) relayPost(w http.ResponseWriter, r *http.Request, c caller) {
	var e envelope.Envelope
	if !s.decode(w, r, &e) {
		return
	}
	if e.From != c.Mac || !strings.HasPrefix(e.To, "dev-") {
		s.fail(w, http.StatusBadRequest, "the relay sends from its own mac id to a device")
		return
	}
	// Only to its own phones: a Mac can't drop mail into another tenant's.
	if d, err := s.Store.GetDevice(r.Context(), e.To); err != nil || d.Owner != c.Mac || s.expired(r.Context(), e.To) {
		s.fail(w, http.StatusNotFound, "no such device on this Mac, or its key expired")
		return
	}
	if !s.limits.allow(c.Mac, relayPerHour, s.now()) {
		s.fail(w, http.StatusTooManyRequests, "relay send limit reached")
		return
	}
	s.put(w, r.Context(), e)
}

func (s *Server) relayAck(w http.ResponseWriter, r *http.Request, c caller) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	s.ack(w, r.Context(), c.Mac, req.IDs)
}

// ---- admin ----

// createInvite returns a single-use code. Only its hash is stored, so the
// database never holds a usable invite.
func (s *Server) createInvite(w http.ResponseWriter, r *http.Request, c caller) {
	raw := make([]byte, 24)
	rand.Read(raw)
	code := "inv-" + envelope.Encode(raw)
	if err := s.Store.CreateInvite(r.Context(), hashCode(code), c.Mac, s.now()); err != nil {
		s.storeErr(w, err)
		return
	}
	s.json(w, http.StatusCreated, map[string]any{"code": code, "expires": s.now().Add(InviteTTL)})
}

func (s *Server) listTenants(w http.ResponseWriter, r *http.Request, _ caller) {
	macs, err := s.Store.ListMacs(r.Context())
	if err != nil {
		s.storeErr(w, err)
		return
	}
	out := make([]map[string]any, 0, len(macs))
	for _, m := range macs {
		t, _ := s.Store.LastSeen(r.Context(), "mac:"+m.ID)
		out = append(out, map[string]any{"id": m.ID, "admin": m.Admin, "created": m.Created, "last_seen": nullTime(t)})
	}
	s.json(w, http.StatusOK, map[string]any{"tenants": out})
}

func (s *Server) removeTenant(w http.ResponseWriter, r *http.Request, c caller) {
	id := r.PathValue("id")
	if id == c.Mac {
		s.fail(w, http.StatusBadRequest, "a Mac can't remove itself")
		return
	}
	if err := s.Store.RemoveMac(r.Context(), id); err != nil {
		s.storeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- shared ----

func (s *Server) maybeCleanup(ctx context.Context) {
	s.cleanupMu.Lock()
	due := s.now().Sub(s.lastCleanup) >= cleanupEvery
	if due {
		s.lastCleanup = s.now()
	}
	s.cleanupMu.Unlock()
	if !due {
		return
	}
	n, err := s.Store.DeleteExpired(ctx, s.now())
	if s.Log != nil {
		s.Log.Info("cleanup", "deleted", n, "err", err)
	}
}

func (s *Server) put(w http.ResponseWriter, ctx context.Context, e envelope.Envelope) {
	if e.V != envelope.Version || e.ID == "" || e.Sig == "" || e.CT == "" {
		s.fail(w, http.StatusBadRequest, "not a v1 envelope")
		return
	}
	if err := s.Store.PutEnvelope(ctx, e, s.now()); err != nil {
		s.storeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) list(w http.ResponseWriter, ctx context.Context, to string, extra map[string]any) {
	recs, err := s.Store.ListEnvelopes(ctx, to, 100, s.now())
	if err != nil {
		s.storeErr(w, err)
		return
	}
	if recs == nil {
		recs = []Record{}
	}
	out := map[string]any{"envelopes": recs}
	for k, v := range extra {
		out[k] = v
	}
	s.json(w, http.StatusOK, out)
}

func (s *Server) ack(w http.ResponseWriter, ctx context.Context, to string, ids []string) {
	if len(ids) > 100 {
		s.fail(w, http.StatusBadRequest, "at most 100 ids per ack")
		return
	}
	if err := s.Store.Ack(ctx, to, ids); err != nil {
		s.storeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		s.fail(w, http.StatusBadRequest, "bad json")
		return false
	}
	return true
}

func (s *Server) storeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrExists):
		s.fail(w, http.StatusConflict, "already exists")
	case errors.Is(err, ErrConflict):
		s.fail(w, http.StatusConflict, "that id is registered with a different key, or revoked")
	case errors.Is(err, ErrNotFound):
		s.fail(w, http.StatusNotFound, "not found")
	case errors.Is(err, ErrUnavailable):
		s.fail(w, http.StatusServiceUnavailable, "the mailbox is starting; try again shortly")
	default:
		if s.Log != nil {
			s.Log.Error("store", "err", err)
		}
		// Callers that reach here have proved who they are (setup token,
		// Mac key or device key), and without the detail a store failure
		// on Cloud Run is undiagnosable from outside.
		s.fail(w, http.StatusInternalServerError, "store error: "+err.Error())
	}
}

// storeErrPublic is storeErr for the one unauthenticated call.
func (s *Server) storeErrPublic(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrExists), errors.Is(err, ErrConflict), errors.Is(err, ErrNotFound), errors.Is(err, ErrUnavailable):
		s.storeErr(w, err)
	default:
		if s.Log != nil {
			s.Log.Error("store", "err", err)
		}
		s.fail(w, http.StatusInternalServerError, "store error")
	}
}

func (s *Server) fail(w http.ResponseWriter, code int, msg string) {
	s.json(w, code, map[string]string{"error": msg})
}

func (s *Server) json(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

// limiter is a per-key sliding window. The service runs as one instance,
// so memory is enough.
type limiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func (l *limiter) allow(key string, perHour int, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.hits == nil {
		l.hits = map[string][]time.Time{}
	}
	cut := now.Add(-time.Hour)
	h := l.hits[key]
	i := 0
	for i < len(h) && h[i].Before(cut) {
		i++
	}
	h = h[i:]
	if len(h) >= perHour {
		l.hits[key] = h
		return false
	}
	l.hits[key] = append(h, now)
	return true
}
