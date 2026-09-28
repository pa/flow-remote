package mailbox

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/subtle"
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

	// The relay polls fast only while the phone is in use.
	PollActive   = 3 * time.Second
	PollIdle     = 60 * time.Second
	ActiveWindow = 10 * time.Minute

	phonePerHour = 30  // from the plan's threat model
	relayPerHour = 600 // caps a runaway session, well above normal use

	// Expired envelopes are deleted in passing, at most this often. The
	// relay calls in at least once a minute, so no scheduled job is needed.
	cleanupEvery = time.Hour

	HeaderSetup = "X-FR-Setup"
)

// Server is the mailbox API. Nobody signs in: the Mac signs requests with
// its key, each phone with its device key, and the mailbox only knows the
// public halves. The Mac registers once with the setup token; devices are
// registered by the Mac after you confirm pairing.
type Server struct {
	Store Store
	// SetupToken lets a Mac register its key. Empty disables registration.
	SetupToken string
	Now        func() time.Time
	Log        *slog.Logger

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
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })

	mux.HandleFunc("POST /v1/macs", s.registerMac)

	// Phone. Pairing is the one unsigned call: the device key isn't
	// registered yet, and the slot has to have been opened by the Mac.
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
	mux.HandleFunc("GET /v1/relay/envelopes", s.mac(s.relayList))
	mux.HandleFunc("POST /v1/relay/envelopes", s.mac(s.relayPost))
	mux.HandleFunc("POST /v1/relay/ack", s.mac(s.relayAck))
	return mux
}

// ---- auth ----

type handler func(http.ResponseWriter, *http.Request, string)

func (s *Server) signed(prefix, presence string, keyFor func(context.Context, string) (string, error), h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		id, err := reqsig.Verify(r, func(id string) (*ecdsa.PublicKey, error) {
			if !strings.HasPrefix(id, prefix) {
				return nil, reqsig.ErrUnsigned
			}
			k, err := keyFor(r.Context(), id)
			if err != nil {
				return nil, err
			}
			return envelope.ParseSignPub(k)
		}, s.now())
		if err != nil {
			s.fail(w, http.StatusUnauthorized, "unsigned, or signed by an unknown key")
			return
		}
		who := presence
		if who == "" {
			who = "mac:" + id
		}
		s.Store.Touch(r.Context(), who, s.now())
		s.maybeCleanup(r.Context())
		h(w, r, id)
	}
}

func (s *Server) device(h handler) http.HandlerFunc {
	return s.signed("dev-", "phone", s.Store.DeviceKey, h)
}

func (s *Server) mac(h handler) http.HandlerFunc {
	return s.signed("mac-", "", s.Store.MacKey, h)
}

// registerMac needs the setup token and a request signed by the key being
// registered, so the token alone can't register someone else's key.
func (s *Server) registerMac(w http.ResponseWriter, r *http.Request) {
	tok := r.Header.Get(HeaderSetup)
	if s.SetupToken == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(s.SetupToken)) != 1 {
		s.fail(w, http.StatusForbidden, "wrong or missing setup token")
		return
	}
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
	_, err = reqsig.Verify(r, func(id string) (*ecdsa.PublicKey, error) {
		if id != req.MacID {
			return nil, reqsig.ErrUnsigned
		}
		return key, nil
	}, s.now())
	if err != nil {
		s.fail(w, http.StatusUnauthorized, "registration must be signed by the key it registers")
		return
	}
	if err := s.Store.RegisterMac(r.Context(), req.MacID, req.SignPub); err != nil {
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
			s.fail(w, http.StatusNotFound, "no open pairing with that code; run `relay pair` again")
			return
		}
		s.storeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) phonePost(w http.ResponseWriter, r *http.Request, dev string) {
	var e envelope.Envelope
	if !s.decode(w, r, &e) {
		return
	}
	if e.From != dev || !strings.HasPrefix(e.To, "mac-") {
		s.fail(w, http.StatusBadRequest, "a device sends as itself, to a mac")
		return
	}
	if _, err := s.Store.MacKey(r.Context(), e.To); err != nil {
		s.fail(w, http.StatusNotFound, "no such mac")
		return
	}
	if !s.limits.allow(dev, phonePerHour, s.now()) {
		s.fail(w, http.StatusTooManyRequests, "limit is 30 messages an hour per device")
		return
	}
	s.put(w, r.Context(), e)
}

func (s *Server) phoneList(w http.ResponseWriter, r *http.Request, dev string) {
	s.list(w, r.Context(), dev, nil)
}

func (s *Server) phoneAck(w http.ResponseWriter, r *http.Request, dev string) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	s.ack(w, r.Context(), dev, req.IDs)
}

// status tells the phone when each Mac last checked in.
func (s *Server) status(w http.ResponseWriter, r *http.Request, _ string) {
	out := map[string]any{}
	for _, id := range r.URL.Query()["mac"] {
		t, _ := s.Store.LastSeen(r.Context(), "mac:"+id)
		out[id] = map[string]any{"last_seen": nullTime(t)}
	}
	s.json(w, http.StatusOK, map[string]any{"macs": out, "now": s.now()})
}

// ---- relay ----

func (s *Server) openPair(w http.ResponseWriter, r *http.Request, _ string) {
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
	if err := s.Store.OpenPair(r.Context(), req.PairID, s.now()); err != nil {
		s.storeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) takePair(w http.ResponseWriter, r *http.Request, _ string) {
	e, err := s.Store.TakePair(r.Context(), r.PathValue("pair"), s.now())
	if err != nil {
		s.storeErr(w, err)
		return
	}
	s.json(w, http.StatusOK, e)
}

func (s *Server) putDevice(w http.ResponseWriter, r *http.Request, _ string) {
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
	if err := s.Store.PutDevice(r.Context(), req.DeviceID, req.SignPub); err != nil {
		s.storeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) revokeDevice(w http.ResponseWriter, r *http.Request, _ string) {
	if err := s.Store.RevokeDevice(r.Context(), r.PathValue("id")); err != nil {
		s.storeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) relayList(w http.ResponseWriter, r *http.Request, macID string) {
	poll := PollIdle
	if t, _ := s.Store.LastSeen(r.Context(), "phone"); s.now().Sub(t) < ActiveWindow {
		poll = PollActive
	}
	s.list(w, r.Context(), macID, map[string]any{"poll_ms": poll.Milliseconds()})
}

func (s *Server) relayPost(w http.ResponseWriter, r *http.Request, macID string) {
	var e envelope.Envelope
	if !s.decode(w, r, &e) {
		return
	}
	if e.From != macID || !strings.HasPrefix(e.To, "dev-") {
		s.fail(w, http.StatusBadRequest, "the relay sends from its own mac id to a device")
		return
	}
	if !s.limits.allow(macID, relayPerHour, s.now()) {
		s.fail(w, http.StatusTooManyRequests, "relay send limit reached")
		return
	}
	s.put(w, r.Context(), e)
}

func (s *Server) relayAck(w http.ResponseWriter, r *http.Request, macID string) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	s.ack(w, r.Context(), macID, req.IDs)
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
