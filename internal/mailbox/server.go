package mailbox

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
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
)

type Server struct {
	Store Store
	// Owner is the one Google account allowed to use this mailbox.
	Owner string
	// Tokens verifies phone sign-ins. nil with DevAuth means local only.
	Tokens *FirebaseVerifier
	// DevAuth accepts "Bearer dev:<email>". Never set it on Cloud Run;
	// cmd/mailbox refuses to start with it there.
	DevAuth bool
	Now     func() time.Time
	Log     *slog.Logger

	limits limiter
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

	// Phone endpoints: Google sign-in as the owner.
	mux.HandleFunc("POST /v1/pair/{pair}", s.phone(s.postPair))
	mux.HandleFunc("POST /v1/envelopes", s.phone(s.phonePost))
	mux.HandleFunc("GET /v1/envelopes", s.phone(s.phoneList))
	mux.HandleFunc("POST /v1/ack", s.phone(s.phoneAck))
	mux.HandleFunc("GET /v1/status", s.phone(s.status))

	// Relay endpoints. Pairing pickup uses the pair id as a capability,
	// since the Mac isn't registered until the phone has sent it.
	mux.HandleFunc("GET /v1/pair/{pair}", s.takePair)
	mux.HandleFunc("GET /v1/relay/envelopes", s.relay(s.relayList))
	mux.HandleFunc("POST /v1/relay/envelopes", s.relay(s.relayPost))
	mux.HandleFunc("POST /v1/relay/ack", s.relay(s.relayAck))
	return mux
}

// ---- auth ----

type ctxKey struct{}

func (s *Server) phone(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email, err := s.phoneEmail(r)
		if err != nil {
			s.fail(w, http.StatusUnauthorized, "sign in as the owner")
			return
		}
		if !strings.EqualFold(email, s.Owner) {
			s.fail(w, http.StatusForbidden, "this mailbox belongs to someone else")
			return
		}
		s.Store.Touch(r.Context(), "phone", s.now())
		h(w, r)
	}
}

func (s *Server) phoneEmail(r *http.Request) (string, error) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return "", ErrToken
	}
	if s.DevAuth {
		if email, ok := strings.CutPrefix(tok, "dev:"); ok {
			return email, nil
		}
	}
	if s.Tokens == nil {
		return "", ErrToken
	}
	c, err := s.Tokens.Verify(tok, s.now())
	if err != nil {
		return "", err
	}
	return c.Email, nil
}

func (s *Server) relay(h func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		macID, err := reqsig.Verify(r, func(id string) (*ecdsa.PublicKey, error) {
			k, err := s.Store.MacKey(r.Context(), id)
			if err != nil {
				return nil, err
			}
			return envelope.ParseSignPub(k)
		}, s.now())
		if err != nil {
			s.fail(w, http.StatusUnauthorized, "unsigned or unknown relay")
			return
		}
		s.Store.Touch(r.Context(), "mac:"+macID, s.now())
		h(w, r, macID)
	}
}

// ---- phone ----

func (s *Server) postPair(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MacID      string            `json:"mac_id"`
		MacSignPub string            `json:"mac_sign_pub"`
		Env        envelope.Envelope `json:"env"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	if _, err := envelope.ParseSignPub(req.MacSignPub); err != nil || req.Env.To != req.MacID {
		s.fail(w, http.StatusBadRequest, "bad pairing request")
		return
	}
	ctx := r.Context()
	if err := s.Store.RegisterMac(ctx, req.MacID, req.MacSignPub); err != nil {
		s.storeErr(w, err)
		return
	}
	if err := s.Store.PutPair(ctx, r.PathValue("pair"), req.Env, s.now()); err != nil {
		s.storeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) phonePost(w http.ResponseWriter, r *http.Request) {
	var e envelope.Envelope
	if !s.decode(w, r, &e) {
		return
	}
	if !strings.HasPrefix(e.From, "dev-") || !strings.HasPrefix(e.To, "mac-") {
		s.fail(w, http.StatusBadRequest, "phones send from a device to a mac")
		return
	}
	if _, err := s.Store.MacKey(r.Context(), e.To); err != nil {
		s.fail(w, http.StatusNotFound, "no such mac; pair first")
		return
	}
	if !s.limits.allow(e.From, phonePerHour, s.now()) {
		s.fail(w, http.StatusTooManyRequests, "limit is 30 messages an hour per device")
		return
	}
	s.put(w, r.Context(), e)
}

func (s *Server) phoneList(w http.ResponseWriter, r *http.Request) {
	to := r.URL.Query().Get("to")
	if !strings.HasPrefix(to, "dev-") {
		s.fail(w, http.StatusBadRequest, "to must be a device id")
		return
	}
	s.list(w, r.Context(), to, nil)
}

func (s *Server) phoneAck(w http.ResponseWriter, r *http.Request) {
	var req struct {
		To  string   `json:"to"`
		IDs []string `json:"ids"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	if !strings.HasPrefix(req.To, "dev-") {
		s.fail(w, http.StatusBadRequest, "to must be a device id")
		return
	}
	s.ack(w, r.Context(), req.To, req.IDs)
}

// status tells the phone when each Mac it knows about last checked in.
func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{}
	for _, id := range r.URL.Query()["mac"] {
		t, _ := s.Store.LastSeen(r.Context(), "mac:"+id)
		out[id] = map[string]any{"last_seen": nullTime(t)}
	}
	s.json(w, http.StatusOK, map[string]any{"macs": out, "now": s.now()})
}

// ---- relay ----

func (s *Server) takePair(w http.ResponseWriter, r *http.Request) {
	e, err := s.Store.TakePair(r.Context(), r.PathValue("pair"), s.now())
	if err != nil {
		s.storeErr(w, err)
		return
	}
	s.json(w, http.StatusOK, e)
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
		s.fail(w, http.StatusConflict, "that mac id is registered with a different key")
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
