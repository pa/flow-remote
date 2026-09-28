package mailbox_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/pa/flow-remote/internal/client"
	"github.com/pa/flow-remote/internal/envelope"
	"github.com/pa/flow-remote/internal/identity"
	"github.com/pa/flow-remote/internal/keystore"
	"github.com/pa/flow-remote/internal/mailbox"
	"github.com/pa/flow-remote/internal/pairing"
	"github.com/pa/flow-remote/internal/reqsig"
)

const owner = "owner@example.com"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type rig struct {
	t     *testing.T
	clk   *clock
	store *mailbox.Memory
	srv   *httptest.Server
	mac   *identity.Mac
	relay *client.Client
	// the simulated phone
	sign     *ecdsa.PrivateKey
	box      *ecdh.PrivateKey
	deviceID string
}

func newRig(t *testing.T) *rig {
	clk := &clock{t: time.Now()}
	store := mailbox.NewMemory()
	s := &mailbox.Server{Store: store, Owner: owner, DevAuth: true, Now: clk.Now}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	mac, _ := identity.LoadOrCreateMac(&keystore.Memory{})
	sign, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	box, _ := ecdh.P256().GenerateKey(rand.Reader)
	return &rig{
		t: t, clk: clk, store: store, srv: srv, mac: mac,
		relay: &client.Client{BaseURL: srv.URL, Mac: mac, Now: clk.Now},
		sign:  sign, box: box, deviceID: "dev-" + envelope.NewID()[:12],
	}
}

// phoneReq sends a request as the phone, signed in as email.
func (r *rig) phoneReq(method, path, email string, body any) (int, []byte) {
	r.t.Helper()
	raw, _ := json.Marshal(body)
	if body == nil {
		raw = nil
	}
	req, _ := http.NewRequest(method, r.srv.URL+path, bytes.NewReader(raw))
	if email != "" {
		req.Header.Set("Authorization", "Bearer dev:"+email)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.Bytes()
}

// pair runs the whole handshake and enrolls the phone.
func (r *rig) pair() {
	r.t.Helper()
	o := pairing.NewOffer(r.mac, r.srv.URL, r.clk.Now())
	secret, _ := envelope.Decode(o.Secret)
	en := pairing.Enrollment{
		Kind: "enroll", PairID: o.PairID, DeviceID: r.deviceID, Name: "test phone",
		SignPub: envelope.EncodeSignPub(&r.sign.PublicKey), BoxPub: envelope.EncodeBoxPub(r.box.PublicKey()),
	}
	m := hmac.New(sha256.New, secret)
	m.Write(en.MACInput())
	en.MAC = envelope.Encode(m.Sum(nil))
	pt, _ := json.Marshal(en)
	e, _ := envelope.Seal(pt, r.sign, r.deviceID, r.mac.ID, r.mac.Box.PublicKey(), r.clk.Now().UnixMilli())

	ctx := context.Background()
	if _, err := r.relay.TakePair(ctx, o.PairID); !errors.Is(err, client.ErrNotFound) {
		r.t.Fatalf("pair before phone posted = %v", err)
	}
	code, body := r.phoneReq("POST", "/v1/pair/"+o.PairID, owner, map[string]any{
		"mac_id": o.MacID, "mac_sign_pub": o.MacSignPub, "env": e,
	})
	if code != http.StatusAccepted {
		r.t.Fatalf("post pair: %d %s", code, body)
	}
	got, err := r.relay.TakePair(ctx, o.PairID)
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err := pairing.Accept(o, r.mac, got, r.clk.Now()); err != nil {
		r.t.Fatalf("accept: %v", err)
	}
	if _, err := r.relay.TakePair(ctx, o.PairID); !errors.Is(err, client.ErrNotFound) {
		r.t.Fatalf("pairing slot readable twice: %v", err)
	}
}

func (r *rig) phoneEnvelope(text string) *envelope.Envelope {
	e, _ := envelope.Seal([]byte(text), r.sign, r.deviceID, r.mac.ID, r.mac.Box.PublicKey(), r.clk.Now().UnixMilli())
	return e
}

func TestRoundTrip(t *testing.T) {
	r := newRig(t)
	r.pair()
	ctx := context.Background()

	// Phone -> Mac.
	if code, body := r.phoneReq("POST", "/v1/envelopes", owner, r.phoneEnvelope("hi mac")); code != http.StatusAccepted {
		t.Fatalf("phone post: %d %s", code, body)
	}
	b, err := r.relay.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Envelopes) != 1 || b.PollMS != mailbox.PollActive.Milliseconds() {
		t.Fatalf("relay list: %+v", b)
	}
	e := b.Envelopes[0].Env
	if err := envelope.Verify(&e, &r.sign.PublicKey); err != nil {
		t.Fatal(err)
	}
	if pt, err := envelope.Open(&e, r.mac.Box); err != nil || string(pt) != "hi mac" {
		t.Fatalf("open: %q %v", pt, err)
	}
	if err := r.relay.Ack(ctx, []string{e.ID}); err != nil {
		t.Fatal(err)
	}
	if b, _ := r.relay.List(ctx); len(b.Envelopes) != 0 {
		t.Fatal("ack didn't delete")
	}

	// Mac -> phone.
	reply, _ := envelope.Seal([]byte("hi phone"), r.mac.Sign, r.mac.ID, r.deviceID, r.box.PublicKey(), r.clk.Now().UnixMilli())
	if err := r.relay.Post(ctx, reply); err != nil {
		t.Fatal(err)
	}
	code, body := r.phoneReq("GET", "/v1/envelopes?to="+r.deviceID, owner, nil)
	var got struct{ Envelopes []mailbox.Record }
	json.Unmarshal(body, &got)
	if code != 200 || len(got.Envelopes) != 1 || got.Envelopes[0].Env.ID != reply.ID {
		t.Fatalf("phone list: %d %s", code, body)
	}

	// The phone stopped using the app, so the relay slows down.
	r.clk.Add(mailbox.ActiveWindow + time.Second)
	if b, _ := r.relay.List(ctx); b.PollMS != mailbox.PollIdle.Milliseconds() {
		t.Fatalf("idle poll = %d", b.PollMS)
	}

	// The Mac's check-ins are visible to the phone.
	_, body = r.phoneReq("GET", "/v1/status?mac="+r.mac.ID, owner, nil)
	var st struct {
		Macs map[string]struct {
			LastSeen *time.Time `json:"last_seen"`
		}
	}
	json.Unmarshal(body, &st)
	if st.Macs[r.mac.ID].LastSeen == nil {
		t.Fatalf("status: %s", body)
	}
}

func TestPhoneAuth(t *testing.T) {
	r := newRig(t)
	r.pair()
	e := r.phoneEnvelope("x")
	if code, _ := r.phoneReq("POST", "/v1/envelopes", "", e); code != http.StatusUnauthorized {
		t.Errorf("no sign-in = %d", code)
	}
	if code, _ := r.phoneReq("POST", "/v1/envelopes", "someone@else.com", e); code != http.StatusForbidden {
		t.Errorf("other account = %d", code)
	}
	if code, _ := r.phoneReq("POST", "/v1/envelopes", "OWNER@example.com", e); code != http.StatusAccepted {
		t.Errorf("owner, other case = %d", code)
	}
	if code, _ := r.phoneReq("POST", "/v1/envelopes", owner, e); code != http.StatusConflict {
		t.Errorf("duplicate id = %d", code)
	}
}

func TestDevAuthOffRejectsDevTokens(t *testing.T) {
	s := &mailbox.Server{Store: mailbox.NewMemory(), Owner: owner}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	req, _ := http.NewRequest("GET", srv.URL+"/v1/status", nil)
	req.Header.Set("Authorization", "Bearer dev:"+owner)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("dev token accepted without DevAuth: %d", resp.StatusCode)
	}
}

func TestPhoneRateLimit(t *testing.T) {
	r := newRig(t)
	r.pair()
	for i := 0; i < 30; i++ {
		if code, body := r.phoneReq("POST", "/v1/envelopes", owner, r.phoneEnvelope("x")); code != http.StatusAccepted {
			t.Fatalf("message %d: %d %s", i, code, body)
		}
	}
	if code, _ := r.phoneReq("POST", "/v1/envelopes", owner, r.phoneEnvelope("x")); code != http.StatusTooManyRequests {
		t.Fatalf("31st message = %d", code)
	}
	r.clk.Add(time.Hour + time.Second)
	if code, _ := r.phoneReq("POST", "/v1/envelopes", owner, r.phoneEnvelope("x")); code != http.StatusAccepted {
		t.Fatalf("after an hour = %d", code)
	}
}

func TestRelayAuth(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()

	// Not registered yet: the phone hasn't paired.
	if _, err := r.relay.List(ctx); err == nil {
		t.Fatal("unregistered mac listed envelopes")
	}
	r.pair()

	// A different Mac key under the same id.
	impostor, _ := identity.LoadOrCreateMac(&keystore.Memory{})
	impostor.ID = r.mac.ID
	bad := &client.Client{BaseURL: r.srv.URL, Mac: impostor, Now: r.clk.Now}
	if _, err := bad.List(ctx); err == nil {
		t.Fatal("wrong key accepted")
	}

	// A signed request whose body was changed in transit.
	body := []byte(`{"ids":["a"]}`)
	req, _ := http.NewRequest("POST", r.srv.URL+"/v1/relay/ack", bytes.NewReader([]byte(`{"ids":["b"]}`)))
	reqsig.Sign(req, r.mac.ID, r.mac.Sign, body, r.clk.Now())
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tampered body = %d", resp.StatusCode)
	}

	// A stale signature.
	old := &client.Client{BaseURL: r.srv.URL, Mac: r.mac, Now: func() time.Time { return r.clk.Now().Add(-3 * time.Minute) }}
	if _, err := old.List(ctx); err == nil {
		t.Fatal("stale signature accepted")
	}

	// The relay can only send as itself, to a device.
	e, _ := envelope.Seal([]byte("x"), r.mac.Sign, "mac-other", r.deviceID, r.box.PublicKey(), r.clk.Now().UnixMilli())
	if err := r.relay.Post(ctx, e); err == nil {
		t.Fatal("relay sent as another mac")
	}
}

func TestMacKeyIsFirstComeFirstServed(t *testing.T) {
	r := newRig(t)
	r.pair()
	other, _ := identity.LoadOrCreateMac(&keystore.Memory{})
	code, _ := r.phoneReq("POST", "/v1/pair/"+envelope.NewID(), owner, map[string]any{
		"mac_id": r.mac.ID, "mac_sign_pub": other.SignPub(), "env": envelope.Envelope{To: r.mac.ID},
	})
	if code != http.StatusConflict {
		t.Fatalf("re-register with another key = %d", code)
	}
}

func TestExpiry(t *testing.T) {
	r := newRig(t)
	r.pair()
	r.phoneReq("POST", "/v1/envelopes", owner, r.phoneEnvelope("x"))
	r.clk.Add(mailbox.Retention + time.Second)
	if b, _ := r.relay.List(context.Background()); len(b.Envelopes) != 0 {
		t.Fatal("expired envelope listed")
	}
	if n, _ := r.store.DeleteExpired(context.Background(), r.clk.Now()); n != 1 {
		t.Fatalf("deleted %d", n)
	}
}
