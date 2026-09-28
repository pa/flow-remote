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

const setupToken = "test-setup-token-0123456789"

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
	s := &mailbox.Server{Store: store, SetupToken: setupToken, Now: clk.Now}
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

// phone sends a request signed with the device key (or unsigned).
func (r *rig) phone(method, path string, body any, signed bool) (int, []byte) {
	r.t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req, _ := http.NewRequest(method, r.srv.URL+path, bytes.NewReader(raw))
	if signed {
		reqsig.Sign(req, r.deviceID, r.sign, raw, r.clk.Now())
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

func (r *rig) enrollment(o pairing.Offer) *envelope.Envelope {
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
	return e
}

// pair registers the Mac, runs the handshake and registers the device.
func (r *rig) pair() {
	r.t.Helper()
	ctx := context.Background()
	if err := r.relay.Register(ctx, setupToken); err != nil {
		r.t.Fatalf("register: %v", err)
	}
	o := pairing.NewOffer(r.mac, "", r.clk.Now())
	e := r.enrollment(o)

	// The phone can't post into a slot the Mac hasn't opened.
	if code, _ := r.phone("POST", "/v1/pair/"+o.PairID, e, false); code != http.StatusNotFound {
		r.t.Fatalf("post into unopened slot = %d", code)
	}
	if err := r.relay.OpenPair(ctx, o.PairID); err != nil {
		r.t.Fatal(err)
	}
	if _, err := r.relay.TakePair(ctx, o.PairID); !errors.Is(err, client.ErrNotFound) {
		r.t.Fatalf("take before the phone posted = %v", err)
	}
	if code, body := r.phone("POST", "/v1/pair/"+o.PairID, e, false); code != http.StatusAccepted {
		r.t.Fatalf("post pair: %d %s", code, body)
	}
	if code, _ := r.phone("POST", "/v1/pair/"+o.PairID, r.enrollment(o), false); code != http.StatusConflict {
		r.t.Fatalf("second enrollment into the same slot = %d", code)
	}
	got, err := r.relay.TakePair(ctx, o.PairID)
	if err != nil {
		r.t.Fatal(err)
	}
	dev, err := pairing.Accept(o, r.mac, got, r.clk.Now())
	if err != nil {
		r.t.Fatalf("accept: %v", err)
	}
	if _, err := r.relay.TakePair(ctx, o.PairID); !errors.Is(err, client.ErrNotFound) {
		r.t.Fatalf("pairing slot readable twice: %v", err)
	}

	// Until the Mac registers it, the device's signature means nothing.
	if code, _ := r.phone("GET", "/v1/envelopes", nil, true); code != http.StatusUnauthorized {
		r.t.Fatalf("unregistered device listed envelopes: %d", code)
	}
	if err := r.relay.PutDevice(ctx, dev); err != nil {
		r.t.Fatal(err)
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
	if code, body := r.phone("POST", "/v1/envelopes", r.phoneEnvelope("hi mac"), true); code != http.StatusAccepted {
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
	if pt, err := envelope.Open(&e, r.mac.Box); err != nil || string(pt) != "hi mac" {
		t.Fatalf("open: %q %v", pt, err)
	}
	r.relay.Ack(ctx, []string{e.ID})
	if b, _ := r.relay.List(ctx); len(b.Envelopes) != 0 {
		t.Fatal("ack didn't delete")
	}

	// Mac -> phone.
	reply, _ := envelope.Seal([]byte("hi phone"), r.mac.Sign, r.mac.ID, r.deviceID, r.box.PublicKey(), r.clk.Now().UnixMilli())
	if err := r.relay.Post(ctx, reply); err != nil {
		t.Fatal(err)
	}
	code, body := r.phone("GET", "/v1/envelopes", nil, true)
	var got struct{ Envelopes []mailbox.Record }
	json.Unmarshal(body, &got)
	if code != 200 || len(got.Envelopes) != 1 || got.Envelopes[0].Env.ID != reply.ID {
		t.Fatalf("phone list: %d %s", code, body)
	}
	r.phone("POST", "/v1/ack", map[string]any{"ids": []string{reply.ID}}, true)
	if _, body := r.phone("GET", "/v1/envelopes", nil, true); bytes.Contains(body, []byte(reply.ID)) {
		t.Fatal("phone ack didn't delete")
	}

	// The phone stopped using the app, so the relay slows down.
	r.clk.Add(mailbox.ActiveWindow + time.Second)
	if b, _ := r.relay.List(ctx); b.PollMS != mailbox.PollIdle.Milliseconds() {
		t.Fatalf("idle poll = %d", b.PollMS)
	}
	_, body = r.phone("GET", "/v1/status?mac="+r.mac.ID, nil, true)
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
	if code, _ := r.phone("POST", "/v1/envelopes", e, false); code != http.StatusUnauthorized {
		t.Errorf("unsigned = %d", code)
	}
	// Signed by a key that isn't the registered one.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	raw, _ := json.Marshal(e)
	req, _ := http.NewRequest("POST", r.srv.URL+"/v1/envelopes", bytes.NewReader(raw))
	reqsig.Sign(req, r.deviceID, other, raw, r.clk.Now())
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong key = %d", resp.StatusCode)
	}
	// A device can't send as another device.
	spoof, _ := envelope.Seal([]byte("x"), r.sign, "dev-someoneelse", r.mac.ID, r.mac.Box.PublicKey(), r.clk.Now().UnixMilli())
	if code, _ := r.phone("POST", "/v1/envelopes", spoof, true); code != http.StatusBadRequest {
		t.Errorf("spoofed from = %d", code)
	}
	// A device key can't call relay endpoints: the id prefix is checked.
	if code, _ := r.phone("GET", "/v1/relay/envelopes", nil, true); code != http.StatusUnauthorized {
		t.Errorf("device on relay endpoint = %d", code)
	}
	if code, _ := r.phone("POST", "/v1/envelopes", e, true); code != http.StatusAccepted {
		t.Errorf("good = %d", code)
	}
	if code, _ := r.phone("POST", "/v1/envelopes", e, true); code != http.StatusConflict {
		t.Errorf("duplicate id = %d", code)
	}
}

func TestRevokedDeviceIsRejected(t *testing.T) {
	r := newRig(t)
	r.pair()
	if err := r.relay.RevokeDevice(context.Background(), r.deviceID); err != nil {
		t.Fatal(err)
	}
	if code, _ := r.phone("GET", "/v1/envelopes", nil, true); code != http.StatusUnauthorized {
		t.Fatalf("revoked device = %d", code)
	}
	// And it can't be brought back by re-registering.
	dev := identity.Device{ID: r.deviceID, SignPub: envelope.EncodeSignPub(&r.sign.PublicKey)}
	if err := r.relay.PutDevice(context.Background(), dev); err == nil {
		t.Fatal("revoked device re-registered")
	}
}

func TestRegistration(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if err := r.relay.Register(ctx, "wrong-token-wrong-token-xx"); err == nil {
		t.Fatal("wrong token accepted")
	}
	// The right token, but the request is signed by a different key than
	// the one in the body.
	other, _ := identity.LoadOrCreateMac(&keystore.Memory{})
	body, _ := json.Marshal(map[string]string{"mac_id": r.mac.ID, "sign_pub": r.mac.SignPub()})
	req, _ := http.NewRequest("POST", r.srv.URL+"/v1/macs", bytes.NewReader(body))
	req.Header.Set(mailbox.HeaderSetup, setupToken)
	reqsig.Sign(req, r.mac.ID, other.Sign, body, r.clk.Now())
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("registration signed by another key = %d", resp.StatusCode)
	}
	if err := r.relay.Register(ctx, setupToken); err != nil {
		t.Fatal(err)
	}
	if err := r.relay.Register(ctx, setupToken); err != nil {
		t.Fatalf("re-registering the same key: %v", err)
	}
	// Another key can't take over the same mac id.
	other.ID = r.mac.ID
	if err := (&client.Client{BaseURL: r.srv.URL, Mac: other, Now: r.clk.Now}).Register(ctx, setupToken); err == nil {
		t.Fatal("mac id taken over")
	}

	// A mailbox with no token accepts no registrations at all.
	closed := httptest.NewServer((&mailbox.Server{Store: mailbox.NewMemory()}).Handler())
	defer closed.Close()
	if err := (&client.Client{BaseURL: closed.URL, Mac: r.mac}).Register(ctx, ""); err == nil {
		t.Fatal("registration with no token configured")
	}
}

func TestPhoneRateLimit(t *testing.T) {
	r := newRig(t)
	r.pair()
	for i := 0; i < 30; i++ {
		if code, body := r.phone("POST", "/v1/envelopes", r.phoneEnvelope("x"), true); code != http.StatusAccepted {
			t.Fatalf("message %d: %d %s", i, code, body)
		}
	}
	if code, _ := r.phone("POST", "/v1/envelopes", r.phoneEnvelope("x"), true); code != http.StatusTooManyRequests {
		t.Fatalf("31st message = %d", code)
	}
	r.clk.Add(time.Hour + time.Second)
	if code, _ := r.phone("POST", "/v1/envelopes", r.phoneEnvelope("x"), true); code != http.StatusAccepted {
		t.Fatalf("after an hour = %d", code)
	}
}

func TestRelayAuth(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if _, err := r.relay.List(ctx); err == nil {
		t.Fatal("unregistered mac listed envelopes")
	}
	r.pair()

	body := []byte(`{"ids":["a"]}`)
	req, _ := http.NewRequest("POST", r.srv.URL+"/v1/relay/ack", bytes.NewReader([]byte(`{"ids":["b"]}`)))
	reqsig.Sign(req, r.mac.ID, r.mac.Sign, body, r.clk.Now())
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tampered body = %d", resp.StatusCode)
	}
	old := &client.Client{BaseURL: r.srv.URL, Mac: r.mac, Now: func() time.Time { return r.clk.Now().Add(-3 * time.Minute) }}
	if _, err := old.List(ctx); err == nil {
		t.Fatal("stale signature accepted")
	}
	e, _ := envelope.Seal([]byte("x"), r.mac.Sign, "mac-other", r.deviceID, r.box.PublicKey(), r.clk.Now().UnixMilli())
	if err := r.relay.Post(ctx, e); err == nil {
		t.Fatal("relay sent as another mac")
	}
}

func TestExpiryCleansUpInPassing(t *testing.T) {
	r := newRig(t)
	r.pair()
	r.phone("POST", "/v1/envelopes", r.phoneEnvelope("x"), true)
	r.clk.Add(mailbox.Retention + time.Second)
	// Any signed request past the cleanup interval deletes expired data.
	if b, _ := r.relay.List(context.Background()); len(b.Envelopes) != 0 {
		t.Fatal("expired envelope listed")
	}
	if n, _ := r.store.DeleteExpired(context.Background(), r.clk.Now()); n != 0 {
		t.Fatalf("%d expired envelopes left behind by in-passing cleanup", n)
	}
}
