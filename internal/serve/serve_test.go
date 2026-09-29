package serve

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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pa/flow-remote/internal/envelope"
	"github.com/pa/flow-remote/internal/flowcli"
	"github.com/pa/flow-remote/internal/identity"
	"github.com/pa/flow-remote/internal/keystore"
	"github.com/pa/flow-remote/internal/pairing"
	"github.com/pa/flow-remote/internal/protocol"
	"github.com/pa/flow-remote/internal/relay"
	"github.com/pa/flow-remote/internal/reqsig"
	"github.com/pa/flow-remote/internal/tunnel"
)

type fakeFlow struct {
	mu     sync.Mutex
	sent   []string
	unread []flowcli.Mail
}

func (f *fakeFlow) LiveTasks(context.Context) ([]flowcli.Task, error) {
	return []flowcli.Task{{Slug: "demo", Name: "Demo task", Live: true}}, nil
}

func (f *fakeFlow) Message(_ context.Context, slug, body, _ string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, slug+"|"+body)
	return "flow-1", nil
}

func (f *fakeFlow) Unread(context.Context) ([]flowcli.Mail, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]flowcli.Mail(nil), f.unread...), nil
}

func (f *fakeFlow) MarkRead(context.Context, string) error { return nil }

// phone does what web/js does, in Go.
type phone struct {
	t    *testing.T
	base string
	id   string
	sign *ecdsa.PrivateKey
	box  *ecdh.PrivateKey
	mac  pairing.Offer
	got  []protocol.Msg // everything received, like the app's local store
}

func newPhone(t *testing.T, base string, offer pairing.Offer) *phone {
	s, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := ecdh.P256().GenerateKey(rand.Reader)
	return &phone{t: t, base: base, id: "dev-" + envelope.NewID()[:16], sign: s, box: b, mac: offer}
}

func (p *phone) seal(v any) *envelope.Envelope {
	macBox, _ := envelope.ParseBoxPub(p.mac.MacBoxPub)
	pt, _ := json.Marshal(v)
	e, err := envelope.Seal(pt, p.sign, p.id, p.mac.MacID, macBox, time.Now().UnixMilli())
	if err != nil {
		p.t.Fatal(err)
	}
	return e
}

func (p *phone) enroll() *envelope.Envelope {
	en := pairing.Enrollment{Kind: "enroll", PairID: p.mac.PairID, DeviceID: p.id, Name: "Test phone",
		SignPub: envelope.EncodeSignPub(&p.sign.PublicKey), BoxPub: envelope.EncodeBoxPub(p.box.PublicKey())}
	secret, _ := envelope.Decode(p.mac.Secret)
	m := hmac.New(sha256.New, secret)
	m.Write(en.MACInput())
	en.MAC = envelope.Encode(m.Sum(nil))
	return p.seal(en)
}

// do sends one request; signed as this phone unless signer says otherwise.
func (p *phone) do(method, path string, body any, sign bool, hdr map[string]string) (*http.Response, []byte) {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req, _ := http.NewRequest(method, p.base+path, bytes.NewReader(raw))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if sign {
		reqsig.Sign(req, p.id, p.sign, raw, time.Now())
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		p.t.Fatal(err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	return res, data
}

// next waits for a message of kind from the Mac, acking what it reads.
// It takes the oldest unclaimed one, including any that arrived while an
// earlier call waited for a different kind.
func (p *phone) next(kind string) protocol.Msg {
	for i, m := range p.got {
		if m.Kind == kind {
			p.got = append(p.got[:i:i], p.got[i+1:]...)
			return m
		}
	}
	macSign, _ := envelope.ParseSignPub(p.mac.MacSignPub)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		res, data := p.do("GET", "/v1/envelopes", nil, true, nil)
		if res.StatusCode != 200 {
			p.t.Fatalf("list: %d %s", res.StatusCode, data)
		}
		var batch struct {
			Envelopes []struct {
				Env envelope.Envelope `json:"env"`
			} `json:"envelopes"`
		}
		json.Unmarshal(data, &batch)
		var ids []string
		var found *protocol.Msg
		for _, r := range batch.Envelopes {
			ids = append(ids, r.Env.ID)
			if envelope.Verify(&r.Env, macSign) != nil {
				p.t.Fatal("an envelope from the Mac didn't verify")
			}
			pt, err := envelope.Open(&r.Env, p.box)
			if err != nil {
				p.t.Fatal(err)
			}
			var m protocol.Msg
			json.Unmarshal(pt, &m)
			if m.Kind == kind && found == nil {
				found = &m
			} else {
				p.got = append(p.got, m)
			}
		}
		if len(ids) > 0 {
			p.do("POST", "/v1/ack", map[string]any{"ids": ids}, true, nil)
		}
		if found != nil {
			return *found
		}
		time.Sleep(100 * time.Millisecond)
	}
	p.t.Fatalf("no %q message from the Mac", kind)
	return protocol.Msg{}
}

func TestServeEndToEnd(t *testing.T) {
	// A short path: macOS limits unix socket paths to about 100 bytes, and
	// t.TempDir() there is longer.
	home, err := os.MkdirTemp("/tmp", "fr-serve-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	ks := &keystore.Memory{}
	mac, _ := identity.LoadOrCreateMac(ks)
	devs, _ := identity.LoadDevices(ks)
	guard, _ := envelope.LoadGuard(filepath.Join(home, "seen.json"))
	state, _ := relay.LoadState(filepath.Join(home, "forwarded.json"))
	flow := &fakeFlow{}
	r := &relay.Relay{Mac: mac, Devices: devs, Guard: guard, State: state, Flow: flow}

	ctx, cancel := context.WithCancel(context.Background())
	listening := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{Home: home, Mac: mac, Relay: r, Tunnel: tunnel.Local{Addr: "127.0.0.1:0"},
			Origins: []string{"https://home.example"}, Listening: func(u string) { listening <- u }})
	}()
	var base string
	select {
	case base = <-listening:
	case err := <-done:
		t.Fatalf("serve stopped: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("serve didn't start")
	}
	t.Cleanup(func() {
		cancel()
		<-done
	})

	// Pairing, the way `flow-remote pair` does it, over the socket.
	mb := Client(home, mac)
	offer := pairing.NewOffer(mac, "", time.Now())
	if err := mb.OpenPair(ctx, offer.PairID); err != nil {
		t.Fatal(err)
	}
	ph := newPhone(t, base, offer)
	if res, data := ph.do("POST", "/v1/pair/"+offer.PairID, ph.enroll(), false, nil); res.StatusCode != 202 {
		t.Fatalf("pair post: %d %s", res.StatusCode, data)
	}
	e, err := mb.TakePair(ctx, offer.PairID)
	if err != nil {
		t.Fatal(err)
	}
	dev, err := pairing.Accept(offer, mac, e, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// `flow-remote pair` is its own process with its own copy of the list;
	// the relay picks the new phone up from the keystore.
	pairDevs, _ := identity.LoadDevices(ks)
	if err := pairDevs.Enroll(dev); err != nil {
		t.Fatal(err)
	}
	if err := mb.PutDevice(ctx, dev); err != nil {
		t.Fatal(err)
	}

	// Send to a session; the relay wakes on the post and answers.
	send := ph.seal(protocol.Msg{Kind: protocol.KindSend, ClientID: "c1", Task: "demo", Body: "hello"})
	if res, data := ph.do("POST", "/v1/envelopes", send, true, nil); res.StatusCode != 202 {
		t.Fatalf("send: %d %s", res.StatusCode, data)
	}
	st := ph.next(protocol.KindStatus)
	if st.State != protocol.Delivered || st.ClientID != "c1" {
		t.Fatalf("status = %+v", st)
	}
	flow.mu.Lock()
	if len(flow.sent) != 1 || !strings.HasPrefix(flow.sent[0], "demo|") || !strings.HasSuffix(flow.sent[0], "hello") {
		t.Fatalf("flow got %q", flow.sent)
	}
	flow.unread = []flowcli.Mail{{ID: "m1", CreatedAt: time.Now(), Kind: "message",
		From: flowcli.Address{TaskSlug: "demo"}, Body: "which one?"}}
	flow.mu.Unlock()

	// A session's reply reaches the phone.
	ph.do("POST", "/v1/envelopes", ph.seal(protocol.Msg{Kind: protocol.KindSync}), true, nil)
	if m := ph.next(protocol.KindMail); m.Mail == nil || m.Mail.Body != "which one?" || m.Mail.Task != "demo" {
		t.Fatalf("mail = %+v", m.Mail)
	}

	// The app is served; the Mac's routes aren't reachable from outside.
	if res, _ := ph.do("GET", "/", nil, false, nil); res.StatusCode != 200 {
		t.Fatalf("app: %d", res.StatusCode)
	}
	req, _ := http.NewRequest("GET", base+"/v1/relay/envelopes", nil)
	reqsig.Sign(req, mac.ID, mac.Sign, nil, time.Now())
	if res, err := http.DefaultClient.Do(req); err != nil || res.StatusCode != 404 {
		t.Fatalf("relay route from outside: %v %v", res.StatusCode, err)
	}
	if res, _ := ph.do("GET", "/v1/envelopes", nil, false, nil); res.StatusCode != 401 {
		t.Fatalf("unsigned list: %d", res.StatusCode)
	}

	// CORS for the app installed from another of your machines, and no one else.
	preflight := func(o string) string {
		res, _ := ph.do("OPTIONS", "/v1/envelopes", nil, false, map[string]string{
			"Origin": o, "Access-Control-Request-Method": "POST"})
		return res.Header.Get("Access-Control-Allow-Origin")
	}
	if got := preflight("https://home.example"); got != "https://home.example" {
		t.Fatalf("allowed origin got %q", got)
	}
	if got := preflight("https://evil.example"); got != "" {
		t.Fatalf("other origin got %q", got)
	}
}

// A second serve on the same home can't start while one runs.
func TestServeHoldsTheDatabase(t *testing.T) {
	home, _ := os.MkdirTemp("/tmp", "fr-serve-")
	t.Cleanup(func() { os.RemoveAll(home) })
	ks := &keystore.Memory{}
	mac, _ := identity.LoadOrCreateMac(ks)
	devs, _ := identity.LoadDevices(ks)
	mk := func() *relay.Relay {
		g, _ := envelope.LoadGuard(filepath.Join(home, "seen.json"))
		s, _ := relay.LoadState(filepath.Join(home, "forwarded.json"))
		return &relay.Relay{Mac: mac, Devices: devs, Guard: g, State: s, Flow: &fakeFlow{}}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	up := make(chan string, 1)
	first := make(chan error, 1)
	go func() {
		first <- Run(ctx, Options{Home: home, Mac: mac, Relay: mk(), Tunnel: tunnel.Local{Addr: "127.0.0.1:0"}, Listening: func(u string) { up <- u }})
	}()
	<-up
	err := Run(ctx, Options{Home: home, Mac: mac, Relay: mk(), Tunnel: tunnel.Local{Addr: "127.0.0.1:0"}})
	if err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("second serve: %v", err)
	}
	// The first one still answers on its socket.
	if _, _, err := Client(home, mac).Devices(ctx); err != nil {
		t.Fatalf("first serve stopped answering: %v", err)
	}
	cancel()
	<-first
}

// recorder stands in for the tunnel: it forwards to serve and keeps every
// byte of every request and response. With tamper set, it flips one byte
// inside the next envelope a phone posts.
type recorder struct {
	mu     sync.Mutex
	target string
	seen   bytes.Buffer
	tamper bool
}

func (rc *recorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	rc.mu.Lock()
	fmt.Fprintf(&rc.seen, "%s %s\n", r.Method, r.URL.RequestURI())
	for k, v := range r.Header {
		fmt.Fprintf(&rc.seen, "%s: %s\n", k, strings.Join(v, ","))
	}
	rc.seen.Write(body)
	if rc.tamper && r.Method == "POST" && r.URL.Path == "/v1/envelopes" {
		var e envelope.Envelope
		json.Unmarshal(body, &e)
		ct := []byte(e.CT)
		ct[len(ct)/2] ^= 1 // one bit, in the middle of the ciphertext
		e.CT = string(ct)
		body, _ = json.Marshal(e)
		rc.tamper = false
	}
	rc.mu.Unlock()
	req, _ := http.NewRequest(r.Method, rc.target+r.URL.RequestURI(), bytes.NewReader(body))
	req.Header = r.Header.Clone()
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	rc.mu.Lock()
	fmt.Fprintf(&rc.seen, "-> %d\n", res.StatusCode)
	rc.seen.Write(out)
	rc.mu.Unlock()
	for k, v := range res.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(res.StatusCode)
	w.Write(out)
}

// What crosses the tunnel, and what the mailbox writes to disk, is sealed:
// message bodies, the session list, statuses and replies never appear in
// plain text, and a changed byte in transit is refused, not delivered.
func TestTunnelSeesOnlySealedEnvelopes(t *testing.T) {
	const (
		toSession   = "phone-secret-7f3a: approve the terraform plan"
		fromSession = "session-secret-91c2: which workspace?"
		sessionName = "Secret task name 55e1"
		tampered    = "tampered-secret-0b4d"
	)
	home, _ := os.MkdirTemp("/tmp", "fr-wire-")
	t.Cleanup(func() { os.RemoveAll(home) })
	ks := &keystore.Memory{}
	mac, _ := identity.LoadOrCreateMac(ks)
	devs, _ := identity.LoadDevices(ks)
	guard, _ := envelope.LoadGuard(filepath.Join(home, "seen.json"))
	state, _ := relay.LoadState(filepath.Join(home, "forwarded.json"))
	flow := &namedFlow{fakeFlow: &fakeFlow{}, name: sessionName}
	r := &relay.Relay{Mac: mac, Devices: devs, Guard: guard, State: state, Flow: flow}

	ctx, cancel := context.WithCancel(context.Background())
	listening := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{Home: home, Mac: mac, Relay: r, Tunnel: tunnel.Local{Addr: "127.0.0.1:0"},
			Listening: func(u string) { listening <- u }})
	}()
	base := <-listening
	rec := &recorder{target: base}
	tun := httptest.NewServer(rec)
	defer tun.Close()

	// Pair through the recording tunnel.
	mb := Client(home, mac)
	offer := pairing.NewOffer(mac, "", time.Now())
	if err := mb.OpenPair(ctx, offer.PairID); err != nil {
		t.Fatal(err)
	}
	ph := newPhone(t, tun.URL, offer)
	if res, data := ph.do("POST", "/v1/pair/"+offer.PairID, ph.enroll(), false, nil); res.StatusCode != 202 {
		t.Fatalf("pair: %d %s", res.StatusCode, data)
	}
	e, _ := mb.TakePair(ctx, offer.PairID)
	dev, err := pairing.Accept(offer, mac, e, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pd, _ := identity.LoadDevices(ks)
	pd.Enroll(dev)
	mb.PutDevice(ctx, dev)

	// Both directions, plus the session list.
	ph.do("POST", "/v1/envelopes", ph.seal(protocol.Msg{Kind: protocol.KindSend, ClientID: "c1", Task: "demo", Body: toSession}), true, nil)
	if st := ph.next(protocol.KindStatus); st.State != protocol.Delivered {
		t.Fatalf("status = %+v", st)
	}
	flow.mu.Lock()
	flow.unread = []flowcli.Mail{{ID: "m1", CreatedAt: time.Now(), Kind: "message", From: flowcli.Address{TaskSlug: "demo"}, Body: fromSession}}
	flow.mu.Unlock()
	ph.do("POST", "/v1/envelopes", ph.seal(protocol.Msg{Kind: protocol.KindSync}), true, nil)
	if m := ph.next(protocol.KindMail); m.Mail == nil || m.Mail.Body != fromSession {
		t.Fatalf("reply = %+v", m.Mail)
	}
	sessions := ph.next(protocol.KindSessions)
	if len(sessions.Sessions) == 0 || sessions.Sessions[0].Name != sessionName {
		t.Fatalf("sessions = %+v", sessions.Sessions)
	}

	// Change one bit of a message in the tunnel.
	rec.mu.Lock()
	rec.tamper = true
	rec.mu.Unlock()
	res, _ := ph.do("POST", "/v1/envelopes", ph.seal(protocol.Msg{Kind: protocol.KindSend, ClientID: "c2", Task: "demo", Body: tampered}), true, nil)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tampered post = %d, want 401 (the request signature covers the body)", res.StatusCode)
	}

	cancel()
	<-done
	flow.mu.Lock()
	for _, s := range flow.sent {
		if strings.Contains(s, tampered) {
			t.Fatal("a tampered message was delivered")
		}
	}
	if len(flow.sent) != 1 || !strings.Contains(flow.sent[0], toSession) {
		t.Fatalf("flow got %q", flow.sent)
	}
	flow.mu.Unlock()

	// The tunnel saw envelopes, never their contents.
	disk, err := os.ReadFile(filepath.Join(home, "mailbox.db"))
	if err != nil {
		t.Fatal(err)
	}
	rec.mu.Lock()
	wire := rec.seen.Bytes()
	rec.mu.Unlock()
	for _, secret := range []string{toSession, fromSession, sessionName, tampered, "Test phone", offer.Secret} {
		if bytes.Contains(wire, []byte(secret)) {
			t.Errorf("the tunnel saw %q in plain text", secret)
		}
		if bytes.Contains(disk, []byte(secret)) {
			t.Errorf("mailbox.db holds %q in plain text", secret)
		}
	}
	if !bytes.Contains(wire, []byte(`"ct":`)) {
		t.Fatal("recorder captured no envelopes; the test isn't looking at the traffic")
	}
	t.Logf("tunnel carried %d bytes; none of it plain text", len(wire))
}

// namedFlow reports one live session with a given name.
type namedFlow struct {
	*fakeFlow
	name string
}

func (f *namedFlow) LiveTasks(context.Context) ([]flowcli.Task, error) {
	return []flowcli.Task{{Slug: "demo", Name: f.name, Live: true}}, nil
}
