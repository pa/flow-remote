package relay

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pa/flow-remote/internal/client"
	"github.com/pa/flow-remote/internal/envelope"
	"github.com/pa/flow-remote/internal/flowcli"
	"github.com/pa/flow-remote/internal/identity"
	"github.com/pa/flow-remote/internal/keystore"
	"github.com/pa/flow-remote/internal/mailbox"
	"github.com/pa/flow-remote/internal/protocol"
	"github.com/pa/flow-remote/internal/reqsig"
)

type fakeFlow struct {
	mu     sync.Mutex
	tasks  []flowcli.Task
	sent   []string // "slug|body|replyTo"
	unread []flowcli.Mail
	read   []string
}

func (f *fakeFlow) LiveTasks(context.Context) ([]flowcli.Task, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]flowcli.Task(nil), f.tasks...), nil
}

func (f *fakeFlow) Message(_ context.Context, slug, body, replyTo string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, slug+"|"+body+"|"+replyTo)
	return "abc123", nil
}

func (f *fakeFlow) Inbox(context.Context) ([]flowcli.Mail, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]flowcli.Mail(nil), f.unread...), nil
}

func (f *fakeFlow) MarkRead(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.read = append(f.read, id)
	return nil
}

type rig struct {
	t             *testing.T
	now           time.Time
	srv           *httptest.Server
	store         *mailbox.Memory
	relay         *Relay
	relayKeystore keystore.Store
	flow          *fakeFlow
	audit         *bytes.Buffer
	sign          *ecdsa.PrivateKey
	box           *ecdh.PrivateKey
	device        identity.Device
}

func newRig(t *testing.T) *rig {
	r := &rig{t: t, now: time.Now(), audit: &bytes.Buffer{}}
	clock := func() time.Time { return r.now }
	store := mailbox.NewMemory()
	r.store = store
	r.srv = httptest.NewServer((&mailbox.Server{Store: store, Now: clock}).Handler())
	t.Cleanup(r.srv.Close)

	ks := &keystore.Memory{}
	r.relayKeystore = ks
	mac, _ := identity.LoadOrCreateMac(ks)
	devs, _ := identity.LoadDevices(ks)
	r.sign, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	r.box, _ = ecdh.P256().GenerateKey(rand.Reader)
	r.device = identity.Device{
		ID: "dev-" + envelope.NewID()[:12], Name: "phone",
		SignPub: envelope.EncodeSignPub(&r.sign.PublicKey), BoxPub: envelope.EncodeBoxPub(r.box.PublicKey()),
		EnrolledAt: r.now,
	}
	devs.Enroll(r.device)
	store.RegisterMac(context.Background(), mailbox.Mac{ID: mac.ID, SignPub: mac.SignPub(), Admin: true, Created: r.now})
	store.PutDevice(context.Background(), mac.ID, r.device.ID, r.device.SignPub)

	r.flow = &fakeFlow{tasks: []flowcli.Task{
		{Slug: "phone-dispatch", Name: "dispatcher", Live: true},
		{Slug: "floci-local-apply", Name: "floci", Tags: []string{"personal"}, Live: true},
		{Slug: "fragile-eol-packages", Name: "customer work", Tags: []string{"fragile"}, Live: true},
	}}
	st, _ := LoadState("")
	r.relay = &Relay{
		Mac: mac, Devices: devs, Guard: envelope.NewMemoryGuard(),
		Mailbox: &client.Client{BaseURL: r.srv.URL, Mac: mac, Now: clock},
		Flow:    r.flow,
		State:   st, Audit: r.audit, Now: clock,
	}
	return r
}

// phoneDo sends a request signed with the phone's device key.
func (r *rig) phoneDo(method, path string, body any) *http.Response {
	r.t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req, _ := http.NewRequest(method, r.srv.URL+path, bytes.NewReader(raw))
	reqsig.Sign(req, r.device.ID, r.sign, raw, r.now)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	return resp
}

func (r *rig) phonePost(e *envelope.Envelope) {
	r.t.Helper()
	raw, _ := json.Marshal(e)
	req, _ := http.NewRequest("POST", r.srv.URL+"/v1/envelopes", bytes.NewReader(raw))
	reqsig.Sign(req, r.device.ID, r.sign, raw, r.now)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusAccepted {
		r.t.Fatalf("phone post: %v %v", err, resp.Status)
	}
}

func (r *rig) phoneSend(m protocol.Msg, ts time.Time) *envelope.Envelope {
	pt, _ := json.Marshal(m)
	e, _ := envelope.Seal(pt, r.sign, r.device.ID, r.relay.Mac.ID, r.relay.Mac.Box.PublicKey(), ts.UnixMilli())
	r.phonePost(e)
	return e
}

// inbox fetches, verifies and opens everything waiting for the phone.
func (r *rig) inbox() []protocol.Msg {
	r.t.Helper()
	resp := r.phoneDo("GET", "/v1/envelopes", nil)
	var got struct{ Envelopes []mailbox.Record }
	json.NewDecoder(resp.Body).Decode(&got)
	var out, ids = []protocol.Msg{}, []string{}
	for _, rec := range got.Envelopes {
		e := rec.Env
		if err := envelope.Verify(&e, &r.relay.Mac.Sign.PublicKey); err != nil {
			r.t.Fatalf("phone got an envelope the Mac didn't sign: %v", err)
		}
		pt, err := envelope.Open(&e, r.box)
		if err != nil {
			r.t.Fatal(err)
		}
		var m protocol.Msg
		json.Unmarshal(pt, &m)
		out = append(out, m)
		ids = append(ids, e.ID)
	}
	r.phoneDo("POST", "/v1/ack", map[string]any{"ids": ids})
	return out
}

func (r *rig) tick() time.Duration {
	r.t.Helper()
	d, err := r.relay.Tick(context.Background())
	if err != nil {
		r.t.Fatal(err)
	}
	return d
}

func byKind(ms []protocol.Msg, kind string) []protocol.Msg {
	var out []protocol.Msg
	for _, m := range ms {
		if m.Kind == kind {
			out = append(out, m)
		}
	}
	return out
}

func TestDeliverAndStatus(t *testing.T) {
	r := newRig(t)
	r.phoneSend(protocol.Msg{Kind: protocol.KindSend, ClientID: "c1", Task: "phone-dispatch", Body: "what's waiting on me?"}, r.now.Add(-5*time.Minute))
	if poll := r.tick(); poll != mailbox.PollActive {
		t.Fatalf("poll = %v", poll)
	}
	if len(r.flow.sent) != 1 || r.flow.sent[0] != "phone-dispatch|[phone · sent 5m ago] what's waiting on me?|" {
		t.Fatalf("flow got %q", r.flow.sent)
	}
	got := r.inbox()
	st := byKind(got, protocol.KindStatus)
	if len(st) != 1 || st[0].State != protocol.Delivered || st[0].ClientID != "c1" || st[0].FlowID != "abc123" {
		t.Fatalf("status %+v", st)
	}
	sess := byKind(got, protocol.KindSessions)
	if len(sess) != 1 || len(sess[0].Sessions) != 3 {
		t.Fatalf("sessions %+v", sess)
	}
	can := map[string]bool{}
	for _, s := range sess[0].Sessions {
		can[s.Slug] = s.CanSend
	}
	// Any paired phone may message any live session.
	if !can["phone-dispatch"] || !can["floci-local-apply"] || !can["fragile-eol-packages"] {
		t.Fatalf("can_send %v", can)
	}
}

func TestRefusals(t *testing.T) {
	r := newRig(t)
	cases := map[string]protocol.Msg{
		"not running": {Kind: protocol.KindSend, ClientID: "b", Task: "some-other-task", Body: "x"},
		"bad slug":    {Kind: protocol.KindSend, ClientID: "c", Task: "../etc; rm", Body: "x"},
		"empty":       {Kind: protocol.KindSend, ClientID: "d", Task: "phone-dispatch", Body: ""},
	}
	for _, m := range cases {
		r.phoneSend(m, r.now)
	}
	r.tick()
	if len(r.flow.sent) != 0 {
		t.Fatalf("flow got %q", r.flow.sent)
	}
	st := byKind(r.inbox(), protocol.KindStatus)
	if len(st) != len(cases) {
		t.Fatalf("got %d statuses", len(st))
	}
	for _, s := range st {
		if s.State != protocol.Refused || s.Reason == "" {
			t.Errorf("%s: %+v", s.ClientID, s)
		}
	}
}

func TestReplayAndStrangers(t *testing.T) {
	r := newRig(t)
	e := r.phoneSend(protocol.Msg{Kind: protocol.KindSend, Task: "phone-dispatch", Body: "once"}, r.now)
	r.tick()
	// The mailbox deleted it on ack, so an attacker who kept a copy can
	// post it again. The relay's guard must catch it.
	r.phonePost(e)
	r.tick()
	if len(r.flow.sent) != 1 {
		t.Fatalf("replayed envelope delivered: %q", r.flow.sent)
	}

	// The mailbox refuses these two itself. The relay mustn't rely on that,
	// since the mailbox is untrusted, so plant them as a compromised
	// mailbox would.
	// A device that was never enrolled.
	s2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pt, _ := json.Marshal(protocol.Msg{Kind: protocol.KindSend, Task: "phone-dispatch", Body: "hi"})
	stranger, _ := envelope.Seal(pt, s2, "dev-stranger00", r.relay.Mac.ID, r.relay.Mac.Box.PublicKey(), r.now.UnixMilli())
	r.store.PutEnvelope(context.Background(), *stranger, r.now)

	// An enrolled device id, signed by someone else's key.
	forged, _ := envelope.Seal(pt, s2, r.device.ID, r.relay.Mac.ID, r.relay.Mac.Box.PublicKey(), r.now.UnixMilli())
	r.store.PutEnvelope(context.Background(), *forged, r.now)
	r.tick()
	// The stranger is kept for one round in case it's a phone paired a
	// moment ago; the next round reads the registry again and drops it.
	if n, _ := r.store.CountEnvelopes(context.Background(), r.relay.Mac.ID, r.now); n != 1 {
		t.Fatalf("after one round, %d envelopes wait; want the stranger's", n)
	}
	r.now = r.now.Add(reloadMin + time.Second)
	r.tick()
	if n, _ := r.store.CountEnvelopes(context.Background(), r.relay.Mac.ID, r.now); n != 0 {
		t.Fatalf("stranger not dropped after a fresh read: %d waiting", n)
	}
	if len(r.flow.sent) != 1 {
		t.Fatalf("stranger or forgery delivered: %q", r.flow.sent)
	}
	for _, want := range []string{"already seen", "unknown or revoked device", "bad signature"} {
		if !strings.Contains(r.audit.String(), want) {
			t.Errorf("audit log missing %q:\n%s", want, r.audit)
		}
	}
	if strings.Contains(r.audit.String(), "once") {
		t.Error("audit log contains a message body")
	}
}

func TestMailForwardedOnceAndReplyMarksRead(t *testing.T) {
	r := newRig(t)
	r.flow.unread = []flowcli.Mail{
		{ID: "m1", Kind: "message", From: flowcli.Address{Assignee: "user", TaskSlug: "floci-local-apply"}, Body: "which provider version?", Urgent: true, CreatedAt: r.now},
		{ID: "m0", Kind: "message", From: flowcli.Address{Assignee: "user", TaskSlug: "floci-local-apply"}, Body: "ancient", CreatedAt: r.now.Add(-30 * 24 * time.Hour)},
	}
	r.tick()
	r.tick()
	mail := byKind(r.inbox(), protocol.KindMail)
	if len(mail) != 1 || mail[0].Mail.FlowID != "m1" || !mail[0].Mail.Urgent {
		t.Fatalf("mail %+v", mail)
	}

	r.phoneSend(protocol.Msg{Kind: protocol.KindSend, Task: "floci-local-apply", Body: "5.x", ReplyTo: "m1"}, r.now)
	r.tick()
	if len(r.flow.read) != 1 || r.flow.read[0] != "m1" {
		t.Fatalf("marked read: %v", r.flow.read)
	}
	if !strings.HasSuffix(r.flow.sent[0], "|m1") {
		t.Fatalf("reply-to not passed: %q", r.flow.sent[0])
	}
}

// Something else reading the human's queue (a dispatch session's `flow
// inbox pop`) marks a reply read before the relay looks. It must still
// reach the phone; mail read before the relay began keeping track mustn't.
func TestReplyReadElsewhereStillForwarded(t *testing.T) {
	r := newRig(t)
	from := flowcli.Address{Assignee: "user", TaskSlug: "floci-local-apply"}
	r.flow.unread = []flowcli.Mail{
		{ID: "old1", Kind: "message", From: from, Body: "read before the relay ran", Mail: "read", CreatedAt: r.now.Add(-time.Hour)},
	}
	r.tick() // starts keeping track
	r.now = r.now.Add(10 * time.Second)
	r.flow.mu.Lock()
	r.flow.unread = append(r.flow.unread,
		flowcli.Mail{ID: "new1", Kind: "message", From: from, Body: "stats of what?", Mail: "read", CreatedAt: r.now},
		flowcli.Mail{ID: "new2", Kind: "message", From: from, Body: "build 26A428", Mail: "unread", CreatedAt: r.now})
	r.flow.mu.Unlock()
	r.tick()
	got := map[string]bool{}
	for _, m := range byKind(r.inbox(), protocol.KindMail) {
		got[m.Mail.FlowID] = true
	}
	if !got["new1"] || !got["new2"] || got["old1"] {
		t.Fatalf("forwarded %v; want new1 and new2, not old1", got)
	}
}

func TestSessionsOnlySentWhenChanged(t *testing.T) {
	r := newRig(t)
	r.tick()
	r.now = r.now.Add(sessionsEvery + time.Second)
	r.tick()
	if n := len(byKind(r.inbox(), protocol.KindSessions)); n != 1 {
		t.Fatalf("unchanged list sent %d times", n)
	}
	r.phoneSend(protocol.Msg{Kind: protocol.KindSync}, r.now)
	r.tick()
	if n := len(byKind(r.inbox(), protocol.KindSessions)); n != 1 {
		t.Fatalf("sync answered %d times", n)
	}
}

// A phone paired after the relay started must be picked up without a
// restart: pairing runs in another process and writes the Keychain.
func TestPicksUpPhonesPairedAfterStart(t *testing.T) {
	r := newRig(t)
	ks := r.relayKeystore
	// Enroll a second phone the way `flow-remote pair` would: a separate
	// Devices loaded from the same keystore.
	other, _ := identity.LoadDevices(ks)
	s2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b2, _ := ecdh.P256().GenerateKey(rand.Reader)
	dev2 := identity.Device{ID: "dev-latecomer00", Name: "second", SignPub: envelope.EncodeSignPub(&s2.PublicKey), BoxPub: envelope.EncodeBoxPub(b2.PublicKey()), EnrolledAt: r.now}
	if err := other.Enroll(dev2); err != nil {
		t.Fatal(err)
	}
	r.store.PutDevice(context.Background(), r.relay.Mac.ID, dev2.ID, dev2.SignPub)

	pt, _ := json.Marshal(protocol.Msg{Kind: protocol.KindSend, Task: "phone-dispatch", Body: "hi from the new phone"})
	e, _ := envelope.Seal(pt, s2, dev2.ID, r.relay.Mac.ID, r.relay.Mac.Box.PublicKey(), r.now.UnixMilli())
	r.store.PutEnvelope(context.Background(), *e, r.now)
	r.tick()
	if len(r.flow.sent) != 1 {
		t.Fatalf("the relay ignored a phone paired after it started: %q\n%s", r.flow.sent, r.audit)
	}
}

func TestStaleSendIsHeldForResend(t *testing.T) {
	r := newRig(t)
	r.phoneSend(protocol.Msg{Kind: protocol.KindSend, ClientID: "old", Task: "phone-dispatch", Body: "go ahead and push"}, r.now.Add(-3*time.Hour))
	r.tick()
	if len(r.flow.sent) != 0 {
		t.Fatalf("a 3-hour-old command was delivered: %q", r.flow.sent)
	}
	st := byKind(r.inbox(), protocol.KindStatus)
	if len(st) != 1 || st[0].State != protocol.Stale || !strings.Contains(st[0].Reason, "3h") {
		t.Fatalf("status %+v", st)
	}
}

func TestReplyToMustMatchForwardedMail(t *testing.T) {
	r := newRig(t)
	r.flow.unread = []flowcli.Mail{{ID: "abc123", Kind: "message", From: flowcli.Address{Assignee: "user", TaskSlug: "floci-local-apply"}, Body: "q?", CreatedAt: r.now}}
	r.tick()
	// Replying from another session, or to an id never forwarded, is refused.
	r.phoneSend(protocol.Msg{Kind: protocol.KindSend, ClientID: "a", Task: "phone-dispatch", Body: "x", ReplyTo: "abc123"}, r.now)
	r.phoneSend(protocol.Msg{Kind: protocol.KindSend, ClientID: "b", Task: "floci-local-apply", Body: "x", ReplyTo: "--urgent"}, r.now)
	r.tick()
	if len(r.flow.sent) != 0 || len(r.flow.read) != 0 {
		t.Fatalf("mismatched reply_to reached flow: sent %q read %q", r.flow.sent, r.flow.read)
	}
}

// hostileMailbox suggests whatever poll interval it likes.
type hostileMailbox struct{ pollMS int64 }

func (h hostileMailbox) List(context.Context) (client.Batch, error) {
	return client.Batch{PollMS: h.pollMS}, nil
}
func (hostileMailbox) Post(context.Context, *envelope.Envelope) error { return nil }
func (hostileMailbox) Ack(context.Context, []string) error            { return nil }

func TestPollIntervalIsClamped(t *testing.T) {
	r := newRig(t)
	for ms, want := range map[int64]time.Duration{1: minPoll, 0: minPoll, 3000: 3 * time.Second, 86_400_000: maxPoll} {
		r.relay.Mailbox = hostileMailbox{pollMS: ms}
		if got := r.tick(); got != want {
			t.Errorf("poll_ms=%d: waited %v, want %v", ms, got, want)
		}
	}
}

func TestAge(t *testing.T) {
	for d, want := range map[time.Duration]string{
		10 * time.Second:             "just now",
		5 * time.Minute:              "sent 5m ago",
		2*time.Hour + 14*time.Minute: "sent 2h 14m ago",
		50 * time.Hour:               "sent 2d 2h ago",
	} {
		if got := age(d); got != want {
			t.Errorf("age(%v) = %q, want %q", d, got, want)
		}
	}
}
