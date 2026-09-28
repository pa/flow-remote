package mailbox_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/pa/flow-remote/internal/client"
	"github.com/pa/flow-remote/internal/envelope"
	"github.com/pa/flow-remote/internal/identity"
	"github.com/pa/flow-remote/internal/keystore"
	"github.com/pa/flow-remote/internal/mailbox"
	"github.com/pa/flow-remote/internal/reqsig"
)

// tenant is a Mac with one phone.
type tenant struct {
	mac      *identity.Mac
	relay    *client.Client
	sign     *ecdsa.PrivateKey
	box      *ecdh.PrivateKey
	deviceID string
}

func (r *rig) newTenant(t *testing.T, invite string) *tenant {
	t.Helper()
	mac, _ := identity.LoadOrCreateMac(&keystore.Memory{})
	sign, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	box, _ := ecdh.P256().GenerateKey(rand.Reader)
	tn := &tenant{mac: mac, relay: &client.Client{BaseURL: r.srv.URL, Mac: mac, Now: r.clk.Now},
		sign: sign, box: box, deviceID: "dev-" + envelope.NewID()[:12]}
	if err := tn.relay.Register(context.Background(), "", invite); err != nil {
		t.Fatalf("register with invite: %v", err)
	}
	dev := identity.Device{ID: tn.deviceID, SignPub: envelope.EncodeSignPub(&sign.PublicKey)}
	if err := tn.relay.PutDevice(context.Background(), dev); err != nil {
		t.Fatal(err)
	}
	return tn
}

// phone sends a request signed by this tenant's phone.
func (r *rig) as(tn *tenant, method, path string, body any) (int, []byte) {
	r.t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req, _ := http.NewRequest(method, r.srv.URL+path, bytes.NewReader(raw))
	reqsig.Sign(req, tn.deviceID, tn.sign, raw, r.clk.Now())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.Bytes()
}

func TestInvites(t *testing.T) {
	r := newRig(t)
	r.pair() // the first Mac, registered with the setup token: an admin
	ctx := context.Background()

	stranger, _ := identity.LoadOrCreateMac(&keystore.Memory{})
	sc := &client.Client{BaseURL: r.srv.URL, Mac: stranger, Now: r.clk.Now}
	if err := sc.Register(ctx, "", ""); err == nil {
		t.Fatal("registered with no token or invite")
	}
	if err := sc.Register(ctx, "", "inv-madeup"); err == nil {
		t.Fatal("registered with a made-up invite")
	}

	code, exp, err := r.relay.Invite(ctx)
	if err != nil || code == "" || exp.Sub(r.clk.Now()) != mailbox.InviteTTL {
		t.Fatalf("invite: %q %v %v", code, exp, err)
	}
	if err := sc.Register(ctx, "", code); err != nil {
		t.Fatalf("register with invite: %v", err)
	}
	// Spent: a second Mac can't use it.
	third, _ := identity.LoadOrCreateMac(&keystore.Memory{})
	if err := (&client.Client{BaseURL: r.srv.URL, Mac: third, Now: r.clk.Now}).Register(ctx, "", code); err == nil {
		t.Fatal("invite used twice")
	}
	// Invited Macs aren't admins.
	if _, _, err := sc.Invite(ctx); err == nil {
		t.Fatal("a member Mac created an invite")
	}
	if _, err := sc.Tenants(ctx); err == nil {
		t.Fatal("a member Mac listed tenants")
	}
	list, err := r.relay.Tenants(ctx)
	if err != nil || len(list) != 2 || !list[0].Admin || list[1].Admin {
		t.Fatalf("tenants: %+v %v", list, err)
	}

	// Expired invites don't work.
	code2, _, _ := r.relay.Invite(ctx)
	r.clk.Add(mailbox.InviteTTL + time.Second)
	fourth, _ := identity.LoadOrCreateMac(&keystore.Memory{})
	if err := (&client.Client{BaseURL: r.srv.URL, Mac: fourth, Now: r.clk.Now}).Register(ctx, "", code2); err == nil {
		t.Fatal("expired invite used")
	}
}

func TestTenantsAreIsolated(t *testing.T) {
	r := newRig(t)
	r.pair()
	ctx := context.Background()
	code, _, _ := r.relay.Invite(ctx)
	b := r.newTenant(t, code)
	a := &tenant{mac: r.mac, relay: r.relay, sign: r.sign, box: r.box, deviceID: r.deviceID}

	seal := func(from *ecdsa.PrivateKey, fromID, toID string, to *ecdh.PublicKey) *envelope.Envelope {
		e, _ := envelope.Seal([]byte("x"), from, fromID, toID, to, r.clk.Now().UnixMilli())
		return e
	}

	// A phone can only send to its own Mac.
	if code, _ := r.as(b, "POST", "/v1/envelopes", seal(b.sign, b.deviceID, a.mac.ID, a.mac.Box.PublicKey())); code != http.StatusBadRequest {
		t.Errorf("B's phone sent to A's Mac: %d", code)
	}
	if code, _ := r.as(b, "POST", "/v1/envelopes", seal(b.sign, b.deviceID, b.mac.ID, b.mac.Box.PublicKey())); code != http.StatusAccepted {
		t.Errorf("B's phone to its own Mac: %d", code)
	}

	// A Mac can only send to its own phones.
	if err := b.relay.Post(ctx, seal(b.mac.Sign, b.mac.ID, a.deviceID, a.box.PublicKey())); err == nil {
		t.Error("B's Mac sent to A's phone")
	}

	// Queues are separate.
	if batch, _ := a.relay.List(ctx); len(batch.Envelopes) != 0 {
		t.Errorf("A's Mac sees %d envelopes meant for B", len(batch.Envelopes))
	}
	if batch, _ := b.relay.List(ctx); len(batch.Envelopes) != 1 {
		t.Errorf("B's Mac sees %d of its own envelopes", len(batch.Envelopes))
	}

	// A Mac can't claim, revoke or re-register another tenant's phone.
	if err := b.relay.RevokeDevice(ctx, a.deviceID); err == nil {
		t.Error("B revoked A's phone")
	}
	if code, _ := r.as(a, "GET", "/v1/envelopes", nil); code != http.StatusOK {
		t.Errorf("A's phone after B's revoke attempt: %d", code)
	}
	if err := b.relay.PutDevice(ctx, identity.Device{ID: a.deviceID, SignPub: envelope.EncodeSignPub(&a.sign.PublicKey)}); err == nil {
		t.Error("B claimed A's phone")
	}

	// Pairing slots belong to the Mac that opened them.
	pairID := envelope.NewID()
	if err := a.relay.OpenPair(ctx, pairID); err != nil {
		t.Fatal(err)
	}
	enroll := seal(b.sign, "dev-newphone00", a.mac.ID, a.mac.Box.PublicKey())
	r.phone("POST", "/v1/pair/"+pairID, enroll, false)
	if _, err := b.relay.TakePair(ctx, pairID); err == nil {
		t.Error("B took A's pairing")
	}
	intoA := seal(b.sign, "dev-newphone01", b.mac.ID, b.mac.Box.PublicKey())
	other := envelope.NewID()
	a.relay.OpenPair(ctx, other)
	if code, _ := r.phone("POST", "/v1/pair/"+other, intoA, false); code != http.StatusNotFound {
		t.Errorf("an enrollment for B landed in A's slot: %d", code)
	}

	// Status and poll speed are per tenant.
	_, body := r.as(b, "GET", "/v1/status?mac="+a.mac.ID, nil)
	var st struct{ Macs map[string]any }
	json.Unmarshal(body, &st)
	if _, leaked := st.Macs[a.mac.ID]; leaked || len(st.Macs) != 1 {
		t.Errorf("B's phone saw status for %v", st.Macs)
	}
	r.clk.Add(mailbox.ActiveWindow + time.Second)
	r.as(b, "GET", "/v1/envelopes", nil) // only B's phone is active now
	if batch, _ := a.relay.List(ctx); batch.PollMS != mailbox.PollIdle.Milliseconds() {
		t.Errorf("B's phone sped up A's relay: poll %d", batch.PollMS)
	}
	if batch, _ := b.relay.List(ctx); batch.PollMS != mailbox.PollActive.Milliseconds() {
		t.Errorf("B's relay not sped up by its own phone: poll %d", batch.PollMS)
	}
}

func TestRemoveTenant(t *testing.T) {
	r := newRig(t)
	r.pair()
	ctx := context.Background()
	code, _, _ := r.relay.Invite(ctx)
	b := r.newTenant(t, code)

	if err := b.relay.RemoveTenant(ctx, r.mac.ID); err == nil {
		t.Fatal("a member removed the admin")
	}
	if err := r.relay.RemoveTenant(ctx, r.mac.ID); err == nil {
		t.Fatal("the admin removed itself")
	}
	if err := r.relay.RemoveTenant(ctx, b.mac.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := b.relay.List(ctx); err == nil {
		t.Error("removed Mac still accepted")
	}
	if code, _ := r.as(b, "GET", "/v1/envelopes", nil); code != http.StatusUnauthorized {
		t.Errorf("removed tenant's phone: %d", code)
	}
	if code, _ := r.phone("GET", "/v1/envelopes", nil, true); code != http.StatusOK {
		t.Errorf("the admin's own phone after the removal: %d", code)
	}
}
