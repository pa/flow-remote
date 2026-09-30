package pairing

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/pa/flow-remote/internal/envelope"
	"github.com/pa/flow-remote/internal/identity"
	"github.com/pa/flow-remote/internal/interop"
	"github.com/pa/flow-remote/internal/keystore"
)

func newMac(t *testing.T) *identity.Mac {
	t.Helper()
	m, err := identity.LoadOrCreateMac(&keystore.Memory{})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// phone builds an enrollment the way web/js/pairing.js does, with knobs
// for breaking it.
type phone struct {
	sign     *ecdsa.PrivateKey
	box      *ecdh.PrivateKey
	deviceID string
}

func newPhone() phone {
	s, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := ecdh.P256().GenerateKey(rand.Reader)
	return phone{s, b, "dev-" + envelope.NewID()[:12]}
}

func (p phone) enroll(t *testing.T, o Offer, secret []byte, now time.Time, edit func(*Enrollment), signer *ecdsa.PrivateKey) *envelope.Envelope {
	t.Helper()
	en := Enrollment{
		Kind: "enroll", PairID: o.PairID, DeviceID: p.deviceID, Name: "Test iPhone",
		SignPub: envelope.EncodeSignPub(&p.sign.PublicKey), BoxPub: envelope.EncodeBoxPub(p.box.PublicKey()),
	}
	m := hmac.New(sha256.New, secret)
	m.Write(en.MACInput())
	en.MAC = envelope.Encode(m.Sum(nil))
	if edit != nil {
		edit(&en)
	}
	if signer == nil {
		signer = p.sign
	}
	macBox, _ := envelope.ParseBoxPub(o.MacBoxPub)
	pt, _ := json.Marshal(en)
	e, err := envelope.Seal(pt, signer, envelope.Route{From: p.deviceID, To: o.MacID}, macBox, now.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestAccept(t *testing.T) {
	mac := newMac(t)
	now := time.Now()
	o := NewOffer(mac, "https://mailbox.example", now)
	secret, _ := envelope.Decode(o.Secret)
	p := newPhone()

	dev, err := Accept(o, mac, p.enroll(t, o, secret, now, nil, nil), now.Add(30*time.Second))
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if dev.ID != p.deviceID || dev.Name != "Test iPhone" {
		t.Fatalf("got %+v", dev)
	}
	if dev.Fingerprint() != identity.Fingerprint(envelope.EncodeSignPub(&p.sign.PublicKey), envelope.EncodeBoxPub(p.box.PublicKey())) {
		t.Fatal("fingerprint mismatch")
	}
}

func TestAcceptRejects(t *testing.T) {
	mac := newMac(t)
	now := time.Now()
	o := NewOffer(mac, "", now)
	secret, _ := envelope.Decode(o.Secret)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	cases := []struct {
		name   string
		secret []byte
		edit   func(*Enrollment)
		signer *ecdsa.PrivateKey
		at     time.Time
		want   error
	}{
		{"expired", secret, nil, nil, now.Add(TTL + time.Second), ErrExpired},
		{"wrong code", []byte("not the secret!!"), nil, nil, now, ErrBadMAC},
		{"other pair id", secret, func(e *Enrollment) { e.PairID = "x" }, nil, now, ErrMismatch},
		{"name changed after MAC", secret, func(e *Enrollment) { e.Name = "evil" }, nil, now, ErrBadMAC},
		{"key swapped after MAC", secret, func(e *Enrollment) { e.SignPub = envelope.EncodeSignPub(&other.PublicKey) }, nil, now, ErrBadMAC},
		{"signed by a key it doesn't enroll", secret, nil, other, now, envelope.ErrSignature},
	}
	for _, c := range cases {
		p := newPhone()
		e := p.enroll(t, o, c.secret, now, c.edit, c.signer)
		if _, err := Accept(o, mac, e, c.at); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
}

func TestCleanName(t *testing.T) {
	if got := cleanName("iPhone\x1b[31m red"); got != "iPhone[31m red" {
		t.Fatalf("escape not stripped: %q", got)
	}
	if got := cleanName(""); got != "unnamed device" {
		t.Fatalf("empty: %q", got)
	}
}

// The real phone code scans a Go offer link and enrolls; Go accepts it and
// both sides show the same fingerprints.
func TestInteropEnroll(t *testing.T) {
	mac := newMac(t)
	now := time.Now()
	o := NewOffer(mac, "https://mailbox.example", now)
	var got struct {
		Env            envelope.Envelope `json:"env"`
		DeviceID       string            `json:"device_id"`
		Fingerprint    string            `json:"fingerprint"`
		MacFingerprint string            `json:"mac_fingerprint"`
	}
	interop.Node(t, map[string]any{
		"mode": "enroll", "link": o.Link("https://flow-remote.example"), "name": "Node phone", "now": now.UnixMilli(),
	}, &got)

	dev, err := Accept(o, mac, &got.Env, now)
	if err != nil {
		t.Fatalf("Go rejected a WebCrypto enrollment: %v", err)
	}
	if dev.ID != got.DeviceID || dev.Name != "Node phone" {
		t.Fatalf("device %+v", dev)
	}
	if dev.Fingerprint() != got.Fingerprint {
		t.Fatalf("device fingerprint: Go %q, phone %q", dev.Fingerprint(), got.Fingerprint)
	}
	if mac.Fingerprint() != got.MacFingerprint {
		t.Fatalf("mac fingerprint: Go %q, phone %q", mac.Fingerprint(), got.MacFingerprint)
	}
}
