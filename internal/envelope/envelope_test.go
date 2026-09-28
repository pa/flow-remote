package envelope

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

type party struct {
	sign *ecdsa.PrivateKey
	box  *ecdh.PrivateKey
}

func newParty(t *testing.T) party {
	t.Helper()
	s, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return party{s, b}
}

func TestSealVerifyOpen(t *testing.T) {
	phone, mac := newParty(t), newParty(t)
	now := time.Now().UnixMilli()
	e, err := Seal([]byte("hello mac"), phone.sign, "dev-1", "mac", mac.box.PublicKey(), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(e, &phone.sign.PublicKey); err != nil {
		t.Fatalf("verify: %v", err)
	}
	pt, err := Open(e, mac.box)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(pt) != "hello mac" {
		t.Fatalf("got %q", pt)
	}
}

func TestTamperIsRejected(t *testing.T) {
	phone, mac := newParty(t), newParty(t)
	fresh := func() *Envelope {
		e, err := Seal([]byte("x"), phone.sign, "dev-1", "mac", mac.box.PublicKey(), time.Now().UnixMilli())
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	cases := map[string]func(*Envelope){
		"to":   func(e *Envelope) { e.To = "other" },
		"from": func(e *Envelope) { e.From = "dev-2" },
		"ts":   func(e *Envelope) { e.TS++ },
		"id":   func(e *Envelope) { e.ID = NewID() },
		"ct":   func(e *Envelope) { e.CT = fresh().CT },
		"epk":  func(e *Envelope) { e.EPK = fresh().EPK },
	}
	for name, mutate := range cases {
		e := fresh()
		mutate(e)
		if err := Verify(e, &phone.sign.PublicKey); !errors.Is(err, ErrSignature) {
			t.Errorf("%s: verify = %v, want ErrSignature", name, err)
		}
	}
}

func TestWrongSignerAndWrongRecipient(t *testing.T) {
	phone, mac, other := newParty(t), newParty(t), newParty(t)
	e, _ := Seal([]byte("x"), phone.sign, "dev-1", "mac", mac.box.PublicKey(), time.Now().UnixMilli())
	if err := Verify(e, &other.sign.PublicKey); !errors.Is(err, ErrSignature) {
		t.Fatalf("other signer verified: %v", err)
	}
	if _, err := Open(e, other.box); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("other recipient opened: %v", err)
	}
}

// A mailbox that re-signs nothing can still try to splice a ciphertext into
// a new header. The GCM tag binds the header, so Open must fail even if
// the signature check were skipped.
func TestHeaderBoundIntoCiphertext(t *testing.T) {
	phone, mac := newParty(t), newParty(t)
	e, _ := Seal([]byte("x"), phone.sign, "dev-1", "mac", mac.box.PublicKey(), time.Now().UnixMilli())
	e.To = "mac-2"
	if _, err := Open(e, mac.box); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("spliced header opened: %v", err)
	}
}

func TestGuard(t *testing.T) {
	phone, mac := newParty(t), newParty(t)
	now := time.Now()
	path := filepath.Join(t.TempDir(), "seen.json")
	g, err := LoadGuard(path)
	if err != nil {
		t.Fatal(err)
	}
	seal := func(ts time.Time) *Envelope {
		e, _ := Seal([]byte("x"), phone.sign, "dev-1", "mac", mac.box.PublicKey(), ts.UnixMilli())
		return e
	}

	e := seal(now)
	if err := g.Admit(e, now); err != nil {
		t.Fatalf("first admit: %v", err)
	}
	if err := g.Admit(e, now); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay = %v", err)
	}

	// Survives a restart.
	g2, err := LoadGuard(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := g2.Admit(e, now.Add(time.Hour)); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay after reload = %v", err)
	}

	// A message that waited two days while the Mac slept is accepted.
	if err := g2.Admit(seal(now.Add(-48*time.Hour)), now); err != nil {
		t.Fatalf("2-day-old admit: %v", err)
	}
	if err := g2.Admit(seal(now.Add(-8*24*time.Hour)), now); !errors.Is(err, ErrExpired) {
		t.Fatalf("8-day-old = %v", err)
	}
	if err := g2.Admit(seal(now.Add(10*time.Minute)), now); !errors.Is(err, ErrFuture) {
		t.Fatalf("future = %v", err)
	}
	if err := g2.Admit(seal(now.Add(2*time.Minute)), now); err != nil {
		t.Fatalf("within skew: %v", err)
	}
}

func TestKeyEncodingRoundTrip(t *testing.T) {
	p := newParty(t)
	sp, err := ParseSignPub(EncodeSignPub(&p.sign.PublicKey))
	if err != nil || !sp.Equal(&p.sign.PublicKey) {
		t.Fatalf("sign pub round trip: %v", err)
	}
	bp, err := ParseBoxPub(EncodeBoxPub(p.box.PublicKey()))
	if err != nil || !bp.Equal(p.box.PublicKey()) {
		t.Fatalf("box pub round trip: %v", err)
	}
}
