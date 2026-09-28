package envelope_test

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	. "github.com/pa/flow-remote/internal/envelope"
	"github.com/pa/flow-remote/internal/interop"
)

type keys struct {
	sign *ecdsa.PrivateKey
	box  *ecdh.PrivateKey
}

func newKeys(t *testing.T) keys {
	s, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := ecdh.P256().GenerateKey(rand.Reader)
	return keys{s, b}
}

func TestInteropPhoneToMac(t *testing.T) {
	mac := newKeys(t)
	var got struct {
		SignPub string   `json:"sign_pub"`
		Env     Envelope `json:"env"`
	}
	interop.Node(t, map[string]any{
		"mode": "seal", "plaintext": "from webcrypto ✓",
		"mac_box_pub": EncodeBoxPub(mac.box.PublicKey()), "ts": time.Now().UnixMilli(),
	}, &got)

	pub, err := ParseSignPub(got.SignPub)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(&got.Env, pub); err != nil {
		t.Fatalf("Go could not verify a WebCrypto envelope: %v", err)
	}
	pt, err := Open(&got.Env, mac.box)
	if err != nil {
		t.Fatalf("Go could not open a WebCrypto envelope: %v", err)
	}
	if string(pt) != "from webcrypto ✓" {
		t.Fatalf("got %q", pt)
	}
}

func TestInteropMacToPhone(t *testing.T) {
	mac := newKeys(t)
	var phone struct {
		SignPub string          `json:"sign_pub"`
		BoxPub  string          `json:"box_pub"`
		BoxJWK  json.RawMessage `json:"box_jwk"`
	}
	interop.Node(t, map[string]any{"mode": "gen"}, &phone)

	boxPub, err := ParseBoxPub(phone.BoxPub)
	if err != nil {
		t.Fatal(err)
	}
	e, err := Seal([]byte("reply from go ✓"), mac.sign, "mac", "dev-js", boxPub, time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Plaintext string `json:"plaintext"`
	}
	interop.Node(t, map[string]any{
		"mode": "open", "env": e, "box_jwk": phone.BoxJWK, "box_pub": phone.BoxPub,
		"mac_sign_pub": EncodeSignPub(&mac.sign.PublicKey),
	}, &got)
	if got.Plaintext != "reply from go ✓" {
		t.Fatalf("WebCrypto opened %q", got.Plaintext)
	}
}
