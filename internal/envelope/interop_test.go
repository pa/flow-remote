package envelope

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"testing"
	"time"
)

// node runs testdata/interop.mjs, which drives web/js/envelope.js through
// WebCrypto. It proves the phone and the Mac agree on every byte.
func node(t *testing.T, req, resp any) {
	t.Helper()
	bin, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; WebCrypto interop not checked")
	}
	in, _ := json.Marshal(req)
	cmd := exec.Command(bin, "testdata/interop.mjs")
	cmd.Stdin = bytes.NewReader(in)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, stderr.String())
	}
	if err := json.Unmarshal(out, resp); err != nil {
		t.Fatalf("node output %q: %v", out, err)
	}
}

func TestInteropPhoneToMac(t *testing.T) {
	mac := newParty(t)
	var got struct {
		SignPub string   `json:"sign_pub"`
		Env     Envelope `json:"env"`
	}
	node(t, map[string]any{
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
	mac := newParty(t)
	var phone struct {
		SignPub string          `json:"sign_pub"`
		BoxPub  string          `json:"box_pub"`
		BoxJWK  json.RawMessage `json:"box_jwk"`
	}
	node(t, map[string]any{"mode": "gen"}, &phone)

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
	node(t, map[string]any{
		"mode": "open", "env": e, "box_jwk": phone.BoxJWK, "box_pub": phone.BoxPub,
		"mac_sign_pub": EncodeSignPub(&mac.sign.PublicKey),
	}, &got)
	if got.Plaintext != "reply from go ✓" {
		t.Fatalf("WebCrypto opened %q", got.Plaintext)
	}
}
