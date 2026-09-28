package reqsig_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pa/flow-remote/internal/envelope"
	"github.com/pa/flow-remote/internal/interop"
	"github.com/pa/flow-remote/internal/reqsig"
)

func keyOnly(want string, k *ecdsa.PublicKey) func(string) (*ecdsa.PublicKey, error) {
	return func(id string) (*ecdsa.PublicKey, error) {
		if id != want {
			return nil, errors.New("unknown")
		}
		return k, nil
	}
}

func TestSignVerify(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	mk := func(method, url, body string) *http.Request {
		r, _ := http.NewRequest(method, url, strings.NewReader(body))
		return r
	}
	r := mk("POST", "http://x/v1/ack?a=1", `{"ids":[]}`)
	reqsig.Sign(r, "dev-a", k, []byte(`{"ids":[]}`), now)
	if id, err := reqsig.Verify(r, keyOnly("dev-a", &k.PublicKey), now); err != nil || id != "dev-a" {
		t.Fatalf("verify: %q %v", id, err)
	}

	cases := map[string]func() *http.Request{
		"other path": func() *http.Request {
			r := mk("POST", "http://x/v1/ack?a=2", `{"ids":[]}`)
			reqsig.Sign(r, "dev-a", k, []byte(`{"ids":[]}`), now)
			r.URL.RawQuery = "a=1&b=2"
			return r
		},
		"other method": func() *http.Request {
			r := mk("GET", "http://x/v1/ack", "")
			reqsig.Sign(r, "dev-a", k, nil, now)
			r.Method = "DELETE"
			return r
		},
		"stale": func() *http.Request {
			r := mk("GET", "http://x/v1/ack", "")
			reqsig.Sign(r, "dev-a", k, nil, now.Add(-3*time.Minute))
			return r
		},
		"unknown id": func() *http.Request {
			r := mk("GET", "http://x/v1/ack", "")
			reqsig.Sign(r, "dev-b", k, nil, now)
			return r
		},
	}
	for name, mkReq := range cases {
		if _, err := reqsig.Verify(mkReq(), keyOnly("dev-a", &k.PublicKey), now); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

// The phone's WebCrypto signature must verify in Go.
func TestInteropPhoneSignature(t *testing.T) {
	now := time.Now()
	body := `{"ids":["x"]}`
	var got struct {
		SignPub string            `json:"sign_pub"`
		Headers map[string]string `json:"headers"`
	}
	interop.Node(t, map[string]any{
		"mode": "signreq", "method": "POST", "path": "/v1/status?mac=mac-1", "body": body,
		"id": "dev-js", "ts": now.UnixMilli(),
	}, &got)
	pub, err := envelope.ParseSignPub(got.SignPub)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := http.NewRequest("POST", "http://mailbox/v1/status?mac=mac-1", strings.NewReader(body))
	for k, v := range got.Headers {
		r.Header.Set(k, v)
	}
	if id, err := reqsig.Verify(r, keyOnly("dev-js", pub), now); err != nil || id != "dev-js" {
		t.Fatalf("Go rejected the phone's signature: %q %v", id, err)
	}
}
