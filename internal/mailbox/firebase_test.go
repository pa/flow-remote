package mailbox

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFirebaseVerifier(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=600")
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kid": "k1", "kty": "RSA",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	defer jwks.Close()

	now := time.Now()
	v := &FirebaseVerifier{ProjectID: "proj", TenantID: "tenant-1", JWKSURL: jwks.URL}
	good := map[string]any{
		"iss": "https://securetoken.google.com/proj", "aud": "proj", "sub": "u1",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"email": "owner@example.com", "email_verified": true,
		"firebase": map[string]any{"tenant": "tenant-1"},
	}
	mint := func(claims map[string]any, kid string, k *rsa.PrivateKey) string {
		h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid})
		c, _ := json.Marshal(claims)
		in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
		sum := sha256.Sum256([]byte(in))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
		return in + "." + base64.RawURLEncoding.EncodeToString(sig)
	}
	with := func(k string, val any) map[string]any {
		c := map[string]any{}
		for kk, vv := range good {
			c[kk] = vv
		}
		c[k] = val
		return c
	}

	c, err := v.Verify(mint(good, "k1", key), now)
	if err != nil || c.Email != "owner@example.com" {
		t.Fatalf("good token: %v", err)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	bad := map[string]string{
		"wrong key":     mint(good, "k1", other),
		"unknown kid":   mint(good, "k2", key),
		"other project": mint(with("aud", "evil"), "k1", key),
		"expired":       mint(with("exp", now.Add(-time.Hour).Unix()), "k1", key),
		"other tenant":  mint(with("firebase", map[string]any{"tenant": "t2"}), "k1", key),
		"no tenant":     mint(with("firebase", map[string]any{}), "k1", key),
		"unverified":    mint(with("email_verified", false), "k1", key),
		"not a jwt":     "abc",
	}
	for name, tok := range bad {
		if _, err := v.Verify(tok, now); !errors.Is(err, ErrToken) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}
