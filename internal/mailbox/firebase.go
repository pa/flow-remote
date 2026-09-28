package mailbox

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const googleJWKS = "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"

var ErrToken = errors.New("mailbox: bad sign-in token")

// Claims are the parts of a Firebase / Identity Platform ID token the
// mailbox uses.
type Claims struct {
	Iss           string `json:"iss"`
	Aud           string `json:"aud"`
	Sub           string `json:"sub"`
	Exp           int64  `json:"exp"`
	Iat           int64  `json:"iat"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Firebase      struct {
		Tenant string `json:"tenant"`
	} `json:"firebase"`
}

// FirebaseVerifier checks RS256 ID tokens against Google's published keys.
type FirebaseVerifier struct {
	ProjectID string
	TenantID  string // "" when the app has no tenant
	JWKSURL   string // defaults to googleJWKS
	Client    *http.Client

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	expires   time.Time
	lastFetch time.Time
}

func (v *FirebaseVerifier) Verify(token string, now time.Time) (Claims, error) {
	var c Claims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return c, ErrToken
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSeg(parts[0], &hdr); err != nil || hdr.Alg != "RS256" {
		return c, ErrToken
	}
	key, err := v.key(hdr.Kid, now)
	if err != nil {
		return c, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return c, ErrToken
	}
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, h[:], sig) != nil {
		return c, ErrToken
	}
	if err := decodeSeg(parts[1], &c); err != nil {
		return c, ErrToken
	}
	const skew = 60
	switch {
	case c.Iss != "https://securetoken.google.com/"+v.ProjectID, c.Aud != v.ProjectID:
		return c, fmt.Errorf("%w: wrong project", ErrToken)
	case now.Unix() > c.Exp+skew, c.Iat > now.Unix()+skew, c.Sub == "":
		return c, fmt.Errorf("%w: expired or not yet valid", ErrToken)
	case c.Firebase.Tenant != v.TenantID:
		return c, fmt.Errorf("%w: wrong tenant", ErrToken)
	case !c.EmailVerified:
		return c, fmt.Errorf("%w: email not verified", ErrToken)
	}
	return c, nil
}

func decodeSeg(seg string, out any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

var maxAge = regexp.MustCompile(`max-age=(\d+)`)

func (v *FirebaseVerifier) key(kid string, now time.Time) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	k, ok := v.keys[kid]
	if ok && now.Before(v.expires) {
		return k, nil
	}
	// An unknown kid could be Google rotating keys, or junk. Refetch at
	// most once a minute so junk tokens can't make us hammer Google.
	if !ok && now.Before(v.expires) && now.Sub(v.lastFetch) < time.Minute {
		return nil, ErrToken
	}
	v.lastFetch = now
	url, client := v.JWKSURL, v.Client
	if url == "" {
		url = googleJWKS
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch signing keys: %w", err)
	}
	defer resp.Body.Close()
	var set struct {
		Keys []struct {
			Kid, Kty, N, E string
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, fmt.Errorf("signing keys: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		n, err1 := base64.RawURLEncoding.DecodeString(k.N)
		e, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if k.Kty != "RSA" || err1 != nil || err2 != nil {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	ttl := time.Hour
	if m := maxAge.FindStringSubmatch(resp.Header.Get("Cache-Control")); m != nil {
		if s, err := strconv.Atoi(m[1]); err == nil {
			ttl = time.Duration(s) * time.Second
		}
	}
	v.keys, v.expires = keys, now.Add(ttl)
	k, ok = keys[kid]
	if !ok {
		return nil, ErrToken
	}
	return k, nil
}
