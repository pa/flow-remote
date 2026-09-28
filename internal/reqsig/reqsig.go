// Package reqsig authenticates the relay to the mailbox. The relay has no
// Google login. It signs each request with the Mac's sign key, and the
// mailbox checks it against the key the phone registered at pairing.
package reqsig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"github.com/pa/flow-remote/internal/envelope"
)

const (
	HeaderMac = "X-FR-Mac"
	HeaderTS  = "X-FR-TS"
	HeaderSig = "X-FR-Sig"

	// Window is how far a request's timestamp may be from the mailbox clock.
	Window = 2 * time.Minute
)

var ErrUnsigned = errors.New("reqsig: missing or bad signature")

func input(method, path string, ts int64, body []byte) []byte {
	h := sha256.Sum256(body)
	return []byte("flow-remote/v1 req\n" + method + "\n" + path + "\n" + strconv.FormatInt(ts, 10) + "\n" + hex.EncodeToString(h[:]))
}

// Sign adds the signature headers. path includes the query string.
func Sign(r *http.Request, macID string, key *ecdsa.PrivateKey, body []byte, now time.Time) error {
	ts := now.UnixMilli()
	h := sha256.Sum256(input(r.Method, r.URL.RequestURI(), ts, body))
	rr, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		return err
	}
	sig := make([]byte, 64)
	rr.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	r.Header.Set(HeaderMac, macID)
	r.Header.Set(HeaderTS, strconv.FormatInt(ts, 10))
	r.Header.Set(HeaderSig, envelope.Encode(sig))
	return nil
}

// Verify checks the headers against keyFor(macID) and returns the mac id.
// It reads the body and puts it back so handlers can read it again.
func Verify(r *http.Request, keyFor func(macID string) (*ecdsa.PublicKey, error), now time.Time) (string, error) {
	macID := r.Header.Get(HeaderMac)
	ts, err := strconv.ParseInt(r.Header.Get(HeaderTS), 10, 64)
	if macID == "" || err != nil {
		return "", ErrUnsigned
	}
	if d := now.Sub(time.UnixMilli(ts)); d > Window || d < -Window {
		return "", ErrUnsigned
	}
	sig, err := envelope.Decode(r.Header.Get(HeaderSig))
	if err != nil || len(sig) != 64 {
		return "", ErrUnsigned
	}
	key, err := keyFor(macID)
	if err != nil || key == nil {
		return "", ErrUnsigned
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return "", err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	h := sha256.Sum256(input(r.Method, r.URL.RequestURI(), ts, body))
	if !ecdsa.Verify(key, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return "", ErrUnsigned
	}
	return macID, nil
}
