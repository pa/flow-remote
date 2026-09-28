// Package envelope is the wire format shared by the phone, the mailbox and
// the relay. An envelope is sealed to the recipient's box key (ECDH P-256,
// HKDF-SHA256, AES-256-GCM) and signed by the sender's sign key (ECDSA
// P-256, SHA-256, raw r||s). Every primitive is one WebCrypto supports, so
// the PWA can produce byte-identical envelopes without a crypto library.
//
// The mailbox sees V, ID, From, To and TS, and nothing else it can use.
// See docs/PROTOCOL.md for the exact byte layout.
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strconv"
)

const (
	Version = 1
	tag     = "flow-remote/v1"
)

var b64 = base64.RawURLEncoding

// Envelope is what travels through the mailbox. All binary fields are
// unpadded base64url.
type Envelope struct {
	V    int    `json:"v"`
	ID   string `json:"id"`   // 16 random bytes; the replay key
	From string `json:"from"` // sender identity id
	To   string `json:"to"`   // recipient identity id
	TS   int64  `json:"ts"`   // sender clock, unix milliseconds
	EPK  string `json:"epk"`  // ephemeral ECDH public key, uncompressed point
	CT   string `json:"ct"`   // 12-byte GCM nonce || ciphertext || tag
	Sig  string `json:"sig"`  // ECDSA over SigningInput, raw r||s
}

var (
	ErrVersion   = errors.New("envelope: unsupported version")
	ErrSignature = errors.New("envelope: bad signature")
	ErrDecrypt   = errors.New("envelope: cannot open")
)

// header is the part of the envelope bound into the GCM tag, so the mailbox
// can't move a ciphertext to another envelope.
func (e *Envelope) header() string {
	return tag + "\n" + strconv.Itoa(e.V) + "\n" + e.ID + "\n" + e.From + "\n" + e.To + "\n" + strconv.FormatInt(e.TS, 10)
}

// SigningInput is the exact byte string the sender signs.
func (e *Envelope) SigningInput() []byte {
	return []byte(e.header() + "\n" + e.EPK + "\n" + e.CT)
}

// NewID returns a fresh random envelope id.
func NewID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return b64.EncodeToString(b)
}

// Seal encrypts plaintext to recipient and signs the result with sender.
// ts is unix milliseconds.
func Seal(plaintext []byte, sender *ecdsa.PrivateKey, from, to string, recipient *ecdh.PublicKey, ts int64) (*Envelope, error) {
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	e := &Envelope{V: Version, ID: NewID(), From: from, To: to, TS: ts, EPK: b64.EncodeToString(eph.PublicKey().Bytes())}

	aead, err := sealKey(eph, recipient, eph.PublicKey(), recipient)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)
	ct := aead.Seal(nonce, nonce, plaintext, []byte(e.header()))
	e.CT = b64.EncodeToString(ct)

	e.Sig, err = sign(sender, e.SigningInput())
	if err != nil {
		return nil, err
	}
	return e, nil
}

// Verify checks the version and the sender's signature. Call it before Open,
// and before trusting any field.
func Verify(e *Envelope, sender *ecdsa.PublicKey) error {
	if e.V != Version {
		return ErrVersion
	}
	sig, err := b64.DecodeString(e.Sig)
	if err != nil || len(sig) != 64 {
		return ErrSignature
	}
	h := sha256.Sum256(e.SigningInput())
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(sender, h[:], r, s) {
		return ErrSignature
	}
	return nil
}

// Open decrypts a verified envelope with the recipient's box key.
func Open(e *Envelope, recipient *ecdh.PrivateKey) ([]byte, error) {
	epkRaw, err := b64.DecodeString(e.EPK)
	if err != nil {
		return nil, ErrDecrypt
	}
	epk, err := ecdh.P256().NewPublicKey(epkRaw)
	if err != nil {
		return nil, ErrDecrypt
	}
	aead, err := sealKey(recipient, epk, epk, recipient.PublicKey())
	if err != nil {
		return nil, ErrDecrypt
	}
	ct, err := b64.DecodeString(e.CT)
	if err != nil || len(ct) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrDecrypt
	}
	n := aead.NonceSize()
	pt, err := aead.Open(nil, ct[:n], ct[n:], []byte(e.header()))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// sealKey derives the AES-256-GCM key. info binds the ephemeral key and the
// recipient's static key: tag || epk || recipient.
func sealKey(priv *ecdh.PrivateKey, peer, epk, recip *ecdh.PublicKey) (cipher.AEAD, error) {
	shared, err := priv.ECDH(peer)
	if err != nil {
		return nil, err
	}
	info := append([]byte(tag), epk.Bytes()...)
	info = append(info, recip.Bytes()...)
	key, err := hkdf.Key(sha256.New, shared, nil, string(info), 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sign returns a raw r||s signature, the format WebCrypto produces.
func sign(k *ecdsa.PrivateKey, msg []byte) (string, error) {
	h := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, k, h[:])
	if err != nil {
		return "", err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return b64.EncodeToString(out), nil
}

// ParseSignPub parses an uncompressed P-256 point (WebCrypto "raw" export).
func ParseSignPub(s string) (*ecdsa.PublicKey, error) {
	raw, err := b64.DecodeString(s)
	if err != nil {
		return nil, err
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	if err != nil {
		return nil, fmt.Errorf("sign key: %w", err)
	}
	return pub, nil
}

// ParseBoxPub parses an uncompressed P-256 ECDH point.
func ParseBoxPub(s string) (*ecdh.PublicKey, error) {
	raw, err := b64.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return ecdh.P256().NewPublicKey(raw)
}

// EncodeSignPub and EncodeBoxPub are the inverse of the parsers.
func EncodeSignPub(k *ecdsa.PublicKey) string {
	raw, _ := k.Bytes()
	return b64.EncodeToString(raw)
}

func EncodeBoxPub(k *ecdh.PublicKey) string { return b64.EncodeToString(k.Bytes()) }

// Decode and Encode are the unpadded base64url used for every binary field.
func Decode(s string) ([]byte, error) { return b64.DecodeString(s) }
func Encode(b []byte) string          { return b64.EncodeToString(b) }
