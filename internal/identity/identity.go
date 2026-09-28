// Package identity holds the Mac's own key pairs and the registry of
// enrolled phones, both kept in a keystore.
package identity

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/pa/flow-remote/internal/envelope"
	"github.com/pa/flow-remote/internal/keystore"
)

const (
	itemMac     = "mac-identity"
	itemDevices = "devices"
)

// Mac is this relay's identity. ID is what envelopes put in from/to.
type Mac struct {
	ID   string
	Sign *ecdsa.PrivateKey
	Box  *ecdh.PrivateKey
}

type storedMac struct {
	ID   string `json:"id"`
	Sign []byte `json:"sign"` // raw scalar
	Box  []byte `json:"box"`
}

// LoadOrCreateMac reads the Mac identity, generating and saving one on
// first run.
func LoadOrCreateMac(ks keystore.Store) (*Mac, error) {
	b, err := ks.Get(itemMac)
	if errors.Is(err, keystore.ErrNotFound) {
		return createMac(ks)
	}
	if err != nil {
		return nil, err
	}
	var s storedMac
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("mac identity: %w", err)
	}
	sign, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), s.Sign)
	if err != nil {
		return nil, fmt.Errorf("mac sign key: %w", err)
	}
	box, err := ecdh.P256().NewPrivateKey(s.Box)
	if err != nil {
		return nil, fmt.Errorf("mac box key: %w", err)
	}
	return &Mac{ID: s.ID, Sign: sign, Box: box}, nil
}

func createMac(ks keystore.Store) (*Mac, error) {
	sign, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	box, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signRaw, err := sign.Bytes()
	if err != nil {
		return nil, err
	}
	m := &Mac{ID: "mac-" + envelope.NewID()[:10], Sign: sign, Box: box}
	b, _ := json.Marshal(storedMac{ID: m.ID, Sign: signRaw, Box: box.Bytes()})
	if err := ks.Put(itemMac, b); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Mac) SignPub() string { return envelope.EncodeSignPub(&m.Sign.PublicKey) }
func (m *Mac) BoxPub() string  { return envelope.EncodeBoxPub(m.Box.PublicKey()) }

func (m *Mac) Fingerprint() string { return Fingerprint(m.SignPub(), m.BoxPub()) }

// Fingerprint is what a person compares on the two screens during pairing:
// the first 10 bytes of SHA-256(sign_pub || box_pub), in groups of four
// hex digits. web/js/envelope.js computes the same string.
func Fingerprint(signPub, boxPub string) string {
	h := sha256.New()
	for _, k := range []string{signPub, boxPub} {
		raw, _ := envelope.Decode(k)
		h.Write(raw)
	}
	x := hex.EncodeToString(h.Sum(nil)[:10])
	var groups []string
	for i := 0; i < len(x); i += 4 {
		groups = append(groups, x[i:i+4])
	}
	return strings.Join(groups, " ")
}

// Device is an enrolled phone. Only public keys are stored.
type Device struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	SignPub    string    `json:"sign_pub"`
	BoxPub     string    `json:"box_pub"`
	EnrolledAt time.Time `json:"enrolled_at"`
	RevokedAt  time.Time `json:"revoked_at,omitzero"`
}

func (d Device) Revoked() bool { return !d.RevokedAt.IsZero() }

func (d Device) Fingerprint() string { return Fingerprint(d.SignPub, d.BoxPub) }

// Devices is the enrolled-device registry. It lives in the keystore next
// to the Mac's keys, so enrolling a device takes the same access as
// stealing the Mac's identity.
type Devices struct {
	ks   keystore.Store
	byID map[string]Device
}

func LoadDevices(ks keystore.Store) (*Devices, error) {
	d := &Devices{ks: ks, byID: map[string]Device{}}
	b, err := ks.Get(itemDevices)
	if errors.Is(err, keystore.ErrNotFound) {
		return d, nil
	}
	if err != nil {
		return nil, err
	}
	var list []Device
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("devices: %w", err)
	}
	for _, dev := range list {
		d.byID[dev.ID] = dev
	}
	return d, nil
}

// Active returns the device if it's enrolled and not revoked.
func (d *Devices) Active(id string) (Device, bool) {
	dev, ok := d.byID[id]
	if !ok || dev.Revoked() {
		return Device{}, false
	}
	return dev, true
}

func (d *Devices) List() []Device {
	out := make([]Device, 0, len(d.byID))
	for _, dev := range d.byID {
		out = append(out, dev)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EnrolledAt.Before(out[j].EnrolledAt) })
	return out
}

func (d *Devices) Enroll(dev Device) error {
	if _, ok := d.byID[dev.ID]; ok {
		return fmt.Errorf("device %s is already enrolled", dev.ID)
	}
	d.byID[dev.ID] = dev
	return d.save()
}

// Revoke keeps the record, so the device id can never be enrolled again
// with different keys.
func (d *Devices) Revoke(id string, now time.Time) error {
	dev, ok := d.byID[id]
	if !ok {
		return fmt.Errorf("no device %s", id)
	}
	if dev.Revoked() {
		return nil
	}
	dev.RevokedAt = now
	d.byID[id] = dev
	return d.save()
}

func (d *Devices) save() error {
	b, err := json.Marshal(d.List())
	if err != nil {
		return err
	}
	return d.ks.Put(itemDevices, b)
}
