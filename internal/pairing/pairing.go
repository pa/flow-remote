// Package pairing enrolls a phone with the Mac.
//
//  1. The Mac makes an Offer: its public keys, a random pair id and a
//     one-time secret, valid for two minutes. It shows the Offer as a QR
//     code. The Offer rides in the URL fragment, which browsers never send
//     to a server, so the mailbox never sees the secret.
//  2. The phone generates its keys and sends an Enrollment inside an
//     ordinary envelope, sealed to the Mac and signed with the new device
//     key. The Enrollment carries an HMAC made with the one-time secret.
//  3. The Mac opens it, checks the HMAC (only someone who saw the QR has
//     the secret) and the signature (they hold the key they're
//     enrolling), then shows the device name and fingerprint. You confirm
//     on the Mac after comparing it with the phone's screen.
//
// The mailbox only carries the enrollment envelope, and it can't read or
// alter it.
package pairing

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/pa/flow-remote/internal/envelope"
	"github.com/pa/flow-remote/internal/identity"
)

const TTL = 2 * time.Minute

var (
	ErrExpired  = errors.New("pairing: offer expired")
	ErrMismatch = errors.New("pairing: enrollment doesn't match this offer")
	ErrBadMAC   = errors.New("pairing: wrong one-time code")
)

var deviceID = regexp.MustCompile(`^dev-[A-Za-z0-9_-]{8,32}$`)

// Offer is what the QR code carries.
type Offer struct {
	V          int    `json:"v"`
	MacID      string `json:"mac_id"`
	MacSignPub string `json:"mac_sign_pub"`
	MacBoxPub  string `json:"mac_box_pub"`
	PairID     string `json:"pair_id"`
	Secret     string `json:"secret"`
	Expires    int64  `json:"exp"` // unix ms
	Mailbox    string `json:"mailbox"`
}

func NewOffer(mac *identity.Mac, mailbox string, now time.Time) Offer {
	secret := make([]byte, 16)
	rand.Read(secret)
	return Offer{
		V: envelope.Version, MacID: mac.ID, MacSignPub: mac.SignPub(), MacBoxPub: mac.BoxPub(),
		PairID: envelope.NewID(), Secret: envelope.Encode(secret),
		Expires: now.Add(TTL).UnixMilli(), Mailbox: mailbox,
	}
}

// Link is the URL the QR code encodes. appURL is where the PWA is served.
func (o Offer) Link(appURL string) string {
	b, _ := json.Marshal(o)
	return strings.TrimRight(appURL, "/") + "/#pair=" + envelope.Encode(b)
}

// Enrollment is the plaintext the phone seals to the Mac.
type Enrollment struct {
	Kind     string `json:"kind"` // "enroll"
	PairID   string `json:"pair_id"`
	DeviceID string `json:"device_id"`
	Name     string `json:"name"`
	SignPub  string `json:"sign_pub"`
	BoxPub   string `json:"box_pub"`
	MAC      string `json:"mac"`
}

// MACInput is the byte string the one-time secret authenticates.
func (e Enrollment) MACInput() []byte {
	return []byte("flow-remote/v1 enroll\n" + e.PairID + "\n" + e.DeviceID + "\n" + e.Name + "\n" + e.SignPub + "\n" + e.BoxPub)
}

func computeMAC(secret []byte, e Enrollment) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write(e.MACInput())
	return m.Sum(nil)
}

// Accept checks an enrollment envelope against the offer and returns the
// device to show for confirmation. It doesn't enroll anything; the caller
// does that after a person confirms the fingerprint.
func Accept(o Offer, mac *identity.Mac, env *envelope.Envelope, now time.Time) (identity.Device, error) {
	if now.UnixMilli() > o.Expires {
		return identity.Device{}, ErrExpired
	}
	if env.To != mac.ID || env.V != envelope.Version {
		return identity.Device{}, ErrMismatch
	}
	pt, err := envelope.Open(env, mac.Box)
	if err != nil {
		return identity.Device{}, err
	}
	var en Enrollment
	if err := json.Unmarshal(pt, &en); err != nil {
		return identity.Device{}, fmt.Errorf("pairing: %w", err)
	}
	if en.Kind != "enroll" || en.PairID != o.PairID || env.From != en.DeviceID {
		return identity.Device{}, ErrMismatch
	}
	secret, err := envelope.Decode(o.Secret)
	if err != nil {
		return identity.Device{}, err
	}
	got, err := envelope.Decode(en.MAC)
	if err != nil || !hmac.Equal(got, computeMAC(secret, en)) {
		return identity.Device{}, ErrBadMAC
	}
	signPub, err := envelope.ParseSignPub(en.SignPub)
	if err != nil {
		return identity.Device{}, err
	}
	if err := envelope.Verify(env, signPub); err != nil {
		return identity.Device{}, err
	}
	if _, err := envelope.ParseBoxPub(en.BoxPub); err != nil {
		return identity.Device{}, fmt.Errorf("device box key: %w", err)
	}
	if !deviceID.MatchString(en.DeviceID) {
		return identity.Device{}, fmt.Errorf("pairing: bad device id %q", en.DeviceID)
	}
	return identity.Device{
		ID: en.DeviceID, Name: cleanName(en.Name),
		SignPub: en.SignPub, BoxPub: en.BoxPub, EnrolledAt: now,
	}, nil
}

// cleanName keeps a device name safe to print in a terminal.
func cleanName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsPrint(r) && b.Len() < 40 {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "unnamed device"
	}
	return b.String()
}
