// Package mailbox is the Cloud Run service between phones and Macs. It
// stores sealed envelopes until the recipient acks them or they expire. It
// can't read them, and it doesn't need to trust anything inside them.
//
// Each Mac is a tenant, identified by its key, the way an account is a key
// pair in Happier. A phone belongs to the Mac that enrolled it and can only
// reach that Mac; a Mac can only manage its own phones. Your other Macs and
// other people's Macs are separate by construction.
package mailbox

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/pa/flow-remote/internal/envelope"
)

const (
	Retention = envelope.Retention
	PairTTL   = 2 * time.Minute
	InviteTTL = 24 * time.Hour
)

var (
	ErrExists   = errors.New("mailbox: already exists")
	ErrNotFound = errors.New("mailbox: not found")
	ErrConflict = errors.New("mailbox: registered with a different key or owner")
)

// Record is an envelope plus what the mailbox knows about it.
type Record struct {
	Env        envelope.Envelope `json:"env" bson:"env"`
	To         string            `json:"-" bson:"to"`
	Seq        int64             `json:"seq" bson:"seq"` // arrival order
	ReceivedAt time.Time         `json:"received_at" bson:"received_at"`
	ExpiresAt  time.Time         `json:"-" bson:"expires_at"`
}

// Mac is a tenant.
type Mac struct {
	ID      string    `json:"id"`
	SignPub string    `json:"-"`
	Admin   bool      `json:"admin"` // may create invites and remove tenants
	Created time.Time `json:"created"`
}

// Device is a phone enrolled by one Mac.
type Device struct {
	SignPub string
	Owner   string // the mac id that enrolled it
}

type Store interface {
	PutEnvelope(ctx context.Context, e envelope.Envelope, now time.Time) error
	// ListEnvelopes returns up to limit envelopes for to, oldest first.
	ListEnvelopes(ctx context.Context, to string, limit int, now time.Time) ([]Record, error)
	// Ack deletes envelopes for to by id. Ids for someone else are ignored.
	Ack(ctx context.Context, to string, ids []string) error

	// OpenPair makes a slot, owned by macID, that a phone may post one
	// enrollment into.
	OpenPair(ctx context.Context, pairID, macID string, now time.Time) error
	// PutPair fills an open, empty slot whose owner is e.To: ErrNotFound
	// if there's no such slot, ErrExists if it's already filled.
	PutPair(ctx context.Context, pairID string, e envelope.Envelope, now time.Time) error
	// TakePair returns and deletes a filled slot owned by macID.
	TakePair(ctx context.Context, pairID, macID string, now time.Time) (envelope.Envelope, error)

	// RegisterMac binds a mac id to its key, first come first served.
	RegisterMac(ctx context.Context, m Mac) error
	GetMac(ctx context.Context, macID string) (Mac, error)
	ListMacs(ctx context.Context) ([]Mac, error)
	// RemoveMac deletes a tenant: the Mac, its devices, and their queues.
	RemoveMac(ctx context.Context, macID string) error

	// CreateInvite stores an invite by the hash of its code.
	CreateInvite(ctx context.Context, hash, createdBy string, now time.Time) error
	// UseInvite consumes an unexpired invite; ErrNotFound otherwise.
	UseInvite(ctx context.Context, hash string, now time.Time) error

	// PutDevice registers a phone for owner; ErrConflict if the id is known
	// with another key or owner, or is revoked.
	PutDevice(ctx context.Context, owner, deviceID, signPub string) error
	// RevokeDevice revokes a device of owner's; ErrNotFound if it isn't theirs.
	RevokeDevice(ctx context.Context, owner, deviceID string) error
	// GetDevice returns an active device; ErrNotFound if unknown or revoked.
	GetDevice(ctx context.Context, deviceID string) (Device, error)
	// ListDevices returns owner's active devices' ids.
	ListDevices(ctx context.Context, owner string) ([]string, error)

	// Touch and LastSeen track presence: "mac:<id>", "phone:<mac id>",
	// "dev:<device id>".
	Touch(ctx context.Context, who string, now time.Time) error
	LastSeen(ctx context.Context, who string) (time.Time, error)

	// DeleteExpired removes envelopes, pairings and invites past expiry.
	DeleteExpired(ctx context.Context, now time.Time) (int, error)
}

// Memory is a Store for local runs and tests.
type Memory struct {
	mu      sync.Mutex
	seq     int64
	envs    map[string]Record // by envelope id
	pairs   map[string]pairSlot
	macs    map[string]Mac
	devs    map[string]device
	invites map[string]time.Time // hash -> expiry
	seen    map[string]time.Time
}

type pairSlot struct {
	owner     string
	env       *envelope.Envelope // nil while open and empty
	expiresAt time.Time
}

type device struct {
	signPub, owner string
	revoked        bool
}

func NewMemory() *Memory {
	return &Memory{
		envs: map[string]Record{}, pairs: map[string]pairSlot{}, macs: map[string]Mac{},
		devs: map[string]device{}, invites: map[string]time.Time{}, seen: map[string]time.Time{},
	}
}

func (m *Memory) PutEnvelope(_ context.Context, e envelope.Envelope, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.envs[e.ID]; ok {
		return ErrExists
	}
	m.seq++
	m.envs[e.ID] = Record{Env: e, To: e.To, Seq: m.seq, ReceivedAt: now, ExpiresAt: now.Add(Retention)}
	return nil
}

func (m *Memory) ListEnvelopes(_ context.Context, to string, limit int, now time.Time) ([]Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Record
	for _, r := range m.envs {
		if r.To == to && now.Before(r.ExpiresAt) {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Memory) Ack(_ context.Context, to string, ids []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range ids {
		if r, ok := m.envs[id]; ok && r.To == to {
			delete(m.envs, id)
		}
	}
	return nil
}

func (m *Memory) OpenPair(_ context.Context, pairID, macID string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.pairs[pairID]; ok {
		return ErrExists
	}
	m.pairs[pairID] = pairSlot{owner: macID, expiresAt: now.Add(PairTTL)}
	return nil
}

func (m *Memory) PutPair(_ context.Context, pairID string, e envelope.Envelope, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	slot, ok := m.pairs[pairID]
	if !ok || slot.owner != e.To || !now.Before(slot.expiresAt) {
		return ErrNotFound
	}
	if slot.env != nil {
		return ErrExists
	}
	slot.env = &e
	m.pairs[pairID] = slot
	return nil
}

func (m *Memory) TakePair(_ context.Context, pairID, macID string, now time.Time) (envelope.Envelope, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	slot, ok := m.pairs[pairID]
	if !ok || slot.owner != macID || slot.env == nil || !now.Before(slot.expiresAt) {
		return envelope.Envelope{}, ErrNotFound
	}
	delete(m.pairs, pairID)
	return *slot.env, nil
}

func (m *Memory) RegisterMac(_ context.Context, mac Mac) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cur, ok := m.macs[mac.ID]; ok {
		if cur.SignPub != mac.SignPub {
			return ErrConflict
		}
		return ErrExists
	}
	m.macs[mac.ID] = mac
	return nil
}

func (m *Memory) GetMac(_ context.Context, macID string) (Mac, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mac, ok := m.macs[macID]
	if !ok {
		return Mac{}, ErrNotFound
	}
	return mac, nil
}

func (m *Memory) ListMacs(_ context.Context) ([]Mac, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Mac, 0, len(m.macs))
	for _, mac := range m.macs {
		out = append(out, mac)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out, nil
}

func (m *Memory) RemoveMac(_ context.Context, macID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.macs[macID]; !ok {
		return ErrNotFound
	}
	delete(m.macs, macID)
	gone := map[string]bool{macID: true}
	for id, d := range m.devs {
		if d.owner == macID {
			gone[id] = true
			// Keep the id, revoked, so it can't be re-registered.
			d.revoked = true
			m.devs[id] = d
		}
	}
	for id, r := range m.envs {
		if gone[r.To] {
			delete(m.envs, id)
		}
	}
	for id, s := range m.pairs {
		if s.owner == macID {
			delete(m.pairs, id)
		}
	}
	return nil
}

func (m *Memory) CreateInvite(_ context.Context, hash, _ string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.invites[hash]; ok {
		return ErrExists
	}
	m.invites[hash] = now.Add(InviteTTL)
	return nil
}

func (m *Memory) UseInvite(_ context.Context, hash string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	exp, ok := m.invites[hash]
	if !ok || !now.Before(exp) {
		return ErrNotFound
	}
	delete(m.invites, hash)
	return nil
}

func (m *Memory) PutDevice(_ context.Context, owner, deviceID, signPub string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if d, ok := m.devs[deviceID]; ok {
		if d.revoked || d.signPub != signPub || d.owner != owner {
			return ErrConflict
		}
		return nil
	}
	m.devs[deviceID] = device{signPub: signPub, owner: owner}
	return nil
}

func (m *Memory) RevokeDevice(_ context.Context, owner, deviceID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devs[deviceID]
	if !ok || d.owner != owner {
		return ErrNotFound
	}
	d.revoked = true
	m.devs[deviceID] = d
	return nil
}

func (m *Memory) GetDevice(_ context.Context, deviceID string) (Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devs[deviceID]
	if !ok || d.revoked {
		return Device{}, ErrNotFound
	}
	return Device{SignPub: d.signPub, Owner: d.owner}, nil
}

func (m *Memory) ListDevices(_ context.Context, owner string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for id, d := range m.devs {
		if d.owner == owner && !d.revoked {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (m *Memory) Touch(_ context.Context, who string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seen[who] = now
	return nil
}

func (m *Memory) LastSeen(_ context.Context, who string) (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.seen[who], nil
}

func (m *Memory) DeleteExpired(_ context.Context, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, r := range m.envs {
		if !now.Before(r.ExpiresAt) {
			delete(m.envs, id)
			n++
		}
	}
	for id, r := range m.pairs {
		if !now.Before(r.expiresAt) {
			delete(m.pairs, id)
			n++
		}
	}
	for h, exp := range m.invites {
		if !now.Before(exp) {
			delete(m.invites, h)
			n++
		}
	}
	return n, nil
}
