// Package mailbox is the Cloud Run service between the phone and the Mac.
// It stores sealed envelopes until the recipient acks them or they expire.
// It can't read them, and it doesn't need to trust anything inside them.
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
)

var (
	ErrExists   = errors.New("mailbox: already exists")
	ErrNotFound = errors.New("mailbox: not found")
	ErrConflict = errors.New("mailbox: registered with a different key")
)

// Record is an envelope plus what the mailbox knows about it.
type Record struct {
	Env        envelope.Envelope `json:"env" bson:"env"`
	To         string            `json:"-" bson:"to"`
	Seq        int64             `json:"seq" bson:"seq"` // arrival order
	ReceivedAt time.Time         `json:"received_at" bson:"received_at"`
	ExpiresAt  time.Time         `json:"-" bson:"expires_at"`
}

type Store interface {
	// PutEnvelope stores an envelope; ErrExists if its id is already stored.
	PutEnvelope(ctx context.Context, e envelope.Envelope, now time.Time) error
	// ListEnvelopes returns up to limit envelopes for to, oldest first.
	ListEnvelopes(ctx context.Context, to string, limit int, now time.Time) ([]Record, error)
	// Ack deletes envelopes for to by id. Ids for someone else are ignored.
	Ack(ctx context.Context, to string, ids []string) error

	PutPair(ctx context.Context, pairID string, e envelope.Envelope, now time.Time) error
	// TakePair returns and deletes the pairing envelope.
	TakePair(ctx context.Context, pairID string, now time.Time) (envelope.Envelope, error)

	// RegisterMac binds a mac id to its sign key, first come first served.
	RegisterMac(ctx context.Context, macID, signPub string) error
	MacKey(ctx context.Context, macID string) (string, error)

	// Touch and LastSeen track presence ("mac:<id>", "phone").
	Touch(ctx context.Context, who string, now time.Time) error
	LastSeen(ctx context.Context, who string) (time.Time, error)

	// DeleteExpired removes envelopes and pairings past their expiry.
	DeleteExpired(ctx context.Context, now time.Time) (int, error)
}

// Memory is a Store for local runs and tests.
type Memory struct {
	mu    sync.Mutex
	seq   int64
	envs  map[string]Record // by envelope id
	pairs map[string]Record
	macs  map[string]string
	seen  map[string]time.Time
}

func NewMemory() *Memory {
	return &Memory{envs: map[string]Record{}, pairs: map[string]Record{}, macs: map[string]string{}, seen: map[string]time.Time{}}
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

func (m *Memory) PutPair(_ context.Context, pairID string, e envelope.Envelope, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.pairs[pairID]; ok {
		return ErrExists
	}
	m.pairs[pairID] = Record{Env: e, ReceivedAt: now, ExpiresAt: now.Add(PairTTL)}
	return nil
}

func (m *Memory) TakePair(_ context.Context, pairID string, now time.Time) (envelope.Envelope, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.pairs[pairID]
	if !ok || !now.Before(r.ExpiresAt) {
		return envelope.Envelope{}, ErrNotFound
	}
	delete(m.pairs, pairID)
	return r.Env, nil
}

func (m *Memory) RegisterMac(_ context.Context, macID, signPub string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cur, ok := m.macs[macID]; ok {
		if cur != signPub {
			return ErrConflict
		}
		return nil
	}
	m.macs[macID] = signPub
	return nil
}

func (m *Memory) MacKey(_ context.Context, macID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.macs[macID]
	if !ok {
		return "", ErrNotFound
	}
	return k, nil
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
		if !now.Before(r.ExpiresAt) {
			delete(m.pairs, id)
			n++
		}
	}
	return n, nil
}
