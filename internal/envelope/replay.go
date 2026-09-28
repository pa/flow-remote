package envelope

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// Retention matches the mailbox's expiry: an envelope older than this
	// can't still be in the mailbox, so its id can be forgotten.
	Retention = 7 * 24 * time.Hour
	// FutureSkew is how far ahead of our clock a sender's timestamp may be.
	FutureSkew = 5 * time.Minute
)

var (
	ErrReplay  = errors.New("envelope: already seen")
	ErrExpired = errors.New("envelope: older than retention")
	ErrFuture  = errors.New("envelope: timestamp in the future")
)

// Guard rejects replayed envelopes. It remembers every accepted id for
// Retention, so a replay is caught at any age, and a message that waited
// in the mailbox while the Mac slept is still accepted.
type Guard struct {
	mu   sync.Mutex
	path string           // "" keeps the guard in memory only
	seen map[string]int64 // id -> envelope ts, unix ms
}

// LoadGuard reads the seen-id file at path, creating it on first save.
func LoadGuard(path string) (*Guard, error) {
	g := &Guard{path: path, seen: map[string]int64{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return g, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &g.seen); err != nil {
		return nil, err
	}
	return g, nil
}

// NewMemoryGuard returns a guard that never touches disk.
func NewMemoryGuard() *Guard { return &Guard{seen: map[string]int64{}} }

// Admit records e.ID if the envelope is fresh and new. Call it only after
// Verify has passed, or a forger could burn ids.
func (g *Guard) Admit(e *Envelope, now time.Time) error {
	ts := time.UnixMilli(e.TS)
	if ts.After(now.Add(FutureSkew)) {
		return ErrFuture
	}
	if now.Sub(ts) > Retention {
		return ErrExpired
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.seen[e.ID]; ok {
		return ErrReplay
	}
	g.seen[e.ID] = e.TS
	g.prune(now)
	return g.save()
}

func (g *Guard) prune(now time.Time) {
	cutoff := now.Add(-Retention - FutureSkew).UnixMilli()
	for id, ts := range g.seen {
		if ts < cutoff {
			delete(g.seen, id)
		}
	}
}

func (g *Guard) save() error {
	if g.path == "" {
		return nil
	}
	b, err := json.Marshal(g.seen)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(g.path), 0o700); err != nil {
		return err
	}
	tmp := g.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, g.path)
}
