package mailbox

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"sort"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/pa/flow-remote/internal/envelope"
)

// Bolt is a Store in one file, for a mailbox running on the Mac itself
// (`flow-remote serve`). It holds one person's queues, so it keeps each
// kind of record in its own bucket and scans rather than indexing.
// touchEvery is how often a last-seen time is written to the file; the
// latest stays in memory in between.
const touchEvery = 20 * time.Second

type Bolt struct {
	db *bolt.DB

	mu      sync.Mutex
	seen    map[string]time.Time // latest, in memory
	touched map[string]time.Time // last written
}

var (
	bEnvs  = []byte("envelopes")
	bPairs = []byte("pairs")
	bMacs  = []byte("macs")
	bDevs  = []byte("devices")
	bSeen  = []byte("seen")
)

type boltRec struct {
	Env        envelope.Envelope `json:"env"`
	To         string            `json:"to"`
	Seq        int64             `json:"seq"`
	ReceivedAt time.Time         `json:"received_at"`
	ExpiresAt  time.Time         `json:"expires_at"`
}

type boltPair struct {
	Owner     string             `json:"owner"`
	Env       *envelope.Envelope `json:"env,omitempty"`
	ExpiresAt time.Time          `json:"expires_at"`
}

type boltMac struct {
	ID      string    `json:"id"`
	SignPub string    `json:"sign_pub"`
	Created time.Time `json:"created"`
}

type boltDev struct {
	SignPub string `json:"sign_pub"`
	Owner   string `json:"owner"`
	Revoked bool   `json:"revoked,omitempty"`
}

// OpenBolt opens or creates the database at path. Only one process may
// hold it; a second one waits up to timeout, then fails.
func OpenBolt(path string, timeout time.Duration) (*Bolt, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: timeout})
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bEnvs, bPairs, bMacs, bDevs, bSeen} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Bolt{db: db, seen: map[string]time.Time{}, touched: map[string]time.Time{}}, nil
}

func (s *Bolt) Close() error { return s.db.Close() }

func put(b *bolt.Bucket, key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return b.Put([]byte(key), raw)
}

func get(b *bolt.Bucket, key string, v any) bool {
	raw := b.Get([]byte(key))
	return raw != nil && json.Unmarshal(raw, v) == nil
}

func (s *Bolt) PutEnvelope(_ context.Context, e envelope.Envelope, now time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bEnvs)
		if b.Get([]byte(e.ID)) != nil {
			return ErrExists
		}
		seq, err := b.NextSequence()
		if err != nil {
			return err
		}
		return put(b, e.ID, boltRec{Env: e, To: e.To, Seq: int64(seq), ReceivedAt: now, ExpiresAt: now.Add(Retention)})
	})
}

// envsFor returns to's unexpired envelopes, oldest first.
func envsFor(tx *bolt.Tx, to string, now time.Time) []boltRec {
	var out []boltRec
	tx.Bucket(bEnvs).ForEach(func(_, v []byte) error {
		var r boltRec
		if json.Unmarshal(v, &r) == nil && r.To == to && now.Before(r.ExpiresAt) {
			out = append(out, r)
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out
}

func (s *Bolt) ListEnvelopes(_ context.Context, to string, limit int, now time.Time) ([]Record, error) {
	var out []Record
	err := s.db.View(func(tx *bolt.Tx) error {
		for _, r := range envsFor(tx, to, now) {
			if len(out) == limit {
				break
			}
			out = append(out, Record{Env: r.Env, To: r.To, Seq: r.Seq, ReceivedAt: r.ReceivedAt, ExpiresAt: r.ExpiresAt})
		}
		return nil
	})
	return out, err
}

func (s *Bolt) CountEnvelopes(_ context.Context, to string, now time.Time) (int, error) {
	n := 0
	err := s.db.View(func(tx *bolt.Tx) error {
		n = len(envsFor(tx, to, now))
		return nil
	})
	return n, err
}

func (s *Bolt) Ack(_ context.Context, to string, ids []string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bEnvs)
		for _, id := range ids {
			var r boltRec
			if get(b, id, &r) && r.To == to {
				if err := b.Delete([]byte(id)); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func (s *Bolt) OpenPair(_ context.Context, pairID, macID string, now time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bPairs)
		if b.Get([]byte(pairID)) != nil {
			return ErrExists
		}
		return put(b, pairID, boltPair{Owner: macID, ExpiresAt: now.Add(PairTTL)})
	})
}

func (s *Bolt) PutPair(_ context.Context, pairID string, e envelope.Envelope, now time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bPairs)
		var p boltPair
		if !get(b, pairID, &p) || p.Owner != e.To || !now.Before(p.ExpiresAt) {
			return ErrNotFound
		}
		if p.Env != nil {
			return ErrExists
		}
		p.Env = &e
		return put(b, pairID, p)
	})
}

func (s *Bolt) TakePair(_ context.Context, pairID, macID string, now time.Time) (envelope.Envelope, error) {
	var out envelope.Envelope
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bPairs)
		var p boltPair
		if !get(b, pairID, &p) || p.Owner != macID || p.Env == nil || !now.Before(p.ExpiresAt) {
			return ErrNotFound
		}
		out = *p.Env
		return b.Delete([]byte(pairID))
	})
	return out, err
}

func (s *Bolt) RegisterMac(_ context.Context, m Mac) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bMacs)
		var cur boltMac
		if get(b, m.ID, &cur) {
			if cur.SignPub != m.SignPub {
				return ErrConflict
			}
			return ErrExists
		}
		return put(b, m.ID, boltMac(m))
	})
}

func (s *Bolt) GetMac(_ context.Context, macID string) (Mac, error) {
	var m boltMac
	var ok bool
	s.db.View(func(tx *bolt.Tx) error {
		ok = get(tx.Bucket(bMacs), macID, &m)
		return nil
	})
	if !ok {
		return Mac{}, ErrNotFound
	}
	return Mac(m), nil
}

func (s *Bolt) ListMacs(_ context.Context) ([]Mac, error) {
	var out []Mac
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bMacs).ForEach(func(_, v []byte) error {
			var m boltMac
			if json.Unmarshal(v, &m) == nil {
				out = append(out, Mac(m))
			}
			return nil
		})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out, err
}

// deleteWhere deletes the keys whose value matches. Keys are collected
// first: bbolt doesn't allow deleting while iterating with ForEach.
func deleteWhere(b *bolt.Bucket, match func(v []byte) bool) error {
	var keys [][]byte
	b.ForEach(func(k, v []byte) error {
		if match(v) {
			keys = append(keys, bytes.Clone(k))
		}
		return nil
	})
	for _, k := range keys {
		if err := b.Delete(k); err != nil {
			return err
		}
	}
	return nil
}

func (s *Bolt) PutDevice(_ context.Context, owner, deviceID, signPub string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bDevs)
		var d boltDev
		if get(b, deviceID, &d) {
			if d.Revoked || d.SignPub != signPub || d.Owner != owner {
				return ErrConflict
			}
			return nil
		}
		return put(b, deviceID, boltDev{SignPub: signPub, Owner: owner})
	})
}

func (s *Bolt) RevokeDevice(_ context.Context, owner, deviceID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bDevs)
		var d boltDev
		if !get(b, deviceID, &d) || d.Owner != owner {
			return ErrNotFound
		}
		d.Revoked = true
		return put(b, deviceID, d)
	})
}

func (s *Bolt) GetDevice(_ context.Context, deviceID string) (Device, error) {
	var d boltDev
	var ok bool
	s.db.View(func(tx *bolt.Tx) error {
		ok = get(tx.Bucket(bDevs), deviceID, &d)
		return nil
	})
	if !ok || d.Revoked {
		return Device{}, ErrNotFound
	}
	return Device{SignPub: d.SignPub, Owner: d.Owner}, nil
}

func (s *Bolt) ListDevices(_ context.Context, owner string) ([]string, error) {
	var out []string
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bDevs).ForEach(func(k, v []byte) error {
			var d boltDev
			if json.Unmarshal(v, &d) == nil && d.Owner == owner && !d.Revoked {
				out = append(out, string(k))
			}
			return nil
		})
	})
	sort.Strings(out)
	return out, err
}

// Touch keeps the latest time in memory and writes it at most every
// touchEvery, so a phone polling every few seconds doesn't sync the file
// each time.
func (s *Bolt) Touch(_ context.Context, who string, now time.Time) error {
	s.mu.Lock()
	s.seen[who] = now
	if now.Sub(s.touched[who]) < touchEvery {
		s.mu.Unlock()
		return nil
	}
	s.touched[who] = now
	s.mu.Unlock()
	return s.db.Update(func(tx *bolt.Tx) error {
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], uint64(now.UnixNano()))
		return tx.Bucket(bSeen).Put([]byte(who), buf[:])
	})
}

func (s *Bolt) LastSeen(_ context.Context, who string) (time.Time, error) {
	s.mu.Lock()
	t, ok := s.seen[who]
	s.mu.Unlock()
	if ok {
		return t, nil
	}
	// After a restart, fall back to the last write.
	var out time.Time
	s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bSeen).Get([]byte(who)); len(v) == 8 {
			out = time.Unix(0, int64(binary.BigEndian.Uint64(v)))
		}
		return nil
	})
	return out, nil
}

func (s *Bolt) DeleteExpired(_ context.Context, now time.Time) (int, error) {
	n := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		count := func(match func(v []byte) bool) func(v []byte) bool {
			return func(v []byte) bool {
				if match(v) {
					n++
					return true
				}
				return false
			}
		}
		if err := deleteWhere(tx.Bucket(bEnvs), count(func(v []byte) bool {
			var r boltRec
			return json.Unmarshal(v, &r) == nil && !now.Before(r.ExpiresAt)
		})); err != nil {
			return err
		}
		return deleteWhere(tx.Bucket(bPairs), count(func(v []byte) bool {
			var p boltPair
			return json.Unmarshal(v, &p) == nil && !now.Before(p.ExpiresAt)
		}))
	})
	return n, err
}
