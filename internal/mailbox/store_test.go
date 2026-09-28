package mailbox

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/pa/flow-remote/internal/envelope"
)

// contract is what every Store must do. It runs against Memory always and
// against Mongo when FLOW_REMOTE_MONGO_URI points at a server.
func contract(t *testing.T, s Store) {
	ctx := context.Background()
	now := time.Now().Truncate(time.Millisecond) // Mongo stores milliseconds
	env := func(to string) envelope.Envelope {
		return envelope.Envelope{V: 1, ID: envelope.NewID(), From: "dev-a", To: to, TS: now.UnixMilli(), EPK: "e", CT: "c", Sig: "s"}
	}

	a, b, other := env("mac-1"), env("mac-1"), env("mac-2")
	for _, e := range []envelope.Envelope{a, b, other} {
		if err := s.PutEnvelope(ctx, e, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.PutEnvelope(ctx, a, now); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate put = %v", err)
	}
	recs, err := s.ListEnvelopes(ctx, "mac-1", 10, now)
	if err != nil || len(recs) != 2 || recs[0].Env.ID != a.ID || recs[1].Env.ID != b.ID {
		t.Fatalf("list = %+v, %v", recs, err)
	}
	if recs[0].Env != a {
		t.Fatalf("envelope changed in storage:\n got %+v\nwant %+v", recs[0].Env, a)
	}
	if recs, _ := s.ListEnvelopes(ctx, "mac-1", 1, now); len(recs) != 1 {
		t.Fatalf("limit ignored: %d", len(recs))
	}

	// Ack only deletes the caller's own envelopes.
	if err := s.Ack(ctx, "mac-1", []string{a.ID, other.ID}); err != nil {
		t.Fatal(err)
	}
	if recs, _ := s.ListEnvelopes(ctx, "mac-1", 10, now); len(recs) != 1 || recs[0].Env.ID != b.ID {
		t.Fatalf("after ack: %+v", recs)
	}
	if recs, _ := s.ListEnvelopes(ctx, "mac-2", 10, now); len(recs) != 1 {
		t.Fatal("ack deleted another recipient's envelope")
	}

	// Pairing slots are single-use and expire.
	p := env("mac-1")
	if err := s.PutPair(ctx, "pair-1", p, now); err != nil {
		t.Fatal(err)
	}
	if err := s.PutPair(ctx, "pair-1", p, now); !errors.Is(err, ErrExists) {
		t.Fatalf("second pair put = %v", err)
	}
	got, err := s.TakePair(ctx, "pair-1", now)
	if err != nil || got.ID != p.ID {
		t.Fatalf("take = %+v, %v", got, err)
	}
	if _, err := s.TakePair(ctx, "pair-1", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second take = %v", err)
	}
	s.PutPair(ctx, "pair-2", p, now)
	if _, err := s.TakePair(ctx, "pair-2", now.Add(PairTTL+time.Second)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired take = %v", err)
	}

	// Mac keys: first come first served.
	if err := s.RegisterMac(ctx, "mac-1", "key-a"); err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterMac(ctx, "mac-1", "key-a"); err != nil {
		t.Fatalf("same key again = %v", err)
	}
	if err := s.RegisterMac(ctx, "mac-1", "key-b"); !errors.Is(err, ErrConflict) {
		t.Fatalf("other key = %v", err)
	}
	if k, _ := s.MacKey(ctx, "mac-1"); k != "key-a" {
		t.Fatalf("mac key = %q", k)
	}
	if _, err := s.MacKey(ctx, "mac-9"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing mac = %v", err)
	}

	// Presence.
	if at, _ := s.LastSeen(ctx, "phone"); !at.IsZero() {
		t.Fatalf("unseen = %v", at)
	}
	s.Touch(ctx, "phone", now)
	s.Touch(ctx, "phone", now.Add(time.Second))
	if at, _ := s.LastSeen(ctx, "phone"); !at.Equal(now.Add(time.Second)) {
		t.Fatalf("last seen = %v", at)
	}

	// Expiry.
	later := now.Add(Retention + time.Second)
	if recs, _ := s.ListEnvelopes(ctx, "mac-1", 10, later); len(recs) != 0 {
		t.Fatal("expired envelope listed")
	}
	n, err := s.DeleteExpired(ctx, later)
	if err != nil || n != 3 { // b, other, and the expired pair-2
		t.Fatalf("delete expired = %d, %v", n, err)
	}
}

func TestMemoryContract(t *testing.T) { contract(t, NewMemory()) }

func TestMongoContract(t *testing.T) {
	uri := os.Getenv("FLOW_REMOTE_MONGO_URI")
	if uri == "" {
		t.Skip("set FLOW_REMOTE_MONGO_URI to test the Mongo store")
	}
	ctx := context.Background()
	db := "flow_remote_test_" + envelope.NewID()[:8]
	m, err := OpenMongo(ctx, uri, db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.envs.Database().Drop(ctx) })
	contract(t, m)
}
