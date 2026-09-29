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
	env := func(from, to string) envelope.Envelope {
		return envelope.Envelope{V: 1, ID: envelope.NewID(), From: from, To: to, TS: now.UnixMilli(), EPK: "e", CT: "c", Sig: "s"}
	}

	// Envelopes.
	a, b, other := env("dev-a", "mac-1"), env("dev-a", "mac-1"), env("dev-b", "mac-2")
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
	if err := s.Ack(ctx, "mac-1", []string{a.ID, other.ID}); err != nil {
		t.Fatal(err)
	}
	if recs, _ := s.ListEnvelopes(ctx, "mac-1", 10, now); len(recs) != 1 || recs[0].Env.ID != b.ID {
		t.Fatalf("after ack: %+v", recs)
	}
	if recs, _ := s.ListEnvelopes(ctx, "mac-2", 10, now); len(recs) != 1 {
		t.Fatal("ack deleted another recipient's envelope")
	}

	// Pairing slots: opened by a Mac, filled once, taken once, by that Mac only.
	p := env("dev-p", "mac-1")
	if err := s.PutPair(ctx, "pair-1", p, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("put into unopened slot = %v", err)
	}
	if err := s.OpenPair(ctx, "pair-1", "mac-1", now); err != nil {
		t.Fatal(err)
	}
	if err := s.OpenPair(ctx, "pair-1", "mac-1", now); !errors.Is(err, ErrExists) {
		t.Fatalf("second open = %v", err)
	}
	if err := s.PutPair(ctx, "pair-1", env("dev-p", "mac-2"), now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("enrollment for another Mac accepted into mac-1's slot: %v", err)
	}
	if _, err := s.TakePair(ctx, "pair-1", "mac-1", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("take from empty slot = %v", err)
	}
	if err := s.PutPair(ctx, "pair-1", p, now); err != nil {
		t.Fatal(err)
	}
	if err := s.PutPair(ctx, "pair-1", env("dev-q", "mac-1"), now); !errors.Is(err, ErrExists) {
		t.Fatalf("second put = %v", err)
	}
	if _, err := s.TakePair(ctx, "pair-1", "mac-2", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another Mac took the slot: %v", err)
	}
	got, err := s.TakePair(ctx, "pair-1", "mac-1", now)
	if err != nil || got.ID != p.ID {
		t.Fatalf("take = %+v, %v", got, err)
	}
	if _, err := s.TakePair(ctx, "pair-1", "mac-1", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second take = %v", err)
	}
	s.OpenPair(ctx, "pair-2", "mac-1", now)
	if err := s.PutPair(ctx, "pair-2", p, now.Add(PairTTL+time.Second)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("put into expired slot = %v", err)
	}

	// Macs.
	m1 := Mac{ID: "mac-1", SignPub: "key-a", Admin: true, Created: now}
	if err := s.RegisterMac(ctx, m1); err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterMac(ctx, m1); !errors.Is(err, ErrExists) {
		t.Fatalf("same key again = %v", err)
	}
	if err := s.RegisterMac(ctx, Mac{ID: "mac-1", SignPub: "key-b", Created: now}); !errors.Is(err, ErrConflict) {
		t.Fatalf("other key = %v", err)
	}
	if got, _ := s.GetMac(ctx, "mac-1"); got.SignPub != "key-a" || !got.Admin {
		t.Fatalf("mac = %+v", got)
	}
	if _, err := s.GetMac(ctx, "mac-9"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing mac = %v", err)
	}
	s.RegisterMac(ctx, Mac{ID: "mac-2", SignPub: "key-c", Created: now.Add(time.Second)})
	if list, _ := s.ListMacs(ctx); len(list) != 2 || list[0].ID != "mac-1" || list[1].Admin {
		t.Fatalf("list macs = %+v", list)
	}

	// Invites: single use, and they expire.
	if err := s.CreateInvite(ctx, "h1", "mac-1", now); err != nil {
		t.Fatal(err)
	}
	if err := s.UseInvite(ctx, "h1", now); err != nil {
		t.Fatalf("use = %v", err)
	}
	if err := s.UseInvite(ctx, "h1", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second use = %v", err)
	}
	s.CreateInvite(ctx, "h2", "mac-1", now)
	if err := s.UseInvite(ctx, "h2", now.Add(InviteTTL+time.Second)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired invite used: %v", err)
	}

	// Devices belong to one Mac.
	if err := s.PutDevice(ctx, "mac-1", "dev-1", "key-d"); err != nil {
		t.Fatal(err)
	}
	if err := s.PutDevice(ctx, "mac-1", "dev-1", "key-d"); err != nil {
		t.Fatalf("same device again = %v", err)
	}
	if err := s.PutDevice(ctx, "mac-1", "dev-1", "key-e"); !errors.Is(err, ErrConflict) {
		t.Fatalf("device key swap = %v", err)
	}
	if err := s.PutDevice(ctx, "mac-2", "dev-1", "key-d"); !errors.Is(err, ErrConflict) {
		t.Fatalf("another Mac claimed the device: %v", err)
	}
	if d, _ := s.GetDevice(ctx, "dev-1"); d.SignPub != "key-d" || d.Owner != "mac-1" {
		t.Fatalf("device = %+v", d)
	}
	if err := s.RevokeDevice(ctx, "mac-2", "dev-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another Mac revoked the device: %v", err)
	}
	if err := s.RevokeDevice(ctx, "mac-1", "dev-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetDevice(ctx, "dev-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked device = %v", err)
	}
	if err := s.PutDevice(ctx, "mac-1", "dev-1", "key-d"); !errors.Is(err, ErrConflict) {
		t.Fatalf("re-register revoked device = %v", err)
	}

	// Removing a tenant takes its devices and mail with it.
	s.PutDevice(ctx, "mac-2", "dev-2", "key-f")
	d2 := env("mac-2", "dev-2")
	s.PutEnvelope(ctx, d2, now)
	if err := s.RemoveMac(ctx, "mac-2"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetMac(ctx, "mac-2"); !errors.Is(err, ErrNotFound) {
		t.Fatal("removed mac still there")
	}
	if _, err := s.GetDevice(ctx, "dev-2"); !errors.Is(err, ErrNotFound) {
		t.Fatal("removed tenant's device still active")
	}
	if recs, _ := s.ListEnvelopes(ctx, "dev-2", 10, now); len(recs) != 0 {
		t.Fatal("removed tenant's device still has mail")
	}
	if recs, _ := s.ListEnvelopes(ctx, "mac-2", 10, now); len(recs) != 0 {
		t.Fatal("removed tenant still has mail")
	}
	if err := s.RemoveMac(ctx, "mac-2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second remove = %v", err)
	}

	// Presence.
	if at, _ := s.LastSeen(ctx, "phone:mac-1"); !at.IsZero() {
		t.Fatalf("unseen = %v", at)
	}
	s.Touch(ctx, "phone:mac-1", now)
	s.Touch(ctx, "phone:mac-1", now.Add(time.Second))
	if at, _ := s.LastSeen(ctx, "phone:mac-1"); !at.Equal(now.Add(time.Second)) {
		t.Fatalf("last seen = %v", at)
	}

	// Expiry: b (mac-1), pair-2, and invite h2 are left to expire.
	later := now.Add(Retention + time.Second)
	if recs, _ := s.ListEnvelopes(ctx, "mac-1", 10, later); len(recs) != 0 {
		t.Fatal("expired envelope listed")
	}
	n, err := s.DeleteExpired(ctx, later)
	if err != nil || n != 3 {
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

func TestBoltContract(t *testing.T) {
	s, err := OpenBolt(t.TempDir()+"/mailbox.db", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	contract(t, s)
}

// What's in the file survives a restart; a second process can't open it.
func TestBoltPersists(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/mailbox.db"
	now := time.Now()
	s, err := OpenBolt(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	e := envelope.Envelope{V: 1, ID: envelope.NewID(), From: "mac-1", To: "dev-a", TS: now.UnixMilli()}
	if err := s.PutEnvelope(ctx, e, now); err != nil {
		t.Fatal(err)
	}
	if err := s.PutDevice(ctx, "mac-1", "dev-a", "pub"); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBolt(path, 50*time.Millisecond); err == nil {
		t.Fatal("a second open of a held database succeeded")
	}
	s.Close()

	s, err = OpenBolt(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if recs, _ := s.ListEnvelopes(ctx, "dev-a", 10, now); len(recs) != 1 || recs[0].Env.ID != e.ID {
		t.Fatalf("envelope lost across restart: %+v", recs)
	}
	if d, err := s.GetDevice(ctx, "dev-a"); err != nil || d.Owner != "mac-1" {
		t.Fatalf("device lost across restart: %+v %v", d, err)
	}
}
