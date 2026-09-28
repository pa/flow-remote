package mailbox

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/pa/flow-remote/internal/envelope"
)

// touchEvery limits presence writes. Every poll touches presence, and a
// write per poll would be most of the database bill for no benefit: the
// phone only needs to know the Mac was seen within about a minute.
const touchEvery = 20 * time.Second

// Mongo is the Store on Firestore with MongoDB compatibility. It works on
// plain MongoDB too, which is what the tests use.
type Mongo struct {
	envs, pairs, macs, devices, invites, presence *mongo.Collection

	// IndexErr is why index creation failed, if it did. Not fatal.
	IndexErr error

	mu      sync.Mutex
	touched map[string]time.Time // last presence write per key
	seen    map[string]time.Time // latest presence per key, written or not
	lastSeq int64
}

type envDoc struct {
	ID         string            `bson:"_id"`
	To         string            `bson:"to"`
	Seq        int64             `bson:"seq"`
	ReceivedAt time.Time         `bson:"received_at"`
	ExpiresAt  time.Time         `bson:"expires_at"`
	Env        envelope.Envelope `bson:"env"`
}

type pairDoc struct {
	ID        string             `bson:"_id"`
	Owner     string             `bson:"owner"`
	ExpiresAt time.Time          `bson:"expires_at"`
	Filled    bool               `bson:"filled"`
	Env       *envelope.Envelope `bson:"env,omitempty"`
}

type deviceDoc struct {
	ID      string `bson:"_id"`
	Owner   string `bson:"owner"`
	SignPub string `bson:"sign_pub"`
	Revoked bool   `bson:"revoked"`
}

type inviteDoc struct {
	ID        string    `bson:"_id"` // sha256 of the code
	CreatedBy string    `bson:"created_by"`
	ExpiresAt time.Time `bson:"expires_at"`
}

type macDoc struct {
	ID      string    `bson:"_id"`
	SignPub string    `bson:"sign_pub"`
	Admin   bool      `bson:"admin"`
	Created time.Time `bson:"created"`
}

type presenceDoc struct {
	ID string    `bson:"_id"`
	At time.Time `bson:"at"`
}

// OpenMongo connects and makes sure the indexes exist.
func OpenMongo(ctx context.Context, uri, dbName string) (*Mongo, error) {
	// Cloud Run throttles CPU between requests, so pooled connections go
	// stale while idle; drop them before they do.
	cl, err := mongo.Connect(options.Client().ApplyURI(uri).SetTimeout(10 * time.Second).SetMaxConnIdleTime(15 * time.Second))
	if err != nil {
		return nil, err
	}
	if err := cl.Ping(ctx, nil); err != nil {
		return nil, err
	}
	db := cl.Database(dbName)
	m := &Mongo{
		envs: db.Collection("envelopes"), pairs: db.Collection("pairs"),
		macs: db.Collection("macs"), devices: db.Collection("devices"), invites: db.Collection("invites"),
		presence: db.Collection("presence"),
		touched:  map[string]time.Time{}, seen: map[string]time.Time{},
	}
	if err := m.migrate(ctx); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	// Best effort. Creating indexes needs an index-admin role the service
	// shouldn't hold for a handful of small collections, and Firestore's
	// Enterprise edition runs these queries without an index anyway.
	if _, err := m.envs.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "to", Value: 1}, {Key: "seq", Value: 1}}},
		{Keys: bson.D{{Key: "expires_at", Value: 1}}},
	}); err != nil {
		m.IndexErr = err
	}
	return m, nil
}

// migrate brings records from before tenancy up to date. It's idempotent,
// so it runs on every start. Before tenancy there was one Mac and no admin
// flag or device owner: the oldest Mac becomes the admin, and if there's
// exactly one Mac, devices without an owner become its.
func (m *Mongo) migrate(ctx context.Context) error {
	macs, err := m.ListMacs(ctx)
	if err != nil || len(macs) == 0 {
		return err
	}
	hasAdmin := false
	for _, mac := range macs {
		hasAdmin = hasAdmin || mac.Admin
	}
	if !hasAdmin {
		if _, err := retry(func() (*mongo.UpdateResult, error) {
			return m.macs.UpdateOne(ctx, bson.M{"_id": macs[0].ID}, bson.M{"$set": bson.M{"admin": true}})
		}); err != nil {
			return err
		}
	}
	// Pre-tenancy records have no creation time.
	if _, err := retry(func() (*mongo.UpdateResult, error) {
		return m.macs.UpdateMany(ctx, bson.M{"created": bson.M{"$exists": false}}, bson.M{"$set": bson.M{"created": time.Now()}})
	}); err != nil {
		return err
	}
	if len(macs) == 1 {
		ownerless := bson.M{"$or": bson.A{bson.M{"owner": bson.M{"$exists": false}}, bson.M{"owner": ""}}}
		if _, err := retry(func() (*mongo.UpdateResult, error) {
			return m.devices.UpdateMany(ctx, ownerless, bson.M{"$set": bson.M{"owner": macs[0].ID}})
		}); err != nil {
			return err
		}
	}
	return nil
}

// retry runs op again once after a network error. Firestore's connection
// string disables the driver's own write retries. Every op here is safe to
// repeat: inserts carry fixed ids (a repeat is a duplicate-key error the
// caller already handles) and updates set values rather than add to them.
func retry[T any](op func() (T, error)) (T, error) {
	v, err := op()
	if mongo.IsNetworkError(err) {
		return op()
	}
	return v, err
}

func retryErr(op func() error) error {
	_, err := retry(func() (struct{}, error) { return struct{}{}, op() })
	return err
}

// nextSeq is arrival order. The service runs as one instance, so a
// monotonic clock reading is enough; a restart moves forward in time.
func (m *Mongo) nextSeq(now time.Time) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := now.UnixNano()
	if s <= m.lastSeq {
		s = m.lastSeq + 1
	}
	m.lastSeq = s
	return s
}

func (m *Mongo) PutEnvelope(ctx context.Context, e envelope.Envelope, now time.Time) error {
	_, err := retry(func() (*mongo.InsertOneResult, error) {
		return m.envs.InsertOne(ctx, envDoc{
			ID: e.ID, To: e.To, Seq: m.nextSeq(now), ReceivedAt: now, ExpiresAt: now.Add(Retention), Env: e,
		})
	})
	if mongo.IsDuplicateKeyError(err) {
		return ErrExists
	}
	return err
}

func (m *Mongo) ListEnvelopes(ctx context.Context, to string, limit int, now time.Time) ([]Record, error) {
	cur, err := retry(func() (*mongo.Cursor, error) {
		return m.envs.Find(ctx,
			bson.M{"to": to, "expires_at": bson.M{"$gt": now}},
			options.Find().SetSort(bson.D{{Key: "seq", Value: 1}}).SetLimit(int64(limit)))
	})
	if err != nil {
		return nil, err
	}
	var docs []envDoc
	if err := cur.All(ctx, &docs); err != nil {
		return nil, err
	}
	out := make([]Record, len(docs))
	for i, d := range docs {
		out[i] = Record{Env: d.Env, To: d.To, Seq: d.Seq, ReceivedAt: d.ReceivedAt, ExpiresAt: d.ExpiresAt}
	}
	return out, nil
}

func (m *Mongo) Ack(ctx context.Context, to string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := retry(func() (*mongo.DeleteResult, error) {
		return m.envs.DeleteMany(ctx, bson.M{"to": to, "_id": bson.M{"$in": ids}})
	})
	return err
}

func (m *Mongo) OpenPair(ctx context.Context, pairID, macID string, now time.Time) error {
	_, err := retry(func() (*mongo.InsertOneResult, error) {
		return m.pairs.InsertOne(ctx, pairDoc{ID: pairID, Owner: macID, ExpiresAt: now.Add(PairTTL)})
	})
	if mongo.IsDuplicateKeyError(err) {
		return ErrExists
	}
	return err
}

// PutPair fills the slot in one conditional update, so two posts racing
// for the same slot can't both win, and only a slot owned by the
// envelope's recipient matches.
func (m *Mongo) PutPair(ctx context.Context, pairID string, e envelope.Envelope, now time.Time) error {
	res, err := retry(func() (*mongo.UpdateResult, error) {
		return m.pairs.UpdateOne(ctx,
			bson.M{"_id": pairID, "owner": e.To, "filled": false, "expires_at": bson.M{"$gt": now}},
			bson.M{"$set": bson.M{"filled": true, "env": e}})
	})
	if err != nil {
		return err
	}
	if res.MatchedCount == 1 {
		return nil
	}
	n, err := retry(func() (int64, error) {
		return m.pairs.CountDocuments(ctx, bson.M{"_id": pairID, "owner": e.To, "filled": true, "expires_at": bson.M{"$gt": now}})
	})
	if err != nil {
		return err
	}
	if n > 0 {
		return ErrExists
	}
	return ErrNotFound
}

func (m *Mongo) TakePair(ctx context.Context, pairID, macID string, now time.Time) (envelope.Envelope, error) {
	var d pairDoc
	err := retryErr(func() error {
		return m.pairs.FindOneAndDelete(ctx, bson.M{"_id": pairID, "owner": macID, "filled": true, "expires_at": bson.M{"$gt": now}}).Decode(&d)
	})
	if errors.Is(err, mongo.ErrNoDocuments) || (err == nil && d.Env == nil) {
		return envelope.Envelope{}, ErrNotFound
	}
	if err != nil {
		return envelope.Envelope{}, err
	}
	return *d.Env, nil
}

func (m *Mongo) RegisterMac(ctx context.Context, mac Mac) error {
	_, err := retry(func() (*mongo.InsertOneResult, error) {
		return m.macs.InsertOne(ctx, macDoc{ID: mac.ID, SignPub: mac.SignPub, Admin: mac.Admin, Created: mac.Created})
	})
	if !mongo.IsDuplicateKeyError(err) {
		return err
	}
	cur, err := m.GetMac(ctx, mac.ID)
	if err != nil {
		return err
	}
	if cur.SignPub != mac.SignPub {
		return ErrConflict
	}
	return ErrExists
}

func (m *Mongo) GetMac(ctx context.Context, macID string) (Mac, error) {
	var d macDoc
	err := retryErr(func() error { return m.macs.FindOne(ctx, bson.M{"_id": macID}).Decode(&d) })
	if errors.Is(err, mongo.ErrNoDocuments) {
		return Mac{}, ErrNotFound
	}
	return Mac{ID: d.ID, SignPub: d.SignPub, Admin: d.Admin, Created: d.Created}, err
}

func (m *Mongo) ListMacs(ctx context.Context) ([]Mac, error) {
	cur, err := retry(func() (*mongo.Cursor, error) {
		return m.macs.Find(ctx, bson.M{}, options.Find().SetSort(bson.D{{Key: "created", Value: 1}}))
	})
	if err != nil {
		return nil, err
	}
	var docs []macDoc
	if err := cur.All(ctx, &docs); err != nil {
		return nil, err
	}
	out := make([]Mac, len(docs))
	for i, d := range docs {
		out[i] = Mac{ID: d.ID, SignPub: d.SignPub, Admin: d.Admin, Created: d.Created}
	}
	return out, nil
}

// RemoveMac deletes the tenant. Its devices stay, revoked, so their ids
// can't be registered again.
func (m *Mongo) RemoveMac(ctx context.Context, macID string) error {
	res, err := retry(func() (*mongo.DeleteResult, error) { return m.macs.DeleteOne(ctx, bson.M{"_id": macID}) })
	if err != nil {
		return err
	}
	if res.DeletedCount == 0 {
		return ErrNotFound
	}
	cur, err := retry(func() (*mongo.Cursor, error) { return m.devices.Find(ctx, bson.M{"owner": macID}) })
	if err != nil {
		return err
	}
	var devs []deviceDoc
	if err := cur.All(ctx, &devs); err != nil {
		return err
	}
	ids := []string{macID}
	for _, d := range devs {
		ids = append(ids, d.ID)
	}
	if _, err := retry(func() (*mongo.UpdateResult, error) {
		return m.devices.UpdateMany(ctx, bson.M{"owner": macID}, bson.M{"$set": bson.M{"revoked": true}})
	}); err != nil {
		return err
	}
	if _, err := retry(func() (*mongo.DeleteResult, error) {
		return m.envs.DeleteMany(ctx, bson.M{"to": bson.M{"$in": ids}})
	}); err != nil {
		return err
	}
	_, err = retry(func() (*mongo.DeleteResult, error) { return m.pairs.DeleteMany(ctx, bson.M{"owner": macID}) })
	return err
}

func (m *Mongo) CreateInvite(ctx context.Context, hash, createdBy string, now time.Time) error {
	_, err := retry(func() (*mongo.InsertOneResult, error) {
		return m.invites.InsertOne(ctx, inviteDoc{ID: hash, CreatedBy: createdBy, ExpiresAt: now.Add(InviteTTL)})
	})
	if mongo.IsDuplicateKeyError(err) {
		return ErrExists
	}
	return err
}

// UseInvite deletes the invite in the same call that checks it, so an
// invite can only be used once even under concurrent requests.
func (m *Mongo) UseInvite(ctx context.Context, hash string, now time.Time) error {
	res, err := retry(func() (*mongo.DeleteResult, error) {
		return m.invites.DeleteOne(ctx, bson.M{"_id": hash, "expires_at": bson.M{"$gt": now}})
	})
	if err != nil {
		return err
	}
	if res.DeletedCount == 0 {
		return ErrNotFound
	}
	return nil
}

func (m *Mongo) PutDevice(ctx context.Context, owner, deviceID, signPub string) error {
	_, err := retry(func() (*mongo.InsertOneResult, error) {
		return m.devices.InsertOne(ctx, deviceDoc{ID: deviceID, Owner: owner, SignPub: signPub})
	})
	if !mongo.IsDuplicateKeyError(err) {
		return err
	}
	var d deviceDoc
	if err := retryErr(func() error { return m.devices.FindOne(ctx, bson.M{"_id": deviceID}).Decode(&d) }); err != nil {
		return err
	}
	if d.Revoked || d.SignPub != signPub || d.Owner != owner {
		return ErrConflict
	}
	return nil
}

func (m *Mongo) RevokeDevice(ctx context.Context, owner, deviceID string) error {
	res, err := retry(func() (*mongo.UpdateResult, error) {
		return m.devices.UpdateOne(ctx, bson.M{"_id": deviceID, "owner": owner}, bson.M{"$set": bson.M{"revoked": true}})
	})
	if err != nil {
		return err
	}
	if res.MatchedCount == 0 {
		return ErrNotFound
	}
	return nil
}

func (m *Mongo) GetDevice(ctx context.Context, deviceID string) (Device, error) {
	var d deviceDoc
	err := retryErr(func() error {
		return m.devices.FindOne(ctx, bson.M{"_id": deviceID, "revoked": false}).Decode(&d)
	})
	if errors.Is(err, mongo.ErrNoDocuments) {
		return Device{}, ErrNotFound
	}
	return Device{SignPub: d.SignPub, Owner: d.Owner}, err
}

func (m *Mongo) ListDevices(ctx context.Context, owner string) ([]string, error) {
	cur, err := retry(func() (*mongo.Cursor, error) {
		return m.devices.Find(ctx, bson.M{"owner": owner, "revoked": false}, options.Find().SetSort(bson.D{{Key: "_id", Value: 1}}))
	})
	if err != nil {
		return nil, err
	}
	var docs []deviceDoc
	if err := cur.All(ctx, &docs); err != nil {
		return nil, err
	}
	out := make([]string, len(docs))
	for i, d := range docs {
		out[i] = d.ID
	}
	return out, nil
}

func (m *Mongo) Touch(ctx context.Context, who string, now time.Time) error {
	m.mu.Lock()
	m.seen[who] = now
	if now.Sub(m.touched[who]) < touchEvery {
		m.mu.Unlock()
		return nil
	}
	m.touched[who] = now
	m.mu.Unlock()
	_, err := retry(func() (*mongo.UpdateResult, error) {
		return m.presence.UpdateOne(ctx, bson.M{"_id": who}, bson.M{"$set": bson.M{"at": now}}, options.UpdateOne().SetUpsert(true))
	})
	return err
}

func (m *Mongo) LastSeen(ctx context.Context, who string) (time.Time, error) {
	m.mu.Lock()
	t, ok := m.seen[who]
	m.mu.Unlock()
	if ok {
		return t, nil
	}
	// After a restart, fall back to the last write.
	var d presenceDoc
	err := retryErr(func() error { return m.presence.FindOne(ctx, bson.M{"_id": who}).Decode(&d) })
	if errors.Is(err, mongo.ErrNoDocuments) {
		return time.Time{}, nil
	}
	return d.At, err
}

func (m *Mongo) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	a, err := retry(func() (*mongo.DeleteResult, error) {
		return m.envs.DeleteMany(ctx, bson.M{"expires_at": bson.M{"$lte": now}})
	})
	if err != nil {
		return 0, err
	}
	b, err := retry(func() (*mongo.DeleteResult, error) {
		return m.pairs.DeleteMany(ctx, bson.M{"expires_at": bson.M{"$lte": now}})
	})
	if err != nil {
		return int(a.DeletedCount), err
	}
	c, err := retry(func() (*mongo.DeleteResult, error) {
		return m.invites.DeleteMany(ctx, bson.M{"expires_at": bson.M{"$lte": now}})
	})
	if err != nil {
		return int(a.DeletedCount), err
	}
	return int(a.DeletedCount + b.DeletedCount + c.DeletedCount), nil
}
