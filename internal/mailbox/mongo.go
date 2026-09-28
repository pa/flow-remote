package mailbox

import (
	"context"
	"errors"
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
	envs, pairs, macs, devices, presence *mongo.Collection

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
	ExpiresAt time.Time          `bson:"expires_at"`
	Filled    bool               `bson:"filled"`
	Env       *envelope.Envelope `bson:"env,omitempty"`
}

type deviceDoc struct {
	ID      string `bson:"_id"`
	SignPub string `bson:"sign_pub"`
	Revoked bool   `bson:"revoked"`
}

type macDoc struct {
	ID      string `bson:"_id"`
	SignPub string `bson:"sign_pub"`
}

type presenceDoc struct {
	ID string    `bson:"_id"`
	At time.Time `bson:"at"`
}

// OpenMongo connects and makes sure the indexes exist.
func OpenMongo(ctx context.Context, uri, dbName string) (*Mongo, error) {
	cl, err := mongo.Connect(options.Client().ApplyURI(uri).SetTimeout(10 * time.Second))
	if err != nil {
		return nil, err
	}
	if err := cl.Ping(ctx, nil); err != nil {
		return nil, err
	}
	db := cl.Database(dbName)
	m := &Mongo{
		envs: db.Collection("envelopes"), pairs: db.Collection("pairs"),
		macs: db.Collection("macs"), devices: db.Collection("devices"), presence: db.Collection("presence"),
		touched: map[string]time.Time{}, seen: map[string]time.Time{},
	}
	_, err = m.envs.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "to", Value: 1}, {Key: "seq", Value: 1}}},
		{Keys: bson.D{{Key: "expires_at", Value: 1}}},
	})
	if err != nil {
		return nil, err
	}
	return m, nil
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
	_, err := m.envs.InsertOne(ctx, envDoc{
		ID: e.ID, To: e.To, Seq: m.nextSeq(now), ReceivedAt: now, ExpiresAt: now.Add(Retention), Env: e,
	})
	if mongo.IsDuplicateKeyError(err) {
		return ErrExists
	}
	return err
}

func (m *Mongo) ListEnvelopes(ctx context.Context, to string, limit int, now time.Time) ([]Record, error) {
	cur, err := m.envs.Find(ctx,
		bson.M{"to": to, "expires_at": bson.M{"$gt": now}},
		options.Find().SetSort(bson.D{{Key: "seq", Value: 1}}).SetLimit(int64(limit)))
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
	_, err := m.envs.DeleteMany(ctx, bson.M{"to": to, "_id": bson.M{"$in": ids}})
	return err
}

func (m *Mongo) OpenPair(ctx context.Context, pairID string, now time.Time) error {
	_, err := m.pairs.InsertOne(ctx, pairDoc{ID: pairID, ExpiresAt: now.Add(PairTTL)})
	if mongo.IsDuplicateKeyError(err) {
		return ErrExists
	}
	return err
}

// PutPair fills the slot in one conditional update, so two posts racing
// for the same slot can't both win.
func (m *Mongo) PutPair(ctx context.Context, pairID string, e envelope.Envelope, now time.Time) error {
	res, err := m.pairs.UpdateOne(ctx,
		bson.M{"_id": pairID, "filled": false, "expires_at": bson.M{"$gt": now}},
		bson.M{"$set": bson.M{"filled": true, "env": e}})
	if err != nil {
		return err
	}
	if res.MatchedCount == 1 {
		return nil
	}
	n, err := m.pairs.CountDocuments(ctx, bson.M{"_id": pairID, "filled": true, "expires_at": bson.M{"$gt": now}})
	if err != nil {
		return err
	}
	if n > 0 {
		return ErrExists
	}
	return ErrNotFound
}

func (m *Mongo) TakePair(ctx context.Context, pairID string, now time.Time) (envelope.Envelope, error) {
	var d pairDoc
	err := m.pairs.FindOneAndDelete(ctx, bson.M{"_id": pairID, "filled": true, "expires_at": bson.M{"$gt": now}}).Decode(&d)
	if errors.Is(err, mongo.ErrNoDocuments) || (err == nil && d.Env == nil) {
		return envelope.Envelope{}, ErrNotFound
	}
	if err != nil {
		return envelope.Envelope{}, err
	}
	return *d.Env, nil
}

func (m *Mongo) RegisterMac(ctx context.Context, macID, signPub string) error {
	_, err := m.macs.InsertOne(ctx, macDoc{ID: macID, SignPub: signPub})
	if !mongo.IsDuplicateKeyError(err) {
		return err
	}
	cur, err := m.MacKey(ctx, macID)
	if err != nil {
		return err
	}
	if cur != signPub {
		return ErrConflict
	}
	return nil
}

func (m *Mongo) MacKey(ctx context.Context, macID string) (string, error) {
	var d macDoc
	err := m.macs.FindOne(ctx, bson.M{"_id": macID}).Decode(&d)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return "", ErrNotFound
	}
	return d.SignPub, err
}

func (m *Mongo) PutDevice(ctx context.Context, deviceID, signPub string) error {
	_, err := m.devices.InsertOne(ctx, deviceDoc{ID: deviceID, SignPub: signPub})
	if !mongo.IsDuplicateKeyError(err) {
		return err
	}
	var d deviceDoc
	if err := m.devices.FindOne(ctx, bson.M{"_id": deviceID}).Decode(&d); err != nil {
		return err
	}
	if d.Revoked || d.SignPub != signPub {
		return ErrConflict
	}
	return nil
}

func (m *Mongo) RevokeDevice(ctx context.Context, deviceID string) error {
	_, err := m.devices.UpdateOne(ctx, bson.M{"_id": deviceID}, bson.M{"$set": bson.M{"revoked": true}}, options.UpdateOne().SetUpsert(true))
	return err
}

func (m *Mongo) DeviceKey(ctx context.Context, deviceID string) (string, error) {
	var d deviceDoc
	err := m.devices.FindOne(ctx, bson.M{"_id": deviceID, "revoked": false}).Decode(&d)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return "", ErrNotFound
	}
	return d.SignPub, err
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
	_, err := m.presence.UpdateOne(ctx, bson.M{"_id": who}, bson.M{"$set": bson.M{"at": now}}, options.UpdateOne().SetUpsert(true))
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
	err := m.presence.FindOne(ctx, bson.M{"_id": who}).Decode(&d)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return time.Time{}, nil
	}
	return d.At, err
}

func (m *Mongo) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	a, err := m.envs.DeleteMany(ctx, bson.M{"expires_at": bson.M{"$lte": now}})
	if err != nil {
		return 0, err
	}
	b, err := m.pairs.DeleteMany(ctx, bson.M{"expires_at": bson.M{"$lte": now}})
	if err != nil {
		return int(a.DeletedCount), err
	}
	return int(a.DeletedCount + b.DeletedCount), nil
}
