package mailbox

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/pa/flow-remote/internal/envelope"
)

// ErrUnavailable means the store isn't connected yet.
var ErrUnavailable = errors.New("mailbox: store not connected yet")

// Deferred is a Store that connects in the background. Cloud Run kills a
// container that doesn't listen on $PORT soon after starting, so the
// server listens at once and reports 503 until the database is reachable,
// rather than exiting on the first failed connection.
type Deferred struct {
	inner   atomic.Pointer[storeBox]
	lastErr atomic.Pointer[string]
}

type storeBox struct{ s Store }

// Connect retries open until it succeeds or ctx ends.
func (d *Deferred) Connect(ctx context.Context, open func(context.Context) (Store, error), log func(error)) {
	wait := time.Second
	for {
		s, err := open(ctx)
		if err == nil {
			d.inner.Store(&storeBox{s})
			d.lastErr.Store(nil)
			return
		}
		msg := err.Error()
		d.lastErr.Store(&msg)
		if log != nil {
			log(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(wait*2, 30*time.Second)
	}
}

// Ready returns nil once connected, or the last connection error.
func (d *Deferred) Ready() error {
	if d.inner.Load() != nil {
		return nil
	}
	if e := d.lastErr.Load(); e != nil {
		return errors.New(*e)
	}
	return ErrUnavailable
}

func (d *Deferred) get() (Store, error) {
	b := d.inner.Load()
	if b == nil {
		return nil, ErrUnavailable
	}
	return b.s, nil
}

func (d *Deferred) PutEnvelope(ctx context.Context, e envelope.Envelope, now time.Time) error {
	s, err := d.get()
	if err != nil {
		return err
	}
	return s.PutEnvelope(ctx, e, now)
}

func (d *Deferred) ListEnvelopes(ctx context.Context, to string, limit int, now time.Time) ([]Record, error) {
	s, err := d.get()
	if err != nil {
		return nil, err
	}
	return s.ListEnvelopes(ctx, to, limit, now)
}

func (d *Deferred) Ack(ctx context.Context, to string, ids []string) error {
	s, err := d.get()
	if err != nil {
		return err
	}
	return s.Ack(ctx, to, ids)
}

func (d *Deferred) OpenPair(ctx context.Context, pairID, macID string, now time.Time) error {
	s, err := d.get()
	if err != nil {
		return err
	}
	return s.OpenPair(ctx, pairID, macID, now)
}

func (d *Deferred) PutPair(ctx context.Context, pairID string, e envelope.Envelope, now time.Time) error {
	s, err := d.get()
	if err != nil {
		return err
	}
	return s.PutPair(ctx, pairID, e, now)
}

func (d *Deferred) TakePair(ctx context.Context, pairID, macID string, now time.Time) (envelope.Envelope, error) {
	s, err := d.get()
	if err != nil {
		return envelope.Envelope{}, err
	}
	return s.TakePair(ctx, pairID, macID, now)
}

func (d *Deferred) RegisterMac(ctx context.Context, m Mac) error {
	s, err := d.get()
	if err != nil {
		return err
	}
	return s.RegisterMac(ctx, m)
}

func (d *Deferred) GetMac(ctx context.Context, macID string) (Mac, error) {
	s, err := d.get()
	if err != nil {
		return Mac{}, err
	}
	return s.GetMac(ctx, macID)
}

func (d *Deferred) ListMacs(ctx context.Context) ([]Mac, error) {
	s, err := d.get()
	if err != nil {
		return nil, err
	}
	return s.ListMacs(ctx)
}

func (d *Deferred) RemoveMac(ctx context.Context, macID string) error {
	s, err := d.get()
	if err != nil {
		return err
	}
	return s.RemoveMac(ctx, macID)
}

func (d *Deferred) CreateInvite(ctx context.Context, hash, createdBy string, now time.Time) error {
	s, err := d.get()
	if err != nil {
		return err
	}
	return s.CreateInvite(ctx, hash, createdBy, now)
}

func (d *Deferred) UseInvite(ctx context.Context, hash string, now time.Time) error {
	s, err := d.get()
	if err != nil {
		return err
	}
	return s.UseInvite(ctx, hash, now)
}

func (d *Deferred) PutDevice(ctx context.Context, owner, deviceID, signPub string) error {
	s, err := d.get()
	if err != nil {
		return err
	}
	return s.PutDevice(ctx, owner, deviceID, signPub)
}

func (d *Deferred) RevokeDevice(ctx context.Context, owner, deviceID string) error {
	s, err := d.get()
	if err != nil {
		return err
	}
	return s.RevokeDevice(ctx, owner, deviceID)
}

func (d *Deferred) GetDevice(ctx context.Context, deviceID string) (Device, error) {
	s, err := d.get()
	if err != nil {
		return Device{}, err
	}
	return s.GetDevice(ctx, deviceID)
}

func (d *Deferred) ListDevices(ctx context.Context, owner string) ([]string, error) {
	s, err := d.get()
	if err != nil {
		return nil, err
	}
	return s.ListDevices(ctx, owner)
}

func (d *Deferred) Touch(ctx context.Context, who string, now time.Time) error {
	s, err := d.get()
	if err != nil {
		return err
	}
	return s.Touch(ctx, who, now)
}

func (d *Deferred) LastSeen(ctx context.Context, who string) (time.Time, error) {
	s, err := d.get()
	if err != nil {
		return time.Time{}, err
	}
	return s.LastSeen(ctx, who)
}

func (d *Deferred) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	s, err := d.get()
	if err != nil {
		return 0, err
	}
	return s.DeleteExpired(ctx, now)
}
