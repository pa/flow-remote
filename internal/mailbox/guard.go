package mailbox

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"
)

// Guards against a stranger making the mailbox do work, which on a
// pay-per-operation database is money, and on a single instance is
// availability.
//
//   - The mailbox runs as one instance and every registration, revocation
//     and removal goes through it, so it can hold every Mac and device key
//     in memory: loaded once the store connects (Warm), updated on every
//     write. After that a made-up key id is refused without touching the
//     database at all.
//   - Until Warm finishes, lookups that miss spend from one small global
//     budget, as do the unsigned pairing post and registration, so a flood
//     tops out at a few database operations a second whatever its size.
//   - Each client address gets a request budget.
const (
	keyCacheTTL  = 100 * 365 * 24 * time.Hour // entries leave by drop(), not by age
	missRate     = 5                          // per second, across all clients
	missBurst    = 20                         //
	ipPerMinute  = 600
	maxIPBuckets = 50_000
)

type cacheEntry struct {
	mac     Mac
	dev     Device
	expires time.Time
}

type keyCache struct {
	mu sync.Mutex
	m  map[string]cacheEntry
}

func (c *keyCache) get(id string, now time.Time) (cacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[id]
	if !ok || now.After(e.expires) {
		return cacheEntry{}, false
	}
	return e, true
}

func (c *keyCache) put(id string, e cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]cacheEntry{}
	}
	// Only authenticated ids get here, so this stays small; clear expired
	// entries now and then rather than tracking an order.
	if len(c.m) > 10_000 {
		for k, v := range c.m {
			if time.Now().After(v.expires) {
				delete(c.m, k)
			}
		}
	}
	c.m[id] = e
}

func (c *keyCache) drop(ids ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, id := range ids {
		delete(c.m, id)
	}
}

// bucket is a token bucket.
type bucket struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func (b *bucket) take(rate, burst float64, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.last.IsZero() {
		b.tokens, b.last = burst, now
	}
	b.tokens = min(burst, b.tokens+now.Sub(b.last).Seconds()*rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// ipLimiter keeps one bucket per client IP, dropping idle ones.
type ipLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	swept   time.Time
}

func (l *ipLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	if l.buckets == nil {
		l.buckets = map[string]*bucket{}
	}
	if now.Sub(l.swept) > time.Minute {
		for k, b := range l.buckets {
			b.mu.Lock()
			idle := now.Sub(b.last) > 2*time.Minute
			b.mu.Unlock()
			if idle {
				delete(l.buckets, k)
			}
		}
		l.swept = now
	}
	b := l.buckets[ip]
	if b == nil {
		// Past this many addresses in a minute, new ones share one bucket,
		// so a stream of distinct addresses can't grow memory without bound.
		if len(l.buckets) >= maxIPBuckets {
			ip = "overflow"
			b = l.buckets[ip]
		}
		if b == nil {
			b = &bucket{}
			l.buckets[ip] = b
		}
	}
	l.mu.Unlock()
	return b.take(ipPerMinute/60.0, ipPerMinute/4.0, now)
}

// clientIP is the address to rate-limit on: the connection's own. Nothing
// in front of `flow-remote run` is trusted to name the client, so
// X-Forwarded-For is ignored (internal/serve also drops it).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// spendMiss takes one unit of the global budget for work a stranger can
// cause. False means the mailbox is being flooded; the caller answers 429.
func (s *Server) spendMiss() bool {
	return s.miss.take(missRate, missBurst, s.now())
}

// Warm loads every Mac and device key. Call it once the store is ready.
func (s *Server) Warm(ctx context.Context) error {
	macs, err := s.Store.ListMacs(ctx)
	if err != nil {
		return err
	}
	for _, m := range macs {
		s.keys.put("mac:"+m.ID, cacheEntry{mac: m, expires: s.now().Add(keyCacheTTL)})
		ids, err := s.Store.ListDevices(ctx, m.ID)
		if err != nil {
			return err
		}
		for _, id := range ids {
			d, err := s.Store.GetDevice(ctx, id)
			if err != nil {
				continue
			}
			s.keys.put("dev:"+id, cacheEntry{dev: d, expires: s.now().Add(keyCacheTTL)})
		}
	}
	s.warm.Store(true)
	return nil
}

func (s *Server) lookupDevice(ctx context.Context, id string) (Device, error) {
	if e, ok := s.keys.get("dev:"+id, s.now()); ok {
		return e.dev, nil
	}
	if s.warm.Load() {
		return Device{}, ErrNotFound // the full set is in memory
	}
	if !s.spendMiss() {
		return Device{}, errBusy
	}
	d, err := s.Store.GetDevice(ctx, id)
	if err == nil {
		s.keys.put("dev:"+id, cacheEntry{dev: d, expires: s.now().Add(keyCacheTTL)})
	}
	return d, err
}

func (s *Server) lookupMac(ctx context.Context, id string) (Mac, error) {
	if e, ok := s.keys.get("mac:"+id, s.now()); ok {
		return e.mac, nil
	}
	if s.warm.Load() {
		return Mac{}, ErrNotFound
	}
	if !s.spendMiss() {
		return Mac{}, errBusy
	}
	m, err := s.Store.GetMac(ctx, id)
	if err == nil {
		s.keys.put("mac:"+id, cacheEntry{mac: m, expires: s.now().Add(keyCacheTTL)})
	}
	return m, err
}

// sigCache remembers accepted request signatures for the signing window,
// so a captured request can't be sent again within it. ECDSA signatures
// are randomised, so two honest requests never share one. Only signatures
// that verified are stored, so its size is bounded by honest traffic.
type sigCache struct {
	mu    sync.Mutex
	seen  map[string]time.Time
	swept time.Time
}

// firstUse records sig and reports whether it's new.
func (c *sigCache) firstUse(sig string, now time.Time, window time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = map[string]time.Time{}
	}
	if now.Sub(c.swept) > window {
		for k, t := range c.seen {
			if now.Sub(t) > 2*window {
				delete(c.seen, k)
			}
		}
		c.swept = now
	}
	if _, ok := c.seen[sig]; ok {
		return false
	}
	c.seen[sig] = now
	return true
}
