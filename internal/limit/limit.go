package limit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type entry struct {
	lim  *rate.Limiter
	seen time.Time
}

type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*entry
	r       rate.Limit
	burst   int
	idleTTL time.Duration

	// Idle buckets are swept at most once per sweepEvery, so no request pays
	// for a scan of the whole map. maxBuckets bounds memory when many distinct
	// keys arrive faster than they go idle: past it the map is reset, which
	// costs callers their accumulated debt but never their availability.
	sweepEvery time.Duration
	lastSweep  time.Time
	maxBuckets int
	now        func() time.Time
}

func New(perMinute, burst int) *Limiter {
	if perMinute <= 0 {
		perMinute = 120
	}
	if burst <= 0 {
		burst = 30
	}
	return &Limiter{
		buckets:    map[string]*entry{},
		r:          rate.Limit(float64(perMinute) / 60.0),
		burst:      burst,
		idleTTL:    10 * time.Minute,
		sweepEvery: time.Minute,
		maxBuckets: 100_000,
		now:        time.Now,
	}
}

func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Sub(l.lastSweep) >= l.sweepEvery {
		for k, v := range l.buckets {
			if now.Sub(v.seen) > l.idleTTL {
				delete(l.buckets, k)
			}
		}
		l.lastSweep = now
	}
	e, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxBuckets {
			l.buckets = map[string]*entry{}
		}
		e = &entry{lim: rate.NewLimiter(l.r, l.burst)}
		l.buckets[key] = e
	}
	e.seen = now
	return e.lim.AllowN(now, 1)
}
