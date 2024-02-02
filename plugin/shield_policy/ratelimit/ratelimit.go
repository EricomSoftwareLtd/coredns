package ratelimitpool

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type RateLimit struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type RateLimitGroup struct {
	limiters   map[string]*RateLimit
	sync.Mutex // TODO is this necessary?  benchmark this
}

func NewGroup() *RateLimitGroup {
	group := &RateLimitGroup{
		limiters: map[string]*RateLimit{},
	}
	go group.periodicCleanup()
	return group
}

// get limiter for client with id
// will create a new limiter if does not exist
// will also update limits
func (group *RateLimitGroup) GetLimiterWithSettings(id string, limitPerSec float64, burst int) *RateLimit {
	group.Lock()

	limit := rate.Limit(limitPerSec)
	l := group.limiters[id]
	if l == nil {
		l = &RateLimit{
			limiter: rate.NewLimiter(limit, burst),
		}
		group.limiters[id] = l
		group.Unlock()
	} else {
		group.Unlock()
		if l.limiter.Burst() != burst {
			l.limiter.SetBurst(burst)
		}
		if l.limiter.Limit() != limit {
			l.limiter.SetLimit(limit)
		}
	}
	l.lastSeen = time.Now()
	return l
}

func (pool *RateLimitGroup) periodicCleanup() {
	for {
		time.Sleep(time.Minute)
		pool.Lock()
		for id, client := range pool.limiters {
			if time.Since(client.lastSeen) > 3*time.Minute {
				delete(pool.limiters, id)
			}
		}
		pool.Unlock()
	}
}

func (l *RateLimit) Allow() bool {
	l.lastSeen = time.Now() // TODO data race with periodicCleanup, fix with atomics?
	return l.limiter.Allow()
}
