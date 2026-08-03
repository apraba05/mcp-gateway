package gateway

import (
	"sync"
	"time"
)

// tokenBucket is a concurrency-safe token bucket that starts full and
// refills deterministically by one token per configured interval, up to
// capacity. Refill progress is computed from an injected clock so tests can
// drive time deterministically without sleeping.
type tokenBucket struct {
	mu             sync.Mutex
	capacity       uint32
	refillInterval time.Duration
	tokens         uint32
	lastRefill     time.Time
	clock          func() time.Time
}

func newTokenBucket(capacity uint32, refillInterval time.Duration, clock func() time.Time) *tokenBucket {
	if clock == nil {
		clock = time.Now
	}
	return &tokenBucket{
		capacity:       capacity,
		refillInterval: refillInterval,
		tokens:         capacity,
		lastRefill:     clock(),
		clock:          clock,
	}
}

// allow reports whether a token was available and consumed. When it was
// not, it also returns the bounded duration until the next token refills.
func (b *tokenBucket) allow() (bool, time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.clock()
	b.refillLocked(now)

	if b.tokens > 0 {
		b.tokens--
		return true, 0
	}

	elapsed := now.Sub(b.lastRefill)
	wait := b.refillInterval - elapsed
	if wait <= 0 || wait > b.refillInterval {
		wait = b.refillInterval
	}
	return false, wait
}

// refillLocked advances lastRefill by whole elapsed intervals, crediting one
// token per interval up to capacity. The number of credited intervals is
// capped by the token deficit before being multiplied back into a duration,
// so this cannot overflow even after an arbitrarily long idle period.
func (b *tokenBucket) refillLocked(now time.Time) {
	if b.tokens >= b.capacity {
		b.lastRefill = now
		return
	}
	elapsed := now.Sub(b.lastRefill)
	if elapsed < b.refillInterval {
		return
	}
	deficit := b.capacity - b.tokens
	intervals := elapsed / b.refillInterval
	if intervals >= time.Duration(deficit) {
		// The bucket reaches capacity; any further elapsed time carries no
		// additional value, so drop it rather than let it accumulate.
		b.tokens = b.capacity
		b.lastRefill = now
		return
	}
	credited := uint32(intervals)
	b.tokens += credited
	b.lastRefill = b.lastRefill.Add(time.Duration(credited) * b.refillInterval)
}
