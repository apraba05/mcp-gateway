package gateway

import (
	"sync"
	"testing"
	"time"
)

func TestTokenBucketStartsFullAndExhaustsThenBlocks(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	bucket := newTokenBucket(3, time.Second, clock)

	for i := 0; i < 3; i++ {
		allowed, _ := bucket.allow()
		if !allowed {
			t.Fatalf("attempt %d: allow() = false, want true (bucket starts full)", i)
		}
	}

	allowed, wait := bucket.allow()
	if allowed {
		t.Fatal("allow() = true after exhausting capacity, want false")
	}
	if wait <= 0 || wait > time.Second {
		t.Fatalf("wait = %v, want in (0, 1s]", wait)
	}
}

func TestTokenBucketRefillsDeterministicallyOneTokenPerInterval(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	bucket := newTokenBucket(1, time.Second, clock)

	if allowed, _ := bucket.allow(); !allowed {
		t.Fatal("first allow() = false, want true")
	}
	if allowed, _ := bucket.allow(); allowed {
		t.Fatal("second immediate allow() = true, want false (no time elapsed)")
	}

	now = now.Add(999 * time.Millisecond)
	if allowed, _ := bucket.allow(); allowed {
		t.Fatal("allow() before full interval elapsed = true, want false")
	}

	now = now.Add(1 * time.Millisecond)
	if allowed, _ := bucket.allow(); !allowed {
		t.Fatal("allow() after exactly one interval elapsed = false, want true")
	}

	if allowed, _ := bucket.allow(); allowed {
		t.Fatal("allow() immediately after consuming refilled token = true, want false")
	}
}

func TestTokenBucketRefillDoesNotExceedCapacityEvenAfterLongIdlePeriod(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	bucket := newTokenBucket(2, time.Second, clock)

	// Drain the bucket.
	bucket.allow()
	bucket.allow()

	// Advance far beyond what capacity tokens would require; refill must cap
	// at capacity rather than accumulating unboundedly.
	now = now.Add(1000 * time.Hour)

	allowedCount := 0
	for i := 0; i < 5; i++ {
		if allowed, _ := bucket.allow(); allowed {
			allowedCount++
		}
	}
	if allowedCount != 2 {
		t.Fatalf("allowed count after long idle period = %d, want 2 (capped at capacity)", allowedCount)
	}
}

func TestTokenBucketIsConcurrencySafeAndNeverOverAdmits(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	const capacity = 50
	bucket := newTokenBucket(capacity, time.Hour, clock)

	var wg sync.WaitGroup
	var admitted int64
	var admittedMu sync.Mutex
	const attempts = 500
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if allowed, _ := bucket.allow(); allowed {
				admittedMu.Lock()
				admitted++
				admittedMu.Unlock()
			}
		}()
	}
	wg.Wait()

	if admitted != capacity {
		t.Fatalf("admitted = %d, want exactly %d (no over-admission under concurrency)", admitted, capacity)
	}
}

func TestTokenBucketDefaultsClockToTimeNow(t *testing.T) {
	t.Parallel()

	bucket := newTokenBucket(1, time.Hour, nil)
	if bucket.clock == nil {
		t.Fatal("newTokenBucket(..., nil) left clock nil, want default to time.Now")
	}
	if allowed, _ := bucket.allow(); !allowed {
		t.Fatal("allow() on fresh bucket with default clock = false, want true")
	}
}

func TestTokenBucketLongElapsedIntervalCountDoesNotWrap(t *testing.T) {
	t.Parallel()

	now := time.Unix(0, 0)
	bucket := newTokenBucket(900, 9_896_238*time.Nanosecond, func() time.Time { return now })
	for i := 0; i < 900; i++ {
		bucket.allow()
	}
	now = time.Unix(0, int64(^uint64(0)>>1))

	for i := 0; i < 900; i++ {
		if allowed, _ := bucket.allow(); !allowed {
			t.Fatalf("token %d after maximum elapsed duration was denied; interval count likely wrapped", i+1)
		}
	}
}
