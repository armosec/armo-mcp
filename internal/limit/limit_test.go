package limit

import (
	"fmt"
	"testing"
	"time"
)

func TestLimiterAllowsBurstThenBlocks(t *testing.T) {
	l := New(60, 2) // 1/sec, burst 2
	// Evaluate both calls unconditionally (no short-circuit) so both burst
	// tokens are always consumed before the assertion below.
	first := l.Allow("t1")
	second := l.Allow("t1")
	if !first || !second {
		t.Fatal("first 2 should pass (burst)")
	}
	if l.Allow("t1") {
		t.Fatal("3rd immediate call should be rate-limited")
	}
	// separate tenant has its own bucket
	if !l.Allow("t2") {
		t.Fatal("different tenant should not be limited")
	}
}

// Idle buckets are swept on a timer, not on every call, so a large map is
// never scanned per request.
func TestLimiterSweepsIdleBucketsPeriodically(t *testing.T) {
	l := New(60, 1)
	now := time.Unix(1000, 0)
	l.now = func() time.Time { return now }
	l.Allow("old")
	now = now.Add(l.idleTTL + l.sweepEvery + time.Second)
	l.Allow("new")
	if _, ok := l.buckets["old"]; ok {
		t.Fatal("idle bucket should have been swept")
	}
	if _, ok := l.buckets["new"]; !ok {
		t.Fatal("active bucket must survive the sweep")
	}
}

// A flood of distinct keys cannot grow the map without bound.
func TestLimiterCapsBucketCount(t *testing.T) {
	l := New(60, 1)
	l.maxBuckets = 10
	for i := 0; i < 50; i++ {
		l.Allow(fmt.Sprintf("k%d", i))
	}
	if n := len(l.buckets); n > l.maxBuckets {
		t.Fatalf("buckets = %d, want at most %d", n, l.maxBuckets)
	}
}
