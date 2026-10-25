package cache

import (
	"sync"
	"time"
)

// item holds a cached value with its expiration time.
type item[V any] struct {
	value   V
	expires time.Time
}

// Cache is a thread-safe, TTL-based response cache.
type Cache[V any] struct {
	mu    sync.Mutex
	ttl   time.Duration
	items map[string]item[V]
}

// New creates a new Cache with the given TTL.
// If ttl <= 0, caching is disabled (Get always returns false, Set is a no-op).
func New[V any](ttl time.Duration) *Cache[V] {
	return &Cache[V]{
		ttl:   ttl,
		items: make(map[string]item[V]),
	}
}

// Get retrieves a value from the cache.
// Returns (value, true) if the key exists and has not expired.
// Returns (zero, false) if the key is absent or has expired.
func (c *Cache[V]) Get(key string) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// If caching is disabled, always return false.
	if c.ttl <= 0 {
		var zero V
		return zero, false
	}

	item, exists := c.items[key]
	if !exists {
		var zero V
		return zero, false
	}

	// Check if the item has expired (lazy expiry).
	if time.Now().After(item.expires) {
		delete(c.items, key)
		var zero V
		return zero, false
	}

	return item.value, true
}

// Set stores a value in the cache with the configured TTL.
// If ttl <= 0 (caching disabled), this is a no-op.
func (c *Cache[V]) Set(key string, v V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// If caching is disabled, do nothing.
	if c.ttl <= 0 {
		return
	}

	c.items[key] = item[V]{
		value:   v,
		expires: time.Now().Add(c.ttl),
	}

	// Opportunistic sweep: if map is getting large, clean up expired items.
	if len(c.items) > 4096 {
		c.sweep()
	}
}

// sweep removes all expired items from the cache.
// Must be called with mu held.
func (c *Cache[V]) sweep() {
	now := time.Now()
	for key, item := range c.items {
		if now.After(item.expires) {
			delete(c.items, key)
		}
	}
}
