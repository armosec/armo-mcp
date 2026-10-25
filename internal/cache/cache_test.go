package cache

import (
	"testing"
	"time"
)

func TestCacheSetAndGet(t *testing.T) {
	// Test: Set then Get returns the value
	c := New[string](100 * time.Millisecond)
	c.Set("key1", "value1")
	v, ok := c.Get("key1")
	if !ok || v != "value1" {
		t.Errorf("Expected Get to return ('value1', true), got (%q, %v)", v, ok)
	}
}

func TestCacheExpiry(t *testing.T) {
	// Test: after ttl elapses, Get returns false
	c := New[string](20 * time.Millisecond)
	c.Set("key1", "value1")
	v, ok := c.Get("key1")
	if !ok || v != "value1" {
		t.Errorf("Before expiry: Expected Get to return ('value1', true), got (%q, %v)", v, ok)
	}
	time.Sleep(40 * time.Millisecond)
	v, ok = c.Get("key1")
	if ok {
		t.Errorf("After expiry: Expected Get to return (_, false), got (%q, %v)", v, ok)
	}
}

func TestCacheDisabled(t *testing.T) {
	// Test: New[int](0) cache never returns a hit
	c := New[int](0)
	c.Set("key1", 42)
	v, ok := c.Get("key1")
	if ok {
		t.Errorf("Disabled cache: Expected Get to return (_, false), got (%v, %v)", v, ok)
	}
}

func TestCacheMultipleKeys(t *testing.T) {
	c := New[int](100 * time.Millisecond)
	c.Set("key1", 1)
	c.Set("key2", 2)
	c.Set("key3", 3)

	v1, ok1 := c.Get("key1")
	v2, ok2 := c.Get("key2")
	v3, ok3 := c.Get("key3")

	if !ok1 || v1 != 1 {
		t.Errorf("key1: expected (1, true), got (%v, %v)", v1, ok1)
	}
	if !ok2 || v2 != 2 {
		t.Errorf("key2: expected (2, true), got (%v, %v)", v2, ok2)
	}
	if !ok3 || v3 != 3 {
		t.Errorf("key3: expected (3, true), got (%v, %v)", v3, ok3)
	}
}

func TestCacheAbsentKey(t *testing.T) {
	c := New[string](100 * time.Millisecond)
	v, ok := c.Get("nonexistent")
	if ok {
		t.Errorf("Expected Get to return (_, false) for absent key, got (%q, %v)", v, ok)
	}
}
