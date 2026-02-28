package gateway

import (
	"sync"
	"time"
)

type principalLimiter struct {
	mu      sync.Mutex
	limit   int
	now     func() time.Time
	windows map[string]rateWindow
}

type rateWindow struct {
	startMinute time.Time
	count       int
}

func newPrincipalLimiter(limit int, now func() time.Time) *principalLimiter {
	if now == nil {
		now = time.Now
	}
	return &principalLimiter{limit: limit, now: now, windows: map[string]rateWindow{}}
}

func (l *principalLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now().UTC().Truncate(time.Minute)
	window := l.windows[key]
	if window.startMinute.IsZero() || !window.startMinute.Equal(now) {
		window = rateWindow{startMinute: now, count: 0}
	}
	if window.count >= l.limit {
		l.windows[key] = window
		return false
	}
	window.count++
	l.windows[key] = window
	return true
}

type principalBreaker struct {
	mu        sync.Mutex
	threshold int
	cooldown  time.Duration
	now       func() time.Time
	states    map[string]breakerState
}

type breakerState struct {
	failures  int
	openUntil time.Time
}

func newPrincipalBreaker(threshold int, cooldown time.Duration, now func() time.Time) *principalBreaker {
	if now == nil {
		now = time.Now
	}
	return &principalBreaker{threshold: threshold, cooldown: cooldown, now: now, states: map[string]breakerState{}}
}

func (b *principalBreaker) Allow(key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	st := b.states[key]
	if st.openUntil.IsZero() {
		return true
	}
	if b.now().UTC().Before(st.openUntil) {
		return false
	}
	st.openUntil = time.Time{}
	st.failures = 0
	b.states[key] = st
	return true
}

func (b *principalBreaker) ObserveSuccess(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	st := b.states[key]
	st.failures = 0
	st.openUntil = time.Time{}
	b.states[key] = st
}

func (b *principalBreaker) ObserveFailure(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	st := b.states[key]
	st.failures++
	if st.failures >= b.threshold {
		st.openUntil = b.now().UTC().Add(b.cooldown)
		st.failures = 0
	}
	b.states[key] = st
}
