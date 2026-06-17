package llm

import (
	"sync"
	"time"
)

// defaultMaxTokens is the per-call output token cap used when the operator has not
// set JANUS_LLM_MAX_TOKENS_PER_REQUEST.
const defaultMaxTokens = 800

// rateLimiter is a simple sliding-window limiter: at most `limit` events per
// `window`. A limit <= 0 disables limiting (allow always returns true). It is the
// cost/abuse guard behind JANUS_LLM_MAX_REQUESTS_PER_MINUTE (LLM-002/004).
type rateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	events []time.Time
	now    func() time.Time // injectable for deterministic tests
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, now: time.Now}
}

// allow reports whether an event may proceed now, recording it if so. It evicts
// events older than the window before checking the limit. Safe for concurrent use.
func (r *rateLimiter) allow() bool {
	if r == nil || r.limit <= 0 {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := r.now().Add(-r.window)
	kept := r.events[:0]
	for _, t := range r.events {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	r.events = kept
	if len(r.events) >= r.limit {
		return false
	}
	r.events = append(r.events, r.now())
	return true
}

// maxTokens resolves the per-call output token cap from config, falling back to
// the default when unset (0).
func maxTokens(configured int) int {
	if configured > 0 {
		return configured
	}
	return defaultMaxTokens
}
