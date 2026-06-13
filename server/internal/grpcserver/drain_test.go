package grpcserver

import (
	"sync"
	"testing"
	"time"
)

// WP-019: the webhook circuit breaker is touched concurrently by every
// dispatch goroutine. Run under `go test -race` to prove its locking is sound.
func TestWebhookCircuitConcurrent(t *testing.T) {
	c := &webhookCircuit{
		failures:      make(map[string]int),
		cooldownUntil: make(map[string]time.Time),
	}
	urls := []string{"https://a.example", "https://b.example", "https://c.example"}
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			u := urls[n%len(urls)]
			for j := 0; j < 100; j++ {
				if j%3 == 0 {
					c.recordFailure(u)
				} else if j%3 == 1 {
					c.recordSuccess(u)
				} else {
					_ = c.isOpen(u)
				}
			}
		}(i)
	}
	wg.Wait()
}

// OPS-001: WaitWebhooks must block until in-flight dispatches finish, and must
// return false (not hang) if they exceed the timeout. This is the fault
// injection that proves graceful shutdown won't drop critical-finding webhooks
// — and won't hang a rolling update if a webhook endpoint is slow (WP-019).

func TestWaitWebhooksDrainsCleanly(t *testing.T) {
	s := &Server{}

	// Simulate three in-flight dispatches that each take a short time.
	var started sync.WaitGroup
	started.Add(3)
	for i := 0; i < 3; i++ {
		s.webhookWg.Add(1)
		go func() {
			defer s.webhookWg.Done()
			started.Done()
			time.Sleep(20 * time.Millisecond)
		}()
	}
	started.Wait() // ensure all goroutines are running before we wait

	if ok := s.WaitWebhooks(2 * time.Second); !ok {
		t.Fatal("WaitWebhooks reported timeout for dispatches that should have finished")
	}
}

func TestWaitWebhooksTimesOut(t *testing.T) {
	s := &Server{}

	// One dispatch that outlives the wait timeout.
	release := make(chan struct{})
	s.webhookWg.Add(1)
	go func() {
		defer s.webhookWg.Done()
		<-release
	}()

	start := time.Now()
	if ok := s.WaitWebhooks(50 * time.Millisecond); ok {
		t.Fatal("WaitWebhooks reported clean drain but a dispatch was still blocked")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("WaitWebhooks took %v; should have returned near the 50ms timeout", elapsed)
	}
	close(release) // let the goroutine finish so the test doesn't leak
	s.webhookWg.Wait()
}
