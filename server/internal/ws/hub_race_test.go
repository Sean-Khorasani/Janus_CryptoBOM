package ws

import (
	"sync"
	"testing"
)

// WP-019: concurrency/race coverage. Run under `go test -race ./internal/ws/`.
// The hub is shared across the gRPC ingest path and HTTP handlers, so concurrent
// Broadcast + ClientCount must be data-race free.
func TestHubConcurrentBroadcast(t *testing.T) {
	h := New()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				h.Broadcast("telemetry_update", map[string]int{"n": n, "j": j})
				_ = h.ClientCount()
			}
		}(i)
	}
	wg.Wait()
	if c := h.ClientCount(); c != 0 {
		t.Fatalf("ClientCount = %d, want 0 (no clients connected)", c)
	}
}
