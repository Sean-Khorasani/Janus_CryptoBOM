package ws

import (
	"net"
	"testing"
	"time"
)

// TestBroadcastTenantFiltering verifies BroadcastTenant only reaches connections in the
// target tenant (WP-020), while a connection with no tenant (single-tenant deployments)
// still receives everything.
func TestBroadcastTenantFiltering(t *testing.T) {
	h := New()

	// Build three connections directly (bypassing the upgrade handshake) so we can
	// assert per-tenant delivery. Each server end is registered with the hub; a reader
	// goroutine on the client end drains a frame and signals arrival on a channel.
	type peer struct {
		conn *wsConn
		got  chan struct{}
	}
	mk := func(tenant string) peer {
		c, s := net.Pipe()
		wc := &wsConn{conn: s, tenant: tenant, done: make(chan struct{})}
		got := make(chan struct{}, 1)
		go func() {
			buf := make([]byte, 4096)
			if _, err := c.Read(buf); err == nil { // net.Pipe writes a frame atomically
				got <- struct{}{}
			}
		}()
		h.register <- wc
		return peer{conn: wc, got: got}
	}
	acme := mk("acme")
	globex := mk("globex")
	legacy := mk("") // no tenant → receives all

	// Wait until run() has registered all three.
	deadline := time.Now().Add(time.Second)
	for h.ClientCount() < 3 && time.Now().Before(deadline) {
	}
	if h.ClientCount() != 3 {
		t.Fatalf("ClientCount = %d, want 3", h.ClientCount())
	}

	h.BroadcastTenant("acme", "finding_status", map[string]string{"id": "f1"})

	received := func(p peer) bool {
		select {
		case <-p.got:
			return true
		case <-time.After(200 * time.Millisecond):
			return false
		}
	}

	if !received(acme) {
		t.Error("acme client did not receive its tenant's event")
	}
	if !received(legacy) {
		t.Error("tenant-less client should receive all tenant events")
	}
	if received(globex) {
		t.Error("globex client received another tenant's event (leak)")
	}

	h.unregister <- acme.conn
	h.unregister <- globex.conn
	h.unregister <- legacy.conn
}
