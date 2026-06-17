// Package agentauth implements per-agent authentication for the agent->server
// direction (WP-029 P1). Each agent holds a unique HMAC key derived from a server
// master key (HKDF), and authenticates requests with a replay-windowed token. This
// is symmetric and quantum-safe, and complements the asymmetric ML-DSA command
// signing used in the server->agent direction. Per-agent keys give per-agent
// revocation and isolation that the single shared command-signing key cannot.
package agentauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// KeyLen is the derived per-agent key length in bytes.
const KeyLen = 32

// GRPCMethod and GRPCPath are the fixed (method, path) the per-agent request token binds
// to for gRPC calls. The telemetry service is single, so per-RPC binding isn't needed;
// both the agent client and the server interceptor must use these same values.
const (
	GRPCMethod = "GRPC"
	GRPCPath   = "janus.telemetry"
)

// DeriveKey derives a stable per-agent key from the server master key and the agent
// id via HKDF-SHA256. The master never leaves the server/HSM; an agent receives only
// its own derived key. Deterministic: identical (master, agentID) yields the same key,
// so the server can re-derive on demand without storing per-agent secrets.
func DeriveKey(master []byte, agentID string) ([]byte, error) {
	if len(master) == 0 || agentID == "" {
		return nil, fmt.Errorf("agentauth: master key and agent id are required")
	}
	r := hkdf.New(sha256.New, master, nil, []byte("janus-agent-key:"+agentID))
	key := make([]byte, KeyLen)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// Token computes the request authentication token: hex HMAC-SHA256 over a canonical
// (agentID, method, path, ts) tuple keyed by the agent's key. The agent sends this
// alongside agentID and ts; the server recomputes and compares.
func Token(key []byte, agentID, method, path string, tsUnix int64) string {
	mac := hmac.New(sha256.New, key)
	fmt.Fprintf(mac, "%s\n%s\n%s\n%d", agentID, method, path, tsUnix)
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify validates a presented token in constant time and confirms ts is within
// +/- window seconds of now (replay guard). A window of 0 disables the freshness
// check. Returns false on any mismatch.
func Verify(key []byte, agentID, method, path string, tsUnix, now, window int64, token string) bool {
	if window > 0 {
		if d := now - tsUnix; d > window || d < -window {
			return false
		}
	}
	expected := Token(key, agentID, method, path, tsUnix)
	return hmac.Equal([]byte(expected), []byte(token))
}
