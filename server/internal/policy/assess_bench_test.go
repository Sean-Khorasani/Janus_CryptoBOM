package policy

import (
	"fmt"
	"testing"

	"github.com/janus-cbom/janus/server/internal/pb"
)

// WP-019 performance baseline. `policy.Assess` runs on every telemetry ingest,
// so it is the server's hottest CPU path. This benchmark establishes a baseline
// for a realistic 200-component payload; record `ns/op` in release evidence and
// watch for regressions.
//
//	go test -bench=BenchmarkAssess -benchmem ./internal/policy/
func BenchmarkAssess(b *testing.B) {
	e := NewEngine(NIST2026Profile())
	e.osv = nil // offline: no live OSV network calls in the benchmark

	algos := []struct {
		name string
		role int32
		kb   uint32
	}{
		{"RSA", pb.CryptoRoleSignature, 2048},
		{"ECDSA", pb.CryptoRoleSignature, 256},
		{"AES-256-GCM", pb.CryptoRoleSymmetric, 256},
		{"ML-KEM-768", pb.CryptoRoleKEM, 0},
		{"SHA-1", pb.CryptoRoleHash, 0},
	}

	components := make([]*pb.CbomComponent, 0, 200)
	for i := 0; i < 200; i++ {
		a := algos[i%len(algos)]
		components = append(components, &pb.CbomComponent{
			BomRef: fmt.Sprintf("file:src/mod_%d.go", i),
			Name:   fmt.Sprintf("component-%d", i),
			Algorithms: []*pb.CryptoAlgorithm{
				{Name: a.name, Role: a.role, KeyBits: a.kb, Confidence: 0.85},
			},
		})
	}
	payload := &pb.CbomTelemetryPayload{
		TelemetryId: "bench",
		HostUuid:    "bench-host",
		Components:  components,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Fresh findings each iteration; Assess populates payload.Findings.
		payload.Findings = nil
		e.Assess(payload)
	}
}
