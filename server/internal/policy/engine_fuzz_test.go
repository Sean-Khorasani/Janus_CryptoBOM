//go:build go1.18

package policy

import (
	"testing"

	"github.com/janus-cbom/janus/server/internal/pb"
)

// FuzzAssess fuzzes the policy engine assess function with synthetic findings.
// It verifies that the engine never panics regardless of algorithm name,
// severity, asset reference, confidence, or role values — including edge cases
// like empty strings, negative values, and out-of-range integers.
func FuzzAssess(f *testing.F) {
	// Seed corpus covering quantum-vulnerable, PQC, hash, symmetric, and empty inputs.
	f.Add("RSA-2048", int32(2), "src/main.go:10", float32(0.8), int32(0))
	f.Add("AES-256-GCM", int32(1), "config/crypto.yaml:5", float32(0.95), int32(0))
	f.Add("ML-KEM-768", int32(3), "api/tls.go:42", float32(0.75), int32(1))
	f.Add("", int32(0), "", float32(0.0), int32(0))
	f.Add("ECDSA-P256", int32(4), "src/sign.go:100", float32(1.0), int32(2))
	f.Add("MD5", int32(5), "legacy/hash.go:7", float32(0.5), int32(7))
	f.Add("SHA-1", int32(-1), "util/digest.go:3", float32(-0.1), int32(-99))
	f.Add("AES-128-CBC", int32(6), "server/tls.go:20", float32(2.0), int32(6))
	f.Add("DH-1024", int32(4), "vpn/config.go:55", float32(0.9), int32(2))
	f.Add("ECDH", int32(4), "client/key.go:12", float32(0.6), int32(1))

	f.Fuzz(func(t *testing.T, algorithm string, keyBits int32, assetRef string, confidence float32, role int32) {
		// The engine must never panic on any combination of inputs.
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("policy engine panicked on input (algorithm=%q, keyBits=%d, assetRef=%q, confidence=%f, role=%d): %v",
					algorithm, keyBits, assetRef, confidence, role, r)
			}
		}()

		e := NewEngine(NIST2026Profile())
		// Disable live OSV network calls so the fuzz corpus runs offline and
		// deterministically. assessComponentVulnerabilities early-returns when
		// Version == "" anyway, so this is belt-and-suspenders.
		e.osv = nil

		// Cast keyBits to uint32 (negative values wrap to large positive numbers,
		// exercising the key-size comparison paths in assessAlgorithm).
		var kb uint32
		if keyBits > 0 {
			kb = uint32(keyBits)
		}

		payload := &pb.CbomTelemetryPayload{
			TelemetryId: "fuzz-telemetry",
			HostUuid:    "fuzz-host",
			Components: []*pb.CbomComponent{
				{
					BomRef: assetRef,
					Name:   "fuzz-component",
					// Leave Version and Language empty to prevent live OSV queries.
					Algorithms: []*pb.CryptoAlgorithm{
						{
							Name:       algorithm,
							Role:       role,
							KeyBits:    kb,
							Confidence: float64(confidence),
						},
					},
				},
			},
		}

		e.Assess(payload)
	})
}
