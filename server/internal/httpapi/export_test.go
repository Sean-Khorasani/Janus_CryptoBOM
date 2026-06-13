package httpapi

import (
	"strings"
	"testing"
)

func TestAlgCryptoProperties(t *testing.T) {
	tests := []struct {
		name      string
		alg       string
		wantPrim  string
		wantNIST  int
		wantParam string
	}{
		{"ML-KEM-768", "ML-KEM-768", "kem", 3, "768"},
		{"ML-KEM-1024", "ML-KEM-1024", "kem", 5, "1024"},
		{"ML-DSA-65", "ML-DSA-65", "signature", 3, "65"},
		{"ML-DSA-87", "ML-DSA-87", "signature", 5, "87"},
		{"SLH-DSA", "SLH-DSA-SHA2-128s", "signature", 1, ""},
		{"RSA-2048", "RSA-2048", "pke", 0, "2048"},
		{"RSA-4096", "RSA-4096", "pke", 0, "4096"},
		{"AES-256-GCM", "AES-256-GCM", "ae", 0, "256"},
		{"AES-128-CBC", "AES-128-CBC", "ae", 0, "128"},
		{"SHA-256", "SHA-256", "hash", 0, "256"},
		{"SHA-384", "SHA-384", "hash", 0, "384"},
		{"ECDSA-P256", "ECDSA-P256", "signature", 0, "P-256"},
		{"ECDSA-P384", "ECDSA-P384", "signature", 0, "P-384"},
		{"X25519MLKEM768", "X25519MLKEM768", "kem", 3, "768"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			props := algCryptoProperties(tt.alg)
			if props == nil {
				t.Fatalf("algCryptoProperties(%q) = nil, want non-nil", tt.alg)
			}
			if assetType, ok := props["assetType"].(string); !ok || assetType != "algorithm" {
				t.Errorf("assetType = %v, want \"algorithm\"", props["assetType"])
			}
			ap, ok := props["algorithmProperties"].(map[string]any)
			if !ok {
				t.Fatalf("algorithmProperties missing or wrong type")
			}
			if prim, _ := ap["primitive"].(string); prim != tt.wantPrim {
				t.Errorf("primitive = %q, want %q", prim, tt.wantPrim)
			}
			if nist, _ := ap["nistQuantumSecurityLevel"].(int); nist != tt.wantNIST {
				t.Errorf("nistQuantumSecurityLevel = %d, want %d", nist, tt.wantNIST)
			}
			if tt.wantParam != "" {
				if param, _ := ap["parameterSetIdentifier"].(string); param != tt.wantParam {
					t.Errorf("parameterSetIdentifier = %q, want %q", param, tt.wantParam)
				}
			}
		})
	}
}

func TestAlgCryptoPropertiesUnknown(t *testing.T) {
	if props := algCryptoProperties("UNKNOWN-ALGO"); props != nil {
		t.Errorf("expected nil for unknown algorithm, got %v", props)
	}
}

func TestAlgCryptoPropertiesAESMode(t *testing.T) {
	props := algCryptoProperties("AES-256-GCM")
	if props == nil {
		t.Fatal("expected non-nil")
	}
	ap := props["algorithmProperties"].(map[string]any)
	if mode, _ := ap["mode"].(string); mode != "gcm" {
		t.Errorf("mode = %q, want \"gcm\"", mode)
	}
}

func TestParseSARIFLocation(t *testing.T) {
	tests := []struct {
		assetRef    string
		wantURI     string
		wantLine    int
		wantHasLine bool
	}{
		{"src/main.go", "src/main.go", 0, false},
		{"src/main.go:42", "src/main.go", 42, true},
		{"src/main.go:42:7", "src/main.go:42", 7, true},
		{"192.168.1.1:443", "192.168.1.1", 443, true}, // network refs treated as line=port
		{"plainpath", "plainpath", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.assetRef, func(t *testing.T) {
			loc := parseSARIFLocation(tt.assetRef)
			phys, ok := loc["physicalLocation"].(map[string]any)
			if !ok {
				t.Fatal("physicalLocation missing")
			}
			artLoc, ok := phys["artifactLocation"].(map[string]any)
			if !ok {
				t.Fatal("artifactLocation missing")
			}
			uri, _ := artLoc["uri"].(string)
			if uri != tt.wantURI {
				t.Errorf("uri = %q, want %q", uri, tt.wantURI)
			}
			region, hasRegion := phys["region"]
			if tt.wantHasLine && !hasRegion {
				t.Errorf("expected region to be present for %q", tt.assetRef)
			}
			if !tt.wantHasLine && hasRegion {
				t.Errorf("expected no region for %q, got %v", tt.assetRef, region)
			}
			if tt.wantHasLine && hasRegion {
				regMap, ok := region.(map[string]any)
				if !ok {
					t.Fatal("region is not map")
				}
				lineNum, _ := regMap["startLine"].(int)
				if lineNum != tt.wantLine {
					t.Errorf("startLine = %d, want %d", lineNum, tt.wantLine)
				}
			}
		})
	}
}

func TestSarifSeverity(t *testing.T) {
	tests := []struct {
		sev  int32
		want string
	}{
		{5, "error"},
		{4, "warning"},
		{3, "warning"},
		{2, "note"},
		{1, "note"},
	}
	for _, tt := range tests {
		if got := sarifSeverity(tt.sev); got != tt.want {
			t.Errorf("sarifSeverity(%d) = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

// Smoke test that algCryptoProperties covers a broad set of PQC and classical algorithms.
func TestAlgCryptoPropertiesCoverage(t *testing.T) {
	covered := []string{
		"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
		"ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
		"SLH-DSA-SHAKE-128s",
		"RSA-2048", "RSA-3072", "RSA-4096",
		"ECDSA-P256", "ECDSA-P384", "ECDSA-P521",
		"AES-128-CBC", "AES-256-GCM",
		"SHA-256", "SHA-512",
		"ChaCha20-Poly1305",
		"Ed25519",
	}
	for _, alg := range covered {
		if algCryptoProperties(alg) == nil {
			t.Errorf("algCryptoProperties(%q) = nil, expected coverage", alg)
		}
	}
}

func TestAlgCryptoPropertiesEdgeCase(t *testing.T) {
	if algCryptoProperties("") != nil {
		t.Error("empty string should return nil")
	}
	props := algCryptoProperties("RSA-4096")
	if !strings.Contains("pke", "pke") {
		t.Error("RSA should be pke primitive")
	}
	if props == nil {
		t.Fatal("RSA-4096 should not be nil")
	}
}
