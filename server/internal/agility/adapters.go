package agility

import "strings"

// Adapter capability matrix for crypto-agility negotiation exercises (WP-023).
//
// Each entry describes a migration adapter that Janus can drive (the same set
// the agent's mutation engine supports: nginx, apache, ssh, windows-trust-store,
// windows-schannel-policy) and the post-quantum algorithms it can negotiate at
// a given minimum toolchain version. This is curated reference data, not a live
// probe — the harness uses it to classify per-adapter readiness deterministically
// and offline. Sources: docs/ALGORITHM_COMPATIBILITY.md and the agent adapter set.
//
// Knowledge horizon: 2025-08. Values reflect mainline OpenSSL 3.5 (native
// ML-KEM hybrid groups), OpenSSH 9.9 (mlkem768x25519), and Windows SChannel as
// observed classical-only for TLS group negotiation on current builds.

// AdapterCapability is one adapter's negotiation surface.
type AdapterCapability struct {
	Name string `json:"name"`
	// Transport classifies what the adapter negotiates: "tls", "ssh",
	// "trust-store", or "schannel-policy".
	Transport string `json:"transport"`
	// SupportedKEMs are the PQC / hybrid key-exchange mechanisms the adapter can
	// negotiate at MinVersionNote, in canonical form (e.g. "X25519MLKEM768").
	SupportedKEMs []string `json:"supported_kems"`
	// SupportedSignatures are the PQC signature algorithms usable for
	// certificates/host keys on this adapter (e.g. "ML-DSA-65").
	SupportedSignatures []string `json:"supported_signatures"`
	// MinVersionNote states the minimum toolchain that unlocks the above.
	MinVersionNote string `json:"min_version_note"`
	// SupportsNegotiation is true when the adapter can negotiate algorithms at
	// runtime (TLS/SSH) rather than relying on static trust configuration.
	SupportsNegotiation bool `json:"supports_negotiation"`
	// SupportsRollback is true when a migration on this adapter is reversible
	// via the agent mutation engine (backup → write → validate → reload → restore).
	SupportsRollback bool   `json:"supports_rollback"`
	Notes            string `json:"notes"`
}

// BuiltinAdapters returns the curated adapter capability matrix.
func BuiltinAdapters() []AdapterCapability {
	return []AdapterCapability{
		{
			Name:                "nginx",
			Transport:           "tls",
			SupportedKEMs:       []string{"X25519MLKEM768", "SecP256r1MLKEM768"},
			SupportedSignatures: []string{"ML-DSA-65", "ML-DSA-87"},
			MinVersionNote:      "nginx with OpenSSL >= 3.5 (native hybrid groups) or OpenSSL 3.3/3.4 + oqs-provider",
			SupportsNegotiation: true,
			SupportsRollback:    true,
			Notes:               "Hybrid KEM negotiated via ssl_ecdh_curve/groups; PQC leaf cert requires a CA that issues ML-DSA.",
		},
		{
			Name:                "apache",
			Transport:           "tls",
			SupportedKEMs:       []string{"X25519MLKEM768", "SecP256r1MLKEM768"},
			SupportedSignatures: []string{"ML-DSA-65", "ML-DSA-87"},
			MinVersionNote:      "httpd/mod_ssl with OpenSSL >= 3.5 or OpenSSL 3.3/3.4 + oqs-provider",
			SupportsNegotiation: true,
			SupportsRollback:    true,
			Notes:               "Same OpenSSL backing as nginx; SSLOpenSSLConfCmd Groups drives hybrid negotiation.",
		},
		{
			Name:                "ssh",
			Transport:           "ssh",
			SupportedKEMs:       []string{"mlkem768x25519-sha256", "sntrup761x25519-sha512"},
			SupportedSignatures: []string{}, // PQC host-key signatures not yet standardized in OpenSSH
			MinVersionNote:      "OpenSSH >= 9.9 (mlkem768x25519), or >= 9.0 (sntrup761x25519 hybrid)",
			SupportsNegotiation: true,
			SupportsRollback:    true,
			Notes:               "Hybrid KEX via KexAlgorithms; PQC host-key signatures await standardization.",
		},
		{
			Name:                "windows-trust-store",
			Transport:           "trust-store",
			SupportedKEMs:       []string{},
			SupportedSignatures: []string{"ML-DSA-65", "ML-DSA-87"},
			MinVersionNote:      "Windows CNG with ML-DSA available (Insider/Server preview builds)",
			SupportsNegotiation: false,
			SupportsRollback:    true,
			Notes:               "Trust anchors, not a runtime negotiator; can hold PQC CA certs once CNG exposes ML-DSA verification.",
		},
		{
			Name:                "windows-schannel-policy",
			Transport:           "schannel-policy",
			SupportedKEMs:       []string{}, // SChannel observed classical-only for group negotiation
			SupportedSignatures: []string{},
			MinVersionNote:      "No SChannel build negotiates ML-KEM hybrid groups as of 2025-08 (probe: build 26200)",
			SupportsNegotiation: false,
			SupportsRollback:    true,
			Notes:               "Group policy controls classical curves only; PQC TLS negotiation not yet exposed by SChannel.",
		},
	}
}

// normalizeAlgorithm maps common aliases to the canonical names used in the
// adapter matrix so target inputs from policies (Kyber, Dilithium, ml_kem_768…)
// match regardless of spelling.
func normalizeAlgorithm(a string) string {
	s := strings.ToUpper(strings.TrimSpace(a))
	s = strings.ReplaceAll(s, "_", "-")
	switch s {
	case "KYBER", "KYBER768", "ML-KEM", "ML-KEM-768", "MLKEM768", "ML-KEM768":
		return "ML-KEM-768"
	case "KYBER1024", "ML-KEM-1024", "MLKEM1024":
		return "ML-KEM-1024"
	case "DILITHIUM", "DILITHIUM3", "ML-DSA", "ML-DSA-65", "MLDSA65":
		return "ML-DSA-65"
	case "DILITHIUM5", "ML-DSA-87", "MLDSA87":
		return "ML-DSA-87"
	case "X25519MLKEM768", "X25519-MLKEM768", "X25519+ML-KEM-768":
		return "X25519MLKEM768"
	case "SECP256R1MLKEM768", "P256-ML-KEM-768":
		return "SecP256r1MLKEM768"
	}
	return s
}

// adapterCovers reports whether an adapter can negotiate/use a target algorithm.
// It matches a pure ML-KEM-768 target against any hybrid group that embeds it,
// since deploying a hybrid group is how nginx/apache/ssh actually field ML-KEM-768.
func adapterCovers(a AdapterCapability, target string) bool {
	t := normalizeAlgorithm(target)
	for _, k := range a.SupportedKEMs {
		ck := normalizeAlgorithm(k)
		if ck == t {
			return true
		}
		// A pure ML-KEM-768 requirement is satisfied by a hybrid group that
		// contains it (e.g. X25519MLKEM768, mlkem768x25519-sha256).
		if t == "ML-KEM-768" && strings.Contains(strings.ToUpper(ck), "MLKEM768") {
			return true
		}
	}
	for _, s := range a.SupportedSignatures {
		if normalizeAlgorithm(s) == t {
			return true
		}
	}
	return false
}
