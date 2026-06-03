package policy

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/janus-cbom/janus/server/internal/pb"
)

type Profile struct {
	Version               string
	MinimumRSAKeyBits     uint32
	MinimumDHSafePrimeBits uint32
	RequireTLS13          bool
	RequireHybridPQTLS13  bool
	PreferredKEM          string
	PreferredSignature    string
}

type Engine struct {
	profile Profile
}

func NIST2026Profile() Profile {
	return Profile{
		Version:               "nist-pqc-2026.1",
		MinimumRSAKeyBits:     3072,
		MinimumDHSafePrimeBits: 3072,
		RequireTLS13:          true,
		RequireHybridPQTLS13:  true,
		PreferredKEM:          "X25519MLKEM768",
		PreferredSignature:    "ML-DSA-65",
	}
}

func NewEngine(profile Profile) *Engine {
	return &Engine{profile: profile}
}

func (e *Engine) ProfileVersion() string {
	return e.profile.Version
}

func (e *Engine) Assess(payload *pb.CbomTelemetryPayload) {
	for _, component := range payload.Components {
		for _, alg := range component.Algorithms {
			e.assessAlgorithm(payload, component, alg)
		}
	}
	for _, obs := range payload.NetworkObservations {
		e.assessNetwork(payload, obs)
	}
}

func (e *Engine) assessAlgorithm(payload *pb.CbomTelemetryPayload, component *pb.CbomComponent, alg *pb.CryptoAlgorithm) {
	name := strings.ToUpper(alg.Name)
	family := strings.ToUpper(alg.Family)
	classicalPublicKey := containsAny(name, "RSA", "ECDSA", "ECDH", "ECDHE", "DH", "DSA") ||
		containsAny(family, "RSA", "ECC", "ECDH", "DIFFIE", "DSA")

	if isPublicKeyRole(alg.Role) && classicalPublicKey {
		alg.QuantumVulnerable = true
		alg.Status = "quantum-vulnerable"
		severity := pb.RiskSeverityHigh
		title := "Classical public-key cryptography is quantum-vulnerable"
		desc := fmt.Sprintf("%s uses %s for %s. Migrate to hybrid/PQC profile %s + %s where supported.", component.BomRef, alg.Name, roleName(alg.Role), e.profile.PreferredKEM, e.profile.PreferredSignature)
		rule := "JANUS-PQC-001"
		if strings.Contains(name, "RSA") && alg.KeyBits > 0 && alg.KeyBits < e.profile.MinimumRSAKeyBits {
			severity = pb.RiskSeverityCritical
			title = "RSA key size below 2026 transition threshold"
			desc = fmt.Sprintf("%s uses RSA-%d; minimum transitional threshold is RSA-%d and target state is PQC/hybrid.", component.BomRef, alg.KeyBits, e.profile.MinimumRSAKeyBits)
			rule = "JANUS-PQC-002"
		}
		appendFinding(payload, severity, title, desc, component.BomRef, alg.Name, rule, "hybrid-tls13-mlkem-mldsa")
		return
	}

	if strings.Contains(name, "MD5") || strings.Contains(name, "SHA1") || strings.Contains(name, "SHA-1") {
		appendFinding(payload,
			pb.RiskSeverityHigh,
			"Deprecated hash detected",
			fmt.Sprintf("%s references %s. Replace with SHA-384/SHA-512/SHA-3 according to the calling protocol.", component.BomRef, alg.Name),
			component.BomRef,
			alg.Name,
			"JANUS-CLASSICAL-003",
			"hash-modernization",
		)
	}

	if strings.Contains(name, "AES-128") && alg.Role == pb.CryptoRoleSymmetric {
		appendFinding(payload,
			pb.RiskSeverityMedium,
			"AES-128 used where long-term confidentiality may require AES-256",
			fmt.Sprintf("%s references AES-128. Review data lifetime and upgrade crown-jewel or long-retention data paths to AES-256.", component.BomRef),
			component.BomRef,
			alg.Name,
			"JANUS-PQC-004",
			"symmetric-margin-upgrade",
		)
	}
}

func (e *Engine) assessNetwork(payload *pb.CbomTelemetryPayload, obs *pb.NetworkObservation) {
	if obs.Cleartext {
		appendFinding(payload,
			pb.RiskSeverityCritical,
			"Cleartext service observed",
			fmt.Sprintf("%s exposes %s without cryptographic protection.", obs.Endpoint, obs.Protocol),
			obs.Endpoint,
			"cleartext",
			"JANUS-NET-001",
			"enable-tls13-hybrid",
		)
		return
	}

	version := strings.ToUpper(obs.TlsVersion)
	if strings.HasPrefix(version, "TLS1.0") || strings.HasPrefix(version, "TLS1.1") || strings.HasPrefix(version, "TLS1.2") || version == "" {
		appendFinding(payload,
			pb.RiskSeverityHigh,
			"TLS endpoint is not validated as TLS 1.3",
			fmt.Sprintf("%s negotiated or reported %q. Target is TLS 1.3 with hybrid ECDHE-MLKEM support.", obs.Endpoint, obs.TlsVersion),
			obs.Endpoint,
			obs.CipherSuite,
			"JANUS-NET-002",
			"tls13-hybrid-key-exchange",
		)
	}

	group := strings.ToUpper(obs.NamedGroup)
	if e.profile.RequireHybridPQTLS13 && !obs.PqcHybrid && !strings.Contains(group, "MLKEM") && !strings.Contains(group, "ML-KEM") {
		appendFinding(payload,
			pb.RiskSeverityCritical,
			"TLS key exchange is classical-only",
			fmt.Sprintf("%s did not prove hybrid ML-KEM key agreement. Observed group=%q cipher=%q.", obs.Endpoint, obs.NamedGroup, obs.CipherSuite),
			obs.Endpoint,
			obs.NamedGroup,
			"JANUS-PQC-005",
			"X25519MLKEM768",
		)
	}

	sig := strings.ToUpper(obs.SignatureAlgorithm)
	if containsAny(sig, "RSA", "ECDSA") {
		appendFinding(payload,
			pb.RiskSeverityHigh,
			"Certificate signature remains classical",
			fmt.Sprintf("%s certificate uses %s. Pilot ML-DSA or SLH-DSA in private trust domains and track public PKI readiness.", obs.Endpoint, obs.SignatureAlgorithm),
			obs.Endpoint,
			obs.SignatureAlgorithm,
			"JANUS-PQC-006",
			"certificate-signature-modernization",
		)
	}
}

func appendFinding(payload *pb.CbomTelemetryPayload, severity int32, title, description, assetRef, algorithm, rule, profile string) {
	if hasFinding(payload, assetRef, algorithm, rule) {
		return
	}
	payload.Findings = append(payload.Findings, finding(severity, title, description, assetRef, algorithm, rule, profile))
}

func finding(severity int32, title, description, assetRef, algorithm, rule, profile string) *pb.CryptoFinding {
	return &pb.CryptoFinding{
		FindingId:        uuid.NewString(),
		Severity:         severity,
		Title:            title,
		Description:      description,
		AssetRef:         assetRef,
		Algorithm:        algorithm,
		PolicyRuleId:     rule,
		MigrationProfile: profile,
	}
}

func hasFinding(payload *pb.CbomTelemetryPayload, assetRef, algorithm, rule string) bool {
	for _, f := range payload.Findings {
		if f.AssetRef == assetRef && f.Algorithm == algorithm && f.PolicyRuleId == rule {
			return true
		}
	}
	return false
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func isPublicKeyRole(role int32) bool {
	switch role {
	case pb.CryptoRoleKEM, pb.CryptoRoleKeyExchange, pb.CryptoRoleSignature, pb.CryptoRoleCertPublicKey, pb.CryptoRoleCertSignature:
		return true
	default:
		return false
	}
}

func roleName(role int32) string {
	switch role {
	case pb.CryptoRoleKEM:
		return "KEM"
	case pb.CryptoRoleKeyExchange:
		return "key exchange"
	case pb.CryptoRoleSignature:
		return "signature"
	case pb.CryptoRoleCertPublicKey:
		return "certificate public key"
	case pb.CryptoRoleCertSignature:
		return "certificate signature"
	default:
		return "cryptographic operation"
	}
}
