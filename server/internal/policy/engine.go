package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/janus-cbom/janus/server/internal/pb"
	"gopkg.in/yaml.v3"
)

type Profile struct {
	Version                string `yaml:"version" json:"version"`
	MinimumRSAKeyBits      uint32 `yaml:"minimum_rsa_key_bits" json:"minimum_rsa_key_bits"`
	MinimumDHSafePrimeBits uint32 `yaml:"minimum_dh_safe_prime_bits" json:"minimum_dh_safe_prime_bits"`
	RequireTLS13           bool   `yaml:"require_tls_13" json:"require_tls_13"`
	RequireHybridPQTLS13   bool   `yaml:"require_hybrid_pq_tls_13" json:"require_hybrid_pq_tls_13"`
	PreferredKEM           string `yaml:"preferred_kem" json:"preferred_kem"`
	PreferredSignature     string `yaml:"preferred_signature" json:"preferred_signature"`
}

type Engine struct {
	mu       sync.RWMutex
	active   string
	profiles map[string]Profile
	osv      *OSVClient
}

func NIST2026Profile() Profile {
	return Profile{
		Version:                "nist-pqc-2026.1",
		MinimumRSAKeyBits:      3072,
		MinimumDHSafePrimeBits: 3072,
		RequireTLS13:           true,
		RequireHybridPQTLS13:   true,
		PreferredKEM:           "X25519MLKEM768",
		PreferredSignature:     "ML-DSA-65",
	}
}

func NewEngine(profile Profile) *Engine {
	e := &Engine{
		profiles: make(map[string]Profile),
		active:   profile.Version,
		osv:      NewOSVClient(true),
	}
	e.profiles[profile.Version] = profile
	return e
}

func LoadEngine(policiesDir string) (*Engine, error) {
	e := &Engine{
		profiles: make(map[string]Profile),
		active:   "nist-pqc-2026.1",
		osv:      NewOSVClient(true),
	}

	// Always seed NIST profile by default
	nist := NIST2026Profile()
	e.profiles[nist.Version] = nist

	files, err := filepath.Glob(filepath.Join(policiesDir, "*.yaml"))
	if err == nil {
		for _, file := range files {
			data, err := os.ReadFile(file)
			if err != nil {
				continue
			}
			var p Profile
			if err := yaml.Unmarshal(data, &p); err == nil && p.Version != "" {
				e.profiles[p.Version] = p
				if strings.Contains(file, "nist-pqc-2026") {
					e.active = p.Version
				}
			}
		}
	}

	return e, nil
}

func (e *Engine) ProfileVersion() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.active
}

func (e *Engine) GetActiveProfile() Profile {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.profiles[e.active]
}

func (e *Engine) SetActiveProfile(version string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.profiles[version]; !ok {
		return fmt.Errorf("profile %s not found", version)
	}
	e.active = version
	return nil
}

func (e *Engine) AddProfile(p Profile) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.profiles[p.Version] = p
}

func (e *Engine) AvailableProfiles() []Profile {
	e.mu.RLock()
	defer e.mu.RUnlock()
	list := make([]Profile, 0, len(e.profiles))
	for _, p := range e.profiles {
		list = append(list, p)
	}
	return list
}

func (e *Engine) Assess(payload *pb.CbomTelemetryPayload) {
	profile := e.GetActiveProfile()
	for _, component := range payload.Components {
		for _, alg := range component.Algorithms {
			e.assessAlgorithm(payload, component, alg, profile)
		}
		e.assessComponentVulnerabilities(payload, component)
	}
	for _, obs := range payload.NetworkObservations {
		e.assessNetwork(payload, obs, profile)
	}
}

func findEvidenceIDs(payload *pb.CbomTelemetryPayload, assetRef string) []string {
	var ids []string
	cleanRef := assetRef
	if idx := strings.Index(assetRef, ":"); idx != -1 {
		cleanRef = assetRef[idx+1:]
	}
	cleanRef = strings.ReplaceAll(cleanRef, "/", "\\")

	for _, ev := range payload.Evidence {
		evTarget := strings.ReplaceAll(ev.Target, "/", "\\")
		if ev.Target == assetRef || evTarget == cleanRef || (len(cleanRef) > 4 && strings.Contains(evTarget, cleanRef)) || (len(evTarget) > 4 && strings.Contains(cleanRef, evTarget)) {
			ids = append(ids, ev.EvidenceId)
		}
	}
	return ids
}

func (e *Engine) assessAlgorithm(payload *pb.CbomTelemetryPayload, component *pb.CbomComponent, alg *pb.CryptoAlgorithm, profile Profile) {
	// Skip low-confidence findings (test code, comment/string matches)
	if alg.Confidence > 0 && alg.Confidence < 0.4 {
		return
	}
	// Skip test-only code entirely
	if alg.Status == "test-only" {
		return
	}

	name := strings.ToUpper(alg.Name)
	family := strings.ToUpper(alg.Family)
	classicalPublicKey := containsAny(name, "RSA", "ECDSA", "ECDH", "ECDHE", "DH", "DSA") ||
		containsAny(family, "RSA", "ECC", "ECDH", "DIFFIE", "DSA")

	if isPublicKeyRole(alg.Role) && classicalPublicKey {
		alg.QuantumVulnerable = true
		severity := int32(pb.RiskSeverityHigh)
		var title, desc, rule, profileName string
		evidenceIDs := findEvidenceIDs(payload, component.BomRef)

		// Adjust severity based on usage intent
		severity = adjustSeverityForIntent(severity, alg)

		if alg.Role == pb.CryptoRoleCertSignature || alg.Role == pb.CryptoRoleSignature || alg.Role == pb.CryptoRoleCertPublicKey {
			title = "Classical public-key signature cryptography is quantum-vulnerable"
			desc = fmt.Sprintf("%s uses %s for %s. Migrate to PQC signature standard %s (ML-DSA) or SLH-DSA.", component.BomRef, alg.Name, roleName(alg.Role), profile.PreferredSignature)
			rule = "JANUS-PQC-001"
			profileName = "certificate-signature-modernization"
			if strings.Contains(name, "RSA") && alg.KeyBits > 0 && alg.KeyBits < profile.MinimumRSAKeyBits {
				severity = adjustSeverityForIntent(pb.RiskSeverityCritical, alg)
				title = "RSA key size below 2026 transition threshold"
				desc = fmt.Sprintf("%s uses RSA-%d; minimum transitional threshold is RSA-%d. Migrate to signature standard %s (ML-DSA).", component.BomRef, alg.KeyBits, profile.MinimumRSAKeyBits, profile.PreferredSignature)
				rule = "JANUS-PQC-002"
			}
		} else {
			title = "Classical key exchange / KEM cryptography is quantum-vulnerable"
			desc = fmt.Sprintf("%s uses %s for %s. Migrate to hybrid/PQC key establishment standard %s (ML-KEM).", component.BomRef, alg.Name, roleName(alg.Role), profile.PreferredKEM)
			rule = "JANUS-PQC-007"
			profileName = "hybrid-tls13-key-exchange"
		}

		// Annotate description with usage context for operator awareness
		if isLowRiskIntent(alg) {
			desc += fmt.Sprintf(" [Usage context: %s — severity adjusted from original assessment]", alg.Status)
		}

		appendFinding(payload, severity, title, desc, component.BomRef, alg.Name, rule, profileName, evidenceIDs)
		return
	}

	if strings.Contains(name, "MD5") || strings.Contains(name, "SHA1") || strings.Contains(name, "SHA-1") {
		evidenceIDs := findEvidenceIDs(payload, component.BomRef)
		severity := adjustSeverityForIntent(pb.RiskSeverityHigh, alg)
		appendFinding(payload,
			severity,
			"Deprecated hash detected",
			fmt.Sprintf("%s references %s. Replace with SHA-384/SHA-512/SHA-3 according to the calling protocol.", component.BomRef, alg.Name),
			component.BomRef,
			alg.Name,
			"JANUS-CLASSICAL-003",
			"hash-modernization",
			evidenceIDs,
		)
	}

	if strings.Contains(name, "AES-128") && alg.Role == pb.CryptoRoleSymmetric {
		evidenceIDs := findEvidenceIDs(payload, component.BomRef)
		severity := adjustSeverityForIntent(pb.RiskSeverityMedium, alg)
		appendFinding(payload,
			severity,
			"AES-128 used where long-term confidentiality may require AES-256",
			fmt.Sprintf("%s references AES-128. Review data lifetime and upgrade crown-jewel or long-retention data paths to AES-256.", component.BomRef),
			component.BomRef,
			alg.Name,
			"JANUS-PQC-004",
			"symmetric-margin-upgrade",
			evidenceIDs,
		)
	}
}

// adjustSeverityForIntent lowers severity when the algorithm usage is verification-only or negotiation.
func adjustSeverityForIntent(baseSeverity int32, alg *pb.CryptoAlgorithm) int32 {
	if alg == nil {
		return baseSeverity
	}
	status := strings.ToLower(alg.Status)
	switch {
	case status == "verify" || status == "parse":
		// Verification-only usage: private key is not at risk, downgrade by 2 levels
		if baseSeverity >= 2 {
			return baseSeverity - 2
		}
		return pb.RiskSeverityInfo
	case status == "negotiate":
		// Negotiation context: algorithm may not be selected, downgrade by 1
		if baseSeverity >= 1 {
			return baseSeverity - 1
		}
		return pb.RiskSeverityInfo
	default:
		return baseSeverity
	}
}

// isLowRiskIntent returns true if the algorithm status indicates verify/negotiate/parse context.
func isLowRiskIntent(alg *pb.CryptoAlgorithm) bool {
	s := strings.ToLower(alg.Status)
	return s == "verify" || s == "parse" || s == "negotiate"
}

func (e *Engine) assessNetwork(payload *pb.CbomTelemetryPayload, obs *pb.NetworkObservation, profile Profile) {
	evidenceIDs := findEvidenceIDs(payload, obs.Endpoint)
	if obs.Cleartext {
		appendFinding(payload,
			pb.RiskSeverityCritical,
			"Cleartext service observed",
			fmt.Sprintf("%s exposes %s without cryptographic protection.", obs.Endpoint, obs.Protocol),
			obs.Endpoint,
			"cleartext",
			"JANUS-NET-001",
			"enable-tls13-hybrid",
			evidenceIDs,
		)
		return
	}

	version := strings.ToUpper(obs.TlsVersion)
	if strings.HasPrefix(version, "TLS1.0") || strings.HasPrefix(version, "TLS1.1") || strings.HasPrefix(version, "TLS1.2") || version == "" {
		appendFinding(payload,
			pb.RiskSeverityHigh,
			"TLS 1.3 is not enabled (blocks hybrid PQC key exchange)",
			fmt.Sprintf("%s negotiated or reported %q. Hybrid post-quantum key agreement (ML-KEM) requires TLS 1.3. Enable TLS 1.3 first.", obs.Endpoint, obs.TlsVersion),
			obs.Endpoint,
			obs.CipherSuite,
			"JANUS-NET-002",
			"enable-tls13-first",
			evidenceIDs,
		)
	}

	group := strings.ToUpper(obs.NamedGroup)
	if profile.RequireHybridPQTLS13 && !obs.PqcHybrid && !strings.Contains(group, "MLKEM") && !strings.Contains(group, "ML-KEM") {
		appendFinding(payload,
			pb.RiskSeverityCritical,
			"TLS key exchange is classical-only",
			fmt.Sprintf("%s did not prove hybrid ML-KEM key agreement. Observed group=%q cipher=%q.", obs.Endpoint, obs.NamedGroup, obs.CipherSuite),
			obs.Endpoint,
			obs.NamedGroup,
			"JANUS-PQC-005",
			"X25519MLKEM768",
			evidenceIDs,
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
			evidenceIDs,
		)
	}
}

func appendFinding(payload *pb.CbomTelemetryPayload, severity int32, title, description, assetRef, algorithm, rule, profile string, evidenceIDs []string) {
	if hasFinding(payload, assetRef, algorithm, rule) {
		return
	}
	f := finding(severity, title, description, assetRef, algorithm, rule, profile)
	f.EvidenceIds = evidenceIDs
	payload.Findings = append(payload.Findings, f)
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

type localVulnerability struct {
	ID          string
	Package     string
	Ecosystem   string
	Vulnerable  string
	Title       string
	Description string
	Severity    int32
	FixedIn     string
}

var localAdvisories = []localVulnerability{
	{
		ID:          "CVE-2023-48795",
		Package:     "golang.org/x/crypto",
		Ecosystem:   "Go",
		Vulnerable:  "0.17.0",
		Title:       "SSH Terrapin attack vulnerability",
		Description: "Prefix truncation attack in SSH handshake protocol allows MITM attacker to degrade security parameters.",
		Severity:    4, // High
		FixedIn:     "0.17.0",
	},
	{
		ID:          "CVE-2024-24789",
		Package:     "golang.org/x/crypto",
		Ecosystem:   "Go",
		Vulnerable:  "0.21.0",
		Title:       "golang.org/x/crypto/x509 Certificate verification bypass",
		Description: "Panic during cert verification on specific key usages allows denial of service.",
		Severity:    3, // Medium
		FixedIn:     "0.21.0",
	},
	{
		ID:          "CVE-2023-3446",
		Package:     "openssl",
		Ecosystem:   "native",
		Vulnerable:  "3.0.10",
		Title:       "OpenSSL DH_check() excessive time complexity",
		Description: "DH_check() performs excessive computation, causing denial of service.",
		Severity:    3, // Medium
		FixedIn:     "3.0.10",
	},
	{
		ID:          "CVE-2024-22369",
		Package:     "node-forge",
		Ecosystem:   "npm",
		Vulnerable:  "1.3.1",
		Title:       "node-forge RSA signature verification bypass",
		Description: "Verification fails to validate correct padding, allowing signature spoofing.",
		Severity:    5, // Critical
		FixedIn:     "1.3.1",
	},
}

func (e *Engine) assessComponentVulnerabilities(payload *pb.CbomTelemetryPayload, component *pb.CbomComponent) {
	if component.Version == "" {
		return
	}
	// Check local advisory database first
	for _, adv := range localAdvisories {
		if strings.EqualFold(component.Name, adv.Package) {
			if compareVersions(component.Version, adv.Vulnerable) < 0 {
				evidenceIDs := findEvidenceIDs(payload, component.BomRef)
				appendFinding(payload,
					adv.Severity,
					adv.Title,
					fmt.Sprintf("%s. Affected version: %s. Upgrade package to version %s or newer.", adv.Description, component.Version, adv.FixedIn),
					component.BomRef,
					adv.ID,
					adv.ID,
					"third-party-package-upgrade",
					evidenceIDs,
				)
			}
		}
	}

	// Query OSV.dev for live vulnerability data (if enabled)
	if e.osv != nil && component.Language != "" {
		vulns, err := e.osv.QueryPackage(component.Language, component.Name, component.Version)
		if err == nil && len(vulns) > 0 {
			// Filter to crypto-relevant vulnerabilities only
			cryptoVulns := FilterCryptoRelevant(vulns)
			for _, v := range cryptoVulns {
				evidenceIDs := findEvidenceIDs(payload, component.BomRef)
				severity := OSVSeverityToJanus(v.Severity)
				fixed := GetFixedVersion(v)
				appendFinding(payload,
					severity,
					v.Summary,
					fmt.Sprintf("%s [OSV: %s]. Fix: upgrade to %s.", v.Details, v.ID, fixed),
					component.BomRef,
					v.ID,
					v.ID,
					"third-party-package-upgrade",
					evidenceIDs,
				)
			}
		}
	}
}

func compareVersions(v1, v2 string) int {
	parts1 := parseVersion(v1)
	parts2 := parseVersion(v2)
	for i := 0; i < 3; i++ {
		if parts1[i] < parts2[i] {
			return -1
		}
		if parts1[i] > parts2[i] {
			return 1
		}
	}
	return 0
}

func parseVersion(v string) [3]int {
	v = strings.TrimPrefix(v, "v")
	parts := strings.Split(v, ".")
	var res [3]int
	for i := 0; i < len(parts) && i < 3; i++ {
		fmt.Sscanf(parts[i], "%d", &res[i])
	}
	return res
}
