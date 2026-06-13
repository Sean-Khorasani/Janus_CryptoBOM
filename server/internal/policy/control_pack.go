package policy

// ControlRule describes a single versioned compliance rule with framework references.
type ControlRule struct {
	RuleID          string   `json:"rule_id"`
	Title           string   `json:"title"`
	Description     string   `json:"description"`
	Rationale       string   `json:"rationale"`
	FrameworkRefs   []string `json:"framework_refs"`
	EffectiveDate   string   `json:"effective_date"`
	ExpiryDate      string   `json:"expiry_date,omitempty"`
	Severity        int      `json:"severity"`
	RemediationHint string   `json:"remediation_hint"`
}

// ControlPack is a versioned collection of compliance rules.
type ControlPack struct {
	PackID        string        `json:"pack_id"`
	Name          string        `json:"name"`
	Version       string        `json:"version"`
	EffectiveDate string        `json:"effective_date"`
	Rules         []ControlRule `json:"rules"`
}

// builtinRules is the authoritative list of Janus policy rule IDs emitted by the engine.
// Note: CVE-based rule IDs (e.g. "CVE-2023-48795") are dynamic and are not included here.
var builtinRules = []ControlRule{
	{
		RuleID:      "JANUS-PQC-001",
		Title:       "Classical public-key signature cryptography is quantum-vulnerable",
		Description: "Detects RSA, ECDSA, DSA, or Ed25519 algorithms used in signature or certificate roles. These algorithms are broken by Grover/Shor attacks on a cryptographically relevant quantum computer (CRQC).",
		Rationale:   "Harvest-Now-Decrypt-Later (HNDL) adversaries capture today's signatures for replay after a CRQC becomes available. NIST FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA) are the mandated replacements effective 2025-08-13.",
		FrameworkRefs: []string{
			"NIST.FIPS.204",
			"NIST.FIPS.205",
			"NIST.SP.800-208",
			"NSA-CISA-PQC-2022",
		},
		EffectiveDate:   "2025-08-13",
		Severity:        4,
		RemediationHint: "Migrate to ML-DSA-65 (FIPS 204) or SLH-DSA. Pilot in private trust domains first; track public PKI readiness for ECDSA.",
	},
	{
		RuleID:      "JANUS-PQC-002",
		Title:       "RSA key size below 2026 transition threshold",
		Description: "RSA key is below the minimum transitional size defined by the active policy profile (default 3072 bits). Sub-threshold RSA is both classically weak today and quantum-vulnerable.",
		Rationale:   "NIST SP 800-131A Rev.2 disallows RSA < 2048 for new use and recommends 3072 for 2031+ security. Under CNSA 2.0 and PQC transition guidance, anything below 3072 is high-risk.",
		FrameworkRefs: []string{
			"NIST.SP.800-131A",
			"NIST.FIPS.204",
			"CNSA-2.0",
		},
		EffectiveDate:   "2025-08-13",
		Severity:        5,
		RemediationHint: "Replace RSA with ML-DSA-65 for signatures, or at minimum upgrade to RSA-3072 as a stopgap.",
	},
	{
		RuleID:      "JANUS-PQC-004",
		Title:       "AES-128 used where long-term confidentiality may require AES-256",
		Description: "Detects AES-128 in symmetric encryption roles. Grover's algorithm halves the effective key strength, leaving AES-128 with approximately 64-bit post-quantum security.",
		Rationale:   "NIST and NSA recommend AES-256 for data requiring long-term confidentiality. AES-128 is insufficient for any secret that may be exposed to a CRQC. CNSA 2.0 mandates AES-256 exclusively.",
		FrameworkRefs: []string{
			"NIST.FIPS.197",
			"CNSA-2.0",
			"NSA-CISA-PQC-2022",
		},
		EffectiveDate:   "2025-08-13",
		Severity:        3,
		RemediationHint: "Upgrade crown-jewel and long-retention data paths to AES-256. AES-128 may be acceptable for ephemeral, low-sensitivity data.",
	},
	{
		RuleID:      "JANUS-PQC-005",
		Title:       "TLS key exchange is classical-only",
		Description: "The TLS connection did not use a hybrid ML-KEM key agreement group (e.g. X25519MLKEM768). Classical-only key exchange (X25519, P-256) is vulnerable to retrospective decryption by a CRQC.",
		Rationale:   "HNDL adversaries record TLS sessions today for decryption post-CRQC. ML-KEM (FIPS 203) in hybrid mode provides quantum-safe forward secrecy. CNSA 2.0 mandates ML-KEM-1024.",
		FrameworkRefs: []string{
			"NIST.FIPS.203",
			"CNSA-2.0",
			"NSA-CISA-PQC-2022",
		},
		EffectiveDate:   "2025-08-13",
		Severity:        5,
		RemediationHint: "Enable X25519MLKEM768 (NIST profile) or ML-KEM-1024 (CNSA 2.0) in your TLS library configuration. TLS 1.3 is a prerequisite.",
	},
	{
		RuleID:      "JANUS-PQC-006",
		Title:       "Certificate signature remains classical",
		Description: "The server certificate uses a classical signature algorithm (RSA or ECDSA). While TLS 1.3 protects forward secrecy, a signed certificate with a weak algorithm can be forged post-CRQC.",
		Rationale:   "NIST FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA) are now standardised. CA/Browser Forum and public PKI readiness is tracked; deployment should start in private trust domains.",
		FrameworkRefs: []string{
			"NIST.FIPS.204",
			"NIST.FIPS.205",
			"CNSA-2.0",
		},
		EffectiveDate:   "2025-08-13",
		Severity:        4,
		RemediationHint: "Pilot ML-DSA or SLH-DSA certificates in private PKI. Monitor CA/Browser Forum timelines for public trust inclusion.",
	},
	{
		RuleID:      "JANUS-PQC-007",
		Title:       "Classical key exchange / KEM cryptography is quantum-vulnerable",
		Description: "Detects classical key exchange or KEM algorithms (DH, ECDH, ECDHE) in non-signature roles. These are broken by Shor's algorithm on a CRQC.",
		Rationale:   "Key establishment is the highest-priority migration target under HNDL threat. NIST FIPS 203 (ML-KEM) is the standardised post-quantum KEM. Hybrid operation with classical algorithms is recommended during transition.",
		FrameworkRefs: []string{
			"NIST.FIPS.203",
			"NIST.SP.800-227",
			"NSA-CISA-PQC-2022",
		},
		EffectiveDate:   "2025-08-13",
		Severity:        4,
		RemediationHint: "Migrate to hybrid ML-KEM (X25519MLKEM768 for NIST profile, ML-KEM-1024 for CNSA 2.0). Prioritise long-lived key material.",
	},
	{
		RuleID:      "JANUS-CLASSICAL-003",
		Title:       "Deprecated hash algorithm detected",
		Description: "Detects MD5 or SHA-1 usage. Both algorithms are cryptographically broken: MD5 since 1996, SHA-1 since 2017 (SHAttered collision). Neither should appear in any security-relevant context.",
		Rationale:   "NIST SP 800-131A Rev.2 disallows MD5 and SHA-1 for all security functions. Collision attacks are practical with consumer hardware.",
		FrameworkRefs: []string{
			"NIST.SP.800-131A",
			"NIST.FIPS.180-4",
			"CNSA-2.0",
		},
		EffectiveDate:   "2025-08-13",
		Severity:        4,
		RemediationHint: "Replace MD5/SHA-1 with SHA-384 or SHA-512 (general use), or SHA-3 where protocol permits. Check the calling protocol — some legacy protocols specify SHA-1 in headers/wire format and require protocol-level migration.",
	},
	{
		RuleID:      "JANUS-NET-001",
		Title:       "Cleartext service observed",
		Description: "A network service is transmitting data without cryptographic protection (no TLS/DTLS). All data, including credentials, is exposed to passive eavesdropping and active tampering.",
		Rationale:   "Unencrypted services violate basic transport security baselines required by NIST SP 800-52 Rev.2, PCI DSS, and virtually all compliance frameworks. TLS is a prerequisite for any PQC migration.",
		FrameworkRefs: []string{
			"NIST.SP.800-52",
			"NIST.SP.800-131A",
			"CNSA-2.0",
		},
		EffectiveDate:   "2025-08-13",
		Severity:        5,
		RemediationHint: "Enable TLS 1.3 with an ML-KEM hybrid key exchange group. Cleartext services block all downstream PQC improvements.",
	},
	{
		RuleID:      "JANUS-NET-002",
		Title:       "TLS 1.3 is not enabled",
		Description: "The endpoint negotiated TLS 1.0, 1.1, or 1.2. Hybrid post-quantum key agreement (ML-KEM via X25519MLKEM768 or equivalent) requires TLS 1.3.",
		Rationale:   "TLS 1.2 and below cannot carry the ECDHE+ML-KEM hybrid groups defined in IETF draft-ietf-tls-hybrid-design. TLS 1.3 is required as a foundation for PQC. NIST SP 800-52 Rev.2 mandates TLS 1.3.",
		FrameworkRefs: []string{
			"NIST.SP.800-52",
			"IETF-TLS-HYBRID",
			"CNSA-2.0",
		},
		EffectiveDate:   "2025-08-13",
		Severity:        4,
		RemediationHint: "Enable TLS 1.3 in the server configuration. Disable TLS 1.0 and 1.1. TLS 1.2 may be retained for legacy client compatibility but hybrid PQC requires TLS 1.3.",
	},
	{
		RuleID:      "JANUS-CNSA-001",
		Title:       "CNSA 2.0: ECDSA curve below P-384 minimum",
		Description: "Detects ECDSA or ECC usage with P-256 (secp256r1/prime256v1). CNSA 2.0 sets P-384 as the minimum acceptable classical elliptic curve for national security systems.",
		Rationale:   "NSA CNSA 2.0 (September 2022) mandates ECDSA P-384 as the minimum for NSS/DoD systems and requires migration to ML-DSA-87 for new deployments. P-256 is explicitly prohibited.",
		FrameworkRefs: []string{
			"CNSA-2.0",
			"NSA-CISA-PQC-2022",
			"NIST.FIPS.204",
		},
		EffectiveDate:   "2022-09-07",
		Severity:        4,
		RemediationHint: "Upgrade to ECDSA P-384 as a transitional measure, then migrate to ML-DSA-87 per CNSA 2.0 schedule.",
	},
	{
		RuleID:      "JANUS-CNSA-002",
		Title:       "CNSA 2.0: SHA-256 is below hash minimum",
		Description: "Detects SHA-256 used in hash roles on systems under CNSA 2.0. CNSA 2.0 sets SHA-384 as the minimum hash strength for national security systems.",
		Rationale:   "NSA CNSA 2.0 (September 2022) mandates SHA-384 or SHA-512 for all hashing in NSS environments. SHA-256 is insufficient.",
		FrameworkRefs: []string{
			"CNSA-2.0",
			"NSA-CISA-PQC-2022",
			"NIST.FIPS.180-4",
		},
		EffectiveDate:   "2022-09-07",
		Severity:        3,
		RemediationHint: "Upgrade hash operations to SHA-384 or SHA-512 where CNSA 2.0 compliance is required.",
	},
	{
		RuleID:      "JANUS-CNSA-003",
		Title:       "CNSA 2.0: AES-128 is prohibited",
		Description: "Detects AES-128 in symmetric encryption roles on systems under CNSA 2.0. CNSA 2.0 mandates AES-256 exclusively for symmetric encryption in national security systems.",
		Rationale:   "NSA CNSA 2.0 (September 2022) explicitly prohibits AES-128 for NSS environments. AES-256 is the only approved symmetric cipher.",
		FrameworkRefs: []string{
			"CNSA-2.0",
			"NSA-CISA-PQC-2022",
			"NIST.FIPS.197",
		},
		EffectiveDate:   "2022-09-07",
		Severity:        4,
		RemediationHint: "Replace all AES-128 usage with AES-256. This is a hard requirement under CNSA 2.0 — no exceptions.",
	},
}

// ruleIndex is a pre-built map from RuleID to ControlRule for O(1) lookup.
var ruleIndex map[string]ControlRule

func init() {
	ruleIndex = make(map[string]ControlRule, len(builtinRules))
	for _, r := range builtinRules {
		ruleIndex[r.RuleID] = r
	}
}

// BuiltinControlPack returns the versioned control pack containing all built-in Janus policy rules.
// CVE-based rule IDs emitted by the vulnerability advisory scanner are dynamic and are
// not included in this pack — GetRule will return (_, false) for CVE-* identifiers.
func BuiltinControlPack() ControlPack {
	rules := make([]ControlRule, len(builtinRules))
	copy(rules, builtinRules)
	return ControlPack{
		PackID:        "janus-builtin-v1",
		Name:          "Janus Built-in PQC Compliance Rules",
		Version:       "1.0.0",
		EffectiveDate: "2025-08-13",
		Rules:         rules,
	}
}

// GetRule returns the ControlRule for the given ruleID, or (ControlRule{}, false) if not found.
func GetRule(ruleID string) (ControlRule, bool) {
	r, ok := ruleIndex[ruleID]
	return r, ok
}
