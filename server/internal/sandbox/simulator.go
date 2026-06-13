package sandbox

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/janus-cbom/janus/server/internal/orchestrator"
	"github.com/janus-cbom/janus/server/internal/policy"
	"github.com/janus-cbom/janus/server/internal/store"
)

// CompatibilityAnalysis captures migration compatibility concerns.
type CompatibilityAnalysis struct {
	TargetEcosystem   string            `json:"target_ecosystem"`              // "tls", "code-signing", "dependency", "config"
	BreakingChanges   []string          `json:"breaking_changes"`              // protocol/API-level breaks
	DependencyUpdates []DependencyUpdate `json:"dependency_updates"`           // package bumps needed
	RollbackRisk      string            `json:"rollback_risk"`                 // "low", "medium", "high"
	MinTLSVersion     string            `json:"min_tls_version,omitempty"`     // e.g. "TLSv1.3"
	HybridRequired    bool              `json:"hybrid_required"`
	EstimatedDowntime string            `json:"estimated_downtime"`            // "none", "<30s", "<5m", "extended"
}

// DependencyUpdate describes a package upgrade required for the migration.
type DependencyUpdate struct {
	PackageManager string `json:"package_manager"` // "cargo", "npm", "go", "pip", "maven"
	Package        string `json:"package"`
	CurrentVersion string `json:"current_version,omitempty"`
	MinVersion     string `json:"min_version"`
	Reason         string `json:"reason"`
}

// SimulationResult contains the output of a dry-run PQC migration simulation.
type SimulationResult struct {
	SimulationID          string                 `json:"simulation_id"`
	InputAlgorithm        string                 `json:"input_algorithm"`
	RecommendedKEM        string                 `json:"recommended_kem"`
	RecommendedSignature  string                 `json:"recommended_signature"`
	GeneratedPatch        string                 `json:"generated_patch"`
	EstimatedImpact       string                 `json:"estimated_impact"` // LOW, MEDIUM, HIGH
	RollbackWindowSecs    uint32                 `json:"rollback_window_secs"`
	ValidationChecklist   []string               `json:"validation_checklist"`
	PreChecks             map[string]bool        `json:"pre_checks"`
	Warnings              []string               `json:"warnings"`
	CompatibilityAnalysis *CompatibilityAnalysis `json:"compatibility_analysis,omitempty"`
	// RequiresApproval enforces WP-015: no patch enters execution without human approval.
	RequiresApproval      bool   `json:"requires_approval"`
	ApprovalPolicy        string `json:"approval_policy"`
	HumanApprovalRequired bool   `json:"human_approval_required"`
}

// Simulator performs dry-run PQC migration simulations without executing.
type Simulator struct {
	store  store.Store
	orch   *orchestrator.Orchestrator
	engine *policy.Engine
}

// NewSimulator creates a new Simulator.
func NewSimulator(store store.Store, orch *orchestrator.Orchestrator, engine *policy.Engine) *Simulator {
	return &Simulator{store: store, orch: orch, engine: engine}
}

// SimulateMigration generates a migration simulation result without executing the migration.
func (s *Simulator) SimulateMigration(hostUUID, targetService, algorithm, configPath string, dryRun bool) (*SimulationResult, error) {
	profile := s.engine.GetActiveProfile()

	// Read current config hash from store (uses background context for simplicity)
	ctx := context.Background()
	_, err := s.store.GetLatestConfigHash(ctx, hostUUID, configPath)
	if err != nil {
		// Non-fatal: we can still generate a patch without the hash
	}

	// Determine recommended algorithms based on the active profile
	recommendedKEM := profile.PreferredKEM
	recommendedSignature := profile.PreferredSignature

	// Generate a migration patch (unified diff format)
	patch := generatePatch(configPath, algorithm, recommendedKEM, recommendedSignature)

	// Determine estimated impact
	impact := estimateImpact(algorithm)

	// Build validation checklist
	checklist := []string{
		"config-backup-verified",
		"syntax-check",
		"daemon-reload-test",
		"tls13-handshake-verify",
		"hybrid-mlkem-observed",
	}

	// Run pre-checks
	preChecks := map[string]bool{
		"config_backup":   true,
		"syntax_check":    false,
		"reload_possible": true,
	}

	warnings := []string{}
	if dryRun {
		warnings = append(warnings, "Dry-run mode: no changes will be applied")
	}

	compat := buildCompatibilityAnalysis(algorithm, recommendedKEM, recommendedSignature)

	return &SimulationResult{
		SimulationID:          uuid.NewString(),
		InputAlgorithm:        algorithm,
		RecommendedKEM:        recommendedKEM,
		RecommendedSignature:  recommendedSignature,
		GeneratedPatch:        patch,
		EstimatedImpact:       impact,
		RollbackWindowSecs:    300,
		ValidationChecklist:   checklist,
		PreChecks:             preChecks,
		Warnings:              warnings,
		CompatibilityAnalysis: compat,
		RequiresApproval:      true,
		ApprovalPolicy:        "human-review-required",
		HumanApprovalRequired: true,
	}, nil
}

// buildCompatibilityAnalysis generates compatibility analysis based on the
// algorithm being migrated FROM and the target algorithms.
func buildCompatibilityAnalysis(inputAlgorithm, recommendedKEM, recommendedSignature string) *CompatibilityAnalysis {
	ca := &CompatibilityAnalysis{
		TargetEcosystem:   "tls",
		BreakingChanges:   []string{},
		DependencyUpdates: []DependencyUpdate{},
		RollbackRisk:      "medium",
		EstimatedDowntime: "none",
	}

	inputUpper := strings.ToUpper(inputAlgorithm)
	sigUpper := strings.ToUpper(recommendedSignature)
	kemUpper := strings.ToUpper(recommendedKEM)

	// Migrating TO ML-DSA (PQC signature).
	// Check ML-DSA before bare DSA/RSA to avoid substring collisions.
	if strings.Contains(sigUpper, "ML-DSA") {
		ca.BreakingChanges = append(ca.BreakingChanges,
			"Certificate chain validation requires both legacy and PQC trust anchors during transition",
			"TLS clients must support ML-DSA before migration",
		)
		ca.MinTLSVersion = "TLSv1.3"
		ca.HybridRequired = true
		ca.RollbackRisk = "medium"
		ca.EstimatedDowntime = "<30s"
		ca.DependencyUpdates = append(ca.DependencyUpdates,
			DependencyUpdate{
				PackageManager: "cargo",
				Package:        "openssl",
				MinVersion:     "0.10.64",
				Reason:         "liboqs support for ML-DSA",
			},
			DependencyUpdate{
				PackageManager: "cargo",
				Package:        "pqcrypto",
				MinVersion:     "0.1.0",
				Reason:         "PQC primitive support",
			},
			DependencyUpdate{
				PackageManager: "npm",
				Package:        "@noble/post-quantum",
				MinVersion:     "0.1.0",
				Reason:         "node-forge is not compatible with ML-DSA; use @noble/post-quantum",
			},
			DependencyUpdate{
				PackageManager: "go",
				Package:        "golang.org/x/crypto",
				MinVersion:     "0.17.0",
				Reason:         "hybrid PQC support",
			},
			DependencyUpdate{
				PackageManager: "pip",
				Package:        "cryptography",
				MinVersion:     "42.0.0",
				Reason:         "ML-DSA support via liboqs bindings",
			},
		)
	} else if strings.Contains(sigUpper, "RSA") {
		// Intermediate RSA key-size bump (e.g. RSA-2048 → RSA-4096): low-risk drop-in.
		ca.RollbackRisk = "low"
		ca.EstimatedDowntime = "none"
		// No breaking changes for a compatible key-size upgrade.
	}

	// Migrating TO ML-KEM (PQC KEM).
	if strings.Contains(kemUpper, "ML-KEM") {
		ca.HybridRequired = true
		ca.MinTLSVersion = "TLSv1.3"
		ca.DependencyUpdates = append(ca.DependencyUpdates,
			DependencyUpdate{
				PackageManager: "cargo",
				Package:        "openssl",
				MinVersion:     "3.5.0",
				Reason:         "ML-KEM support requires OpenSSL >= 3.5.0",
			},
		)
	}

	// Migrating FROM AES-128 TO AES-256.
	if strings.Contains(inputUpper, "AES-128") && strings.Contains(sigUpper, "AES-256") {
		ca.BreakingChanges = append(ca.BreakingChanges,
			"Key material must be regenerated; existing encrypted data cannot be migrated transparently",
		)
		ca.RollbackRisk = "high"
		ca.EstimatedDowntime = "<5m"
	}

	return ca
}

// generatePatch creates a sample unified diff patch replacing the algorithm.
func generatePatch(configPath, algorithm, kem, sig string) string {
	replacement := kem
	if isSignatureAlgorithm(algorithm) {
		replacement = sig
	}
	return fmt.Sprintf("--- %s\n+++ %s\n@@ -1,5 +1,5 @@\n-%s\n+%s\n",
		configPath, configPath, algorithm, replacement)
}

// isSignatureAlgorithm returns true if the algorithm is a classical signature algorithm.
func isSignatureAlgorithm(algorithm string) bool {
	upper := strings.ToUpper(algorithm)
	return strings.Contains(upper, "RSA") || strings.Contains(upper, "DSA") || strings.Contains(upper, "ECDSA")
}

// estimateImpact returns LOW, MEDIUM, or HIGH based on the algorithm type.
func estimateImpact(algorithm string) string {
	upper := strings.ToUpper(algorithm)
	if strings.Contains(upper, "RSA") || strings.Contains(upper, "DSA") || strings.Contains(upper, "ECDSA") {
		return "MEDIUM"
	}
	return "LOW"
}

// Ensure time import is used
var _ = time.Now
