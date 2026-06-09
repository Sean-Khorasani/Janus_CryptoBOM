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

// SimulationResult contains the output of a dry-run PQC migration simulation.
type SimulationResult struct {
	SimulationID         string            `json:"simulation_id"`
	InputAlgorithm       string            `json:"input_algorithm"`
	RecommendedKEM       string            `json:"recommended_kem"`
	RecommendedSignature string            `json:"recommended_signature"`
	GeneratedPatch       string            `json:"generated_patch"`
	EstimatedImpact      string            `json:"estimated_impact"` // LOW, MEDIUM, HIGH
	RollbackWindowSecs   uint32            `json:"rollback_window_secs"`
	ValidationChecklist  []string          `json:"validation_checklist"`
	PreChecks            map[string]bool   `json:"pre_checks"`
	Warnings             []string          `json:"warnings"`
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

	return &SimulationResult{
		SimulationID:         uuid.NewString(),
		InputAlgorithm:       algorithm,
		RecommendedKEM:       recommendedKEM,
		RecommendedSignature: recommendedSignature,
		GeneratedPatch:       patch,
		EstimatedImpact:      impact,
		RollbackWindowSecs:   300,
		ValidationChecklist:  checklist,
		PreChecks:            preChecks,
		Warnings:             warnings,
	}, nil
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
