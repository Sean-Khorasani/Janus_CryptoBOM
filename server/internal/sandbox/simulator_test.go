package sandbox

import (
	"context"
	"errors"
	"testing"

	"github.com/janus-cbom/janus/server/internal/orchestrator"
	"github.com/janus-cbom/janus/server/internal/policy"
	"github.com/janus-cbom/janus/server/internal/store"
)

// ---------------------------------------------------------------------------
// Minimal mock store — only GetLatestConfigHash is exercised by Simulator.
// ---------------------------------------------------------------------------

type mockStore struct {
	store.Store // embed nil; panics on any unconfigured method
}

func (m *mockStore) GetLatestConfigHash(_ context.Context, _, _ string) (string, error) {
	return "", errors.New("no hash")
}

// newTestSimulator builds a Simulator backed by a mock store and the NIST 2026 policy profile.
func newTestSimulator() *Simulator {
	st := &mockStore{}
	orch := orchestrator.New([]byte("test-signing-key-32-bytes-padding!"))
	engine := policy.NewEngine(policy.NIST2026Profile())
	return NewSimulator(st, orch, engine)
}

// ---------------------------------------------------------------------------
// buildCompatibilityAnalysis tests
// ---------------------------------------------------------------------------

// TestCompatibilityRSAToMLDSA verifies that migrating from RSA-2048 to ML-DSA triggers
// hybrid_required=true, TLSv1.3, and a non-empty dependency_updates list.
func TestCompatibilityRSAToMLDSA(t *testing.T) {
	ca := buildCompatibilityAnalysis("RSA-2048", "X25519MLKEM768", "ML-DSA-65")

	if !ca.HybridRequired {
		t.Error("expected hybrid_required=true when migrating to ML-DSA")
	}
	if ca.MinTLSVersion != "TLSv1.3" {
		t.Errorf("expected min_tls_version=TLSv1.3, got %q", ca.MinTLSVersion)
	}
	if len(ca.DependencyUpdates) == 0 {
		t.Error("expected non-empty dependency_updates for RSA-2048 → ML-DSA migration")
	}
	if len(ca.BreakingChanges) == 0 {
		t.Error("expected non-empty breaking_changes for RSA-2048 → ML-DSA migration")
	}
}

// TestCompatibilityRSAKeyBump verifies that RSA-2048 → RSA-4096 is a low-risk drop-in
// with no breaking changes and rollback_risk="low".
func TestCompatibilityRSAKeyBump(t *testing.T) {
	ca := buildCompatibilityAnalysis("RSA-2048", "", "RSA-4096")

	if ca.RollbackRisk != "low" {
		t.Errorf("expected rollback_risk=low for RSA key-size bump, got %q", ca.RollbackRisk)
	}
	if len(ca.BreakingChanges) != 0 {
		t.Errorf("expected no breaking_changes for RSA key-size bump, got %v", ca.BreakingChanges)
	}
	if ca.HybridRequired {
		t.Error("expected hybrid_required=false for pure RSA key-size bump")
	}
}

// TestCompatibilityMLKEMSetsHybrid verifies that a ML-KEM target sets hybrid_required and TLSv1.3.
func TestCompatibilityMLKEMSetsHybrid(t *testing.T) {
	ca := buildCompatibilityAnalysis("ECDH", "ML-KEM-1024", "ML-DSA-87")

	if !ca.HybridRequired {
		t.Error("expected hybrid_required=true when targeting ML-KEM")
	}
	if ca.MinTLSVersion != "TLSv1.3" {
		t.Errorf("expected min_tls_version=TLSv1.3, got %q", ca.MinTLSVersion)
	}
}

// TestCompatibilityAES128ToAES256 verifies high rollback risk and breaking changes for key migration.
func TestCompatibilityAES128ToAES256(t *testing.T) {
	ca := buildCompatibilityAnalysis("AES-128", "", "AES-256")

	if ca.RollbackRisk != "high" {
		t.Errorf("expected rollback_risk=high for AES-128→AES-256, got %q", ca.RollbackRisk)
	}
	if len(ca.BreakingChanges) == 0 {
		t.Error("expected non-empty breaking_changes for AES-128→AES-256 key migration")
	}
	if ca.EstimatedDowntime != "<5m" {
		t.Errorf("expected estimated_downtime=<5m for AES key migration, got %q", ca.EstimatedDowntime)
	}
}

// TestCompatibilityMLDSADependencyPackages verifies the specific package managers are represented
// in the dependency updates for an RSA → ML-DSA migration.
func TestCompatibilityMLDSADependencyPackages(t *testing.T) {
	ca := buildCompatibilityAnalysis("RSA-2048", "", "ML-DSA-65")

	managers := map[string]bool{}
	for _, dep := range ca.DependencyUpdates {
		managers[dep.PackageManager] = true
	}

	for _, required := range []string{"cargo", "npm", "go", "pip"} {
		if !managers[required] {
			t.Errorf("expected dependency_updates to include package manager %q", required)
		}
	}
}

// ---------------------------------------------------------------------------
// SimulateMigration approval-enforcement tests
// ---------------------------------------------------------------------------

// TestSimulateMigrationHumanApprovalRequired verifies that HumanApprovalRequired is always true.
func TestSimulateMigrationHumanApprovalRequired(t *testing.T) {
	sim := newTestSimulator()
	result, err := sim.SimulateMigration("host-1", "nginx", "RSA-2048", "/etc/nginx/nginx.conf", true)
	if err != nil {
		t.Fatalf("SimulateMigration returned error: %v", err)
	}
	if !result.HumanApprovalRequired {
		t.Error("expected HumanApprovalRequired=true in SimulationResult")
	}
	if !result.RequiresApproval {
		t.Error("expected RequiresApproval=true in SimulationResult")
	}
	if result.ApprovalPolicy != "human-review-required" {
		t.Errorf("expected ApprovalPolicy=%q, got %q", "human-review-required", result.ApprovalPolicy)
	}
}

// TestSimulateMigrationIncludesCompatibility verifies that CompatibilityAnalysis is populated.
func TestSimulateMigrationIncludesCompatibility(t *testing.T) {
	sim := newTestSimulator()
	result, err := sim.SimulateMigration("host-1", "nginx", "RSA-2048", "/etc/nginx/nginx.conf", false)
	if err != nil {
		t.Fatalf("SimulateMigration returned error: %v", err)
	}
	if result.CompatibilityAnalysis == nil {
		t.Fatal("expected non-nil CompatibilityAnalysis in SimulationResult")
	}
	// NIST 2026 profile uses ML-DSA-65 as preferred signature, so hybrid should be required.
	if !result.CompatibilityAnalysis.HybridRequired {
		t.Error("expected HybridRequired=true for RSA-2048 with NIST 2026 profile (ML-DSA target)")
	}
}
