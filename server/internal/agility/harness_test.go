package agility

import "testing"

// WP-023: per-adapter negotiation harness + adapter capability matrix.

func TestNormalizeAlgorithmAliases(t *testing.T) {
	cases := map[string]string{
		"Kyber":             "ML-KEM-768",
		"kyber768":          "ML-KEM-768",
		"ml_kem_768":        "ML-KEM-768",
		"Dilithium":         "ML-DSA-65",
		"ML-DSA-87":         "ML-DSA-87",
		"x25519mlkem768":    "X25519MLKEM768",
		"SecP256r1MLKEM768": "SecP256r1MLKEM768",
	}
	for in, want := range cases {
		if got := normalizeAlgorithm(in); got != want {
			t.Errorf("normalizeAlgorithm(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHarness_NginxReadyForHybrid(t *testing.T) {
	rep := RunNegotiationHarness([]string{"X25519MLKEM768", "ML-DSA-65"})
	got := adapterResult(t, rep, "nginx")
	if got.Readiness != ReadinessReady {
		t.Fatalf("nginx readiness = %q, want ready (matched=%v missing=%v)", got.Readiness, got.MatchedTargets, got.MissingTargets)
	}
	if !got.CanNegotiate || !got.CanRollback {
		t.Errorf("nginx should negotiate and rollback")
	}
}

func TestHarness_PureMLKEMSatisfiedByHybrid(t *testing.T) {
	// A pure ML-KEM-768 requirement should be covered by nginx's hybrid group.
	rep := RunNegotiationHarness([]string{"ML-KEM-768"})
	got := adapterResult(t, rep, "nginx")
	if got.Readiness != ReadinessReady {
		t.Fatalf("nginx should field pure ML-KEM-768 via hybrid group; readiness=%q missing=%v", got.Readiness, got.MissingTargets)
	}
}

func TestHarness_SchannelUnsupported(t *testing.T) {
	rep := RunNegotiationHarness([]string{"X25519MLKEM768"})
	got := adapterResult(t, rep, "windows-schannel-policy")
	if got.Readiness != ReadinessUnsupported {
		t.Fatalf("schannel readiness = %q, want unsupported", got.Readiness)
	}
	if got.CanNegotiate {
		t.Error("schannel policy must not be marked as negotiating PQC groups")
	}
	// Even when unsupported for negotiation, rollback (registry) is reversible.
	if !got.CanRollback {
		t.Error("schannel policy migration should be reversible")
	}
}

func TestHarness_SSHHybridKEX(t *testing.T) {
	rep := RunNegotiationHarness([]string{"ML-KEM-768"})
	got := adapterResult(t, rep, "ssh")
	if got.Readiness != ReadinessReady {
		t.Fatalf("ssh should field ML-KEM-768 via mlkem768x25519; readiness=%q", got.Readiness)
	}
}

func TestHarness_GradeAndCounts(t *testing.T) {
	rep := RunNegotiationHarness([]string{"X25519MLKEM768"})
	total := rep.ReadyCount + rep.PartialCount + rep.UnsupportedCount
	if total != len(BuiltinAdapters()) {
		t.Fatalf("counts (%d) don't sum to adapter total (%d)", total, len(BuiltinAdapters()))
	}
	if rep.OverallGrade == "" {
		t.Error("expected a grade")
	}
	if rep.Method == "" {
		t.Error("report must document its method (offline capability evaluation)")
	}
}

func TestHarness_EmptyTargets(t *testing.T) {
	rep := RunNegotiationHarness(nil)
	if rep.ReadyCount != 0 {
		t.Errorf("no targets → no adapter should be ready, got %d", rep.ReadyCount)
	}
}

func TestEstimateTTSADays_HardcodingLengthens(t *testing.T) {
	neg := RunNegotiationHarness([]string{"X25519MLKEM768"})
	agile := EstimateTTSADays(Scorecard{HardcodeIndex: 0.0, BlastRadiusScore: 0.0}, neg)
	hardcoded := EstimateTTSADays(Scorecard{HardcodeIndex: 0.9, BlastRadiusScore: 0.8}, neg)
	if hardcoded <= agile {
		t.Fatalf("hardcoded posture TTSA (%.1f) should exceed agile posture (%.1f)", hardcoded, agile)
	}
	if agile < 1.0 {
		t.Errorf("TTSA estimate should never be below 1 day, got %.2f", agile)
	}
}

func adapterResult(t *testing.T, rep NegotiationReport, name string) AdapterNegotiationResult {
	t.Helper()
	for _, a := range rep.Adapters {
		if a.Adapter == name {
			return a
		}
	}
	t.Fatalf("adapter %q not found in report", name)
	return AdapterNegotiationResult{}
}
