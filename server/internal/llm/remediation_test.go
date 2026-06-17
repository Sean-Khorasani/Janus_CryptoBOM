package llm

import (
	"context"
	"net/http"
	"testing"

	"github.com/janus-cbom/janus/server/internal/store"
)

func TestValidatePatch(t *testing.T) {
	valid := "--- a/config/tls.conf\n+++ b/config/tls.conf\n@@ -1 +1 @@\n-MinProtocol=TLSv1.2\n+MinProtocol=TLSv1.3\n"
	cases := []struct {
		name    string
		patch   string
		wantErr bool
	}{
		{"empty is allowed", "", false},
		{"valid relative diff", valid, false},
		{"dev/null add", "--- /dev/null\n+++ b/new.conf\n@@ -0,0 +1 @@\n+x=1\n", false},
		{"absolute path", "--- a/x\n+++ /etc/passwd\n@@ -1 +1 @@\n-a\n+b\n", true},
		{"path traversal", "--- a/../../etc/shadow\n+++ b/../../etc/shadow\n@@ -1 +1 @@\n-a\n+b\n", true},
		{"home expansion", "--- a/x\n+++ ~/secrets\n@@ -1 +1 @@\n-a\n+b\n", true},
		{"no hunk header", "--- a/x\n+++ b/x\nsome prose without a hunk\n", true},
		{"nul byte", "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\x00\n+b\n", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidatePatch(c.patch)
			if (err != nil) != c.wantErr {
				t.Fatalf("ValidatePatch(%q) err=%v, wantErr=%v", c.name, err, c.wantErr)
			}
		})
	}
}

func TestValidatePatchOversize(t *testing.T) {
	big := "--- a/x\n+++ b/x\n@@ -1 +1 @@\n+"
	for len(big) <= maxPatchBytes {
		big += "AAAAAAAAAAAAAAAA"
	}
	if err := ValidatePatch(big); err == nil {
		t.Fatal("oversize patch must be rejected")
	}
}

// fakeRemediationStore implements just enough of store.Store for GenerateRemediation.
type fakeRemediationStore struct {
	store.Store
	job        *store.LLMAnalysisJob
	suggestion *store.LLMSuggestion
	prov       *store.LLMProvenance
}

func (f *fakeRemediationStore) GetAnalysisJob(_ context.Context, _ string) (*store.LLMAnalysisJob, error) {
	return f.job, nil
}
func (f *fakeRemediationStore) UpdateAnalysisJob(_ context.Context, j *store.LLMAnalysisJob) error {
	f.job = j
	return nil
}
func (f *fakeRemediationStore) RecordProvenance(_ context.Context, p *store.LLMProvenance) error {
	f.prov = p
	return nil
}
func (f *fakeRemediationStore) CreateSuggestion(_ context.Context, s *store.LLMSuggestion) error {
	f.suggestion = s
	return nil
}

func newRemediationFixture(t *testing.T, content string) (*Service, *fakeRemediationStore) {
	t.Helper()
	svc, _ := mockProvider(t, ModeSuggestRemediation, func(w http.ResponseWriter, r *http.Request) {
		chatCompletion(w, content)
	})
	fs := &fakeRemediationStore{job: &store.LLMAnalysisJob{JobID: "j1", FindingID: "f1", Status: JobStatusQueued}}
	svc.store = fs
	return svc, fs
}

func TestGenerateRemediation_ValidPatch(t *testing.T) {
	content := `{"recommendation_type":"config_change","target_algorithm":"TLS1.3","candidate_patch":"--- a/tls.conf\n+++ b/tls.conf\n@@ -1 +1 @@\n-TLSv1.2\n+TLSv1.3\n","assumptions":["server supports 1.3"],"compatibility_notes":"none","validation_required":["handshake test"],"confidence":0.8}`
	svc, fs := newRemediationFixture(t, content)

	s, err := svc.GenerateRemediation(context.Background(), "j1", []byte(`{"finding_id":"f1"}`))
	if err != nil {
		t.Fatalf("GenerateRemediation: %v", err)
	}
	if s.ValidationStatus != "passed" {
		t.Fatalf("expected validation passed, got %q (%s)", s.ValidationStatus, s.ValidationDetail)
	}
	if !s.HumanApprovalRequired {
		t.Fatal("human_approval_required must always be true")
	}
	if fs.suggestion == nil || fs.prov == nil {
		t.Fatal("suggestion and provenance must be persisted")
	}
	if fs.job.Status != JobStatusCompleted {
		t.Fatalf("job should be completed, got %q", fs.job.Status)
	}
}

func TestGenerateRemediation_UnsafePatchDropped(t *testing.T) {
	content := `{"recommendation_type":"config_change","target_algorithm":"TLS1.3","candidate_patch":"--- a/x\n+++ b/../../etc/shadow\n@@ -1 +1 @@\n-a\n+b\n","assumptions":[],"compatibility_notes":"","validation_required":[],"confidence":0.5}`
	svc, _ := newRemediationFixture(t, content)

	s, err := svc.GenerateRemediation(context.Background(), "j1", []byte(`{}`))
	if err != nil {
		t.Fatalf("GenerateRemediation: %v", err)
	}
	if s.ValidationStatus != "failed" {
		t.Fatalf("traversal patch must fail validation, got %q", s.ValidationStatus)
	}
	if s.CandidatePatch != "" {
		t.Fatal("a patch that fails the deterministic check must be dropped, not surfaced")
	}
	if s.ValidationDetail == "" {
		t.Fatal("failed validation must record a reason")
	}
}

func TestGenerateRemediation_AutonomousApply(t *testing.T) {
	// A high-confidence config_change suggestion with an allowlisted patch must trigger
	// the injected enqueuer when the governor is enabled; a disabled governor must not.
	content := `{"recommendation_type":"config_change","target_algorithm":"TLS1.3","candidate_patch":"--- a/etc/app.conf\n+++ b/etc/app.conf\n@@ -1 +1 @@\n-TLSv1.2\n+TLSv1.3\n","assumptions":[],"compatibility_notes":"","validation_required":[],"confidence":0.97}`

	run := func(enabled bool) (called bool, dryRun bool) {
		svc, _ := newRemediationFixture(t, content)
		cfg := enabledConfig()
		cfg.Enabled = enabled
		svc.EnableAutonomousRemediation(NewGovernor(cfg), func(_ context.Context, _ *store.LLMSuggestion, dr bool) error {
			called, dryRun = true, dr
			return nil
		})
		if _, err := svc.GenerateRemediation(context.Background(), "j1", []byte(`{}`)); err != nil {
			t.Fatalf("GenerateRemediation: %v", err)
		}
		return called, dryRun
	}

	if called, dryRun := run(true); !called || !dryRun {
		t.Fatalf("enabled governor must auto-apply in dry-run; called=%v dryRun=%v", called, dryRun)
	}
	if called, _ := run(false); called {
		t.Fatal("disabled governor must not auto-apply")
	}
}

func TestGenerateRemediation_ModeGate(t *testing.T) {
	// analysis_only must refuse remediation generation before any provider call.
	svc, _ := mockProvider(t, ModeAnalysisOnly, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("provider must not be called when mode forbids remediation")
	})
	svc.store = &fakeRemediationStore{job: &store.LLMAnalysisJob{JobID: "j1", FindingID: "f1"}}
	if _, err := svc.GenerateRemediation(context.Background(), "j1", []byte(`{}`)); err == nil {
		t.Fatal("expected mode-gate error in analysis_only mode")
	}
}
