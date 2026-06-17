package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/janus-cbom/janus/server/internal/config"
	"github.com/janus-cbom/janus/server/internal/llm"
	"github.com/janus-cbom/janus/server/internal/orchestrator"
	"github.com/janus-cbom/janus/server/internal/pb"
	"github.com/janus-cbom/janus/server/internal/policy"
	"github.com/janus-cbom/janus/server/internal/store"
	"github.com/janus-cbom/janus/server/internal/ws"
)

// The test-connection model-compatibility check (LLM-004) flags a configured model that
// the provider's catalog does not list, without failing the reachability test.
func TestLLMTestConnectionModelCompat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]string{{"id": "gpt-4o-mini"}}, // analysis present, remediation absent
		})
	}))
	defer srv.Close()
	t.Setenv("JANUS_TEST_LLM_KEY", "k")

	api := &API{cfg: config.Config{LLM: config.LLMConfig{
		BaseURL:          srv.URL,
		APIKeyEnv:        "JANUS_TEST_LLM_KEY",
		ModelAnalysis:    "gpt-4o-mini",
		ModelRemediation: "gpt-4o",
	}}}
	rr := httptest.NewRecorder()
	api.llmTestConnection(rr, httptest.NewRequest(http.MethodPost, "/api/llm/test-connection", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var res struct {
		OK                        bool  `json:"ok"`
		ModelAnalysisAvailable    *bool `json:"model_analysis_available"`
		ModelRemediationAvailable *bool `json:"model_remediation_available"`
		Warning                   string
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !res.OK {
		t.Fatal("reachable provider must report ok=true even with a model mismatch")
	}
	if res.ModelAnalysisAvailable == nil || !*res.ModelAnalysisAvailable {
		t.Error("analysis model should be reported available")
	}
	if res.ModelRemediationAvailable == nil || *res.ModelRemediationAvailable {
		t.Error("remediation model should be reported unavailable")
	}
	if res.Warning == "" {
		t.Error("a missing configured model must surface a warning")
	}
}

type suggestionMockStore struct {
	store.Store
	job        *store.LLMAnalysisJob
	sug        *store.LLMSuggestion
	findings   []store.Finding
	commands   []*pb.MigrationCommand
	auditCount int
}

func (m *suggestionMockStore) GetAnalysisJob(_ context.Context, _ string) (*store.LLMAnalysisJob, error) {
	return m.job, nil
}
func (m *suggestionMockStore) GetSuggestionByJob(_ context.Context, _ string) (*store.LLMSuggestion, error) {
	return m.sug, nil
}
func (m *suggestionMockStore) GetSuggestionByFinding(_ context.Context, _ string) (*store.LLMSuggestion, error) {
	return m.sug, nil
}
func (m *suggestionMockStore) GetSuggestionByID(_ context.Context, _ string) (*store.LLMSuggestion, error) {
	if m.sug == nil {
		return nil, store.ErrSuggestionNotFound
	}
	return m.sug, nil
}
func (m *suggestionMockStore) Findings(_ context.Context, _ int, _ string) ([]store.Finding, error) {
	return m.findings, nil
}
func (m *suggestionMockStore) GetLatestConfigHash(_ context.Context, _, _ string) (string, error) {
	return "deadbeef", nil
}
func (m *suggestionMockStore) InsertMigrationCommand(_ context.Context, c *pb.MigrationCommand) error {
	m.commands = append(m.commands, c)
	return nil
}
func (m *suggestionMockStore) VerifyAuditChain(_ context.Context) (*store.AuditChainResult, error) {
	return &store.AuditChainResult{Valid: true}, nil
}
func (m *suggestionMockStore) GetAgentCredential(_ context.Context, _ string) (*store.AgentCredential, error) {
	return nil, nil
}
func (m *suggestionMockStore) UpsertAgentCredential(_ context.Context, _ *store.AgentCredential) error {
	return nil
}
func (m *suggestionMockStore) SetAgentCredentialStatus(_ context.Context, _, _, _ string) error {
	return nil
}
func (m *suggestionMockStore) ListAgentCredentials(_ context.Context) ([]store.AgentCredential, error) {
	return nil, nil
}
func (m *suggestionMockStore) TouchAgentCredential(_ context.Context, _ string) error { return nil }
func (m *suggestionMockStore) CreateComplianceException(_ context.Context, _ *store.ComplianceException) error {
	return nil
}
func (m *suggestionMockStore) ListComplianceExceptions(_ context.Context) ([]store.ComplianceException, error) {
	return nil, nil
}
func (m *suggestionMockStore) RevokeComplianceException(_ context.Context, _ string) error {
	return nil
}
func (m *suggestionMockStore) CreateTenant(_ context.Context, _ *store.Tenant) error { return nil }
func (m *suggestionMockStore) ListTenants(_ context.Context) ([]store.Tenant, error) {
	return nil, nil
}
func (m *suggestionMockStore) InsertAuditLog(_ context.Context, _ *store.AuditLog) error {
	m.auditCount++
	return nil
}

// A completed remediation job's detail must carry the suggestion, not a verdict.
func TestLLMJobDetailAttachesSuggestion(t *testing.T) {
	mock := &suggestionMockStore{
		job: &store.LLMAnalysisJob{JobID: "j1", FindingID: "f1", JobType: llm.JobTypeRemediationSuggestion, Status: llm.JobStatusCompleted},
		sug: &store.LLMSuggestion{SuggestionID: "s1", JobID: "j1", FindingID: "f1", RecommendationType: "config_change", ValidationStatus: "passed", HumanApprovalRequired: true},
	}
	api := &API{store: mock}
	req := httptest.NewRequest(http.MethodGet, "/api/llm/jobs/j1", nil)
	rr := httptest.NewRecorder()
	api.llmJobs(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := resp["suggestion"]; !ok {
		t.Fatalf("remediation job detail must include a suggestion; body=%s", rr.Body.String())
	}
	if _, ok := resp["verdict"]; ok {
		t.Fatal("remediation job detail must not include a verdict")
	}
}

func TestLLMSuggestionGet(t *testing.T) {
	mock := &suggestionMockStore{
		sug: &store.LLMSuggestion{SuggestionID: "s1", FindingID: "f1", RecommendationType: "dependency_upgrade", ValidationStatus: "passed", HumanApprovalRequired: true},
	}
	api := &API{store: mock}
	req := httptest.NewRequest(http.MethodGet, "/api/llm/suggestions/f1", nil)
	rr := httptest.NewRecorder()
	api.llmSuggestion(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var got store.LLMSuggestion
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.SuggestionID != "s1" || !got.HumanApprovalRequired {
		t.Fatalf("unexpected suggestion: %+v", got)
	}
}

// Review without operator/admin role must be forbidden before any store access.
func TestReviewSuggestionGuards(t *testing.T) {
	api := &API{}
	r := httptest.NewRequest(http.MethodPost, "/api/llm/suggestions/s1/review", nil)
	ctx := context.WithValue(r.Context(), RoleContextKey, "viewer")
	rr := httptest.NewRecorder()
	api.reviewSuggestion(rr, r.WithContext(ctx), "s1")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("viewer must be forbidden, got %d", rr.Code)
	}
}

// applyTestAPI wires the real (cheap) orchestrator/engine/ws so the enqueue path runs end
// to end against the mock store.
func applyTestAPI(mock *suggestionMockStore) *API {
	return &API{
		store:  mock,
		orch:   orchestrator.New([]byte("0123456789abcdef0123456789abcdef")),
		engine: policy.NewEngine(policy.Profile{Version: "t", PreferredKEM: "ML-KEM-1024", PreferredSignature: "ML-DSA-87"}),
		wsHub:  ws.New(),
	}
}

func approvedConfigSuggestion() *store.LLMSuggestion {
	return &store.LLMSuggestion{
		SuggestionID:          "s1",
		FindingID:             "f1",
		RecommendationType:    "config_change",
		ValidationStatus:      "passed",
		HumanApprovalRequired: true,
		ReviewDecision:        "approved",
		CandidatePatch:        "--- a/etc/nginx/nginx.conf\n+++ b/etc/nginx/nginx.conf\n@@ -1 +1 @@\n-ssl_protocols TLSv1.2;\n+ssl_protocols TLSv1.3;\n",
	}
}

func applyReq(api *API, role string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/llm/suggestions/s1/apply", strings.NewReader(`{"dry_run":true}`))
	ctx := context.WithValue(r.Context(), RoleContextKey, role)
	ctx = context.WithValue(ctx, UserContextKey, "op1")
	rr := httptest.NewRecorder()
	api.applySuggestion(rr, r.WithContext(ctx), "s1")
	return rr
}

func TestApplySuggestion_Success(t *testing.T) {
	mock := &suggestionMockStore{
		sug:      approvedConfigSuggestion(),
		findings: []store.Finding{{FindingID: "f1", HostUUID: "h1", AssetRef: "etc/nginx/nginx.conf:10"}},
	}
	api := applyTestAPI(mock)
	rr := applyReq(api, "operator")
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if len(mock.commands) != 1 {
		t.Fatalf("expected 1 enqueued command, got %d", len(mock.commands))
	}
	cmd := mock.commands[0]
	if cmd.HostUuid != "h1" || !cmd.DryRun || len(cmd.SignedDirective) == 0 {
		t.Fatalf("command not built correctly: %+v", cmd)
	}
	if mock.auditCount == 0 {
		t.Error("apply must be audited")
	}
}

func TestApplySuggestion_Refusals(t *testing.T) {
	t.Run("viewer forbidden", func(t *testing.T) {
		api := applyTestAPI(&suggestionMockStore{sug: approvedConfigSuggestion()})
		if rr := applyReq(api, "viewer"); rr.Code != http.StatusForbidden {
			t.Fatalf("got %d", rr.Code)
		}
	})
	t.Run("not approved", func(t *testing.T) {
		s := approvedConfigSuggestion()
		s.ReviewDecision = ""
		api := applyTestAPI(&suggestionMockStore{sug: s})
		if rr := applyReq(api, "operator"); rr.Code != http.StatusConflict {
			t.Fatalf("got %d", rr.Code)
		}
	})
	t.Run("validation not passed", func(t *testing.T) {
		s := approvedConfigSuggestion()
		s.ValidationStatus = "failed"
		s.CandidatePatch = ""
		api := applyTestAPI(&suggestionMockStore{sug: s})
		if rr := applyReq(api, "operator"); rr.Code != http.StatusUnprocessableEntity {
			t.Fatalf("got %d", rr.Code)
		}
	})
	t.Run("source-file patch rejected by allowlist", func(t *testing.T) {
		s := approvedConfigSuggestion()
		s.CandidatePatch = "--- a/src/crypto.go\n+++ b/src/crypto.go\n@@ -1 +1 @@\n-md5\n+sha256\n"
		mock := &suggestionMockStore{sug: s}
		api := applyTestAPI(mock)
		rr := applyReq(api, "operator")
		if rr.Code != http.StatusUnprocessableEntity {
			t.Fatalf("got %d body=%s", rr.Code, rr.Body.String())
		}
		if len(mock.commands) != 0 {
			t.Error("a non-allowlisted patch must NOT enqueue a command")
		}
	})
}
