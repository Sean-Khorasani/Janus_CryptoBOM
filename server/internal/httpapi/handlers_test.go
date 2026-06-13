package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/janus-cbom/janus/server/internal/config"
	"github.com/janus-cbom/janus/server/internal/policy"
	"github.com/janus-cbom/janus/server/internal/store"
)

var errDBDown = errors.New("connection refused")

// ---------------------------------------------------------------------------
// Minimal mock store for handler tests
// ---------------------------------------------------------------------------

type handlerMockStore struct {
	store.Store // embed nil — panics on any unconfigured method
	findings   []store.Finding
	components []store.Component
	events     []store.FindingLifecycleEvent
	certHealth *store.CertHealth
	pingErr    error
}

func (m *handlerMockStore) Findings(_ context.Context, _ int) ([]store.Finding, error) {
	return m.findings, nil
}
func (m *handlerMockStore) Components(_ context.Context, _ int) ([]store.Component, error) {
	return m.components, nil
}
func (m *handlerMockStore) ListLifecycleEvents(_ context.Context, findingID string) ([]store.FindingLifecycleEvent, error) {
	var out []store.FindingLifecycleEvent
	for _, e := range m.events {
		if e.FindingID == findingID {
			out = append(out, e)
		}
	}
	return out, nil
}
func (m *handlerMockStore) GetCertHealth(_ context.Context) (*store.CertHealth, error) {
	if m.certHealth != nil {
		return m.certHealth, nil
	}
	return &store.CertHealth{}, nil
}
func (m *handlerMockStore) Ping(_ context.Context) error {
	return m.pingErr
}

func newTestAPI(mock *handlerMockStore) *API {
	return &API{store: mock}
}

// ---------------------------------------------------------------------------
// complianceRules tests
// ---------------------------------------------------------------------------

func TestComplianceRules(t *testing.T) {
	api := newTestAPI(&handlerMockStore{})
	req := httptest.NewRequest(http.MethodGet, "/api/policy/rules", nil)
	rr := httptest.NewRecorder()
	api.complianceRules(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var pack policy.ControlPack
	if err := json.NewDecoder(rr.Body).Decode(&pack); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(pack.Rules) == 0 {
		t.Error("expected at least one rule in pack")
	}
}

func TestComplianceRulesMethodNotAllowed(t *testing.T) {
	api := newTestAPI(&handlerMockStore{})
	req := httptest.NewRequest(http.MethodPost, "/api/policy/rules", nil)
	rr := httptest.NewRecorder()
	api.complianceRules(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

func TestComplianceRuleByIDKnown(t *testing.T) {
	api := newTestAPI(&handlerMockStore{})
	req := httptest.NewRequest(http.MethodGet, "/api/policy/rules/JANUS-PQC-001", nil)
	req.URL.Path = "/api/policy/rules/JANUS-PQC-001"
	rr := httptest.NewRecorder()
	api.complianceRuleByID(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var rule policy.ControlRule
	if err := json.NewDecoder(rr.Body).Decode(&rule); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rule.RuleID != "JANUS-PQC-001" {
		t.Errorf("rule_id = %q, want JANUS-PQC-001", rule.RuleID)
	}
}

func TestComplianceRuleByIDUnknown(t *testing.T) {
	api := newTestAPI(&handlerMockStore{})
	req := httptest.NewRequest(http.MethodGet, "/api/policy/rules/JANUS-DOES-NOT-EXIST", nil)
	req.URL.Path = "/api/policy/rules/JANUS-DOES-NOT-EXIST"
	rr := httptest.NewRecorder()
	api.complianceRuleByID(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// findingTimeline tests
// ---------------------------------------------------------------------------

func TestFindingTimeline(t *testing.T) {
	now := time.Now()
	mock := &handlerMockStore{
		events: []store.FindingLifecycleEvent{
			{EventID: "e1", FindingID: "f123", HostUUID: "h1", EventType: "status_change",
				FromStatus: "open", ToStatus: "accepted_risk", Actor: "admin", OccurredAt: now},
		},
	}
	api := newTestAPI(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/findings/f123/timeline", nil)
	req.URL.Path = "/api/findings/f123/timeline"
	rr := httptest.NewRecorder()
	api.findingTimeline(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var events []store.FindingLifecycleEvent
	if err := json.NewDecoder(rr.Body).Decode(&events); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("got %d events, want 1", len(events))
	}
	if events[0].EventID != "e1" {
		t.Errorf("event_id = %q, want e1", events[0].EventID)
	}
}

func TestFindingTimelineEmptyReturnsArray(t *testing.T) {
	api := newTestAPI(&handlerMockStore{})
	req := httptest.NewRequest(http.MethodGet, "/api/findings/unknown-id/timeline", nil)
	req.URL.Path = "/api/findings/unknown-id/timeline"
	rr := httptest.NewRecorder()
	api.findingTimeline(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	// Must return empty JSON array, not null
	body := strings.TrimSpace(rr.Body.String())
	if body == "null" || body == "" {
		t.Error("empty timeline should return [] not null")
	}
	var events []store.FindingLifecycleEvent
	if err := json.Unmarshal([]byte(body), &events); err != nil {
		t.Fatalf("json parse error: %v (body: %s)", err, body)
	}
	// events may be empty slice — that's fine
}

func TestFindingTimelineNonTimelinePath(t *testing.T) {
	api := newTestAPI(&handlerMockStore{})
	req := httptest.NewRequest(http.MethodGet, "/api/findings/f123/status", nil)
	req.URL.Path = "/api/findings/f123/status"
	rr := httptest.NewRecorder()
	api.findingTimeline(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("non-timeline path should 404, got %d", rr.Code)
	}
}

func TestFindingTimelineMethodNotAllowed(t *testing.T) {
	api := newTestAPI(&handlerMockStore{})
	req := httptest.NewRequest(http.MethodPut, "/api/findings/f1/timeline", nil)
	req.URL.Path = "/api/findings/f1/timeline"
	rr := httptest.NewRecorder()
	api.findingTimeline(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// exportCycloneDX tests
// ---------------------------------------------------------------------------

func TestExportCycloneDXIncludesCryptoProperties(t *testing.T) {
	mock := &handlerMockStore{
		components: []store.Component{
			{BomRef: "comp-1", Name: "openssl", Version: "3.0", ComponentType: "library",
				FilePath: "src/crypto.c", Algorithms: []string{"AES-256-GCM", "SHA-256"}},
			{BomRef: "comp-2", Name: "libpqcrypto", Version: "0.1", ComponentType: "library",
				Algorithms: []string{"ML-KEM-768"}},
		},
	}
	api := newTestAPI(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/export/cyclonedx", nil)
	rr := httptest.NewRecorder()
	api.exportCycloneDX(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var result map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v, want CycloneDX", result["bomFormat"])
	}
	if _, ok := result["serialNumber"]; !ok {
		t.Error("serialNumber must be present")
	}
	comps, ok := result["components"].([]any)
	if !ok || len(comps) != 2 {
		t.Fatalf("components count = %d, want 2", len(comps))
	}
	// First component (AES-256-GCM) should have cryptoProperties
	first := comps[0].(map[string]any)
	if _, hasCrypto := first["cryptoProperties"]; !hasCrypto {
		t.Error("first component should have cryptoProperties (has AES-256-GCM)")
	}
	// Second component (ML-KEM-768) should have cryptoProperties with kem primitive
	second := comps[1].(map[string]any)
	cryptoProps, ok := second["cryptoProperties"].(map[string]any)
	if !ok {
		t.Fatal("ML-KEM-768 component missing cryptoProperties")
	}
	algProps, ok := cryptoProps["algorithmProperties"].(map[string]any)
	if !ok {
		t.Fatal("algorithmProperties missing")
	}
	if algProps["primitive"] != "kem" {
		t.Errorf("ML-KEM-768 primitive = %v, want kem", algProps["primitive"])
	}
	if algProps["nistQuantumSecurityLevel"].(float64) != 3 {
		t.Errorf("ML-KEM-768 NIST level = %v, want 3", algProps["nistQuantumSecurityLevel"])
	}
}

func TestExportCycloneDXMethodNotAllowed(t *testing.T) {
	api := newTestAPI(&handlerMockStore{})
	req := httptest.NewRequest(http.MethodPost, "/api/export/cyclonedx", nil)
	rr := httptest.NewRecorder()
	api.exportCycloneDX(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// exportSARIF tests
// ---------------------------------------------------------------------------

func TestExportSARIFUsesRealVersion(t *testing.T) {
	mock := &handlerMockStore{
		findings: []store.Finding{
			{FindingID: "f1", PolicyRuleID: "JANUS-PQC-001", Severity: 4,
				Title: "RSA-2048 detected", AssetRef: "src/main.go:42", Algorithm: "RSA-2048", Confidence: 0.88},
		},
	}
	api := newTestAPI(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/export/sarif", nil)
	rr := httptest.NewRecorder()
	api.exportSARIF(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var sarif map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&sarif); err != nil {
		t.Fatalf("decode: %v", err)
	}
	runs := sarif["runs"].([]any)
	tool := runs[0].(map[string]any)["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)
	ver := driver["version"].(string)
	if strings.Contains(ver, "0.1.0") {
		t.Errorf("SARIF version %q should not be hardcoded 0.1.0", ver)
	}
	// Verify source location region is parsed
	results := runs[0].(map[string]any)["results"].([]any)
	if len(results) == 0 {
		t.Fatal("no SARIF results")
	}
	firstResult := results[0].(map[string]any)
	locations := firstResult["locations"].([]any)
	physLoc := locations[0].(map[string]any)["physicalLocation"].(map[string]any)
	if _, hasRegion := physLoc["region"]; !hasRegion {
		t.Error("SARIF result for src/main.go:42 should include region with startLine")
	}
}

func TestExportSARIFMethodNotAllowed(t *testing.T) {
	api := newTestAPI(&handlerMockStore{})
	req := httptest.NewRequest(http.MethodPost, "/api/export/sarif", nil)
	rr := httptest.NewRecorder()
	api.exportSARIF(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

func TestExportSARIFEmptyFindings(t *testing.T) {
	api := newTestAPI(&handlerMockStore{})
	req := httptest.NewRequest(http.MethodGet, "/api/export/sarif", nil)
	rr := httptest.NewRecorder()
	api.exportSARIF(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// GET /api/admin/release-check tests
// ---------------------------------------------------------------------------

// TestReleaseCheckRequiresAdmin verifies that insufficient role returns 403.
// We test via the RequireRole middleware wrapper, not by calling the handler directly.
func TestReleaseCheckRequiresAdmin(t *testing.T) {
	api := newTestAPI(&handlerMockStore{})
	// Wrap the handler exactly as server.go does.
	wrapped := RequireRole([]string{"admin"})(http.HandlerFunc(api.releaseCheck))

	// No role in context → 403.
	t.Run("no_role", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/admin/release-check", nil)
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403 (no role)", rr.Code)
		}
	})

	// Viewer role → 403.
	t.Run("viewer_role", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/admin/release-check", nil)
		ctx := context.WithValue(req.Context(), RoleContextKey, "viewer")
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403 (viewer role)", rr.Code)
		}
	})

	// Operator role → 403 (admin only).
	t.Run("operator_role", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/admin/release-check", nil)
		ctx := context.WithValue(req.Context(), RoleContextKey, "operator")
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403 (operator role)", rr.Code)
		}
	})
}

// TestReleaseCheckPassesWithConfig verifies that an admin with a configured
// signing key gets a 200 response with release_ready determined only by
// hard failures (warn-level checks must not block release_ready).
func TestReleaseCheckPassesWithConfig(t *testing.T) {
	mock := &handlerMockStore{}
	api := newTestAPI(mock)
	api.cfg = config.Config{
		CommandSigningKey: []byte("aaaabbbbccccddddeeeeffffgggghhhh"), // 32 bytes
	}

	req := httptest.NewRequest(http.MethodGet, "/api/admin/release-check", nil)
	// Inject admin role directly into the handler context (bypasses middleware).
	ctx := context.WithValue(req.Context(), RoleContextKey, "admin")
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()
	api.releaseCheck(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}

	var result map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// With valid config and no DB error, release_ready must be true.
	releaseReady, ok := result["release_ready"].(bool)
	if !ok {
		t.Fatal("release_ready field missing or not bool")
	}
	if !releaseReady {
		t.Errorf("release_ready = false, want true (db pass, signing_key pass; policy warn must not block)")
	}

	// Checks array must be present and non-empty.
	checks, ok := result["checks"].([]any)
	if !ok || len(checks) == 0 {
		t.Fatal("checks field missing or empty")
	}

	// Timestamp must be present.
	if _, ok := result["timestamp"]; !ok {
		t.Error("timestamp field missing")
	}
}

// TestReleaseCheckDBFailSetsNotReady verifies that a DB ping failure
// causes release_ready to be false.
func TestReleaseCheckDBFailSetsNotReady(t *testing.T) {
	mock := &handlerMockStore{pingErr: errDBDown}
	api := newTestAPI(mock)
	api.cfg = config.Config{
		CommandSigningKey: []byte("aaaabbbbccccddddeeeeffffgggghhhh"),
	}

	req := httptest.NewRequest(http.MethodGet, "/api/admin/release-check", nil)
	ctx := context.WithValue(req.Context(), RoleContextKey, "admin")
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()
	api.releaseCheck(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var result map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result["release_ready"].(bool) {
		t.Error("release_ready = true with DB failure, want false")
	}
}

// TestReleaseCheckMethodNotAllowed ensures non-GET is rejected.
func TestReleaseCheckMethodNotAllowed(t *testing.T) {
	api := newTestAPI(&handlerMockStore{})
	req := httptest.NewRequest(http.MethodPost, "/api/admin/release-check", nil)
	ctx := context.WithValue(req.Context(), RoleContextKey, "admin")
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()
	api.releaseCheck(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// hostFindings tests (WP-013)
// ---------------------------------------------------------------------------

func (m *handlerMockStore) FindingsByHost(_ context.Context, hostUUID string) ([]store.Finding, error) {
	var out []store.Finding
	for _, f := range m.findings {
		if f.HostUUID == hostUUID {
			out = append(out, f)
		}
	}
	return out, nil
}

func TestHostFindingsReturnsFiltered(t *testing.T) {
	mock := &handlerMockStore{
		findings: []store.Finding{
			{FindingID: "f1", HostUUID: "host-aaa", Severity: 5, Title: "RSA-1024 detected"},
			{FindingID: "f2", HostUUID: "host-bbb", Severity: 4, Title: "ECDSA-P256 detected"},
			{FindingID: "f3", HostUUID: "host-aaa", Severity: 3, Title: "AES-128 detected"},
		},
	}
	api := newTestAPI(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/hosts/host-aaa/findings", nil)
	req.URL.Path = "/api/hosts/host-aaa/findings"
	rr := httptest.NewRecorder()
	api.hostFindings(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var findings []store.Finding
	if err := json.NewDecoder(rr.Body).Decode(&findings); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(findings) != 2 {
		t.Errorf("got %d findings, want 2 (only host-aaa findings)", len(findings))
	}
	for _, f := range findings {
		if f.HostUUID != "host-aaa" {
			t.Errorf("finding %q has wrong host_uuid %q, want host-aaa", f.FindingID, f.HostUUID)
		}
	}
}

func TestHostFindingsEmptyReturnsArray(t *testing.T) {
	api := newTestAPI(&handlerMockStore{})
	req := httptest.NewRequest(http.MethodGet, "/api/hosts/no-such-host/findings", nil)
	req.URL.Path = "/api/hosts/no-such-host/findings"
	rr := httptest.NewRecorder()
	api.hostFindings(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := strings.TrimSpace(rr.Body.String())
	if body == "null" || body == "" {
		t.Error("empty host findings should return [] not null")
	}
	var findings []store.Finding
	if err := json.Unmarshal([]byte(body), &findings); err != nil {
		t.Fatalf("json parse error: %v (body: %s)", err, body)
	}
}

func TestHostFindingsMethodNotAllowed(t *testing.T) {
	api := newTestAPI(&handlerMockStore{})
	req := httptest.NewRequest(http.MethodPost, "/api/hosts/host-aaa/findings", nil)
	req.URL.Path = "/api/hosts/host-aaa/findings"
	rr := httptest.NewRecorder()
	api.hostFindings(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}
