package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/janus-cbom/janus/server/internal/store"
	"github.com/janus-cbom/janus/server/internal/ws"
)

// bulkMockStore records UpdateFindingStatus calls and can fail specific IDs.
type bulkMockStore struct {
	store.Store
	failIDs map[string]bool
	calls   []string
	audits  int
}

func (m *bulkMockStore) UpdateFindingStatus(_ context.Context, findingID, _, _ string) error {
	m.calls = append(m.calls, findingID)
	if m.failIDs[findingID] {
		return errDBDown
	}
	return nil
}
func (m *bulkMockStore) VerifyAuditChain(_ context.Context) (*store.AuditChainResult, error) {
	return &store.AuditChainResult{Valid: true}, nil
}
func (m *bulkMockStore) GetAgentCredential(_ context.Context, _ string) (*store.AgentCredential, error) {
	return nil, nil
}
func (m *bulkMockStore) UpsertAgentCredential(_ context.Context, _ *store.AgentCredential) error {
	return nil
}
func (m *bulkMockStore) SetAgentCredentialStatus(_ context.Context, _, _, _ string) error { return nil }
func (m *bulkMockStore) ListAgentCredentials(_ context.Context) ([]store.AgentCredential, error) {
	return nil, nil
}
func (m *bulkMockStore) TouchAgentCredential(_ context.Context, _ string) error { return nil }
func (m *bulkMockStore) CreateComplianceException(_ context.Context, _ *store.ComplianceException) error {
	return nil
}
func (m *bulkMockStore) ListComplianceExceptions(_ context.Context) ([]store.ComplianceException, error) {
	return nil, nil
}
func (m *bulkMockStore) RevokeComplianceException(_ context.Context, _ string) error { return nil }
func (m *bulkMockStore) CreateTenant(_ context.Context, _ *store.Tenant) error       { return nil }
func (m *bulkMockStore) ListTenants(_ context.Context) ([]store.Tenant, error)       { return nil, nil }
func (m *bulkMockStore) InsertAuditLog(_ context.Context, _ *store.AuditLog) error {
	m.audits++
	return nil
}

func bulkAPI(mock *bulkMockStore) *API {
	return &API{store: mock, wsHub: ws.New()}
}

func TestBulkUpdate_MixedSuccessAndFailure(t *testing.T) {
	mock := &bulkMockStore{failIDs: map[string]bool{"f2": true}}
	api := bulkAPI(mock)
	bodyJSON := `[{"finding_id":"f1","status":"accepted_risk"},{"finding_id":"f2","status":"remediated"},{"finding_id":"f3","status":"remediated"}]`
	req := httptest.NewRequest(http.MethodPost, "/api/findings/bulk-update", strings.NewReader(bodyJSON))
	req = req.WithContext(context.WithValue(req.Context(), UserContextKey, "alice"))
	rr := httptest.NewRecorder()
	api.bulkUpdateFindings(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var out struct {
		Updated int                `json:"updated"`
		Failed  int                `json:"failed"`
		Results []bulkUpdateResult `json:"results"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Updated != 2 || out.Failed != 1 {
		t.Fatalf("updated=%d failed=%d, want 2/1", out.Updated, out.Failed)
	}
	if len(out.Results) != 3 || out.Results[1].OK {
		t.Fatalf("expected f2 to fail: %+v", out.Results)
	}
	if mock.audits != 1 {
		t.Errorf("expected one audit log entry, got %d", mock.audits)
	}
}

func TestBulkUpdate_WrapperShapeAndActor(t *testing.T) {
	mock := &bulkMockStore{}
	api := bulkAPI(mock)
	body := `{"updates":[{"finding_id":"f1","status":"remediated"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/findings/bulk-update", strings.NewReader(body))
	// no UserContextKey → actor falls back to "operator"
	rr := httptest.NewRecorder()
	api.bulkUpdateFindings(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if len(mock.calls) != 1 || mock.calls[0] != "f1" {
		t.Fatalf("expected UpdateFindingStatus(f1), got %v", mock.calls)
	}
}

func TestBulkUpdate_RejectsOversizeAndEmpty(t *testing.T) {
	api := bulkAPI(&bulkMockStore{})

	// Empty.
	req := httptest.NewRequest(http.MethodPost, "/api/findings/bulk-update", strings.NewReader(`[]`))
	rr := httptest.NewRecorder()
	api.bulkUpdateFindings(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("empty batch status = %d, want 400", rr.Code)
	}

	// Oversize (> 100).
	var sb strings.Builder
	sb.WriteString("[")
	for i := 0; i < bulkUpdateMax+1; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"finding_id":"x","status":"remediated"}`)
	}
	sb.WriteString("]")
	req = httptest.NewRequest(http.MethodPost, "/api/findings/bulk-update", strings.NewReader(sb.String()))
	rr = httptest.NewRecorder()
	api.bulkUpdateFindings(rr, req)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("oversize batch status = %d, want 422", rr.Code)
	}
}
