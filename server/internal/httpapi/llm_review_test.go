package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidReviewDecision(t *testing.T) {
	for _, d := range []string{"approved", "rejected"} {
		if !validReviewDecision(d) {
			t.Errorf("%q should be valid", d)
		}
	}
	for _, d := range []string{"", "maybe", "APPROVED", "approve", "reject"} {
		if validReviewDecision(d) {
			t.Errorf("%q should be invalid", d)
		}
	}
}

// The review action is operator/admin-only and validates the decision before any
// store access — both rejection paths return without touching the store (LLM-022).
func TestReviewVerdictGuards(t *testing.T) {
	api := &API{} // nil store is fine: these paths return before any store call
	call := func(role, body string) int {
		r := httptest.NewRequest(http.MethodPost, "/api/llm/verdicts/v123/review", strings.NewReader(body))
		ctx := context.WithValue(r.Context(), RoleContextKey, role)
		ctx = context.WithValue(ctx, UserContextKey, "tester")
		w := httptest.NewRecorder()
		api.reviewVerdict(w, r.WithContext(ctx), "v123")
		return w.Code
	}

	if code := call("viewer", `{"decision":"approved"}`); code != http.StatusForbidden {
		t.Fatalf("viewer must be forbidden: got %d", code)
	}
	if code := call("operator", `{"decision":"maybe"}`); code != http.StatusBadRequest {
		t.Fatalf("invalid decision must be 400: got %d", code)
	}
	if code := call("admin", `{"decision":"rejected"`); code != http.StatusBadRequest {
		t.Fatalf("malformed body must be 400: got %d", code)
	}
}
