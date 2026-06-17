package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/janus-cbom/janus/server/internal/hsm"
)

// Once an HSM backend is wired via SetHSM (HSM-01), the endpoints must be live — not the
// 501 "HSM not configured" that they returned when SetHSM was never called.
func TestHSMEndpointsLiveAfterSetHSM(t *testing.T) {
	api := &API{}
	api.SetHSM(hsm.NewSoftHSM2())

	// generate -> list -> sign -> verify round trip through the handlers.
	genBody := `{"algorithm":"ML-DSA-65"}`
	gw := httptest.NewRecorder()
	api.hsmGenerateKey(gw, httptest.NewRequest(http.MethodPost, "/api/hsm/keys", strings.NewReader(genBody)))
	if gw.Code != http.StatusCreated {
		t.Fatalf("generate: status %d body=%s", gw.Code, gw.Body.String())
	}
	var gen struct {
		KeyID string `json:"key_id"`
	}
	if err := json.Unmarshal(gw.Body.Bytes(), &gen); err != nil || gen.KeyID == "" {
		t.Fatalf("generate did not return a key_id: body=%s", gw.Body.String())
	}

	lw := httptest.NewRecorder()
	api.hsmListKeys(lw, httptest.NewRequest(http.MethodGet, "/api/hsm/keys", nil))
	if lw.Code != http.StatusOK {
		t.Fatalf("list keys: status %d (must not be 501 once wired)", lw.Code)
	}
}

func TestHSMUnconfiguredStill501(t *testing.T) {
	// Defensive: with no backend the handler must fail closed, not panic.
	api := &API{}
	w := httptest.NewRecorder()
	api.hsmListKeys(w, httptest.NewRequest(http.MethodGet, "/api/hsm/keys", nil))
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 when HSM unconfigured, got %d", w.Code)
	}
}
