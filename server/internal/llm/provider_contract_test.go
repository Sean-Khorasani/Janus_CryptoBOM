package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/janus-cbom/janus/server/internal/config"
	"github.com/janus-cbom/janus/server/internal/store"
)

// mockProvider spins up an OpenAI-compatible /chat/completions endpoint whose
// behaviour is driven by the handler the test supplies. The returned Service is
// pointed at it with a dummy API key so callLLMForVerdict / callLLMForRemediation
// exercise the real request/parse path without a live provider (LLM-019). The
// same harness backs the LLM-011 generation tests.
func mockProvider(t *testing.T, mode CapabilityMode, handler http.HandlerFunc) (*Service, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	const keyEnv = "JANUS_TEST_LLM_KEY"
	t.Setenv(keyEnv, "test-key")

	cfg := config.Config{LLM: config.LLMConfig{
		BaseURL:          srv.URL,
		APIKeyEnv:        keyEnv,
		ModelAnalysis:    "gpt-4o-mini",
		ModelRemediation: "gpt-4o",
		TimeoutSeconds:   5,
		CapabilityMode:   string(mode),
	}}
	return NewService(nil, cfg), srv
}

// chatCompletion writes an OpenAI-compatible envelope wrapping the given assistant content.
func chatCompletion(w http.ResponseWriter, content string) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"model": "gpt-4o-mini",
		"choices": []map[string]any{
			{"message": map[string]string{"content": content}},
		},
		"usage": map[string]int{"prompt_tokens": 120, "completion_tokens": 40},
	})
}

func TestProviderContract_ValidVerdict(t *testing.T) {
	svc, _ := mockProvider(t, ModeAnalysisOnly, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("missing/incorrect auth header: %q", got)
		}
		chatCompletion(w, `{"verdict":"confirmed","adjusted_severity":null,"confidence":0.9,"reasoning":"weak cipher","evidence_citations":["ev-1"],"abstention_reason":null}`)
	})

	job := &store.LLMAnalysisJob{JobID: "j1", FindingID: "f1"}
	verdict, prov, err := svc.callLLMForVerdict(context.Background(), job, []byte(`{"finding_id":"f1"}`), "false-positive-triage")
	if err != nil {
		t.Fatalf("callLLMForVerdict: %v", err)
	}
	if verdict.Verdict != VerdictConfirmed || verdict.Confidence != 0.9 {
		t.Fatalf("unexpected verdict: %+v", verdict)
	}
	if prov.TokensIn != 120 || prov.TokensOut != 40 {
		t.Fatalf("provenance token counts not captured: %+v", prov)
	}
	if prov.InputHash == "" || prov.OutputHash == "" {
		t.Fatalf("provenance hashes must be populated")
	}
}

func TestProviderContract_ProviderError(t *testing.T) {
	svc, _ := mockProvider(t, ModeAnalysisOnly, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":"upstream boom"}`)
	})
	job := &store.LLMAnalysisJob{JobID: "j1", FindingID: "f1"}
	_, _, err := svc.callLLMForVerdict(context.Background(), job, []byte(`{}`), "x")
	if err == nil {
		t.Fatal("expected error on HTTP 500")
	}
}

func TestProviderContract_MalformedContentAbstains(t *testing.T) {
	// Invariant 1.3: an unparseable assistant payload must degrade to abstain, not crash.
	svc, _ := mockProvider(t, ModeAnalysisOnly, func(w http.ResponseWriter, r *http.Request) {
		chatCompletion(w, "this is not json at all")
	})
	job := &store.LLMAnalysisJob{JobID: "j1", FindingID: "f1"}
	verdict, _, err := svc.callLLMForVerdict(context.Background(), job, []byte(`{}`), "x")
	if err != nil {
		t.Fatalf("malformed content should not error at the call layer: %v", err)
	}
	if verdict.Verdict != VerdictAbstain {
		t.Fatalf("expected abstain on malformed content, got %q", verdict.Verdict)
	}
	if verdict.AbstentionReason == "" {
		t.Fatal("abstain verdict must carry a reason")
	}
}

func TestProviderContract_CodeFenceStripped(t *testing.T) {
	svc, _ := mockProvider(t, ModeAnalysisOnly, func(w http.ResponseWriter, r *http.Request) {
		chatCompletion(w, "```json\n{\"verdict\":\"abstain\",\"confidence\":0.0,\"abstention_reason\":\"insufficient evidence\",\"evidence_citations\":[]}\n```")
	})
	job := &store.LLMAnalysisJob{JobID: "j1", FindingID: "f1"}
	verdict, _, err := svc.callLLMForVerdict(context.Background(), job, []byte(`{}`), "x")
	if err != nil {
		t.Fatalf("callLLMForVerdict: %v", err)
	}
	if verdict.Verdict != VerdictAbstain {
		t.Fatalf("fenced JSON not parsed, got %q", verdict.Verdict)
	}
}

func TestRateLimiter(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	rl := newRateLimiter(2, time.Minute)
	rl.now = func() time.Time { return base }

	if !rl.allow() || !rl.allow() {
		t.Fatal("first two requests within the window must be allowed")
	}
	if rl.allow() {
		t.Fatal("third request within the window must be denied")
	}
	// Advance past the window: the budget resets.
	rl.now = func() time.Time { return base.Add(61 * time.Second) }
	if !rl.allow() {
		t.Fatal("request after the window must be allowed")
	}
}

func TestRateLimiterDisabled(t *testing.T) {
	rl := newRateLimiter(0, time.Minute) // 0 == unlimited
	for i := 0; i < 100; i++ {
		if !rl.allow() {
			t.Fatal("limit<=0 must never deny")
		}
	}
	var nilRL *rateLimiter
	if !nilRL.allow() {
		t.Fatal("nil limiter must allow")
	}
}

func TestMaxTokens(t *testing.T) {
	if got := maxTokens(0); got != defaultMaxTokens {
		t.Fatalf("0 should fall back to default %d, got %d", defaultMaxTokens, got)
	}
	if got := maxTokens(256); got != 256 {
		t.Fatalf("configured value should win, got %d", got)
	}
}
