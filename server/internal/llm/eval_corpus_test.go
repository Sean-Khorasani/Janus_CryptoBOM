package llm

import (
	"encoding/json"
	"os"
	"testing"
)

// corpusEntry is one labeled evidence package in testdata/fp_corpus.json (LLM-019).
type corpusEntry struct {
	Name      string         `json:"name"`
	Injection bool           `json:"injection"`
	Note      string         `json:"note"`
	Evidence  map[string]any `json:"evidence"`
}

func loadCorpus(t *testing.T) []corpusEntry {
	t.Helper()
	raw, err := os.ReadFile("testdata/fp_corpus.json")
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var entries []corpusEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("corpus is empty")
	}
	return entries
}

// TestCorpusWellFormed guards the corpus shape so eval runs never silently skip entries.
func TestCorpusWellFormed(t *testing.T) {
	for _, e := range loadCorpus(t) {
		if e.Name == "" {
			t.Error("corpus entry missing name")
		}
		if _, ok := e.Evidence["finding_id"]; !ok {
			t.Errorf("%s: evidence missing finding_id", e.Name)
		}
	}
}

// TestCorpusInjectionLabelsHold is the offline regression for the LLM-019 injection
// defense: every entry labeled injection=true must be flagged by DetectInjection on its
// serialized evidence, and every benign entry must be clean. This catches a defense that
// silently weakens as the pattern set or the corpus changes — independent of any live
// provider. (Live precision/recall over this corpus needs JANUS_LLM_BASE_URL and is run
// separately via scripts/janus-llm.sh analyze.)
func TestCorpusInjectionLabelsHold(t *testing.T) {
	for _, e := range loadCorpus(t) {
		ev, _ := json.Marshal(e.Evidence)
		hits := DetectInjection(string(ev))
		if e.Injection && len(hits) == 0 {
			t.Errorf("%s: expected injection markers but DetectInjection found none", e.Name)
		}
		if !e.Injection && len(hits) > 0 {
			t.Errorf("%s: benign entry falsely flagged as injection: %v", e.Name, hits)
		}
	}
}
