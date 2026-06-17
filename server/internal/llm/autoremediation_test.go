package llm

import (
	"testing"
	"time"

	"github.com/janus-cbom/janus/server/internal/store"
)

func goodSuggestion() *store.LLMSuggestion {
	return &store.LLMSuggestion{
		SuggestionID:       "s1",
		RecommendationType: RecommendationConfigChange,
		ValidationStatus:   "passed",
		Confidence:         0.95,
		CandidatePatch:     "--- a/etc/app.conf\n+++ b/etc/app.conf\n@@ -1 +1 @@\n-a\n+b\n",
	}
}

func enabledConfig() GovernorConfig {
	return GovernorConfig{
		Enabled:       true,
		DryRunOnly:    true,
		MinConfidence: 0.9,
		AllowedTypes:  map[string]bool{RecommendationConfigChange: true},
		MaxPerHour:    3,
	}
}

func TestGovernorAllowsWhenAllControlsMet(t *testing.T) {
	g := NewGovernor(enabledConfig())
	allow, dryRun, reason := g.Authorize(goodSuggestion())
	if !allow {
		t.Fatalf("expected allow, denied: %s", reason)
	}
	if !dryRun {
		t.Fatal("DryRunOnly must force dry-run")
	}
}

func TestGovernorDisabledNeverAllows(t *testing.T) {
	cfg := enabledConfig()
	cfg.Enabled = false
	if allow, _, _ := NewGovernor(cfg).Authorize(goodSuggestion()); allow {
		t.Fatal("disabled governor must never allow")
	}
	// nil governor is also safe.
	var g *RemediationGovernor
	if allow, _, _ := g.Authorize(goodSuggestion()); allow {
		t.Fatal("nil governor must never allow")
	}
}

// Every single unmet control must deny — fail-closed.
func TestGovernorFailsClosedPerControl(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*store.LLMSuggestion)
	}{
		{"validation not passed", func(s *store.LLMSuggestion) { s.ValidationStatus = "failed" }},
		{"empty patch", func(s *store.LLMSuggestion) { s.CandidatePatch = "" }},
		{"type not allowlisted", func(s *store.LLMSuggestion) { s.RecommendationType = RecommendationAPIRefactor }},
		{"confidence below floor", func(s *store.LLMSuggestion) { s.Confidence = 0.5 }},
		{"source-file patch", func(s *store.LLMSuggestion) {
			s.CandidatePatch = "--- a/src/x.go\n+++ b/src/x.go\n@@ -1 +1 @@\n-a\n+b\n"
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := goodSuggestion()
			c.mutate(s)
			if allow, _, _ := NewGovernor(enabledConfig()).Authorize(s); allow {
				t.Fatalf("%s must deny", c.name)
			}
		})
	}
}

func TestGovernorBudgetExhaustionAndNoBurnOnRefusal(t *testing.T) {
	cfg := enabledConfig()
	cfg.MaxPerHour = 2
	g := NewGovernor(cfg)

	// A refused suggestion must NOT consume budget.
	bad := goodSuggestion()
	bad.Confidence = 0.1
	for i := 0; i < 5; i++ {
		if allow, _, _ := g.Authorize(bad); allow {
			t.Fatal("low-confidence suggestion must be denied")
		}
	}
	// Now the full budget of 2 is still available.
	if allow, _, _ := g.Authorize(goodSuggestion()); !allow {
		t.Fatal("first allowed call should pass")
	}
	if allow, _, _ := g.Authorize(goodSuggestion()); !allow {
		t.Fatal("second allowed call should pass")
	}
	if allow, _, reason := g.Authorize(goodSuggestion()); allow {
		t.Fatalf("third call must be budget-denied, got allow (reason=%q)", reason)
	}
}

func TestGovernorChangeWindow(t *testing.T) {
	cfg := enabledConfig()
	cfg.AllowedHours = []hourRange{{lo: 2, hi: 4}} // only 02:00–04:59 UTC
	g := NewGovernor(cfg)

	g.now = func() time.Time { return time.Date(2026, 6, 14, 3, 0, 0, 0, time.UTC) } // inside
	if allow, _, reason := g.Authorize(goodSuggestion()); !allow {
		t.Fatalf("inside window must allow: %s", reason)
	}
	g.now = func() time.Time { return time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC) } // outside
	if allow, _, _ := g.Authorize(goodSuggestion()); allow {
		t.Fatal("outside window must deny")
	}
}

func TestGovernorLiveModeRequiresExplicitOptIn(t *testing.T) {
	// The dangerous combination (autonomous + live) is only reachable when DryRunOnly=false.
	cfg := enabledConfig()
	cfg.DryRunOnly = false
	allow, dryRun, _ := NewGovernor(cfg).Authorize(goodSuggestion())
	if !allow || dryRun {
		t.Fatalf("explicit DryRunOnly=false must yield a live (dryRun=false) authorization; allow=%v dryRun=%v", allow, dryRun)
	}
}

func TestParseHourRanges(t *testing.T) {
	got := parseHourRanges("0-6, 22-23")
	if len(got) != 2 || got[0] != (hourRange{0, 6}) || got[1] != (hourRange{22, 23}) {
		t.Fatalf("parse: %+v", got)
	}
	if parseHourRanges("") != nil {
		t.Fatal("empty -> nil (any time)")
	}
	if r := parseHourRanges("9-5,bad,30-31"); len(r) != 0 {
		t.Fatalf("malformed ranges must be dropped: %+v", r)
	}
}
