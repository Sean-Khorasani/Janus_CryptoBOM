package llm

import (
	"context"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/janus-cbom/janus/server/internal/store"
)

// RemediationEnqueuer converts a suggestion into a signed migration command and enqueues
// it. It is implemented in the httpapi layer (which owns the orchestrator) and injected
// here so the llm package stays free of the orchestrator dependency.
type RemediationEnqueuer func(ctx context.Context, s *store.LLMSuggestion, dryRun bool) error

// GovernorConfig controls autonomous remediation (LLM-017). It is read from env in the
// llm package to avoid touching the shared config.go. Every control is fail-closed.
//
// Env vars (defaults in parens):
//
//	JANUS_LLM_AUTOREMEDIATE_ENABLED        (false)         — master kill switch
//	JANUS_LLM_AUTOREMEDIATE_DRYRUN         (true)          — force dry-run; set false to apply live
//	JANUS_LLM_AUTOREMEDIATE_MIN_CONFIDENCE (0.9)           — minimum suggestion confidence
//	JANUS_LLM_AUTOREMEDIATE_TYPES          (config_change) — allowed recommendation types (csv)
//	JANUS_LLM_AUTOREMEDIATE_MAX_PER_HOUR   (3)             — budget cap (canary/blast-radius)
//	JANUS_LLM_AUTOREMEDIATE_WINDOW         ("" = any)      — allowed UTC hour ranges, e.g. "0-6,22-23"
//
// SECURITY NOTE: this rides on the same shared-HMAC migration path as manual migration,
// which lacks per-agent command keys + replay resistance (MIG-01, unbuilt). LLM-017 does
// not weaken that foundation — it only changes trigger frequency. The proportionate
// mitigations are exactly these controls plus the agent's own passive-by-default gate and
// extension allowlist. Enabling autonomous + live (DRYRUN=false) requires the operator to
// validate in their own environment first.
type GovernorConfig struct {
	Enabled       bool
	DryRunOnly    bool
	MinConfidence float64
	AllowedTypes  map[string]bool
	MaxPerHour    int
	AllowedHours  []hourRange // empty = any time
}

type hourRange struct{ lo, hi int } // inclusive UTC hours [lo, hi]

// RemediationGovernor decides whether a freshly generated suggestion may be auto-applied.
type RemediationGovernor struct {
	cfg     GovernorConfig
	mu      sync.Mutex
	budget  *rateLimiter
	now     func() time.Time
	auditFn func(action, detail string) // optional, for skip/allow audit
}

// EnableAutonomousRemediation wires the governor + command enqueuer onto the service
// (LLM-017). Called once at startup by the httpapi layer. With either nil, autonomous
// remediation is off — which is the default, since GenerateRemediation only auto-applies
// when both are set AND the governor authorizes.
func (s *Service) EnableAutonomousRemediation(g *RemediationGovernor, enq RemediationEnqueuer) {
	s.governor = g
	s.enqueuer = enq
}

// maybeAutoApply runs the autonomous-remediation decision for a freshly generated,
// already-persisted suggestion. It never fails the generation flow — an enqueue error is
// swallowed (logged by the enqueuer) so the suggestion still stands for manual review.
func (s *Service) maybeAutoApply(ctx context.Context, suggestion *store.LLMSuggestion) {
	if s.governor == nil || s.enqueuer == nil {
		return
	}
	allow, dryRun, _ := s.governor.Authorize(suggestion)
	if !allow {
		return
	}
	_ = s.enqueuer(ctx, suggestion, dryRun)
}

// LoadGovernorFromEnv builds a governor from the JANUS_LLM_AUTOREMEDIATE_* env vars.
func LoadGovernorFromEnv() *RemediationGovernor {
	cfg := GovernorConfig{
		Enabled:       boolEnv("JANUS_LLM_AUTOREMEDIATE_ENABLED", false),
		DryRunOnly:    boolEnv("JANUS_LLM_AUTOREMEDIATE_DRYRUN", true),
		MinConfidence: floatEnv("JANUS_LLM_AUTOREMEDIATE_MIN_CONFIDENCE", 0.9),
		AllowedTypes:  csvSet(envOr("JANUS_LLM_AUTOREMEDIATE_TYPES", RecommendationConfigChange)),
		MaxPerHour:    intEnv("JANUS_LLM_AUTOREMEDIATE_MAX_PER_HOUR", 3),
		AllowedHours:  parseHourRanges(os.Getenv("JANUS_LLM_AUTOREMEDIATE_WINDOW")),
	}
	return NewGovernor(cfg)
}

// NewGovernor builds a governor with an explicit config (used by tests).
func NewGovernor(cfg GovernorConfig) *RemediationGovernor {
	return &RemediationGovernor{
		cfg:    cfg,
		budget: newRateLimiter(cfg.MaxPerHour, time.Hour),
		now:    time.Now,
	}
}

// Authorize reports whether a suggestion may be auto-applied right now, the dry-run flag
// to use, and (on refusal) a reason. It is fail-closed: any unmet control denies. Budget
// is consumed only when every other control passes, so a refusal never burns the budget.
func (g *RemediationGovernor) Authorize(s *store.LLMSuggestion) (allow bool, dryRun bool, reason string) {
	if g == nil || !g.cfg.Enabled {
		return false, false, "autonomous remediation disabled"
	}
	if s.ValidationStatus != "passed" || s.CandidatePatch == "" {
		return false, false, "no deterministically-validated patch"
	}
	if !g.cfg.AllowedTypes[s.RecommendationType] {
		return false, false, "recommendation type " + s.RecommendationType + " not in autonomous allowlist"
	}
	if s.Confidence < g.cfg.MinConfidence {
		return false, false, "confidence below autonomous floor"
	}
	if _, ok, why := AgentWillApplyPatch(s.CandidatePatch); !ok {
		return false, false, why
	}
	if !g.withinWindow() {
		return false, false, "outside the autonomous change window"
	}
	// Budget last: do not consume a slot on an otherwise-refused suggestion.
	g.mu.Lock()
	ok := g.budget.allow()
	g.mu.Unlock()
	if !ok {
		return false, false, "autonomous remediation budget exhausted for this hour"
	}
	return true, g.cfg.DryRunOnly, ""
}

func (g *RemediationGovernor) withinWindow() bool {
	if len(g.cfg.AllowedHours) == 0 {
		return true
	}
	h := g.now().UTC().Hour()
	for _, r := range g.cfg.AllowedHours {
		if h >= r.lo && h <= r.hi {
			return true
		}
	}
	return false
}

// --- env helpers (kept local to avoid touching config.go) ---

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func boolEnv(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func intEnv(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func floatEnv(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

func csvSet(s string) map[string]bool {
	out := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out[p] = true
		}
	}
	return out
}

// parseHourRanges parses "0-6,22-23" into inclusive UTC hour ranges; malformed parts are
// skipped (fail-closed: a garbled window yields no ranges, which means "any time" only if
// the whole string was empty — a partial parse that drops everything denies via window).
func parseHourRanges(s string) []hourRange {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var ranges []hourRange
	for _, part := range strings.Split(s, ",") {
		lohi := strings.SplitN(strings.TrimSpace(part), "-", 2)
		if len(lohi) != 2 {
			continue
		}
		lo, e1 := strconv.Atoi(strings.TrimSpace(lohi[0]))
		hi, e2 := strconv.Atoi(strings.TrimSpace(lohi[1]))
		if e1 != nil || e2 != nil || lo < 0 || hi > 23 || lo > hi {
			continue
		}
		ranges = append(ranges, hourRange{lo, hi})
	}
	return ranges
}
