package agility

import (
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
)

// Negotiation exercise harness (WP-023). Given a set of target PQC algorithms
// (drawn from the active policy profile), the harness evaluates each migration
// adapter's ability to negotiate/field those targets, classifies readiness,
// and reports replacement paths and rollback availability. The evaluation is
// deterministic and offline — it grades against the curated adapter capability
// matrix rather than performing live handshakes, and labels itself as such.

// Readiness classifies how prepared an adapter is to field the targets.
type Readiness string

const (
	ReadinessReady       Readiness = "ready"       // every target covered
	ReadinessPartial     Readiness = "partial"     // some targets covered
	ReadinessUnsupported Readiness = "unsupported" // no targets covered (or no negotiation surface)
)

// AdapterNegotiationResult is one adapter's evaluation against the targets.
type AdapterNegotiationResult struct {
	Adapter         string    `json:"adapter"`
	Transport       string    `json:"transport"`
	Readiness       Readiness `json:"readiness"`
	CanNegotiate    bool      `json:"can_negotiate"`
	CanRollback     bool      `json:"can_rollback"`
	MatchedTargets  []string  `json:"matched_targets"`
	MissingTargets  []string  `json:"missing_targets"`
	ReplacementPath string    `json:"replacement_path"`
	Notes           string    `json:"notes"`
}

// NegotiationReport is the full per-adapter negotiation exercise output.
type NegotiationReport struct {
	ExerciseID       string                     `json:"exercise_id"`
	RunAt            time.Time                  `json:"run_at"`
	Targets          []string                   `json:"targets"`
	Adapters         []AdapterNegotiationResult `json:"adapters"`
	ReadyCount       int                        `json:"ready_count"`
	PartialCount     int                        `json:"partial_count"`
	UnsupportedCount int                        `json:"unsupported_count"`
	OverallGrade     string                     `json:"overall_grade"`
	Summary          string                     `json:"summary"`
	// Method documents that this is a capability evaluation, not a live probe.
	Method string `json:"method"`
}

// RunNegotiationHarness evaluates every builtin adapter against the targets.
func RunNegotiationHarness(targets []string) NegotiationReport {
	return runNegotiationHarness(BuiltinAdapters(), targets)
}

func runNegotiationHarness(adapters []AdapterCapability, targets []string) NegotiationReport {
	// Normalize + de-duplicate targets for stable reporting.
	seen := map[string]bool{}
	norm := make([]string, 0, len(targets))
	for _, t := range targets {
		n := normalizeAlgorithm(t)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		norm = append(norm, n)
	}
	sort.Strings(norm)

	report := NegotiationReport{
		ExerciseID: uuid.New().String(),
		RunAt:      time.Now().UTC(),
		Targets:    norm,
		Adapters:   []AdapterNegotiationResult{},
		Method:     "capability-evaluation (offline; grades against curated adapter matrix, not a live handshake)",
	}

	for _, a := range adapters {
		res := AdapterNegotiationResult{
			Adapter:      a.Name,
			Transport:    a.Transport,
			CanNegotiate: a.SupportsNegotiation,
			CanRollback:  a.SupportsRollback,
			Notes:        a.Notes,
		}
		for _, t := range norm {
			if a.SupportsNegotiation && adapterCovers(a, t) {
				res.MatchedTargets = append(res.MatchedTargets, t)
			} else {
				res.MissingTargets = append(res.MissingTargets, t)
			}
		}

		switch {
		case len(norm) == 0:
			res.Readiness = ReadinessUnsupported
		case len(res.MissingTargets) == 0:
			res.Readiness = ReadinessReady
		case len(res.MatchedTargets) > 0:
			res.Readiness = ReadinessPartial
		default:
			res.Readiness = ReadinessUnsupported
		}
		res.ReplacementPath = replacementPath(a, res)

		switch res.Readiness {
		case ReadinessReady:
			report.ReadyCount++
		case ReadinessPartial:
			report.PartialCount++
		default:
			report.UnsupportedCount++
		}
		report.Adapters = append(report.Adapters, res)
	}

	report.OverallGrade = gradeNegotiation(report)
	report.Summary = fmt.Sprintf(
		"Evaluated %d adapter(s) against %d PQC target(s): %d ready, %d partial, %d unsupported. Grade: %s.",
		len(adapters), len(norm), report.ReadyCount, report.PartialCount, report.UnsupportedCount, report.OverallGrade,
	)
	return report
}

func replacementPath(a AdapterCapability, res AdapterNegotiationResult) string {
	if !a.SupportsNegotiation {
		return fmt.Sprintf("%s has no runtime negotiation surface; PQC posture is governed by %s configuration. %s",
			a.Name, a.Transport, a.MinVersionNote)
	}
	switch res.Readiness {
	case ReadinessReady:
		return fmt.Sprintf("Field hybrid PQC by setting negotiated groups; toolchain ready: %s. Rollback is reversible via the mutation engine.", a.MinVersionNote)
	case ReadinessPartial:
		return fmt.Sprintf("Partial: %v negotiable now; %v require a newer toolchain (%s).", res.MatchedTargets, res.MissingTargets, a.MinVersionNote)
	default:
		return fmt.Sprintf("No targets negotiable on the current matrix; upgrade required: %s.", a.MinVersionNote)
	}
}

func gradeNegotiation(r NegotiationReport) string {
	total := len(r.Adapters)
	if total == 0 {
		return "F"
	}
	// Weight ready as 1.0 and partial as 0.5 of an adapter's contribution.
	score := (float64(r.ReadyCount) + 0.5*float64(r.PartialCount)) / float64(total)
	switch {
	case score >= 0.90:
		return "A"
	case score >= 0.75:
		return "B"
	case score >= 0.60:
		return "C"
	case score >= 0.45:
		return "D"
	default:
		return "F"
	}
}

// EstimateTTSADays produces an honest, labeled estimate of Time-To-Swap-Algorithm
// in days from a scorecard plus the negotiation readiness. It is a heuristic for
// planning, NOT a measured drill result: hardcoded algorithms and high blast
// radius lengthen the estimate; adapter readiness shortens it.
func EstimateTTSADays(sc Scorecard, neg NegotiationReport) float64 {
	// Base effort: 5 days for a fully agile, ready posture.
	base := 5.0
	// Hardcoding penalty: up to +40 days when everything is wired into source.
	base += sc.HardcodeIndex * 40.0
	// Blast radius penalty: up to +20 days for high concentration.
	base += sc.BlastRadiusScore * 20.0
	// Negotiation readiness discount/penalty.
	if len(neg.Adapters) > 0 {
		readyFrac := (float64(neg.ReadyCount) + 0.5*float64(neg.PartialCount)) / float64(len(neg.Adapters))
		base += (1.0 - readyFrac) * 15.0 // up to +15 days when no adapter is ready
	}
	if base < 1.0 {
		base = 1.0
	}
	return base
}
