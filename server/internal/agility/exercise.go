package agility

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ExerciseReport is the output of a dry-run agility exercise.
type ExerciseReport struct {
	ExerciseID   string            `json:"exercise_id"`
	RunAt        time.Time         `json:"run_at"`
	HostCount    int               `json:"host_count"`
	PassCount    int               `json:"pass_count"`
	FailCount    int               `json:"fail_count"`
	SkipCount    int               `json:"skip_count"`
	Findings     []ExerciseFinding `json:"findings"`
	OverallGrade string            `json:"overall_grade"` // A/B/C/D/F
	Summary      string            `json:"summary"`
}

// ExerciseFinding records the pass/fail result for one dimension on one host.
type ExerciseFinding struct {
	HostUUID  string  `json:"host_uuid"`
	Dimension string  `json:"dimension"` // e.g. "hardcode_index", "negotiation_coverage"
	Score     float64 `json:"score"`
	Passed    bool    `json:"passed"`
	Reason    string  `json:"reason"`
}

// RunExercise executes a dry-run agility assessment across all recent scorecards.
// It does not mutate any state.
//
// Thresholds:
//   - HardcodeIndex < 0.2     → pass (lower is better)
//   - NegotiationCoverage > 0.7 → pass (higher is better)
//   - BlastRadiusScore < 0.5  → pass (lower is better)
//   - MaturityLevel >= 2      → pass
//
// Overall grade: A ≥ 90 %, B ≥ 75 %, C ≥ 60 %, D ≥ 45 %, F < 45 %
func RunExercise(scorecards []Scorecard) ExerciseReport {
	report := ExerciseReport{
		ExerciseID: uuid.New().String(),
		RunAt:      time.Now().UTC(),
		HostCount:  len(scorecards),
		Findings:   []ExerciseFinding{},
	}

	if len(scorecards) == 0 {
		report.OverallGrade = "F"
		report.Summary = "No scorecards available; cannot assess agility readiness."
		return report
	}

	totalChecks := 0
	passChecks := 0

	for _, sc := range scorecards {
		host := sc.HostUUID

		// Dimension 1: hardcode_index
		hi := ExerciseFinding{
			HostUUID:  host,
			Dimension: "hardcode_index",
			Score:     sc.HardcodeIndex,
			Passed:    sc.HardcodeIndex < 0.2,
		}
		if hi.Passed {
			hi.Reason = fmt.Sprintf("hardcode index %.2f is below threshold 0.20", sc.HardcodeIndex)
		} else {
			hi.Reason = fmt.Sprintf("hardcode index %.2f meets or exceeds threshold 0.20; algorithms hardcoded in source", sc.HardcodeIndex)
		}
		report.Findings = append(report.Findings, hi)
		totalChecks++
		if hi.Passed {
			passChecks++
		}

		// Dimension 2: negotiation_coverage
		nc := ExerciseFinding{
			HostUUID:  host,
			Dimension: "negotiation_coverage",
			Score:     sc.NegotiationCoverage,
			Passed:    sc.NegotiationCoverage > 0.7,
		}
		if nc.Passed {
			nc.Reason = fmt.Sprintf("negotiation coverage %.2f exceeds threshold 0.70", sc.NegotiationCoverage)
		} else {
			nc.Reason = fmt.Sprintf("negotiation coverage %.2f is at or below threshold 0.70; services lack algorithm negotiation", sc.NegotiationCoverage)
		}
		report.Findings = append(report.Findings, nc)
		totalChecks++
		if nc.Passed {
			passChecks++
		}

		// Dimension 3: blast_radius_score
		br := ExerciseFinding{
			HostUUID:  host,
			Dimension: "blast_radius_score",
			Score:     sc.BlastRadiusScore,
			Passed:    sc.BlastRadiusScore < 0.5,
		}
		if br.Passed {
			br.Reason = fmt.Sprintf("blast radius score %.2f is below threshold 0.50", sc.BlastRadiusScore)
		} else {
			br.Reason = fmt.Sprintf("blast radius score %.2f meets or exceeds threshold 0.50; algorithm concentration risk is high", sc.BlastRadiusScore)
		}
		report.Findings = append(report.Findings, br)
		totalChecks++
		if br.Passed {
			passChecks++
		}

		// Dimension 4: maturity_level
		ml := ExerciseFinding{
			HostUUID:  host,
			Dimension: "maturity_level",
			Score:     float64(sc.MaturityLevel),
			Passed:    sc.MaturityLevel >= MaturityPlanned,
		}
		if ml.Passed {
			ml.Reason = fmt.Sprintf("maturity level %d (%s) meets minimum required level 2 (planned)", sc.MaturityLevel, sc.MaturityName)
		} else {
			ml.Reason = fmt.Sprintf("maturity level %d (%s) is below minimum required level 2 (planned)", sc.MaturityLevel, sc.MaturityName)
		}
		report.Findings = append(report.Findings, ml)
		totalChecks++
		if ml.Passed {
			passChecks++
		}
	}

	// Tally pass/fail counts across all hosts.
	for _, f := range report.Findings {
		if f.Passed {
			report.PassCount++
		} else {
			report.FailCount++
		}
	}

	// Compute overall grade.
	pct := float64(passChecks) / float64(totalChecks)
	switch {
	case pct >= 0.90:
		report.OverallGrade = "A"
	case pct >= 0.75:
		report.OverallGrade = "B"
	case pct >= 0.60:
		report.OverallGrade = "C"
	case pct >= 0.45:
		report.OverallGrade = "D"
	default:
		report.OverallGrade = "F"
	}

	report.Summary = fmt.Sprintf(
		"Assessed %d host(s) across 4 agility dimensions. %d/%d checks passed (%.0f%%). Grade: %s.",
		len(scorecards), passChecks, totalChecks, pct*100, report.OverallGrade,
	)
	return report
}
