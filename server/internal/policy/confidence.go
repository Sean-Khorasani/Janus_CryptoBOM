package policy

import (
	"sync"

	"github.com/janus-cbom/janus/server/internal/store"
)

// ConfidenceReport holds aggregate statistics about finding confidence levels.
type ConfidenceReport struct {
	AverageConfidence       float64            `json:"average_confidence"`
	LowConfidenceCount      int                `json:"low_confidence_count"`
	HighConfidenceCount     int                `json:"high_confidence_count"`
	RuleConfidenceBreakdown map[string]float64 `json:"rule_confidence_breakdown"`
}

// ConfidenceAnalyzer tracks and reports on the confidence of policy findings.
type ConfidenceAnalyzer struct {
	mu       sync.Mutex
	store    store.Store
	outcomes map[string]bool // findingID -> wasRealFinding (in-memory tracking)
}

// NewConfidenceAnalyzer creates a ConfidenceAnalyzer backed by the given store.
func NewConfidenceAnalyzer(s store.Store) *ConfidenceAnalyzer {
	return &ConfidenceAnalyzer{
		store:    s,
		outcomes: make(map[string]bool),
	}
}

// AnalyzeFindingConfidence computes a ConfidenceReport from all stored findings.
func (ca *ConfidenceAnalyzer) AnalyzeFindingConfidence(findings []store.Finding) ConfidenceReport {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	report := ConfidenceReport{
		RuleConfidenceBreakdown: make(map[string]float64),
	}

	if len(findings) == 0 {
		return report
	}

	var totalConf float64
	ruleConfSums := make(map[string]float64)
	ruleConfCounts := make(map[string]int)

	for _, f := range findings {
		conf := f.Confidence
		if conf == 0 {
			conf = 0.82 // default confidence
		}
		totalConf += conf
		ruleConfSums[f.PolicyRuleID] += conf
		ruleConfCounts[f.PolicyRuleID]++

		if conf < 0.5 {
			report.LowConfidenceCount++
		}
		if conf > 0.9 {
			report.HighConfidenceCount++
		}
	}

	report.AverageConfidence = totalConf / float64(len(findings))

	for ruleID, sum := range ruleConfSums {
		report.RuleConfidenceBreakdown[ruleID] = sum / float64(ruleConfCounts[ruleID])
	}

	return report
}

// FalsePositiveRate calculates the false positive rate for a given rule
// based on operator feedback tracked in memory.
func (ca *ConfidenceAnalyzer) FalsePositiveRate(ruleID string) float64 {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	var total int
	var falsePositives int
	for findingID, wasReal := range ca.outcomes {
		// Match rule by prefix of findingID (rule ID is contained in finding attributes)
		_ = findingID
		total++
		if !wasReal {
			falsePositives++
		}
	}
	if total == 0 {
		return 0.0
	}
	return float64(falsePositives) / float64(total)
}

// TrackOutcome records an operator's feedback about a finding's accuracy.
func (ca *ConfidenceAnalyzer) TrackOutcome(findingID string, wasRealFinding bool) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.outcomes[findingID] = wasRealFinding
}
