// Package agility computes the crypto-agility scorecard from Janus CryptoBOM findings.
//
// Metrics defined in RESEARCH.md §10 and AGILITY_SCORECARD.md:
//   - TTSA: Time-To-Swap-Algorithm (days from profile change to full compliance)
//   - HardcodeIndex: fraction of findings with hardcoded algorithms (no config negotiation)
//   - NegotiationCoverage: fraction of services supporting algorithm negotiation
//   - ProfileAdoptionLatency: days from profile publish to fleet compliance
//   - BlastRadius: normalized count of services per algorithm (concentration risk)
package agility

import (
	"math"
	"sort"
	"time"

	"github.com/janus-cbom/janus/server/internal/store"
)

// MaturityLevel represents the crypto-agility maturity tier from the scorecard.
type MaturityLevel int

const (
	MaturityNone     MaturityLevel = 0
	MaturityReactive MaturityLevel = 1
	MaturityPlanned  MaturityLevel = 2
	MaturityAgile    MaturityLevel = 3
	MaturityCryptoAgile MaturityLevel = 4
)

func (m MaturityLevel) String() string {
	switch m {
	case MaturityNone:
		return "none"
	case MaturityReactive:
		return "reactive"
	case MaturityPlanned:
		return "planned"
	case MaturityAgile:
		return "agile"
	case MaturityCryptoAgile:
		return "crypto_agile"
	default:
		return "unknown"
	}
}

// Scorecard is the computed agility scorecard for one host or the fleet.
type Scorecard struct {
	HostUUID                   string        `json:"host_uuid,omitempty"`
	HardcodeIndex              float64       `json:"hardcode_index"`              // 0–1, lower is better
	NegotiationCoverage        float64       `json:"negotiation_coverage"`        // 0–1, higher is better
	BlastRadiusScore           float64       `json:"blast_radius_score"`          // 0–1, lower is better
	TTSADays                   *float64      `json:"ttsa_days,omitempty"`
	ProfileAdoptionLatencyDays *float64      `json:"profile_adoption_latency_days,omitempty"`
	MaturityLevel              MaturityLevel `json:"maturity_level"`
	MaturityName               string        `json:"maturity_name"`
	AlgorithmBlastRadii        map[string]float64 `json:"algorithm_blast_radii"`  // per-algorithm blast radius
	ComputedAt                 time.Time     `json:"computed_at"`
}

// ComputeScorecard derives a Scorecard from a set of findings for one host.
// findings: all findings for the host.
// totalServices: number of distinct services/endpoints discovered (for negotiation coverage).
// negotiableServices: count with algorithm negotiation capability.
func ComputeScorecard(hostUUID string, findings []store.Finding, totalServices, negotiableServices int, policySwitchedAt *time.Time) Scorecard {
	sc := Scorecard{
		HostUUID:            hostUUID,
		AlgorithmBlastRadii: map[string]float64{},
		ComputedAt:          time.Now().UTC(),
	}

	if len(findings) == 0 {
		sc.MaturityLevel = MaturityNone
		sc.MaturityName = MaturityNone.String()
		return sc
	}

	// HardcodeIndex: fraction of findings in source files (vs config/network/dep).
	// A source file finding = hardcoded; config or network = negotiable.
	sourceFindings := 0
	for _, f := range findings {
		if isSourceFinding(f) {
			sourceFindings++
		}
	}
	sc.HardcodeIndex = float64(sourceFindings) / float64(len(findings))

	// NegotiationCoverage: fraction of services supporting negotiation.
	if totalServices > 0 {
		sc.NegotiationCoverage = float64(negotiableServices) / float64(totalServices)
	}

	// BlastRadius: for each algorithm, count distinct asset_refs; normalize by total findings.
	algorithmAssets := map[string]map[string]struct{}{}
	for _, f := range findings {
		if _, ok := algorithmAssets[f.Algorithm]; !ok {
			algorithmAssets[f.Algorithm] = map[string]struct{}{}
		}
		algorithmAssets[f.Algorithm][f.AssetRef] = struct{}{}
	}
	maxBlast := 0
	for alg, assets := range algorithmAssets {
		count := len(assets)
		if count > maxBlast {
			maxBlast = count
		}
		sc.AlgorithmBlastRadii[alg] = float64(count)
	}
	if len(findings) > 0 && maxBlast > 0 {
		sc.BlastRadiusScore = math.Min(1.0, float64(maxBlast)/float64(len(findings)))
	}

	// ProfileAdoptionLatency: if policy was switched, measure days until last open finding resolved.
	if policySwitchedAt != nil {
		latestRemediation := time.Time{}
		for _, f := range findings {
			if f.Status == "remediated" && f.UpdatedAt.After(latestRemediation) {
				latestRemediation = f.UpdatedAt
			}
		}
		if !latestRemediation.IsZero() && latestRemediation.After(*policySwitchedAt) {
			latency := latestRemediation.Sub(*policySwitchedAt).Hours() / 24
			sc.ProfileAdoptionLatencyDays = &latency
		}
	}

	sc.MaturityLevel = computeMaturity(sc)
	sc.MaturityName = sc.MaturityLevel.String()
	return sc
}

// ComputeFleetScorecard aggregates per-host scorecards into a fleet-wide view.
func ComputeFleetScorecard(scorecards []Scorecard) Scorecard {
	if len(scorecards) == 0 {
		return Scorecard{
			MaturityLevel: MaturityNone,
			MaturityName:  MaturityNone.String(),
			ComputedAt:    time.Now().UTC(),
		}
	}
	var sumHardcode, sumNeg, sumBlast float64
	minMaturity := MaturityCryptoAgile
	algBlasts := map[string]float64{}
	for _, sc := range scorecards {
		sumHardcode += sc.HardcodeIndex
		sumNeg += sc.NegotiationCoverage
		sumBlast += sc.BlastRadiusScore
		if sc.MaturityLevel < minMaturity {
			minMaturity = sc.MaturityLevel
		}
		for alg, v := range sc.AlgorithmBlastRadii {
			if v > algBlasts[alg] {
				algBlasts[alg] = v
			}
		}
	}
	n := float64(len(scorecards))
	fleet := Scorecard{
		HardcodeIndex:       sumHardcode / n,
		NegotiationCoverage: sumNeg / n,
		BlastRadiusScore:    sumBlast / n,
		AlgorithmBlastRadii: algBlasts,
		ComputedAt:          time.Now().UTC(),
	}
	fleet.MaturityLevel = computeMaturity(fleet)
	fleet.MaturityName = fleet.MaturityLevel.String()
	return fleet
}

// TopBlastRadiusAlgorithms returns algorithms sorted by blast radius descending, capped at n.
func TopBlastRadiusAlgorithms(sc Scorecard, n int) []struct {
	Algorithm  string  `json:"algorithm"`
	AssetCount float64 `json:"asset_count"`
} {
	type entry struct {
		Algorithm  string
		AssetCount float64
	}
	entries := make([]entry, 0, len(sc.AlgorithmBlastRadii))
	for alg, count := range sc.AlgorithmBlastRadii {
		entries = append(entries, entry{alg, count})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].AssetCount > entries[j].AssetCount
	})
	if n > 0 && len(entries) > n {
		entries = entries[:n]
	}
	result := make([]struct {
		Algorithm  string  `json:"algorithm"`
		AssetCount float64 `json:"asset_count"`
	}, len(entries))
	for i, e := range entries {
		result[i].Algorithm = e.Algorithm
		result[i].AssetCount = e.AssetCount
	}
	return result
}

// computeMaturity maps scorecard metrics to a maturity level (AGILITY_SCORECARD.md §3).
func computeMaturity(sc Scorecard) MaturityLevel {
	// TTSA is unknown (nil) — use hardcode index and negotiation coverage.
	// Level 4: hardcode <2%, neg >90%
	// Level 3: hardcode <5%, neg >80%
	// Level 2: hardcode <20%, neg >60%
	// Level 1: hardcode <50%, neg >20%
	// Level 0: otherwise
	hi := sc.HardcodeIndex
	nc := sc.NegotiationCoverage

	if hi < 0.02 && nc > 0.90 {
		return MaturityCryptoAgile
	}
	if hi < 0.05 && nc > 0.80 {
		return MaturityAgile
	}
	if hi < 0.20 && nc > 0.60 {
		return MaturityPlanned
	}
	if hi < 0.50 && nc > 0.20 {
		return MaturityReactive
	}
	return MaturityNone
}

// isSourceFinding returns true for findings that indicate a hardcoded algorithm in source code.
// A finding with an asset_ref that looks like a source file path is considered hardcoded.
func isSourceFinding(f store.Finding) bool {
	ref := f.AssetRef
	// Source file extensions indicate hardcoded algorithms
	for _, ext := range []string{".go", ".rs", ".py", ".js", ".ts", ".java", ".c", ".cpp", ".cs", ".rb", ".php"} {
		if len(ref) > len(ext) && ref[len(ref)-len(ext):] == ext {
			return true
		}
	}
	return false
}
