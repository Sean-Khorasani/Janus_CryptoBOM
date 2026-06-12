package agility

import (
	"testing"
	"time"

	"github.com/janus-cbom/janus/server/internal/store"
)

func TestComputeScorecard_EmptyFindings(t *testing.T) {
	sc := ComputeScorecard("host-1", nil, 0, 0, nil)
	if sc.MaturityLevel != MaturityNone {
		t.Errorf("expected MaturityNone for empty findings, got %v", sc.MaturityLevel)
	}
	if sc.HardcodeIndex != 0 {
		t.Errorf("expected HardcodeIndex=0, got %f", sc.HardcodeIndex)
	}
}

func TestComputeScorecard_HardcodeIndex(t *testing.T) {
	findings := []store.Finding{
		{FindingID: "f1", Algorithm: "RSA-2048", AssetRef: "src/crypto.go", Status: "open"},
		{FindingID: "f2", Algorithm: "RSA-2048", AssetRef: "src/key.rs", Status: "open"},
		{FindingID: "f3", Algorithm: "AES-128", AssetRef: "nginx.conf", Status: "open"},
		{FindingID: "f4", Algorithm: "TLSv1.2", AssetRef: "api.example.com:443", Status: "open"},
	}
	sc := ComputeScorecard("host-1", findings, 2, 1, nil)
	// 2 out of 4 are source findings (.go and .rs)
	expectedHI := 2.0 / 4.0
	if abs(sc.HardcodeIndex-expectedHI) > 1e-9 {
		t.Errorf("expected HardcodeIndex=%f, got %f", expectedHI, sc.HardcodeIndex)
	}
}

func TestComputeScorecard_NegotiationCoverage(t *testing.T) {
	sc := ComputeScorecard("host-1", makeFindings(2), 10, 8, nil)
	expected := 8.0 / 10.0
	if abs(sc.NegotiationCoverage-expected) > 1e-9 {
		t.Errorf("expected NegotiationCoverage=%f, got %f", expected, sc.NegotiationCoverage)
	}
}

func TestComputeScorecard_BlastRadius(t *testing.T) {
	findings := []store.Finding{
		{FindingID: "f1", Algorithm: "RSA-2048", AssetRef: "srv-a.conf"},
		{FindingID: "f2", Algorithm: "RSA-2048", AssetRef: "srv-b.conf"},
		{FindingID: "f3", Algorithm: "RSA-2048", AssetRef: "srv-c.conf"},
		{FindingID: "f4", Algorithm: "AES-128", AssetRef: "srv-a.conf"},
	}
	sc := ComputeScorecard("host-1", findings, 0, 0, nil)
	if sc.AlgorithmBlastRadii["RSA-2048"] != 3 {
		t.Errorf("expected RSA-2048 blast radius = 3, got %f", sc.AlgorithmBlastRadii["RSA-2048"])
	}
	if sc.AlgorithmBlastRadii["AES-128"] != 1 {
		t.Errorf("expected AES-128 blast radius = 1, got %f", sc.AlgorithmBlastRadii["AES-128"])
	}
}

func TestComputeScorecard_ProfileAdoptionLatency(t *testing.T) {
	switched := time.Now().Add(-30 * 24 * time.Hour) // 30 days ago
	remediated := time.Now().Add(-10 * 24 * time.Hour) // 10 days ago
	findings := []store.Finding{
		{FindingID: "f1", Algorithm: "RSA-2048", AssetRef: "a.go",
			Status: "remediated", UpdatedAt: remediated},
	}
	sc := ComputeScorecard("host-1", findings, 5, 4, &switched)
	if sc.ProfileAdoptionLatencyDays == nil {
		t.Fatal("expected ProfileAdoptionLatencyDays to be set")
	}
	expectedDays := 20.0
	if abs(*sc.ProfileAdoptionLatencyDays-expectedDays) > 0.5 {
		t.Errorf("expected latency ~%f days, got %f", expectedDays, *sc.ProfileAdoptionLatencyDays)
	}
}

func TestMaturityLevel_String(t *testing.T) {
	cases := map[MaturityLevel]string{
		MaturityNone:        "none",
		MaturityReactive:    "reactive",
		MaturityPlanned:     "planned",
		MaturityAgile:       "agile",
		MaturityCryptoAgile: "crypto_agile",
	}
	for level, want := range cases {
		if level.String() != want {
			t.Errorf("MaturityLevel(%d).String() = %q, want %q", level, level.String(), want)
		}
	}
}

func TestComputeMaturity_Levels(t *testing.T) {
	tests := []struct {
		hi      float64
		nc      float64
		want    MaturityLevel
	}{
		{0.01, 0.95, MaturityCryptoAgile},
		{0.04, 0.85, MaturityAgile},
		{0.15, 0.70, MaturityPlanned},
		{0.30, 0.40, MaturityReactive},
		{0.60, 0.10, MaturityNone},
	}
	for _, tc := range tests {
		sc := Scorecard{HardcodeIndex: tc.hi, NegotiationCoverage: tc.nc}
		got := computeMaturity(sc)
		if got != tc.want {
			t.Errorf("computeMaturity(hi=%.2f, nc=%.2f) = %v, want %v", tc.hi, tc.nc, got, tc.want)
		}
	}
}

func TestTopBlastRadiusAlgorithms(t *testing.T) {
	sc := Scorecard{
		AlgorithmBlastRadii: map[string]float64{
			"RSA-2048": 10, "AES-128": 3, "SHA-1": 7,
		},
	}
	top := TopBlastRadiusAlgorithms(sc, 2)
	if len(top) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(top))
	}
	if top[0].Algorithm != "RSA-2048" {
		t.Errorf("expected RSA-2048 first, got %s", top[0].Algorithm)
	}
	if top[1].Algorithm != "SHA-1" {
		t.Errorf("expected SHA-1 second, got %s", top[1].Algorithm)
	}
}

func TestComputeFleetScorecard_AveragesMetrics(t *testing.T) {
	sc1 := Scorecard{HardcodeIndex: 0.2, NegotiationCoverage: 0.6, BlastRadiusScore: 0.3}
	sc2 := Scorecard{HardcodeIndex: 0.1, NegotiationCoverage: 0.8, BlastRadiusScore: 0.1}
	fleet := ComputeFleetScorecard([]Scorecard{sc1, sc2})
	if abs(fleet.HardcodeIndex-0.15) > 1e-9 {
		t.Errorf("expected fleet HardcodeIndex=0.15, got %f", fleet.HardcodeIndex)
	}
	if abs(fleet.NegotiationCoverage-0.70) > 1e-9 {
		t.Errorf("expected fleet NegotiationCoverage=0.70, got %f", fleet.NegotiationCoverage)
	}
}

func TestIsSourceFinding(t *testing.T) {
	sourcePaths := []string{"src/main.go", "lib/crypto.rs", "utils.py", "index.js", "App.ts"}
	nonSourcePaths := []string{"nginx.conf", "redis.yaml", "host:443", "package.json", ".env"}
	for _, p := range sourcePaths {
		if !isSourceFinding(store.Finding{AssetRef: p}) {
			t.Errorf("expected %q to be a source finding", p)
		}
	}
	for _, p := range nonSourcePaths {
		if isSourceFinding(store.Finding{AssetRef: p}) {
			t.Errorf("expected %q NOT to be a source finding", p)
		}
	}
}

func makeFindings(n int) []store.Finding {
	f := make([]store.Finding, n)
	for i := range f {
		f[i] = store.Finding{FindingID: "f" + string(rune('0'+i)), Algorithm: "RSA-2048", AssetRef: "a.conf"}
	}
	return f
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
