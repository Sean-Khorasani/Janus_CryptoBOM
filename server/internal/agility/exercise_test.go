package agility

import "testing"

func TestRunExerciseAllPass(t *testing.T) {
	// Build scorecards that pass every dimension:
	//   HardcodeIndex < 0.2, NegotiationCoverage > 0.7,
	//   BlastRadiusScore < 0.5, MaturityLevel >= 2.
	scorecards := []Scorecard{
		{
			HostUUID:            "host-a",
			HardcodeIndex:       0.05,
			NegotiationCoverage: 0.90,
			BlastRadiusScore:    0.10,
			MaturityLevel:       MaturityPlanned,
			MaturityName:        MaturityPlanned.String(),
		},
		{
			HostUUID:            "host-b",
			HardcodeIndex:       0.01,
			NegotiationCoverage: 0.95,
			BlastRadiusScore:    0.05,
			MaturityLevel:       MaturityCryptoAgile,
			MaturityName:        MaturityCryptoAgile.String(),
		},
	}

	report := RunExercise(scorecards)

	if report.HostCount != 2 {
		t.Errorf("host_count = %d, want 2", report.HostCount)
	}
	if report.FailCount != 0 {
		t.Errorf("fail_count = %d, want 0", report.FailCount)
	}
	if report.OverallGrade != "A" {
		t.Errorf("overall_grade = %q, want A", report.OverallGrade)
	}
	// 2 hosts * 4 dimensions = 8 findings, all passing.
	if len(report.Findings) != 8 {
		t.Errorf("findings count = %d, want 8", len(report.Findings))
	}
	if report.PassCount != 8 {
		t.Errorf("pass_count = %d, want 8", report.PassCount)
	}
}

func TestRunExerciseAllFail(t *testing.T) {
	// Build scorecards that fail every dimension.
	scorecards := []Scorecard{
		{
			HostUUID:            "host-bad",
			HardcodeIndex:       0.80,
			NegotiationCoverage: 0.10,
			BlastRadiusScore:    0.90,
			MaturityLevel:       MaturityNone,
			MaturityName:        MaturityNone.String(),
		},
	}

	report := RunExercise(scorecards)

	if report.HostCount != 1 {
		t.Errorf("host_count = %d, want 1", report.HostCount)
	}
	if report.PassCount != 0 {
		t.Errorf("pass_count = %d, want 0", report.PassCount)
	}
	if report.FailCount != 4 {
		t.Errorf("fail_count = %d, want 4 (one per dimension)", report.FailCount)
	}
	if report.OverallGrade != "F" {
		t.Errorf("overall_grade = %q, want F", report.OverallGrade)
	}
	for _, f := range report.Findings {
		if f.Passed {
			t.Errorf("expected all findings to fail, but %q passed on host %s", f.Dimension, f.HostUUID)
		}
	}
}

func TestRunExerciseEmpty(t *testing.T) {
	report := RunExercise(nil)

	if report.HostCount != 0 {
		t.Errorf("host_count = %d, want 0", report.HostCount)
	}
	if report.PassCount != 0 {
		t.Errorf("pass_count = %d, want 0", report.PassCount)
	}
	if report.FailCount != 0 {
		t.Errorf("fail_count = %d, want 0", report.FailCount)
	}
	if report.ExerciseID == "" {
		t.Error("exercise_id must not be empty")
	}
	if report.RunAt.IsZero() {
		t.Error("run_at must not be zero")
	}
	if len(report.Findings) != 0 {
		t.Errorf("findings = %d, want 0", len(report.Findings))
	}
}

func TestRunExercisePartialPass(t *testing.T) {
	// 2 hosts: one passes all 4, one fails all 4 → 50% pass rate → grade C.
	scorecards := []Scorecard{
		{
			HostUUID:            "good",
			HardcodeIndex:       0.05,
			NegotiationCoverage: 0.90,
			BlastRadiusScore:    0.10,
			MaturityLevel:       MaturityPlanned,
			MaturityName:        MaturityPlanned.String(),
		},
		{
			HostUUID:            "bad",
			HardcodeIndex:       0.80,
			NegotiationCoverage: 0.10,
			BlastRadiusScore:    0.90,
			MaturityLevel:       MaturityNone,
			MaturityName:        MaturityNone.String(),
		},
	}

	report := RunExercise(scorecards)

	// 4 pass + 4 fail = 8 total, 50% → grade D (D requires ≥45%, C requires ≥60%).
	if report.PassCount != 4 {
		t.Errorf("pass_count = %d, want 4", report.PassCount)
	}
	if report.FailCount != 4 {
		t.Errorf("fail_count = %d, want 4", report.FailCount)
	}
	if report.OverallGrade != "D" {
		t.Errorf("overall_grade = %q, want D (50%% pass rate, threshold for C is 60%%)", report.OverallGrade)
	}
}

func TestRunExerciseSummaryNotEmpty(t *testing.T) {
	sc := Scorecard{
		HostUUID:            "host-x",
		HardcodeIndex:       0.1,
		NegotiationCoverage: 0.8,
		BlastRadiusScore:    0.2,
		MaturityLevel:       MaturityPlanned,
		MaturityName:        MaturityPlanned.String(),
	}
	report := RunExercise([]Scorecard{sc})
	if report.Summary == "" {
		t.Error("summary must not be empty")
	}
}
