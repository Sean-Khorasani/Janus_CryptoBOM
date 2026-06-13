package store

import (
	"context"
	"os"
	"testing"
	"time"
)

// Live-DB smoke test for WP-022/WP-023 SQL: migration 28 (depends_on), the
// wave-plan round-trip including the new column, and the agility-metrics upsert
// that was previously never executed. Skips unless JANUS_TEST_DATABASE_URL is
// set so the normal unit suite stays hermetic.
//
//	JANUS_TEST_DATABASE_URL=postgres://janus:janus@127.0.0.1:5432/janus?sslmode=disable \
//	  go test -run TestWavePlanLiveRoundTrip ./internal/store/
func TestWavePlanLiveRoundTrip(t *testing.T) {
	url := os.Getenv("JANUS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set JANUS_TEST_DATABASE_URL to run the live-DB smoke test")
	}
	ctx := context.Background()
	pg, err := NewPostgres(ctx, PostgresConfig{DatabaseURL: url, MaxConns: 4, MinConns: 1,
		MaxConnLifetime: time.Minute, MaxConnIdleTime: time.Minute})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pg.Close()
	if err := pg.EnsureSchema(ctx); err != nil {
		t.Fatalf("ensure schema (migrations incl. 28): %v", err)
	}

	// Create a dependency plan, then a dependent plan that depends_on it.
	depA := &WavePlan{Name: "smoke-A", WaveNumber: 1, Status: "planned"}
	if err := pg.CreateWavePlan(ctx, depA); err != nil {
		t.Fatalf("create A: %v", err)
	}
	depB := &WavePlan{Name: "smoke-B", WaveNumber: 2, Status: "planned",
		DependsOn: []string{depA.PlanID}, BudgetHours: 10, ActualHours: 4, ComponentCount: 3}
	if err := pg.CreateWavePlan(ctx, depB); err != nil {
		t.Fatalf("create B: %v", err)
	}
	t.Cleanup(func() {
		_ = pg.DeleteWavePlan(ctx, depA.PlanID)
		_ = pg.DeleteWavePlan(ctx, depB.PlanID)
	})

	// Read back and confirm depends_on round-trips through the new JSONB column.
	plans, err := pg.GetWavePlans(ctx)
	if err != nil {
		t.Fatalf("get plans: %v", err)
	}
	var gotB *WavePlan
	for i := range plans {
		if plans[i].PlanID == depB.PlanID {
			gotB = &plans[i]
		}
	}
	if gotB == nil {
		t.Fatal("plan B not returned")
	}
	if len(gotB.DependsOn) != 1 || gotB.DependsOn[0] != depA.PlanID {
		t.Fatalf("depends_on did not round-trip: got %v, want [%s]", gotB.DependsOn, depA.PlanID)
	}
	if gotB.BudgetHours != 10 || gotB.ActualHours != 4 || gotB.ComponentCount != 3 {
		t.Fatalf("budget fields did not round-trip: %+v", gotB)
	}

	// Update should preserve depends_on through the UPDATE path.
	gotB.Status = "active"
	if err := pg.UpdateWavePlan(ctx, gotB); err != nil {
		t.Fatalf("update B: %v", err)
	}

	// Agility metric upsert (WP-023) — previously never executed. Needs a real
	// asset row for the FK, so register one first.
	host := "smoke-host-" + depA.PlanID[:8]
	if _, err := pg.pool.Exec(ctx,
		`INSERT INTO assets (host_uuid, hostname, os_name, os_version, arch, execution_mode)
		 VALUES ($1,$2,'linux','test','x86_64',0) ON CONFLICT (host_uuid) DO NOTHING`,
		host, host); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	t.Cleanup(func() { _, _ = pg.pool.Exec(ctx, `DELETE FROM assets WHERE host_uuid=$1`, host) })

	ttsa := 12.5
	if err := pg.UpsertAgilityMetrics(ctx, &AgilityMetrics{
		HostUUID: host, MeasurementDate: time.Now(), TTSADays: &ttsa,
		HardcodeIndex: 0.2, NegotiationCoverage: 0.7, BlastRadiusScore: 0.3,
	}); err != nil {
		t.Fatalf("upsert agility metrics: %v", err)
	}
	got, err := pg.GetAgilityMetrics(ctx, host)
	if err != nil {
		t.Fatalf("get agility metrics: %v", err)
	}
	if got == nil || got.TTSADays == nil || *got.TTSADays != 12.5 {
		t.Fatalf("agility metric did not round-trip: %+v", got)
	}
}
