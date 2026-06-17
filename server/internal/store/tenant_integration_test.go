package store

import (
	"context"
	"os"
	"testing"
	"time"

	pb "github.com/janus-cbom/janus/server/internal/pb"
)

// Live-DB smoke for the WP-020 tenant-scoped read queries. The dynamic placeholder
// construction in Overview/Findings/Migrations/Components/ReportFindings/AssetTenant is
// only mock-tested in the unit suite, so this exercises each against real PostgreSQL to
// confirm the SQL is valid in both the scoped (tenant set) and fleet-wide (tenant "")
// shapes. Skips unless JANUS_TEST_DATABASE_URL is set so the unit suite stays hermetic.
//
//	JANUS_TEST_DATABASE_URL=postgres://janus:janus@127.0.0.1:5432/janus?sslmode=disable \
//	  go test -run TestTenantScopedReadsLive ./internal/store/
func TestTenantScopedReadsLive(t *testing.T) {
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
		t.Fatalf("ensure schema (migrations incl. 37/38): %v", err)
	}

	// Run every tenant-aware read in both shapes. We assert only on SQL validity
	// (no error); row counts depend on whatever data the dev DB holds.
	for _, tenant := range []string{"", "default", "acme"} {
		if _, err := pg.Overview(ctx, tenant); err != nil {
			t.Fatalf("Overview(%q): %v", tenant, err)
		}
		if _, err := pg.Assets(ctx, tenant); err != nil {
			t.Fatalf("Assets(%q): %v", tenant, err)
		}
		if _, err := pg.Findings(ctx, 10, tenant); err != nil {
			t.Fatalf("Findings(%q): %v", tenant, err)
		}
		if _, err := pg.Components(ctx, 10, tenant); err != nil {
			t.Fatalf("Components(%q): %v", tenant, err)
		}
		if _, err := pg.Migrations(ctx, tenant); err != nil {
			t.Fatalf("Migrations(%q): %v", tenant, err)
		}
		if _, _, err := pg.ReportFindings(ctx, "no-such-scan", QueryParams{Limit: 10, TenantID: tenant}); err != nil {
			t.Fatalf("ReportFindings(%q): %v", tenant, err)
		}
		if _, _, err := pg.AssetsPaginated(ctx, FleetQueryParams{QueryParams: QueryParams{Limit: 10, TenantID: tenant}}); err != nil {
			t.Fatalf("AssetsPaginated(%q): %v", tenant, err)
		}
		if _, _, err := pg.FindingsPaginated(ctx, QueryParams{Limit: 10, TenantID: tenant}); err != nil {
			t.Fatalf("FindingsPaginated(%q): %v", tenant, err)
		}
		if _, _, err := pg.ComponentsPaginated(ctx, QueryParams{Limit: 10, TenantID: tenant}); err != nil {
			t.Fatalf("ComponentsPaginated(%q): %v", tenant, err)
		}
	}

	// AssetTenant on an unknown host must return pgx.ErrNoRows, not a SQL error.
	if _, err := pg.AssetTenant(ctx, "definitely-not-a-host"); err == nil {
		t.Fatal("AssetTenant(unknown) expected pgx.ErrNoRows, got nil")
	}
}

// TestOverviewIdempotentAcrossRescans proves BUG-AGG-1 is fixed: ingesting the same host's
// scan twice must NOT double the Overview component/finding tiles or the CBOM list — those
// reflect current posture (latest scan per host + deduped findings), not cumulative history.
// History stays addressable by explicit scan_id. Gated on JANUS_TEST_DATABASE_URL.
func TestOverviewIdempotentAcrossRescans(t *testing.T) {
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
		t.Fatalf("ensure schema: %v", err)
	}

	const tenant = "aggtest"
	const host = "aggtest-host-1"
	_ = pg.CreateTenant(ctx, &Tenant{TenantID: tenant, Name: "Aggregation Test"})
	if err := pg.UpsertAgent(ctx, &pb.AgentRegistration{
		HostUuid: host, Hostname: "agg-host", OsName: "linux", Arch: "x86_64", AgentVersion: "test",
	}, "127.0.0.1", tenant); err != nil {
		t.Fatalf("upsert agent: %v", err)
	}
	t.Cleanup(func() {
		// assets ON DELETE CASCADE clears scan_runs/scan_components/telemetry_payloads/crypto_findings.
		_, _ = pg.pool.Exec(ctx, `DELETE FROM assets WHERE host_uuid=$1`, host)
		_, _ = pg.pool.Exec(ctx, `DELETE FROM tenants WHERE tenant_id=$1`, tenant)
	})

	mkPayload := func(id string, finished int64) *pb.CbomTelemetryPayload {
		return &pb.CbomTelemetryPayload{
			TelemetryId: id, HostUuid: host, ScanStartedUnix: finished - 1, ScanFinishedUnix: finished,
			Components: []*pb.CbomComponent{
				{BomRef: "comp-openssl", Name: "openssl", ComponentType: "library", Algorithms: []*pb.CryptoAlgorithm{{Name: "RSA"}}},
				{BomRef: "comp-crypto", Name: "crypto", ComponentType: "library"},
			},
			Findings: []*pb.CryptoFinding{
				{FindingId: "agg-f1", Severity: int32(pb.RiskSeverityCritical), Title: "RSA weak", AssetRef: "/agg/a", Algorithm: "RSA", PolicyRuleId: "AGG-R1"},
				{FindingId: "agg-f2", Severity: int32(pb.RiskSeverityHigh), Title: "ECDSA", AssetRef: "/agg/b", Algorithm: "ECDSA", PolicyRuleId: "AGG-R2"},
			},
		}
	}
	// Two scans of the same host, different telemetry_id, increasing scan_finished.
	if err := pg.InsertTelemetry(ctx, mkPayload("agg-scan-1", 1_700_000_000)); err != nil {
		t.Fatalf("insert scan 1: %v", err)
	}
	if err := pg.InsertTelemetry(ctx, mkPayload("agg-scan-2", 1_700_000_100)); err != nil {
		t.Fatalf("insert scan 2: %v", err)
	}

	ov, err := pg.Overview(ctx, tenant)
	if err != nil {
		t.Fatalf("overview: %v", err)
	}
	if ov.Components != 2 {
		t.Errorf("Overview.Components = %d, want 2 (latest scan, not cumulative 4)", ov.Components)
	}
	if ov.Findings != 2 {
		t.Errorf("Overview.Findings = %d, want 2 (distinct, not cumulative 4)", ov.Findings)
	}
	if ov.CriticalFindings != 1 || ov.HighFindings != 1 {
		t.Errorf("crit=%d high=%d, want 1/1 (and crit+high must equal findings)", ov.CriticalFindings, ov.HighFindings)
	}

	// CBOM default view = latest scan per host: 2 components, not 4.
	comps, total, err := pg.ComponentsPaginated(ctx, QueryParams{Limit: 100, TenantID: tenant})
	if err != nil {
		t.Fatalf("components paginated: %v", err)
	}
	if total != 2 || len(comps) != 2 {
		t.Errorf("CBOM latest-scan view total=%d len=%d, want 2/2", total, len(comps))
	}

	// History is preserved: an explicit scan_id still returns that scan's components.
	_, totalScan1, err := pg.ComponentsPaginated(ctx, QueryParams{Limit: 100, TenantID: tenant, ScanID: "agg-scan-1"})
	if err != nil {
		t.Fatalf("components paginated (scan 1): %v", err)
	}
	if totalScan1 != 2 {
		t.Errorf("explicit scan_id drill-down total=%d, want 2 (history preserved)", totalScan1)
	}
}
