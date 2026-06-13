package store

// store_test.go — pure-logic unit tests for the store package.
//
// These tests require no database connection and run with a plain:
//
//	go test ./internal/store/...
//
// Integration tests that exercise a live PostgreSQL database require
// JANUS_DATABASE_URL to be set. Those are skipped automatically when
// the environment variable is absent; they do not use a build tag so
// that the file is always compiled and type-checked.

import (
	"os"
	"testing"
)

// Compile-time assertion: *Postgres must satisfy the Store interface.
// If InsertTelemetry (or any other method) has a signature mismatch,
// this line produces a clear build error rather than a runtime panic.
var _ Store = (*Postgres)(nil)

// TestMigrationVersionsAreUniqueAndMonotonic verifies that:
//  1. Every migration has a unique version number.
//  2. Versions form a gapless sequence starting at 1.
//  3. Every migration has non-empty Description and SQL.
//
// A violation here means EnsureSchema would silently skip or replay
// a migration, corrupting the schema.
func TestMigrationVersionsAreUniqueAndMonotonic(t *testing.T) {
	seen := make(map[int]bool, len(migrations))
	for i, m := range migrations {
		if m.Version <= 0 {
			t.Errorf("migrations[%d]: version must be > 0, got %d", i, m.Version)
		}
		if seen[m.Version] {
			t.Errorf("migrations[%d]: duplicate version %d", i, m.Version)
		}
		seen[m.Version] = true

		if m.Description == "" {
			t.Errorf("migrations[%d] (v%d): Description must not be empty", i, m.Version)
		}
		if m.SQL == "" {
			t.Errorf("migrations[%d] (v%d): SQL must not be empty", i, m.Version)
		}
	}

	// Expect a gapless 1..N sequence.
	n := len(migrations)
	for v := 1; v <= n; v++ {
		if !seen[v] {
			t.Errorf("missing migration version %d (have %d migrations, expected gapless 1..%d)", v, n, n)
		}
	}
}

// TestMigrationVersionsIncreasing verifies that migrations are listed
// in strictly ascending order (a requirement of EnsureSchema's loop).
func TestMigrationVersionsIncreasing(t *testing.T) {
	for i := 1; i < len(migrations); i++ {
		prev := migrations[i-1].Version
		cur := migrations[i].Version
		if cur <= prev {
			t.Errorf("migrations[%d] version %d is not greater than migrations[%d] version %d",
				i, cur, i-1, prev)
		}
	}
}

// TestIntegrationAutoReopenFindings is an integration-only test stub.
// It is skipped unless JANUS_DATABASE_URL is set.
//
// To run against a live database:
//
//	JANUS_DATABASE_URL="postgres://janus:janus@127.0.0.1:5432/janus?sslmode=disable" \
//	  go test ./internal/store/... -run TestIntegrationAutoReopenFindings -v
func TestIntegrationAutoReopenFindings(t *testing.T) {
	if os.Getenv("JANUS_DATABASE_URL") == "" {
		t.Skip("JANUS_DATABASE_URL not set — skipping integration test")
	}
	// Full integration scenario would:
	//   1. Insert a finding via InsertTelemetry.
	//   2. Close it via UpdateFindingStatus(..., "remediated", "test").
	//   3. Re-submit telemetry with the same (asset_ref, algorithm, policy_rule_id).
	//   4. Assert status is back to 'open', reopen_count == 1, reopened_at is set.
	//   5. Assert a 'reopened' lifecycle event exists in finding_lifecycle_events.
	t.Log("integration tests not yet implemented — provide JANUS_DATABASE_URL and extend this test")
}
