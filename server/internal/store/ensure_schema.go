package store

import (
	"context"
	"fmt"
)

func (p *Postgres) EnsureSchema(ctx context.Context) error {
	// Ensure the schema_version table exists for old databases being migrated
	_, _ = p.pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS schema_version (
  version INTEGER PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  description TEXT NOT NULL DEFAULT ''
)`)

	// Read current schema version
	currentVersion := 0
	err := p.pool.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&currentVersion)
	if err != nil {
		currentVersion = 0
	}

	// Run pending migrations
	for _, m := range migrations {
		if m.Version <= currentVersion {
			continue
		}
		tx, err := p.pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin migration v%d: %w", m.Version, err)
		}
		if _, err := tx.Exec(ctx, m.SQL); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("apply migration v%d (%s): %w", m.Version, m.Description, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_version (version, description) VALUES ($1, $2)`, m.Version, m.Description); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("record migration v%d: %w", m.Version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration v%d: %w", m.Version, err)
		}
	}

	return nil
}
