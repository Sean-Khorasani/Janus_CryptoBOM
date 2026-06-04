package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/janus-cbom/janus/server/internal/pb"
)

type Store interface {
	EnsureSchema(context.Context) error
	Ping(context.Context) error
	UpsertAgent(context.Context, *pb.AgentRegistration) error
	InsertTelemetry(context.Context, *pb.CbomTelemetryPayload) error
	InsertMigrationCommand(context.Context, *pb.MigrationCommand) error
	UpdateMigrationStatus(context.Context, *pb.MigrationStatusReport) error
	Overview(context.Context) (*Overview, error)
	Assets(context.Context) ([]Asset, error)
	Components(context.Context, int) ([]Component, error)
	Findings(context.Context, int) ([]Finding, error)
	FindingsPaginated(ctx context.Context, params QueryParams) ([]Finding, int64, error)
	ComponentsPaginated(ctx context.Context, params QueryParams) ([]Component, int64, error)
	UpdateFindingStatus(ctx context.Context, findingID, status, updatedBy string) error
	Migrations(context.Context) ([]Migration, error)
	GetLatestConfigHash(ctx context.Context, hostUUID, configPath string) (string, error)
}

type Postgres struct {
	pool *pgxpool.Pool
}

type Overview struct {
	Assets             int64            `json:"assets"`
	Components         int64            `json:"components"`
	Findings           int64            `json:"findings"`
	CriticalFindings   int64            `json:"critical_findings"`
	HighFindings       int64            `json:"high_findings"`
	OpenMigrations     int64            `json:"open_migrations"`
	AlgorithmHistogram map[string]int64 `json:"algorithm_histogram"`
}

type Asset struct {
	HostUUID      string    `json:"host_uuid"`
	Hostname      string    `json:"hostname"`
	OSName        string    `json:"os_name"`
	OSVersion     string    `json:"os_version"`
	Arch          string    `json:"arch"`
	ExecutionMode int32     `json:"execution_mode"`
	LastSeen      time.Time `json:"last_seen"`
}

type Finding struct {
	FindingID        string    `json:"finding_id"`
	HostUUID         string    `json:"host_uuid"`
	Severity         int32     `json:"severity"`
	Title            string    `json:"title"`
	Description      string    `json:"description"`
	AssetRef         string    `json:"asset_ref"`
	Algorithm        string    `json:"algorithm"`
	PolicyRuleID     string    `json:"policy_rule_id"`
	MigrationProfile string    `json:"migration_profile"`
	Status           string    `json:"status"` // open | accepted_risk | false_positive | remediated
	UpdatedBy        string    `json:"updated_by"`
	UpdatedAt        time.Time `json:"updated_at"`
	CreatedAt        time.Time `json:"created_at"`
	Confidence       float64   `json:"confidence"`
}

// QueryParams is used for paginated, filtered, sorted queries.
type QueryParams struct {
	Limit  int
	Offset int
	Sort   string // column name
	Order  string // asc | desc
	Search string // keyword filter
}

type Component struct {
	HostUUID       string   `json:"host_uuid"`
	TelemetryID    string   `json:"telemetry_id"`
	BomRef         string   `json:"bom_ref"`
	Name           string   `json:"name"`
	Version        string   `json:"version"`
	ComponentType  string   `json:"component_type"`
	FilePath       string   `json:"file_path"`
	Language       string   `json:"language"`
	Algorithms     []string `json:"algorithms"`
	Dependencies   []string `json:"dependencies"`
	Reachable      bool     `json:"reachable"`
	ScanFinishedAt int64    `json:"scan_finished_unix"`
}

type Migration struct {
	CommandID        string    `json:"command_id"`
	HostUUID         string    `json:"host_uuid"`
	TargetService    string    `json:"target_service"`
	MigrationProfile string    `json:"migration_profile"`
	TargetKEM        string    `json:"target_kem"`
	TargetSignature  string    `json:"target_signature"`
	ConfigPath       string    `json:"config_path"`
	State            int32     `json:"state"`
	DryRun           bool      `json:"dry_run"`
	IssuedAt         time.Time `json:"issued_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	LastError        string                `json:"last_error"`
	Output           string                `json:"output"`
	ObservedTLS      *pb.NetworkObservation `json:"observed_tls,omitempty"`
}

func NewPostgres(ctx context.Context, databaseURL string) (*Postgres, error) {
	if databaseURL == "" {
		return nil, errors.New("database URL is required")
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Postgres{pool: pool}, nil
}

func (p *Postgres) Close() {
	p.pool.Close()
}

func (p *Postgres) Ping(ctx context.Context) error {
	return p.pool.Ping(ctx)
}

func (p *Postgres) EnsureSchema(ctx context.Context) error {
	_, err := p.pool.Exec(ctx, schemaSQL)
	if err != nil {
		return err
	}
	// Idempotent column additions for upgrades from older schema versions
	_, _ = p.pool.Exec(ctx, `ALTER TABLE crypto_findings ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'open'`)
	_, _ = p.pool.Exec(ctx, `ALTER TABLE crypto_findings ADD COLUMN IF NOT EXISTS updated_by TEXT NOT NULL DEFAULT ''`)
	_, _ = p.pool.Exec(ctx, `ALTER TABLE crypto_findings ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now()`)
	_, _ = p.pool.Exec(ctx, `ALTER TABLE crypto_findings ADD COLUMN IF NOT EXISTS confidence DOUBLE PRECISION NOT NULL DEFAULT 0.82`)
	_, _ = p.pool.Exec(ctx, `ALTER TABLE migration_transactions ADD COLUMN IF NOT EXISTS observed_tls JSONB`)
	return nil
}

func (p *Postgres) UpsertAgent(ctx context.Context, reg *pb.AgentRegistration) error {
	caps, err := json.Marshal(reg.Capabilities)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx, `
INSERT INTO assets (host_uuid, hostname, os_name, os_version, arch, execution_mode, capabilities, last_seen)
VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, now())
ON CONFLICT (host_uuid) DO UPDATE SET
  hostname = EXCLUDED.hostname,
  os_name = EXCLUDED.os_name,
  os_version = EXCLUDED.os_version,
  arch = EXCLUDED.arch,
  execution_mode = EXCLUDED.execution_mode,
  capabilities = EXCLUDED.capabilities,
  last_seen = now()`,
		reg.HostUuid, reg.Hostname, reg.OsName, reg.OsVersion, reg.Arch, reg.ExecutionMode, string(caps))
	return err
}

func (p *Postgres) InsertTelemetry(ctx context.Context, payload *pb.CbomTelemetryPayload) error {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	cycloneDX := payload.CycloneDxJson
	if cycloneDX == "" {
		cycloneDX = "{}"
	}

	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
INSERT INTO telemetry_payloads (
  telemetry_id, host_uuid, scan_started, scan_finished, component_count,
  finding_count, network_observation_count, cyclone_dx, payload, received_at
) VALUES ($1, $2, to_timestamp($3), to_timestamp($4), $5, $6, $7, $8::jsonb, $9::jsonb, now())
ON CONFLICT (telemetry_id) DO NOTHING`,
		payload.TelemetryId,
		payload.HostUuid,
		payload.ScanStartedUnix,
		payload.ScanFinishedUnix,
		len(payload.Components),
		len(payload.Findings),
		len(payload.NetworkObservations),
		cycloneDX,
		string(payloadJSON),
	)
	if err != nil {
		return err
	}

	for _, f := range payload.Findings {
		evidenceIDs, err := json.Marshal(f.EvidenceIds)
		if err != nil {
			return err
		}
		// Find matching algorithm's confidence
		confidence := 0.82
		for _, comp := range payload.Components {
			if comp.BomRef == f.AssetRef {
				for _, alg := range comp.Algorithms {
					if alg.Name == f.Algorithm {
						confidence = alg.Confidence
						break
					}
				}
			}
		}
		// Deduplicate: match on (asset_ref, algorithm, policy_rule_id), update severity/description if changed
		_, err = tx.Exec(ctx, `
INSERT INTO crypto_findings (
  finding_id, telemetry_id, host_uuid, severity, title, description, asset_ref,
  algorithm, policy_rule_id, migration_profile, evidence_ids, status, updated_by, updated_at, created_at, confidence
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, 'open', '', now(), now(), $12)
ON CONFLICT (asset_ref, algorithm, policy_rule_id) DO UPDATE SET
  severity = EXCLUDED.severity,
  title = EXCLUDED.title,
  description = EXCLUDED.description,
  telemetry_id = EXCLUDED.telemetry_id,
  confidence = EXCLUDED.confidence,
  updated_at = now()
WHERE crypto_findings.status = 'open'`,
			f.FindingId,
			payload.TelemetryId,
			payload.HostUuid,
			f.Severity,
			f.Title,
			f.Description,
			f.AssetRef,
			f.Algorithm,
			f.PolicyRuleId,
			f.MigrationProfile,
			string(evidenceIDs),
			confidence,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

func (p *Postgres) InsertMigrationCommand(ctx context.Context, cmd *pb.MigrationCommand) error {
	_, err := p.pool.Exec(ctx, `
INSERT INTO migration_transactions (
  command_id, host_uuid, target_service, migration_profile, target_kem,
  target_signature, config_path, state, dry_run, issued_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, to_timestamp($10), now())
ON CONFLICT (command_id) DO NOTHING`,
		cmd.CommandId,
		cmd.HostUuid,
		cmd.TargetService,
		cmd.MigrationProfile,
		cmd.TargetKem,
		cmd.TargetSignature,
		cmd.ConfigPath,
		pb.MigrationStatePending,
		cmd.DryRun,
		cmd.IssuedAtUnix,
	)
	return err
}

func (p *Postgres) UpdateMigrationStatus(ctx context.Context, report *pb.MigrationStatusReport) error {
	var obsJSON []byte
	if report.ObservedTls != nil {
		obsJSON, _ = json.Marshal(report.ObservedTls)
	}
	_, err := p.pool.Exec(ctx, `
UPDATE migration_transactions
SET state = $2, updated_at = to_timestamp($3), last_error = $4, output = $5, observed_tls = $6
WHERE command_id = $1`,
		report.CommandId,
		report.State,
		report.ReportedAtUnix,
		report.ErrorVector,
		report.Output,
		obsJSON,
	)
	return err
}

func (p *Postgres) GetLatestConfigHash(ctx context.Context, hostUUID, configPath string) (string, error) {
	var raw []byte
	err := p.pool.QueryRow(ctx, `
SELECT payload FROM telemetry_payloads
WHERE host_uuid = $1
ORDER BY received_at DESC
LIMIT 1`, hostUUID).Scan(&raw)
	if err != nil {
		// If no telemetry or no row, return empty without failing
		return "", nil
	}
	var payload pb.CbomTelemetryPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", err
	}
	for _, ev := range payload.Evidence {
		if ev.Target == configPath && ev.RawArtifactSha256 != "" {
			return ev.RawArtifactSha256, nil
		}
	}
	return "", nil
}

func (p *Postgres) Overview(ctx context.Context) (*Overview, error) {
	out := &Overview{AlgorithmHistogram: map[string]int64{}}
	if err := p.pool.QueryRow(ctx, `SELECT count(*) FROM assets`).Scan(&out.Assets); err != nil {
		return nil, err
	}
	if err := p.pool.QueryRow(ctx, `SELECT COALESCE(sum(component_count),0), COALESCE(sum(finding_count),0) FROM telemetry_payloads`).Scan(&out.Components, &out.Findings); err != nil {
		return nil, err
	}
	if err := p.pool.QueryRow(ctx, `SELECT count(*) FROM crypto_findings WHERE severity = $1`, pb.RiskSeverityCritical).Scan(&out.CriticalFindings); err != nil {
		return nil, err
	}
	if err := p.pool.QueryRow(ctx, `SELECT count(*) FROM crypto_findings WHERE severity = $1`, pb.RiskSeverityHigh).Scan(&out.HighFindings); err != nil {
		return nil, err
	}
	if err := p.pool.QueryRow(ctx, `SELECT count(*) FROM migration_transactions WHERE state NOT IN ($1, $2)`, pb.MigrationStateSucceeded, pb.MigrationStateFailed).Scan(&out.OpenMigrations); err != nil {
		return nil, err
	}

	rows, err := p.pool.Query(ctx, `SELECT algorithm, count(*) FROM crypto_findings GROUP BY algorithm ORDER BY count(*) DESC LIMIT 12`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var alg string
		var count int64
		if err := rows.Scan(&alg, &count); err != nil {
			return nil, err
		}
		out.AlgorithmHistogram[alg] = count
	}
	return out, rows.Err()
}

func (p *Postgres) Assets(ctx context.Context) ([]Asset, error) {
	rows, err := p.pool.Query(ctx, `SELECT host_uuid, hostname, os_name, os_version, arch, execution_mode, last_seen FROM assets ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var assets []Asset
	for rows.Next() {
		var a Asset
		if err := rows.Scan(&a.HostUUID, &a.Hostname, &a.OSName, &a.OSVersion, &a.Arch, &a.ExecutionMode, &a.LastSeen); err != nil {
			return nil, err
		}
		assets = append(assets, a)
	}
	return assets, rows.Err()
}

func (p *Postgres) Components(ctx context.Context, limit int) ([]Component, error) {
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	rows, err := p.pool.Query(ctx, `
SELECT telemetry_id, host_uuid, payload
FROM telemetry_payloads
ORDER BY received_at DESC
LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var components []Component
	for rows.Next() {
		var telemetryID, hostUUID string
		var raw []byte
		if err := rows.Scan(&telemetryID, &hostUUID, &raw); err != nil {
			return nil, err
		}
		var payload pb.CbomTelemetryPayload
		if err := json.Unmarshal(raw, &payload); err != nil {
			continue
		}
		for _, component := range payload.Components {
			algorithms := make([]string, 0, len(component.Algorithms))
			for _, alg := range component.Algorithms {
				if alg.Name != "" {
					algorithms = append(algorithms, alg.Name)
				}
			}
			components = append(components, Component{
				HostUUID:       hostUUID,
				TelemetryID:    telemetryID,
				BomRef:         component.BomRef,
				Name:           component.Name,
				Version:        component.Version,
				ComponentType:  component.ComponentType,
				FilePath:       component.FilePath,
				Language:       component.Language,
				Algorithms:     algorithms,
				Dependencies:   component.Dependencies,
				Reachable:      component.Reachable,
				ScanFinishedAt: payload.ScanFinishedUnix,
			})
			if len(components) >= limit {
				return components, nil
			}
		}
	}
	return components, rows.Err()
}

func (p *Postgres) Findings(ctx context.Context, limit int) ([]Finding, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := p.pool.Query(ctx, `
SELECT finding_id, host_uuid, severity, title, description, asset_ref, algorithm, policy_rule_id, migration_profile,
       COALESCE(status,'open'), COALESCE(updated_by,''), COALESCE(updated_at, created_at), created_at, confidence
FROM crypto_findings
ORDER BY severity DESC, created_at DESC
LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var findings []Finding
	for rows.Next() {
		var f Finding
		if err := rows.Scan(
			&f.FindingID, &f.HostUUID, &f.Severity, &f.Title, &f.Description, &f.AssetRef, &f.Algorithm, &f.PolicyRuleID, &f.MigrationProfile,
			&f.Status, &f.UpdatedBy, &f.UpdatedAt, &f.CreatedAt, &f.Confidence,
		); err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

func (p *Postgres) FindingsPaginated(ctx context.Context, params QueryParams) ([]Finding, int64, error) {
	if params.Limit <= 0 || params.Limit > 500 {
		params.Limit = 50
	}
	if params.Offset < 0 {
		params.Offset = 0
	}
	allowedSort := map[string]string{
		"severity": "severity", "algorithm": "algorithm", "asset_ref": "asset_ref",
		"policy_rule_id": "policy_rule_id", "created_at": "created_at", "status": "status",
	}
	sortCol, ok := allowedSort[params.Sort]
	if !ok {
		sortCol = "severity"
	}
	order := "DESC"
	if params.Order == "asc" {
		order = "ASC"
	}
	searchFilter := ""
	args := []any{params.Limit, params.Offset}
	if params.Search != "" {
		searchFilter = ` AND (title ILIKE $3 OR description ILIKE $3 OR asset_ref ILIKE $3 OR algorithm ILIKE $3 OR policy_rule_id ILIKE $3)`
		args = append(args, "%"+params.Search+"%")
	}
	query := `SELECT finding_id, host_uuid, severity, title, description, asset_ref, algorithm, policy_rule_id, migration_profile,
				 COALESCE(status,'open'), COALESCE(updated_by,''), COALESCE(updated_at, created_at), created_at, confidence
			  FROM crypto_findings WHERE 1=1` + searchFilter +
		` ORDER BY ` + sortCol + ` ` + order + ` LIMIT $1 OFFSET $2`
	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var findings []Finding
	for rows.Next() {
		var f Finding
		if err := rows.Scan(
			&f.FindingID, &f.HostUUID, &f.Severity, &f.Title, &f.Description, &f.AssetRef, &f.Algorithm, &f.PolicyRuleID, &f.MigrationProfile,
			&f.Status, &f.UpdatedBy, &f.UpdatedAt, &f.CreatedAt, &f.Confidence,
		); err != nil {
			return nil, 0, err
		}
		findings = append(findings, f)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	countQuery := `SELECT count(*) FROM crypto_findings WHERE 1=1` + searchFilter
	var total int64
	if err := p.pool.QueryRow(ctx, countQuery, args[2:]...).Scan(&total); err != nil {
		total = int64(len(findings))
	}
	return findings, total, nil
}

func (p *Postgres) ComponentsPaginated(ctx context.Context, params QueryParams) ([]Component, int64, error) {
	// Components are stored in telemetry_payloads JSON — delegate to existing Components() with limit
	limit := params.Limit
	if limit <= 0 || limit > 2000 {
		limit = 100
	}
	comps, err := p.Components(ctx, limit+params.Offset)
	if err != nil {
		return nil, 0, err
	}
	if params.Offset >= len(comps) {
		return nil, int64(len(comps)), nil
	}
	page := comps[params.Offset:]
	if len(page) > limit {
		page = page[:limit]
	}
	return page, int64(len(comps)), nil
}

func (p *Postgres) UpdateFindingStatus(ctx context.Context, findingID, status, updatedBy string) error {
	allowed := map[string]bool{"open": true, "accepted_risk": true, "false_positive": true, "remediated": true}
	if !allowed[status] {
		return errors.New("invalid status value")
	}
	_, err := p.pool.Exec(ctx, `
UPDATE crypto_findings SET status=$2, updated_by=$3, updated_at=now() WHERE finding_id=$1`,
		findingID, status, updatedBy)
	return err
}

func (p *Postgres) Migrations(ctx context.Context) ([]Migration, error) {
	rows, err := p.pool.Query(ctx, `
SELECT command_id, host_uuid, target_service, migration_profile, target_kem, target_signature, config_path,
       state, dry_run, issued_at, updated_at, last_error, output, observed_tls
FROM migration_transactions
ORDER BY updated_at DESC
LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var migrations []Migration
	for rows.Next() {
		var m Migration
		var obsJSON []byte
		if err := rows.Scan(
			&m.CommandID, &m.HostUUID, &m.TargetService, &m.MigrationProfile, &m.TargetKEM, &m.TargetSignature, &m.ConfigPath,
			&m.State, &m.DryRun, &m.IssuedAt, &m.UpdatedAt, &m.LastError, &m.Output, &obsJSON,
		); err != nil {
			return nil, err
		}
		if len(obsJSON) > 0 {
			var obs pb.NetworkObservation
			if err := json.Unmarshal(obsJSON, &obs); err == nil {
				m.ObservedTLS = &obs
			}
		}
		migrations = append(migrations, m)
	}
	return migrations, rows.Err()
}

const schemaSQL = `
CREATE TABLE IF NOT EXISTS assets (
  host_uuid TEXT PRIMARY KEY,
  hostname TEXT NOT NULL,
  os_name TEXT NOT NULL,
  os_version TEXT NOT NULL,
  arch TEXT NOT NULL,
  execution_mode INTEGER NOT NULL,
  capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
  last_seen TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS telemetry_payloads (
  telemetry_id TEXT PRIMARY KEY,
  host_uuid TEXT NOT NULL REFERENCES assets(host_uuid) ON DELETE CASCADE,
  scan_started TIMESTAMPTZ NOT NULL,
  scan_finished TIMESTAMPTZ NOT NULL,
  component_count INTEGER NOT NULL,
  finding_count INTEGER NOT NULL,
  network_observation_count INTEGER NOT NULL,
  cyclone_dx JSONB,
  payload JSONB NOT NULL,
  received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS crypto_findings (
  finding_id TEXT PRIMARY KEY,
  telemetry_id TEXT NOT NULL REFERENCES telemetry_payloads(telemetry_id) ON DELETE CASCADE,
  host_uuid TEXT NOT NULL REFERENCES assets(host_uuid) ON DELETE CASCADE,
  severity INTEGER NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  asset_ref TEXT NOT NULL,
  algorithm TEXT NOT NULL,
  policy_rule_id TEXT NOT NULL,
  migration_profile TEXT NOT NULL,
  evidence_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  status TEXT NOT NULL DEFAULT 'open',
  updated_by TEXT NOT NULL DEFAULT '',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (asset_ref, algorithm, policy_rule_id)
);

CREATE TABLE IF NOT EXISTS migration_transactions (
  command_id TEXT PRIMARY KEY,
  host_uuid TEXT NOT NULL REFERENCES assets(host_uuid) ON DELETE CASCADE,
  target_service TEXT NOT NULL,
  migration_profile TEXT NOT NULL,
  target_kem TEXT NOT NULL,
  target_signature TEXT NOT NULL,
  config_path TEXT NOT NULL,
  state INTEGER NOT NULL,
  dry_run BOOLEAN NOT NULL,
  issued_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_error TEXT NOT NULL DEFAULT '',
  output TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_crypto_findings_host_uuid ON crypto_findings(host_uuid);
CREATE INDEX IF NOT EXISTS idx_crypto_findings_severity ON crypto_findings(severity);
CREATE INDEX IF NOT EXISTS idx_migration_transactions_host_uuid ON migration_transactions(host_uuid);
`
