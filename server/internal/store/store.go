package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
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
	UpdateAgentHeartbeat(ctx context.Context, hb *AgentHeartbeat) error
	GetFleetConfig(ctx context.Context) (*FleetConfig, error)
	UpdateFleetConfig(ctx context.Context, fc *FleetConfig) error
	GetAuditLogs(ctx context.Context) ([]AuditLog, error)
	InsertAuditLog(ctx context.Context, al *AuditLog) error
	GetAgentDiagnostics(ctx context.Context, hostUUID string) (string, error)
	UpdateAgentDiagnostics(ctx context.Context, hostUUID, logs string) error
	GetWebhooks(ctx context.Context) ([]Webhook, error)
	InsertWebhook(ctx context.Context, wh *Webhook) error
	DeleteWebhook(ctx context.Context, webhookID string) error
	GetRetentionPolicy(ctx context.Context) (*RetentionPolicy, error)
	UpdateRetentionPolicy(ctx context.Context, rp *RetentionPolicy) error
	PurgeOldTelemetry(ctx context.Context, days int) (int64, error)
	GetConfigProfiles(ctx context.Context) ([]ConfigProfile, error)
	CreateConfigProfile(ctx context.Context, cp *ConfigProfile) error
	DeleteConfigProfile(ctx context.Context, profileID string) error
	GetAgentProfileMappings(ctx context.Context) ([]AgentProfileMapping, error)
	MapAgentToProfile(ctx context.Context, hostUUID, profileID string) error
	GetConfigForAgent(ctx context.Context, hostUUID string) (*FleetConfig, error)
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
	HostUUID          string    `json:"host_uuid"`
	Hostname          string    `json:"hostname"`
	OSName            string    `json:"os_name"`
	OSVersion         string    `json:"os_version"`
	Arch              string    `json:"arch"`
	ExecutionMode     int32     `json:"execution_mode"`
	LastSeen          time.Time `json:"last_seen"`
	ScanProgress      int       `json:"scan_progress"`
	CurrentScanPath   string    `json:"current_scan_path"`
	CPUUsage          float64   `json:"cpu_usage"`
	MemUsage          float64   `json:"mem_usage"`
	Status            string    `json:"status"`
	TotalFilesScanned int       `json:"total_files_scanned"`
}

type AgentHeartbeat struct {
	HostUUID          string  `json:"host_uuid"`
	ScanProgress      int     `json:"scan_progress"`
	CurrentScanPath   string  `json:"current_scan_path"`
	CPUUsage          float64 `json:"cpu_usage"`
	MemUsage          float64 `json:"mem_usage"`
	Status            string  `json:"status"`
	TotalFilesScanned int     `json:"total_files_scanned"`
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

type Webhook struct {
	WebhookID   string    `json:"webhook_id"`
	URL         string    `json:"url"`
	SecretToken string    `json:"secret_token"`
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"created_at"`
}

type RetentionPolicy struct {
	PolicyKey     string    `json:"policy_key"`
	RetentionDays int       `json:"retention_days"`
	AutoPurge     bool      `json:"auto_purge"`
	UpdatedAt     time.Time `json:"updated_at"`
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
	_, _ = p.pool.Exec(ctx, `ALTER TABLE assets ADD COLUMN IF NOT EXISTS scan_progress INTEGER NOT NULL DEFAULT 0`)
	_, _ = p.pool.Exec(ctx, `ALTER TABLE assets ADD COLUMN IF NOT EXISTS current_scan_path TEXT NOT NULL DEFAULT ''`)
	_, _ = p.pool.Exec(ctx, `ALTER TABLE assets ADD COLUMN IF NOT EXISTS cpu_usage DOUBLE PRECISION NOT NULL DEFAULT 0.0`)
	_, _ = p.pool.Exec(ctx, `ALTER TABLE assets ADD COLUMN IF NOT EXISTS mem_usage DOUBLE PRECISION NOT NULL DEFAULT 0.0`)
	_, _ = p.pool.Exec(ctx, `ALTER TABLE assets ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'offline'`)
	_, _ = p.pool.Exec(ctx, `ALTER TABLE assets ADD COLUMN IF NOT EXISTS total_files_scanned INTEGER NOT NULL DEFAULT 0`)

	// New advanced features tables
	_, _ = p.pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS fleet_configs (
  config_id TEXT PRIMARY KEY,
  exclude_dirs TEXT NOT NULL DEFAULT '',
  min_key_size INTEGER NOT NULL DEFAULT 2048,
  scan_schedule TEXT NOT NULL DEFAULT 'daily',
  llm_api_key TEXT NOT NULL DEFAULT '',
  llm_api_url TEXT NOT NULL DEFAULT 'https://api.openai.com/v1',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`)
	_, _ = p.pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS config_profiles (
  profile_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  exclude_dirs TEXT NOT NULL DEFAULT '',
  min_key_size INTEGER NOT NULL DEFAULT 2048,
  scan_schedule TEXT NOT NULL DEFAULT 'daily',
  llm_api_key TEXT NOT NULL DEFAULT '',
  llm_api_url TEXT NOT NULL DEFAULT 'https://api.openai.com/v1',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`)
	_, _ = p.pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS agent_profile_mappings (
  host_uuid TEXT PRIMARY KEY REFERENCES assets(host_uuid) ON DELETE CASCADE,
  profile_id TEXT NOT NULL REFERENCES config_profiles(profile_id) ON DELETE CASCADE,
  mapped_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`)
	_, _ = p.pool.Exec(ctx, `ALTER TABLE fleet_configs ADD COLUMN IF NOT EXISTS llm_api_key TEXT NOT NULL DEFAULT ''`)
	_, _ = p.pool.Exec(ctx, `ALTER TABLE fleet_configs ADD COLUMN IF NOT EXISTS llm_api_url TEXT NOT NULL DEFAULT 'https://api.openai.com/v1'`)
	_, _ = p.pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS audit_logs (
  log_id TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  action TEXT NOT NULL,
  details TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`)
	_, _ = p.pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS agent_diagnostics (
  host_uuid TEXT PRIMARY KEY REFERENCES assets(host_uuid) ON DELETE CASCADE,
  logs TEXT NOT NULL DEFAULT '',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`)
	_, _ = p.pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS fleet_webhooks (
  webhook_id TEXT PRIMARY KEY,
  url TEXT NOT NULL,
  secret_token TEXT NOT NULL DEFAULT '',
  active INTEGER NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`)
	_, _ = p.pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS fleet_retention_policies (
  policy_key TEXT PRIMARY KEY,
  retention_days INTEGER NOT NULL DEFAULT 90,
  auto_purge INTEGER NOT NULL DEFAULT 1,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`)
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
	rows, err := p.pool.Query(ctx, `SELECT host_uuid, hostname, os_name, os_version, arch, execution_mode, last_seen, scan_progress, current_scan_path, cpu_usage, mem_usage, status, total_files_scanned FROM assets ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var assets []Asset
	for rows.Next() {
		var a Asset
		if err := rows.Scan(&a.HostUUID, &a.Hostname, &a.OSName, &a.OSVersion, &a.Arch, &a.ExecutionMode, &a.LastSeen, &a.ScanProgress, &a.CurrentScanPath, &a.CPUUsage, &a.MemUsage, &a.Status, &a.TotalFilesScanned); err != nil {
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

func (p *Postgres) UpdateAgentHeartbeat(ctx context.Context, hb *AgentHeartbeat) error {
	_, err := p.pool.Exec(ctx, `
UPDATE assets
SET scan_progress = $2,
    current_scan_path = $3,
    cpu_usage = $4,
    mem_usage = $5,
    status = $6,
    total_files_scanned = $7,
    last_seen = now()
WHERE host_uuid = $1`,
		hb.HostUUID, hb.ScanProgress, hb.CurrentScanPath, hb.CPUUsage, hb.MemUsage, hb.Status, hb.TotalFilesScanned)
	return err
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

type FleetConfig struct {
	ConfigID     string    `json:"config_id"`
	ExcludeDirs  string    `json:"exclude_dirs"`
	MinKeySize   int       `json:"min_key_size"`
	ScanSchedule string    `json:"scan_schedule"`
	LLMApiKey    string    `json:"llm_api_key"`
	LLMApiUrl    string    `json:"llm_api_url"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type AuditLog struct {
	LogID     string    `json:"log_id"`
	Username  string    `json:"username"`
	Action    string    `json:"action"`
	Details   string    `json:"details"`
	CreatedAt time.Time `json:"created_at"`
}

func (p *Postgres) GetFleetConfig(ctx context.Context) (*FleetConfig, error) {
	row := p.pool.QueryRow(ctx, `SELECT config_id, exclude_dirs, min_key_size, scan_schedule, llm_api_key, llm_api_url, updated_at FROM fleet_configs LIMIT 1`)
	var fc FleetConfig
	err := row.Scan(&fc.ConfigID, &fc.ExcludeDirs, &fc.MinKeySize, &fc.ScanSchedule, &fc.LLMApiKey, &fc.LLMApiUrl, &fc.UpdatedAt)
	if err != nil {
		_, _ = p.pool.Exec(ctx, `INSERT INTO fleet_configs (config_id, exclude_dirs, min_key_size, scan_schedule, llm_api_key, llm_api_url) VALUES ('default', '.git, target, node_modules, dist, .venv, temp', 2048, 'daily', '', 'https://api.openai.com/v1') ON CONFLICT DO NOTHING`)
		row = p.pool.QueryRow(ctx, `SELECT config_id, exclude_dirs, min_key_size, scan_schedule, llm_api_key, llm_api_url, updated_at FROM fleet_configs LIMIT 1`)
		err = row.Scan(&fc.ConfigID, &fc.ExcludeDirs, &fc.MinKeySize, &fc.ScanSchedule, &fc.LLMApiKey, &fc.LLMApiUrl, &fc.UpdatedAt)
		if err != nil {
			return nil, err
		}
	}
	return &fc, nil
}

func (p *Postgres) UpdateFleetConfig(ctx context.Context, fc *FleetConfig) error {
	_, err := p.pool.Exec(ctx, `
INSERT INTO fleet_configs (config_id, exclude_dirs, min_key_size, scan_schedule, llm_api_key, llm_api_url, updated_at)
VALUES ('default', $1, $2, $3, $4, $5, now())
ON CONFLICT (config_id) DO UPDATE SET
  exclude_dirs = EXCLUDED.exclude_dirs,
  min_key_size = EXCLUDED.min_key_size,
  scan_schedule = EXCLUDED.scan_schedule,
  llm_api_key = EXCLUDED.llm_api_key,
  llm_api_url = EXCLUDED.llm_api_url,
  updated_at = now()`, fc.ExcludeDirs, fc.MinKeySize, fc.ScanSchedule, fc.LLMApiKey, fc.LLMApiUrl)
	return err
}

func (p *Postgres) GetAuditLogs(ctx context.Context) ([]AuditLog, error) {
	rows, err := p.pool.Query(ctx, `SELECT log_id, username, action, details, created_at FROM audit_logs ORDER BY created_at DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var logs []AuditLog
	for rows.Next() {
		var al AuditLog
		if err := rows.Scan(&al.LogID, &al.Username, &al.Action, &al.Details, &al.CreatedAt); err != nil {
			return nil, err
		}
		logs = append(logs, al)
	}
	return logs, nil
}

func (p *Postgres) InsertAuditLog(ctx context.Context, al *AuditLog) error {
	if al.LogID == "" {
		al.LogID = uuid.NewString()
	}
	_, err := p.pool.Exec(ctx, `INSERT INTO audit_logs (log_id, username, action, details) VALUES ($1, $2, $3, $4)`, al.LogID, al.Username, al.Action, al.Details)
	return err
}

func (p *Postgres) GetAgentDiagnostics(ctx context.Context, hostUUID string) (string, error) {
	var logs string
	err := p.pool.QueryRow(ctx, `SELECT logs FROM agent_diagnostics WHERE host_uuid = $1`, hostUUID).Scan(&logs)
	if err != nil {
		return "", nil
	}
	return logs, nil
}

func (p *Postgres) UpdateAgentDiagnostics(ctx context.Context, hostUUID, logs string) error {
	_, err := p.pool.Exec(ctx, `
INSERT INTO agent_diagnostics (host_uuid, logs, updated_at)
VALUES ($1, $2, now())
ON CONFLICT (host_uuid) DO UPDATE SET
  logs = EXCLUDED.logs,
  updated_at = now()`, hostUUID, logs)
	return err
}

func (p *Postgres) GetWebhooks(ctx context.Context) ([]Webhook, error) {
	rows, err := p.pool.Query(ctx, `SELECT webhook_id, url, secret_token, active, created_at FROM fleet_webhooks ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Webhook
	for rows.Next() {
		var w Webhook
		var activeInt int
		if err := rows.Scan(&w.WebhookID, &w.URL, &w.SecretToken, &activeInt, &w.CreatedAt); err != nil {
			return nil, err
		}
		w.Active = activeInt == 1
		list = append(list, w)
	}
	return list, nil
}

func (p *Postgres) InsertWebhook(ctx context.Context, wh *Webhook) error {
	if wh.WebhookID == "" {
		wh.WebhookID = uuid.NewString()
	}
	activeInt := 0
	if wh.Active {
		activeInt = 1
	}
	_, err := p.pool.Exec(ctx, `INSERT INTO fleet_webhooks (webhook_id, url, secret_token, active) VALUES ($1, $2, $3, $4)`, wh.WebhookID, wh.URL, wh.SecretToken, activeInt)
	return err
}

func (p *Postgres) DeleteWebhook(ctx context.Context, webhookID string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM fleet_webhooks WHERE webhook_id = $1`, webhookID)
	return err
}

func (p *Postgres) GetRetentionPolicy(ctx context.Context) (*RetentionPolicy, error) {
	var rp RetentionPolicy
	var autoPurgeInt int
	err := p.pool.QueryRow(ctx, `SELECT policy_key, retention_days, auto_purge, updated_at FROM fleet_retention_policies LIMIT 1`).Scan(&rp.PolicyKey, &rp.RetentionDays, &autoPurgeInt, &rp.UpdatedAt)
	if err != nil {
		_, _ = p.pool.Exec(ctx, `INSERT INTO fleet_retention_policies (policy_key, retention_days, auto_purge) VALUES ('default', 90, 1) ON CONFLICT DO NOTHING`)
		err = p.pool.QueryRow(ctx, `SELECT policy_key, retention_days, auto_purge, updated_at FROM fleet_retention_policies LIMIT 1`).Scan(&rp.PolicyKey, &rp.RetentionDays, &autoPurgeInt, &rp.UpdatedAt)
		if err != nil {
			return nil, err
		}
	}
	rp.AutoPurge = autoPurgeInt == 1
	return &rp, nil
}

func (p *Postgres) UpdateRetentionPolicy(ctx context.Context, rp *RetentionPolicy) error {
	autoPurgeInt := 0
	if rp.AutoPurge {
		autoPurgeInt = 1
	}
	_, err := p.pool.Exec(ctx, `
INSERT INTO fleet_retention_policies (policy_key, retention_days, auto_purge, updated_at)
VALUES ('default', $1, $2, now())
ON CONFLICT (policy_key) DO UPDATE SET
  retention_days = EXCLUDED.retention_days,
  auto_purge = EXCLUDED.auto_purge,
  updated_at = now()`, rp.RetentionDays, autoPurgeInt)
	return err
}

func (p *Postgres) PurgeOldTelemetry(ctx context.Context, days int) (int64, error) {
	cutoff := time.Now().AddDate(0, 0, -days)
	tag, err := p.pool.Exec(ctx, `DELETE FROM telemetry_payloads WHERE received_at < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	_, _ = p.pool.Exec(ctx, `DELETE FROM crypto_findings WHERE updated_at < $1`, cutoff)
	_, _ = p.pool.Exec(ctx, `DELETE FROM audit_logs WHERE created_at < $1`, cutoff)
	return tag.RowsAffected(), nil
}

type ConfigProfile struct {
	ProfileID    string    `json:"profile_id"`
	Name         string    `json:"name"`
	ExcludeDirs  string    `json:"exclude_dirs"`
	MinKeySize   int       `json:"min_key_size"`
	ScanSchedule string    `json:"scan_schedule"`
	LLMApiKey    string    `json:"llm_api_key"`
	LLMApiUrl    string    `json:"llm_api_url"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type AgentProfileMapping struct {
	HostUUID  string    `json:"host_uuid"`
	ProfileID string    `json:"profile_id"`
	MappedAt  time.Time `json:"mapped_at"`
}

func (p *Postgres) GetConfigProfiles(ctx context.Context) ([]ConfigProfile, error) {
	rows, err := p.pool.Query(ctx, `SELECT profile_id, name, exclude_dirs, min_key_size, scan_schedule, llm_api_key, llm_api_url, updated_at FROM config_profiles ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []ConfigProfile
	for rows.Next() {
		var cp ConfigProfile
		if err := rows.Scan(&cp.ProfileID, &cp.Name, &cp.ExcludeDirs, &cp.MinKeySize, &cp.ScanSchedule, &cp.LLMApiKey, &cp.LLMApiUrl, &cp.UpdatedAt); err != nil {
			return nil, err
		}
		list = append(list, cp)
	}
	return list, rows.Err()
}

func (p *Postgres) CreateConfigProfile(ctx context.Context, cp *ConfigProfile) error {
	if cp.ProfileID == "" {
		cp.ProfileID = uuid.NewString()
	}
	_, err := p.pool.Exec(ctx, `
INSERT INTO config_profiles (profile_id, name, exclude_dirs, min_key_size, scan_schedule, llm_api_key, llm_api_url, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, now())
ON CONFLICT (profile_id) DO UPDATE SET
  name = EXCLUDED.name,
  exclude_dirs = EXCLUDED.exclude_dirs,
  min_key_size = EXCLUDED.min_key_size,
  scan_schedule = EXCLUDED.scan_schedule,
  llm_api_key = EXCLUDED.llm_api_key,
  llm_api_url = EXCLUDED.llm_api_url,
  updated_at = now()`, cp.ProfileID, cp.Name, cp.ExcludeDirs, cp.MinKeySize, cp.ScanSchedule, cp.LLMApiKey, cp.LLMApiUrl)
	return err
}

func (p *Postgres) DeleteConfigProfile(ctx context.Context, profileID string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM config_profiles WHERE profile_id = $1`, profileID)
	return err
}

func (p *Postgres) GetAgentProfileMappings(ctx context.Context) ([]AgentProfileMapping, error) {
	rows, err := p.pool.Query(ctx, `SELECT host_uuid, profile_id, mapped_at FROM agent_profile_mappings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []AgentProfileMapping
	for rows.Next() {
		var apm AgentProfileMapping
		if err := rows.Scan(&apm.HostUUID, &apm.ProfileID, &apm.MappedAt); err != nil {
			return nil, err
		}
		list = append(list, apm)
	}
	return list, rows.Err()
}

func (p *Postgres) MapAgentToProfile(ctx context.Context, hostUUID, profileID string) error {
	if profileID == "" {
		_, err := p.pool.Exec(ctx, `DELETE FROM agent_profile_mappings WHERE host_uuid = $1`, hostUUID)
		return err
	}
	_, err := p.pool.Exec(ctx, `
INSERT INTO agent_profile_mappings (host_uuid, profile_id, mapped_at)
VALUES ($1, $2, now())
ON CONFLICT (host_uuid) DO UPDATE SET
  profile_id = EXCLUDED.profile_id,
  mapped_at = now()`, hostUUID, profileID)
	return err
}

func (p *Postgres) GetConfigForAgent(ctx context.Context, hostUUID string) (*FleetConfig, error) {
	var fc FleetConfig
	err := p.pool.QueryRow(ctx, `
SELECT p.profile_id, p.exclude_dirs, p.min_key_size, p.scan_schedule, p.llm_api_key, p.llm_api_url, p.updated_at
FROM agent_profile_mappings m
JOIN config_profiles p ON m.profile_id = p.profile_id
WHERE m.host_uuid = $1`, hostUUID).Scan(&fc.ConfigID, &fc.ExcludeDirs, &fc.MinKeySize, &fc.ScanSchedule, &fc.LLMApiKey, &fc.LLMApiUrl, &fc.UpdatedAt)
	if err == nil {
		return &fc, nil
	}
	return p.GetFleetConfig(ctx)
}
