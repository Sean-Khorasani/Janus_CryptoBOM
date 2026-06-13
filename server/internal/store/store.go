package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/janus-cbom/janus/server/internal/pb"
	"github.com/janus-cbom/janus/server/internal/scanconfig"
)

type Store interface {
	EnsureSchema(context.Context) error
	Ping(context.Context) error
	UpsertAgent(context.Context, *pb.AgentRegistration, string) error
	InsertTelemetry(context.Context, *pb.CbomTelemetryPayload) error
	InsertMigrationCommand(context.Context, *pb.MigrationCommand) error
	UpdateMigrationStatus(context.Context, *pb.MigrationStatusReport) error
	Overview(context.Context) (*Overview, error)
	Assets(context.Context) ([]Asset, error)
	AssetsPaginated(context.Context, FleetQueryParams) ([]Asset, int64, error)
	AgentByID(context.Context, string) (*Asset, error)
	ScanRuns(context.Context, ScanQueryParams) ([]ScanRun, int64, error)
	ConnectionHistory(context.Context, string, QueryParams) ([]ConnectionSession, int64, error)
	ReportFindings(context.Context, string, QueryParams) ([]Finding, int64, error)
	EnqueueAgentCommand(context.Context, *pb.MigrationCommand) error
	DrainAgentCommands(context.Context, string) ([]*pb.MigrationCommand, error)
	MarkAgentCommandDelivered(context.Context, string) error
	MarkAgentCommandExecuting(context.Context, string) error
	AgentCommand(context.Context, string, string) (*AgentCommand, error)
	GetAgentScanConfig(context.Context, string) (*AgentScanConfig, error)
	UpdateAgentScanConfig(context.Context, *AgentScanConfig) error
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
	CreateAnalysisJob(ctx context.Context, job *LLMAnalysisJob) error
	GetAnalysisJob(ctx context.Context, jobID string) (*LLMAnalysisJob, error)
	UpdateAnalysisJob(ctx context.Context, job *LLMAnalysisJob) error
	ListAnalysisJobs(ctx context.Context, params QueryParams) ([]LLMAnalysisJob, int64, error)
	CreateVerdict(ctx context.Context, verdict *LLMVerdict) error
	GetVerdictByFinding(ctx context.Context, findingID string) (*LLMVerdict, error)
	GetVerdictByJob(ctx context.Context, jobID string) (*LLMVerdict, error)
	RecordProvenance(ctx context.Context, prov *LLMProvenance) error
	ListProvenance(ctx context.Context, findingID string) ([]LLMProvenance, error)
	UpsertAgilityMetrics(ctx context.Context, metrics *AgilityMetrics) error
	GetAgilityMetrics(ctx context.Context, hostUUID string) (*AgilityMetrics, error)
	GetFleetAgilityMetrics(ctx context.Context) ([]AgilityMetrics, error)
	CreateWavePlan(ctx context.Context, plan *WavePlan) error
	GetWavePlans(ctx context.Context) ([]WavePlan, error)
	UpdateWavePlan(ctx context.Context, plan *WavePlan) error
	DeleteWavePlan(ctx context.Context, planID string) error
	RecordLifecycleEvent(ctx context.Context, evt *FindingLifecycleEvent) error
	ListLifecycleEvents(ctx context.Context, findingID string) ([]FindingLifecycleEvent, error)
	GetCertHealth(ctx context.Context) (*CertHealth, error)
}

type CertHealth struct {
	Expired       int `json:"expired"`
	Expiring30    int `json:"expiring_30_days"`
	Expiring90    int `json:"expiring_90_days"`
	TotalTracked  int `json:"total_tracked"`
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
	StalledAgents      int64            `json:"stalled_agents"`
	ReadinessScore     int              `json:"readiness_score"`
	ReadinessBreakdown map[string]int   `json:"readiness_breakdown"`
	AlgorithmHistogram map[string]int64 `json:"algorithm_histogram"`
}

type Asset struct {
	HostUUID          string     `json:"host_uuid"`
	Hostname          string     `json:"hostname"`
	OSName            string     `json:"os_name"`
	OSVersion         string     `json:"os_version"`
	Arch              string     `json:"arch"`
	ExecutionMode     int32      `json:"execution_mode"`
	LastSeen          time.Time  `json:"last_seen"`
	ScanProgress      int        `json:"scan_progress"`
	CurrentScanPath   string     `json:"current_scan_path"`
	CPUUsage          float64    `json:"cpu_usage"`
	MemUsage          float64    `json:"mem_usage"`
	Status            string     `json:"status"`
	TotalFilesScanned int        `json:"total_files_scanned"`
	AgentVersion      string     `json:"agent_version"`
	ObservedIP        string     `json:"observed_ip"`
	DNSName           string     `json:"dns_name"`
	FirstRegisteredAt time.Time  `json:"first_registered_at"`
	LastRegisteredAt  time.Time  `json:"last_registered_at"`
	LastScanID        string     `json:"last_scan_id"`
	LastScanFinished  *time.Time `json:"last_scan_finished,omitempty"`
	LastScanSeverity  int        `json:"last_scan_severity"`
	OpenFindings      int        `json:"open_findings"`
}

type AgentHeartbeat struct {
	HostUUID          string  `json:"host_uuid"`
	ScanProgress      int     `json:"scan_progress"`
	CurrentScanPath   string  `json:"current_scan_path"`
	CPUUsage          float64 `json:"cpu_usage"`
	MemUsage          float64 `json:"mem_usage"`
	Status            string  `json:"status"`
	TotalFilesScanned int     `json:"total_files_scanned"`
	MetricsPresent    *bool   `json:"metrics_present,omitempty"`
}

type Finding struct {
	FindingID        string     `json:"finding_id"`
	HostUUID         string     `json:"host_uuid"`
	Severity         int32      `json:"severity"`
	Title            string     `json:"title"`
	Description      string     `json:"description"`
	AssetRef         string     `json:"asset_ref"`
	Algorithm        string     `json:"algorithm"`
	PolicyRuleID     string     `json:"policy_rule_id"`
	MigrationProfile string     `json:"migration_profile"`
	Status           string     `json:"status"` // open | accepted_risk | false_positive | remediated
	UpdatedBy        string     `json:"updated_by"`
	UpdatedAt        time.Time  `json:"updated_at"`
	CreatedAt        time.Time  `json:"created_at"`
	Confidence       float64    `json:"confidence"`
	TelemetryID      string     `json:"telemetry_id"`
	Hostname         string     `json:"hostname"`
	AgentVersion     string     `json:"agent_version"`
	ScanFinished     *time.Time `json:"scan_finished,omitempty"`
}

// QueryParams is used for paginated, filtered, sorted queries.
type QueryParams struct {
	Limit     int
	Offset    int
	Sort      string // column name
	Order     string // asc | desc
	Search    string // keyword filter
	HostUUID  string
	ScanID    string
	Algorithm string
	AssetRef  string
	DateFrom  *time.Time
	DateTo    *time.Time
}

type FleetQueryParams struct {
	QueryParams
	Status   string
	OSName   string
	Severity int
	DateFrom *time.Time
	DateTo   *time.Time
}

type ScanQueryParams struct {
	QueryParams
	HostUUID string
	Severity int
	DateFrom *time.Time
	DateTo   *time.Time
}

type ScanRun struct {
	ScanID                  string    `json:"scan_id"`
	HostUUID                string    `json:"host_uuid"`
	Hostname                string    `json:"hostname"`
	AgentVersion            string    `json:"agent_version"`
	OSName                  string    `json:"os_name"`
	OSVersion               string    `json:"os_version"`
	ObservedIP              string    `json:"observed_ip"`
	ScanStarted             time.Time `json:"scan_started"`
	ScanFinished            time.Time `json:"scan_finished"`
	ReceivedAt              time.Time `json:"received_at"`
	Status                  string    `json:"status"`
	ComponentCount          int       `json:"component_count"`
	FindingCount            int       `json:"finding_count"`
	CriticalCount           int       `json:"critical_count"`
	HighCount               int       `json:"high_count"`
	MaxSeverity             int       `json:"max_severity"`
	NetworkObservationCount int       `json:"network_observation_count"`
}

type ConnectionSession struct {
	SessionID      string     `json:"session_id"`
	HostUUID       string     `json:"host_uuid"`
	ConnectedAt    time.Time  `json:"connected_at"`
	DisconnectedAt *time.Time `json:"disconnected_at,omitempty"`
	LastSeen       time.Time  `json:"last_seen"`
	ObservedIP     string     `json:"observed_ip"`
	AgentVersion   string     `json:"agent_version"`
	Status         string     `json:"status"`
}

type AgentCommand struct {
	CommandID   string     `json:"command_id"`
	HostUUID    string     `json:"host_uuid"`
	Command     string     `json:"command"`
	Status      string     `json:"status"`
	QueuedAt    time.Time  `json:"queued_at"`
	DeliveredAt *time.Time `json:"delivered_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

type AgentScanConfig struct {
	HostUUID                    string   `json:"host_uuid"`
	Configured                  bool     `json:"configured"`
	PolicyVersion               string   `json:"policy_version"`
	ScanRoots                   []string `json:"scan_roots"`
	ExcludeDirs                 []string `json:"exclude_dirs"`
	IncludeExtensions           []string `json:"include_extensions"`
	ScanIntervalSeconds         uint64   `json:"scan_interval_seconds"`
	MaxFileBytes                uint64   `json:"max_file_bytes"`
	MaxBinaryBytes              uint64   `json:"max_binary_bytes"`
	NetworkTargets              []string `json:"network_targets"`
	EnableRuntimeDiscovery      bool     `json:"enable_runtime_discovery"`
	EnableProcessMemoryScraping bool     `json:"enable_process_memory_scraping"`
	EnablePluginDiscovery       bool     `json:"enable_plugin_discovery"`
	EnableActiveTLSProbing      bool     `json:"enable_active_tls_probing"`
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
	CommandID        string                 `json:"command_id"`
	HostUUID         string                 `json:"host_uuid"`
	TargetService    string                 `json:"target_service"`
	MigrationProfile string                 `json:"migration_profile"`
	TargetKEM        string                 `json:"target_kem"`
	TargetSignature  string                 `json:"target_signature"`
	ConfigPath       string                 `json:"config_path"`
	State            int32                  `json:"state"`
	DryRun           bool                   `json:"dry_run"`
	IssuedAt         time.Time              `json:"issued_at"`
	UpdatedAt        time.Time              `json:"updated_at"`
	LastError        string                 `json:"last_error"`
	Output           string                 `json:"output"`
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

// PostgresConfig holds database connection and pool settings.
type PostgresConfig struct {
	DatabaseURL     string
	MaxConns        int
	MinConns        int
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
}

type LLMAnalysisJob struct {
	JobID       string     `json:"job_id"`
	FindingID   string     `json:"finding_id"`
	JobType     string     `json:"job_type"`
	Status      string     `json:"status"`
	ErrorMsg    string     `json:"error,omitempty"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

type LLMVerdict struct {
	VerdictID         string    `json:"verdict_id"`
	JobID             string    `json:"job_id"`
	FindingID         string    `json:"finding_id"`
	Verdict           string    `json:"verdict"`
	AdjustedSeverity  *int      `json:"adjusted_severity,omitempty"`
	Confidence        float64   `json:"confidence"`
	Reasoning         string    `json:"reasoning"`
	EvidenceCitations []string  `json:"evidence_citations"`
	AbstentionReason  string    `json:"abstention_reason,omitempty"`
	Model             string    `json:"model"`
	PromptVersion     string    `json:"prompt_version"`
	CreatedAt         time.Time `json:"created_at"`
}

type LLMProvenance struct {
	ProvenanceID  string    `json:"provenance_id"`
	JobID         string    `json:"job_id"`
	FindingID     string    `json:"finding_id"`
	Provider      string    `json:"provider"`
	Model         string    `json:"model"`
	PromptName    string    `json:"prompt_name"`
	PromptVersion string    `json:"prompt_version"`
	InputHash     string    `json:"input_hash"`
	OutputHash    string    `json:"output_hash"`
	TokensIn      int       `json:"tokens_input"`
	TokensOut     int       `json:"tokens_output"`
	LatencyMS     int       `json:"latency_ms"`
	CreatedAt     time.Time `json:"created_at"`
}

type AgilityMetrics struct {
	MetricID                   string     `json:"metric_id"`
	HostUUID                   string     `json:"host_uuid"`
	MeasurementDate            time.Time  `json:"measurement_date"`
	TTSADays                   *float64   `json:"ttsa_days,omitempty"`
	HardcodeIndex              float64    `json:"hardcode_index"`
	NegotiationCoverage        float64    `json:"negotiation_coverage"`
	ProfileAdoptionLatencyDays *float64   `json:"profile_adoption_latency_days,omitempty"`
	BlastRadiusScore           float64    `json:"blast_radius_score"`
	MeasuredAt                 time.Time  `json:"measured_at"`
}

type WavePlan struct {
	PlanID             string     `json:"plan_id"`
	Name               string     `json:"name"`
	Description        string     `json:"description"`
	WaveNumber         int        `json:"wave_number"`
	AssetIDs           []string   `json:"asset_ids"`
	AlgorithmTargets   []string   `json:"algorithm_targets"`
	StartDate          *time.Time `json:"start_date,omitempty"`
	TargetDate         *time.Time `json:"target_date,omitempty"`
	Status             string     `json:"status"`
	CreatedBy          string     `json:"created_by"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	CanaryTargets      []string   `json:"canary_targets,omitempty" db:"canary_targets"`
	MaintenanceWindow  string     `json:"maintenance_window,omitempty" db:"maintenance_window"`
	ApprovalPolicy     string     `json:"approval_policy,omitempty" db:"approval_policy"`
	BudgetHours        float64    `json:"budget_hours,omitempty" db:"budget_hours"`
	ActualHours        float64    `json:"actual_hours,omitempty" db:"actual_hours"`
	ComponentCount     int        `json:"component_count,omitempty" db:"component_count"`
}

type FindingLifecycleEvent struct {
	EventID    string    `json:"event_id"`
	FindingID  string    `json:"finding_id"`
	HostUUID   string    `json:"host_uuid"`
	EventType  string    `json:"event_type"`
	FromStatus string    `json:"from_status"`
	ToStatus   string    `json:"to_status"`
	Actor      string    `json:"actor"`
	Reason     string    `json:"reason"`
	OccurredAt time.Time `json:"occurred_at"`
}

func NewPostgres(ctx context.Context, cfg PostgresConfig) (*Postgres, error) {
	if cfg.DatabaseURL == "" {
		return nil, errors.New("database URL is required")
	}
	poolCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	if cfg.MaxConns > 0 {
		poolCfg.MaxConns = int32(cfg.MaxConns)
	} else {
		poolCfg.MaxConns = 25
	}
	if cfg.MinConns > 0 {
		poolCfg.MinConns = int32(cfg.MinConns)
	} else {
		poolCfg.MinConns = 5
	}
	if cfg.MaxConnLifetime > 0 {
		poolCfg.MaxConnLifetime = cfg.MaxConnLifetime
	}
	if cfg.MaxConnIdleTime > 0 {
		poolCfg.MaxConnIdleTime = cfg.MaxConnIdleTime
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
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

// migration represents a versioned database schema migration.
type migration struct {
	Version     int
	Description string
	SQL         string
}

// migrations defines all schema versions in order. New migrations are appended.
var migrations = []migration{
	{1, "Initial schema: assets, telemetry_payloads, crypto_findings, migration_transactions", schemaSQL},
	{2, "Add finding status/metadata columns", `
ALTER TABLE crypto_findings ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'open';
ALTER TABLE crypto_findings ADD COLUMN IF NOT EXISTS updated_by TEXT NOT NULL DEFAULT '';
ALTER TABLE crypto_findings ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE crypto_findings ADD COLUMN IF NOT EXISTS confidence DOUBLE PRECISION NOT NULL DEFAULT 0.82;
ALTER TABLE migration_transactions ADD COLUMN IF NOT EXISTS observed_tls JSONB;
`},
	{3, "Add asset telemetry columns", `
ALTER TABLE assets ADD COLUMN IF NOT EXISTS scan_progress INTEGER NOT NULL DEFAULT 0;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS current_scan_path TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN IF NOT EXISTS cpu_usage DOUBLE PRECISION NOT NULL DEFAULT 0.0;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS mem_usage DOUBLE PRECISION NOT NULL DEFAULT 0.0;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'offline';
ALTER TABLE assets ADD COLUMN IF NOT EXISTS total_files_scanned INTEGER NOT NULL DEFAULT 0;
`},
	{4, "Fleet management tables", `
CREATE TABLE IF NOT EXISTS fleet_configs (
  config_id TEXT PRIMARY KEY,
  exclude_dirs TEXT NOT NULL DEFAULT '',
  min_key_size INTEGER NOT NULL DEFAULT 2048,
  scan_schedule TEXT NOT NULL DEFAULT 'daily',
  llm_api_key TEXT NOT NULL DEFAULT '',
  llm_api_url TEXT NOT NULL DEFAULT 'https://api.openai.com/v1',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS config_profiles (
  profile_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  exclude_dirs TEXT NOT NULL DEFAULT '',
  min_key_size INTEGER NOT NULL DEFAULT 2048,
  scan_schedule TEXT NOT NULL DEFAULT 'daily',
  llm_api_key TEXT NOT NULL DEFAULT '',
  llm_api_url TEXT NOT NULL DEFAULT 'https://api.openai.com/v1',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS agent_profile_mappings (
  host_uuid TEXT PRIMARY KEY REFERENCES assets(host_uuid) ON DELETE CASCADE,
  profile_id TEXT NOT NULL REFERENCES config_profiles(profile_id) ON DELETE CASCADE,
  mapped_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
`},
	{5, "Audit, diagnostics, webhooks, retention tables", `
CREATE TABLE IF NOT EXISTS audit_logs (
  log_id TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  action TEXT NOT NULL,
  details TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS agent_diagnostics (
  host_uuid TEXT PRIMARY KEY REFERENCES assets(host_uuid) ON DELETE CASCADE,
  logs TEXT NOT NULL DEFAULT '',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS fleet_webhooks (
  webhook_id TEXT PRIMARY KEY,
  url TEXT NOT NULL,
  secret_token TEXT NOT NULL DEFAULT '',
  active INTEGER NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS fleet_retention_policies (
  policy_key TEXT PRIMARY KEY,
  retention_days INTEGER NOT NULL DEFAULT 90,
  auto_purge INTEGER NOT NULL DEFAULT 1,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
`},
	{6, "Advanced settings table", `
CREATE TABLE IF NOT EXISTS advanced_settings (
  setting_key TEXT PRIMARY KEY,
  setting_value JSONB NOT NULL DEFAULT '{}',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
`},
	{7, "Webhook failure tracking", `
	ALTER TABLE fleet_webhooks ADD COLUMN IF NOT EXISTS failure_count INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE fleet_webhooks ADD COLUMN IF NOT EXISTS last_failure TIMESTAMPTZ;
`},
	{8, "Finding outcomes for confidence analysis", `
CREATE TABLE IF NOT EXISTS finding_outcomes (
  outcome_id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL,
  was_real_finding BOOLEAN NOT NULL,
  operator_feedback TEXT NOT NULL DEFAULT '',
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
`},
	{9, "Advisory cache for third-party vulnerability lookups", `
CREATE TABLE IF NOT EXISTS advisory_cache (
  cve_id TEXT NOT NULL,
  source TEXT NOT NULL,
  package_name TEXT NOT NULL,
  package_version TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  advisory_data JSONB NOT NULL DEFAULT '{}',
  cached_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (cve_id, source)
);
CREATE INDEX IF NOT EXISTS idx_advisory_cache_lookup ON advisory_cache(package_name, package_version, ecosystem);
`},
	{10, "Agent fleet identity and immutable scan history", `
ALTER TABLE assets ADD COLUMN IF NOT EXISTS agent_version TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN IF NOT EXISTS observed_ip TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN IF NOT EXISTS dns_name TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN IF NOT EXISTS first_registered_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE assets ADD COLUMN IF NOT EXISTS last_registered_at TIMESTAMPTZ NOT NULL DEFAULT now();

CREATE TABLE IF NOT EXISTS agent_connection_sessions (
  session_id TEXT PRIMARY KEY,
  host_uuid TEXT NOT NULL REFERENCES assets(host_uuid) ON DELETE CASCADE,
  connected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  disconnected_at TIMESTAMPTZ,
  last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
  observed_ip TEXT NOT NULL DEFAULT '',
  agent_version TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'online'
);
CREATE TABLE IF NOT EXISTS scan_runs (
  scan_id TEXT PRIMARY KEY,
  host_uuid TEXT NOT NULL REFERENCES assets(host_uuid) ON DELETE CASCADE,
  agent_version TEXT NOT NULL DEFAULT '',
  os_name TEXT NOT NULL DEFAULT '',
  os_version TEXT NOT NULL DEFAULT '',
  observed_ip TEXT NOT NULL DEFAULT '',
  scan_started TIMESTAMPTZ NOT NULL,
  scan_finished TIMESTAMPTZ NOT NULL,
  received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  status TEXT NOT NULL DEFAULT 'completed',
  component_count INTEGER NOT NULL DEFAULT 0,
  finding_count INTEGER NOT NULL DEFAULT 0,
  critical_count INTEGER NOT NULL DEFAULT 0,
  high_count INTEGER NOT NULL DEFAULT 0,
  max_severity INTEGER NOT NULL DEFAULT 0,
  network_observation_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS finding_occurrences (
  occurrence_id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scan_runs(scan_id) ON DELETE CASCADE,
  finding_id TEXT NOT NULL,
  host_uuid TEXT NOT NULL REFERENCES assets(host_uuid) ON DELETE CASCADE,
  severity INTEGER NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  asset_ref TEXT NOT NULL,
  algorithm TEXT NOT NULL,
  policy_rule_id TEXT NOT NULL,
  migration_profile TEXT NOT NULL,
  evidence_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  confidence DOUBLE PRECISION NOT NULL DEFAULT 0.82,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS agent_progress_events (
  event_id TEXT PRIMARY KEY,
  host_uuid TEXT NOT NULL REFERENCES assets(host_uuid) ON DELETE CASCADE,
  scan_id TEXT,
  progress INTEGER NOT NULL DEFAULT 0,
  current_path TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT '',
  files_processed INTEGER NOT NULL DEFAULT 0,
  cpu_usage DOUBLE PRECISION NOT NULL DEFAULT 0,
  mem_usage DOUBLE PRECISION NOT NULL DEFAULT 0,
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_assets_fleet_last_seen ON assets(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_assets_fleet_status ON assets(status, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_assets_fleet_os ON assets(os_name, os_version);
CREATE INDEX IF NOT EXISTS idx_connections_host_time ON agent_connection_sessions(host_uuid, connected_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_runs_host_time ON scan_runs(host_uuid, scan_finished DESC);
CREATE INDEX IF NOT EXISTS idx_scan_runs_severity_time ON scan_runs(max_severity DESC, scan_finished DESC);
CREATE INDEX IF NOT EXISTS idx_occurrences_scan_severity ON finding_occurrences(scan_id, severity DESC);
CREATE INDEX IF NOT EXISTS idx_occurrences_host_time ON finding_occurrences(host_uuid, created_at DESC);
`},
	{11, "Backfill historical scan summaries and current finding provenance", `
INSERT INTO scan_runs (scan_id, host_uuid, agent_version, os_name, os_version, observed_ip, scan_started, scan_finished, received_at, status, component_count, finding_count, critical_count, high_count, max_severity, network_observation_count)
SELECT tp.telemetry_id, tp.host_uuid, a.agent_version, a.os_name, a.os_version, a.observed_ip,
       tp.scan_started, tp.scan_finished, tp.received_at, 'completed', tp.component_count, tp.finding_count,
       COALESCE((SELECT count(*) FROM crypto_findings cf WHERE cf.telemetry_id=tp.telemetry_id AND cf.severity>=5),0),
       COALESCE((SELECT count(*) FROM crypto_findings cf WHERE cf.telemetry_id=tp.telemetry_id AND cf.severity=4),0),
       COALESCE((SELECT max(severity) FROM crypto_findings cf WHERE cf.telemetry_id=tp.telemetry_id),0),
       tp.network_observation_count
FROM telemetry_payloads tp JOIN assets a ON a.host_uuid=tp.host_uuid
ON CONFLICT (scan_id) DO NOTHING;
INSERT INTO finding_occurrences (occurrence_id, scan_id, finding_id, host_uuid, severity, title, description, asset_ref, algorithm, policy_rule_id, migration_profile, evidence_ids, confidence, created_at)
SELECT cf.telemetry_id || ':' || cf.finding_id, cf.telemetry_id, cf.finding_id, cf.host_uuid, cf.severity, cf.title, cf.description,
       cf.asset_ref, cf.algorithm, cf.policy_rule_id, cf.migration_profile, cf.evidence_ids, cf.confidence, cf.created_at
FROM crypto_findings cf
ON CONFLICT (occurrence_id) DO NOTHING;
`},
	{12, "Normalize scan components for indexed contextual queries", `
CREATE TABLE IF NOT EXISTS scan_components (
  scan_id TEXT NOT NULL REFERENCES scan_runs(scan_id) ON DELETE CASCADE,
  host_uuid TEXT NOT NULL REFERENCES assets(host_uuid) ON DELETE CASCADE,
  bom_ref TEXT NOT NULL,
  name TEXT NOT NULL,
  version TEXT NOT NULL DEFAULT '',
  component_type TEXT NOT NULL DEFAULT '',
  file_path TEXT NOT NULL DEFAULT '',
  language TEXT NOT NULL DEFAULT '',
  algorithms JSONB NOT NULL DEFAULT '[]'::jsonb,
  dependencies JSONB NOT NULL DEFAULT '[]'::jsonb,
  reachable BOOLEAN NOT NULL DEFAULT false,
  scan_finished TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (scan_id, bom_ref)
);
CREATE INDEX IF NOT EXISTS idx_scan_components_host_time ON scan_components(host_uuid, scan_finished DESC);
CREATE INDEX IF NOT EXISTS idx_scan_components_file ON scan_components(file_path);
`},
	{13, "Durable agent command queue", `
CREATE TABLE IF NOT EXISTS agent_commands (
  command_id TEXT PRIMARY KEY,
  host_uuid TEXT NOT NULL REFERENCES assets(host_uuid) ON DELETE CASCADE,
  command_payload JSONB NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  queued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  delivered_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_agent_commands_delivery ON agent_commands(host_uuid, status, queued_at);
`},
	{14, "Separate managed agents from synthetic scan identities", `
ALTER TABLE assets ADD COLUMN IF NOT EXISTS managed_agent BOOLEAN NOT NULL DEFAULT true;
UPDATE assets SET managed_agent=false WHERE host_uuid='ci-cd-runner';
CREATE INDEX IF NOT EXISTS idx_assets_managed_last_seen ON assets(managed_agent, last_seen DESC);
`},
	{15, "Track command completion and per-agent scan configuration", `
ALTER TABLE agent_commands ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ;
CREATE TABLE IF NOT EXISTS agent_scan_configs (
  host_uuid TEXT PRIMARY KEY REFERENCES assets(host_uuid) ON DELETE CASCADE,
  config JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
`},
	{16, "Remove fabricated reconnect sessions", `
DELETE FROM agent_connection_sessions WHERE status='reconnected';
`},
	{17, "Compact duplicate idle progress events", `
DELETE FROM agent_progress_events older
USING agent_progress_events newer
WHERE older.host_uuid=newer.host_uuid
  AND older.status='Idle' AND newer.status='Idle'
  AND older.progress=newer.progress
  AND older.current_path=newer.current_path
  AND older.files_processed=newer.files_processed
  AND older.recorded_at < newer.recorded_at;
CREATE INDEX IF NOT EXISTS idx_agent_progress_host_time ON agent_progress_events(host_uuid, recorded_at DESC);
`},
	{18, "LLM analysis job queue", `
CREATE TABLE IF NOT EXISTS llm_analysis_jobs (
  job_id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL,
  job_type TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  error_msg TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_llm_jobs_finding ON llm_analysis_jobs(finding_id);
CREATE INDEX IF NOT EXISTS idx_llm_jobs_status ON llm_analysis_jobs(status, created_at DESC);
`},
	{19, "LLM structured verdicts", `
CREATE TABLE IF NOT EXISTS llm_verdicts (
  verdict_id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES llm_analysis_jobs(job_id) ON DELETE CASCADE,
  finding_id TEXT NOT NULL,
  verdict TEXT NOT NULL,
  adjusted_severity INTEGER,
  confidence DOUBLE PRECISION NOT NULL DEFAULT 0.0,
  reasoning TEXT NOT NULL DEFAULT '',
  evidence_citations JSONB NOT NULL DEFAULT '[]'::jsonb,
  abstention_reason TEXT NOT NULL DEFAULT '',
  model TEXT NOT NULL DEFAULT '',
  prompt_version TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_llm_verdicts_job ON llm_verdicts(job_id);
CREATE INDEX IF NOT EXISTS idx_llm_verdicts_finding ON llm_verdicts(finding_id, created_at DESC);
`},
	{20, "LLM call provenance audit trail", `
CREATE TABLE IF NOT EXISTS llm_provenance (
  provenance_id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES llm_analysis_jobs(job_id) ON DELETE CASCADE,
  finding_id TEXT NOT NULL,
  provider TEXT NOT NULL DEFAULT '',
  model TEXT NOT NULL DEFAULT '',
  prompt_name TEXT NOT NULL DEFAULT '',
  prompt_version TEXT NOT NULL DEFAULT '',
  input_hash TEXT NOT NULL DEFAULT '',
  output_hash TEXT NOT NULL DEFAULT '',
  tokens_in INTEGER NOT NULL DEFAULT 0,
  tokens_out INTEGER NOT NULL DEFAULT 0,
  latency_ms INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_llm_provenance_job ON llm_provenance(job_id);
CREATE INDEX IF NOT EXISTS idx_llm_provenance_finding ON llm_provenance(finding_id);
`},
	{21, "Crypto agility metrics per host", `
CREATE TABLE IF NOT EXISTS agility_metrics (
  metric_id TEXT PRIMARY KEY,
  host_uuid TEXT NOT NULL REFERENCES assets(host_uuid) ON DELETE CASCADE,
  measurement_date DATE NOT NULL,
  ttsa_days DOUBLE PRECISION,
  hardcode_index DOUBLE PRECISION NOT NULL DEFAULT 0.0,
  negotiation_coverage DOUBLE PRECISION NOT NULL DEFAULT 0.0,
  profile_adoption_latency_days DOUBLE PRECISION,
  blast_radius_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
  measured_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (host_uuid, measurement_date)
);
CREATE INDEX IF NOT EXISTS idx_agility_metrics_host ON agility_metrics(host_uuid, measurement_date DESC);
`},
	{22, "Migration wave plans", `
CREATE TABLE IF NOT EXISTS wave_plans (
  plan_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  wave_number INTEGER NOT NULL DEFAULT 1,
  asset_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  algorithm_targets JSONB NOT NULL DEFAULT '[]'::jsonb,
  start_date DATE,
  target_date DATE,
  status TEXT NOT NULL DEFAULT 'planned',
  created_by TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_wave_plans_status ON wave_plans(status, wave_number);
`},
	{23, "Finding occurrence lifecycle tracking (WP-013)", `
ALTER TABLE finding_occurrences
  ADD COLUMN IF NOT EXISTS detection_method TEXT NOT NULL DEFAULT 'regex_match',
  ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS reopened_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS reopen_count INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_occurrences_finding_time ON finding_occurrences(finding_id, created_at DESC);
CREATE TABLE IF NOT EXISTS finding_lifecycle_events (
  event_id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL,
  host_uuid TEXT NOT NULL REFERENCES assets(host_uuid) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  from_status TEXT NOT NULL DEFAULT '',
  to_status TEXT NOT NULL,
  actor TEXT NOT NULL DEFAULT 'system',
  reason TEXT NOT NULL DEFAULT '',
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_lifecycle_finding ON finding_lifecycle_events(finding_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_lifecycle_host ON finding_lifecycle_events(host_uuid, occurred_at DESC);
`},
	{24, "TLS certificate health tracking (WP-018)", `
CREATE TABLE IF NOT EXISTS tls_certificates (
  cert_id TEXT PRIMARY KEY,
  host_uuid TEXT NOT NULL REFERENCES assets(host_uuid) ON DELETE CASCADE,
  target TEXT NOT NULL,
  protocol_version TEXT NOT NULL DEFAULT '',
  cipher_suite TEXT NOT NULL DEFAULT '',
  subject TEXT NOT NULL DEFAULT '',
  issuer TEXT NOT NULL DEFAULT '',
  not_after TIMESTAMPTZ,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  scan_id TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_tls_certs_expiry ON tls_certificates(not_after) WHERE not_after IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tls_certs_host ON tls_certificates(host_uuid, last_seen_at DESC);
`},
	{25, "Wave plan canary/maintenance/approval fields (WP-022)", `
ALTER TABLE wave_plans
  ADD COLUMN IF NOT EXISTS canary_targets TEXT[] DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS maintenance_window TEXT DEFAULT '',
  ADD COLUMN IF NOT EXISTS approval_policy TEXT DEFAULT 'operator' CHECK (approval_policy IN ('auto','operator','admin'));
`},
	{26, "Finding reopen tracking columns (WP-013)", `
ALTER TABLE crypto_findings ADD COLUMN IF NOT EXISTS reopen_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE crypto_findings ADD COLUMN IF NOT EXISTS reopened_at TIMESTAMPTZ;
`},
	{27, "Wave plan budget and effort tracking (WP-022)", `
ALTER TABLE wave_plans
ADD COLUMN IF NOT EXISTS budget_hours FLOAT8 DEFAULT 0,
ADD COLUMN IF NOT EXISTS actual_hours FLOAT8 DEFAULT 0,
ADD COLUMN IF NOT EXISTS component_count INTEGER DEFAULT 0;
`},
}

func (p *Postgres) UpsertAgent(ctx context.Context, reg *pb.AgentRegistration, observedIP string) error {
	caps, err := json.Marshal(reg.Capabilities)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx, `
INSERT INTO assets (host_uuid, hostname, os_name, os_version, arch, execution_mode, capabilities, last_seen, agent_version, observed_ip, dns_name, first_registered_at, last_registered_at, managed_agent)
VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, now(), $8, $9, $2, now(), now(), true)
ON CONFLICT (host_uuid) DO UPDATE SET
  hostname = EXCLUDED.hostname,
  os_name = EXCLUDED.os_name,
  os_version = EXCLUDED.os_version,
  arch = EXCLUDED.arch,
  execution_mode = EXCLUDED.execution_mode,
  capabilities = EXCLUDED.capabilities,
  agent_version = EXCLUDED.agent_version,
  observed_ip = EXCLUDED.observed_ip,
  dns_name = EXCLUDED.dns_name,
  managed_agent = true,
  last_registered_at = now(),
  last_seen = now()`,
		reg.HostUuid, reg.Hostname, reg.OsName, reg.OsVersion, reg.Arch, reg.ExecutionMode, string(caps), reg.AgentVersion, observedIP)
	if err != nil {
		return err
	}
	tag, err := p.pool.Exec(ctx, `UPDATE agent_connection_sessions
SET last_seen=now(), observed_ip=$2, agent_version=$3
WHERE session_id=(
  SELECT session_id FROM agent_connection_sessions
  WHERE host_uuid=$1 AND disconnected_at IS NULL AND last_seen >= now() - interval '30 seconds'
  ORDER BY connected_at DESC LIMIT 1
)`, reg.HostUuid, observedIP, reg.AgentVersion)
	if err != nil {
		return err
	}
	if tag.RowsAffected() > 0 {
		return nil
	}
	_, err = p.pool.Exec(ctx, `UPDATE agent_connection_sessions
SET disconnected_at=COALESCE(disconnected_at,last_seen), status='disconnected'
WHERE host_uuid=$1 AND disconnected_at IS NULL`, reg.HostUuid)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx, `INSERT INTO agent_connection_sessions (session_id, host_uuid, observed_ip, agent_version)
VALUES ($2, $1, $3, $4)`, reg.HostUuid, uuid.NewString(), observedIP, reg.AgentVersion)
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
	_, _ = tx.Exec(ctx, `UPDATE agent_commands SET status='completed', completed_at=now()
WHERE host_uuid=$1 AND status='executing'`, payload.HostUuid)

	var criticalCount, highCount, maxSeverity int
	for _, finding := range payload.Findings {
		severity := int(finding.Severity)
		if severity > maxSeverity {
			maxSeverity = severity
		}
		if severity >= int(pb.RiskSeverityCritical) {
			criticalCount++
		} else if severity == int(pb.RiskSeverityHigh) {
			highCount++
		}
	}
	_, err = tx.Exec(ctx, `
INSERT INTO scan_runs (
  scan_id, host_uuid, agent_version, os_name, os_version, observed_ip,
  scan_started, scan_finished, received_at, status, component_count, finding_count,
  critical_count, high_count, max_severity, network_observation_count
)
SELECT $1, a.host_uuid, a.agent_version, a.os_name, a.os_version, a.observed_ip,
       to_timestamp($2), to_timestamp($3), now(), 'completed', $4, $5, $6, $7, $8, $9
FROM assets a WHERE a.host_uuid=$10
ON CONFLICT (scan_id) DO NOTHING`,
		payload.TelemetryId, payload.ScanStartedUnix, payload.ScanFinishedUnix,
		len(payload.Components), len(payload.Findings), criticalCount, highCount, maxSeverity,
		len(payload.NetworkObservations), payload.HostUuid)
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
		_, err = tx.Exec(ctx, `
INSERT INTO finding_occurrences (
  occurrence_id, scan_id, finding_id, host_uuid, severity, title, description,
  asset_ref, algorithm, policy_rule_id, migration_profile, evidence_ids, confidence
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13)
ON CONFLICT (occurrence_id) DO NOTHING`,
			payload.TelemetryId+":"+f.FindingId, payload.TelemetryId, f.FindingId, payload.HostUuid,
			f.Severity, f.Title, f.Description, f.AssetRef, f.Algorithm, f.PolicyRuleId,
			f.MigrationProfile, string(evidenceIDs), confidence)
		if err != nil {
			return err
		}

		// Auto-reopen: if the canonical finding for this (asset_ref, algorithm, policy_rule_id)
		// was previously closed (remediated or accepted_risk), reopen it and record a lifecycle event.
		// We look up by the conflict key tuple — not f.FindingId, which may change between scans.
		var storedFindingID, storedStatus, storedHostUUID string
		err = tx.QueryRow(ctx,
			`SELECT finding_id, status, host_uuid FROM crypto_findings
			 WHERE asset_ref=$1 AND algorithm=$2 AND policy_rule_id=$3`,
			f.AssetRef, f.Algorithm, f.PolicyRuleId,
		).Scan(&storedFindingID, &storedStatus, &storedHostUUID)
		if err == nil && (storedStatus == "remediated" || storedStatus == "accepted_risk") {
			_, err = tx.Exec(ctx,
				`UPDATE crypto_findings
				 SET status='open', reopen_count=reopen_count+1, reopened_at=now(), updated_at=now(), updated_by='system'
				 WHERE finding_id=$1`,
				storedFindingID)
			if err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `
INSERT INTO finding_lifecycle_events (event_id, finding_id, host_uuid, event_type, from_status, to_status, actor, reason, occurred_at)
VALUES ($1, $2, $3, 'reopened', $4, 'open', 'system', 'finding recurred in scan', now())
ON CONFLICT (event_id) DO NOTHING`,
				uuid.New().String(), storedFindingID, storedHostUUID, storedStatus)
			if err != nil {
				return err
			}
		}
	}
	for _, component := range payload.Components {
		algorithms := make([]string, 0, len(component.Algorithms))
		for _, algorithm := range component.Algorithms {
			if algorithm.Name != "" {
				algorithms = append(algorithms, algorithm.Name)
			}
		}
		algorithmJSON, _ := json.Marshal(algorithms)
		dependencyJSON, _ := json.Marshal(component.Dependencies)
		_, err = tx.Exec(ctx, `INSERT INTO scan_components
(scan_id,host_uuid,bom_ref,name,version,component_type,file_path,language,algorithms,dependencies,reachable,scan_finished)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11,to_timestamp($12))
ON CONFLICT (scan_id,bom_ref) DO NOTHING`,
			payload.TelemetryId, payload.HostUuid, component.BomRef, component.Name, component.Version, component.ComponentType,
			component.FilePath, component.Language, string(algorithmJSON), string(dependencyJSON), component.Reachable, payload.ScanFinishedUnix)
		if err != nil {
			return err
		}
	}

	// Upsert TLS certificate health data from network observations (WP-018).
	for _, obs := range payload.NetworkObservations {
		if obs.CertificateNotAfterUnix == 0 {
			continue
		}
		raw := sha256.Sum256([]byte(payload.HostUuid + ":" + obs.Endpoint + ":" + obs.CertificateSubject))
		certID := hex.EncodeToString(raw[:8])
		notAfter := time.Unix(obs.CertificateNotAfterUnix, 0).UTC()
		_, _ = tx.Exec(ctx, `
INSERT INTO tls_certificates (cert_id, host_uuid, target, protocol_version, cipher_suite, subject, issuer, not_after, last_seen_at, scan_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now(), $9)
ON CONFLICT (cert_id) DO UPDATE SET
  protocol_version = EXCLUDED.protocol_version,
  cipher_suite = EXCLUDED.cipher_suite,
  subject = EXCLUDED.subject,
  issuer = EXCLUDED.issuer,
  not_after = EXCLUDED.not_after,
  last_seen_at = now(),
  scan_id = EXCLUDED.scan_id`,
			certID, payload.HostUuid, obs.Endpoint, obs.TlsVersion, obs.CipherSuite,
			obs.CertificateSubject, obs.CertificateIssuer, notAfter, payload.TelemetryId)
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
	status := ""
	switch report.State {
	case int32(pb.MigrationStateApplying):
		status = "executing"
	case int32(pb.MigrationStateSucceeded):
		status = "completed"
	case int32(pb.MigrationStateFailed):
		status = "failed"
	}
	if status != "" {
		_, _ = p.pool.Exec(ctx, `UPDATE agent_commands SET status=$2, completed_at=CASE WHEN $2 IN ('completed','failed') THEN now() ELSE completed_at END WHERE command_id=$1`, report.CommandId, status)
	}
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
	if err := p.pool.QueryRow(ctx, `SELECT count(*) FROM assets WHERE managed_agent`).Scan(&out.Assets); err != nil {
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
	// Count stalled agents (last_seen > 5 minutes ago)
	if err := p.pool.QueryRow(ctx, `SELECT count(*) FROM assets WHERE managed_agent AND last_seen < now() - interval '5 minutes'`).Scan(&out.StalledAgents); err != nil {
		out.StalledAgents = 0
	}

	// Compute Fleet Quantum-Readiness Score (0-100)
	// Formula: 100 - penalty, where penalty comes from critical/high findings and stalled agents
	out.ReadinessBreakdown = make(map[string]int)
	var totalFindings int64
	var remediatedFindings int64
	_ = p.pool.QueryRow(ctx, `SELECT count(*) FROM crypto_findings`).Scan(&totalFindings)
	_ = p.pool.QueryRow(ctx, `SELECT count(*) FROM crypto_findings WHERE status IN ('remediated','accepted_risk')`).Scan(&remediatedFindings)

	penalty := int(out.CriticalFindings)*18 + int(out.HighFindings)*8 + int(out.StalledAgents)*15
	// Bonus for remediation progress
	remediationBonus := 0
	if totalFindings > 0 {
		remediationRate := float64(remediatedFindings) / float64(totalFindings)
		remediationBonus = int(remediationRate * 20)
	}
	out.ReadinessScore = max(0, min(100, 100-penalty+remediationBonus))
	out.ReadinessBreakdown["penalty_from_findings"] = int(out.CriticalFindings)*18 + int(out.HighFindings)*8
	out.ReadinessBreakdown["penalty_from_stalled"] = int(out.StalledAgents) * 15
	out.ReadinessBreakdown["remediation_bonus"] = remediationBonus
	out.ReadinessBreakdown["total_score"] = out.ReadinessScore

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
	assets, _, err := p.AssetsPaginated(ctx, FleetQueryParams{QueryParams: QueryParams{Limit: 5000, Sort: "last_seen", Order: "desc"}})
	return assets, err
}

const assetSelect = `
SELECT a.host_uuid, a.hostname, a.os_name, a.os_version, a.arch, a.execution_mode,
       a.last_seen, a.scan_progress, a.current_scan_path, a.cpu_usage, a.mem_usage,
       CASE WHEN a.last_seen < now() - interval '5 minutes' THEN 'offline' ELSE a.status END,
       a.total_files_scanned, a.agent_version, a.observed_ip, a.dns_name,
       a.first_registered_at, a.last_registered_at,
       COALESCE(sr.scan_id,''), sr.scan_finished, COALESCE(sr.max_severity,0),
       COALESCE((SELECT count(*) FROM crypto_findings cf WHERE cf.host_uuid=a.host_uuid AND cf.status='open'),0)
FROM assets a
LEFT JOIN LATERAL (
  SELECT scan_id, scan_finished, max_severity FROM scan_runs
  WHERE host_uuid=a.host_uuid ORDER BY scan_finished DESC LIMIT 1
) sr ON true`

func scanAsset(rows pgx.Rows) ([]Asset, error) {
	var assets []Asset
	for rows.Next() {
		var a Asset
		if err := rows.Scan(
			&a.HostUUID, &a.Hostname, &a.OSName, &a.OSVersion, &a.Arch, &a.ExecutionMode,
			&a.LastSeen, &a.ScanProgress, &a.CurrentScanPath, &a.CPUUsage, &a.MemUsage,
			&a.Status, &a.TotalFilesScanned, &a.AgentVersion, &a.ObservedIP, &a.DNSName,
			&a.FirstRegisteredAt, &a.LastRegisteredAt, &a.LastScanID, &a.LastScanFinished,
			&a.LastScanSeverity, &a.OpenFindings,
		); err != nil {
			return nil, err
		}
		assets = append(assets, a)
	}
	return assets, rows.Err()
}

func (p *Postgres) AssetsPaginated(ctx context.Context, params FleetQueryParams) ([]Asset, int64, error) {
	if params.Limit <= 0 || params.Limit > 500 {
		params.Limit = 50
	}
	if params.Offset < 0 {
		params.Offset = 0
	}
	allowedSort := map[string]string{
		"hostname": "a.hostname", "os_name": "a.os_name", "os_version": "a.os_version",
		"agent_version": "a.agent_version", "observed_ip": "a.observed_ip", "status": "a.status",
		"last_seen": "a.last_seen", "scan_progress": "a.scan_progress",
		"last_scan_severity": "COALESCE(sr.max_severity,0)", "open_findings": "open_findings",
	}
	sortCol := allowedSort[params.Sort]
	if sortCol == "" {
		sortCol = "a.last_seen"
	}
	order := "DESC"
	if params.Order == "asc" {
		order = "ASC"
	}
	args := []any{}
	where := " WHERE a.managed_agent"
	add := func(clause string, value any) {
		args = append(args, value)
		where += clause + "$" + fmt.Sprint(len(args))
	}
	if params.Search != "" {
		args = append(args, "%"+params.Search+"%")
		n := fmt.Sprint(len(args))
		where += " AND (a.hostname ILIKE $" + n + " OR a.host_uuid ILIKE $" + n + " OR a.os_name ILIKE $" + n + " OR a.os_version ILIKE $" + n + " OR a.agent_version ILIKE $" + n + " OR a.observed_ip ILIKE $" + n + " OR a.dns_name ILIKE $" + n + ")"
	}
	if params.Status != "" {
		add(" AND a.status=", params.Status)
	}
	if params.OSName != "" {
		add(" AND a.os_name=", params.OSName)
	}
	if params.Severity > 0 {
		add(" AND COALESCE(sr.max_severity,0)>=", params.Severity)
	}
	if params.DateFrom != nil {
		add(" AND a.last_seen>=", *params.DateFrom)
	}
	if params.DateTo != nil {
		add(" AND a.last_seen<=", *params.DateTo)
	}
	countArgs := append([]any(nil), args...)
	args = append(args, params.Limit, params.Offset)
	limitPlaceholder, offsetPlaceholder := "$"+fmt.Sprint(len(args)-1), "$"+fmt.Sprint(len(args))
	rows, err := p.pool.Query(ctx, assetSelect+where+" ORDER BY "+sortCol+" "+order+", a.host_uuid ASC LIMIT "+limitPlaceholder+" OFFSET "+offsetPlaceholder, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	assets, err := scanAsset(rows)
	if err != nil {
		return nil, 0, err
	}
	var total int64
	if err := p.pool.QueryRow(ctx, "SELECT count(*) FROM ("+assetSelect+where+") fleet", countArgs...).Scan(&total); err != nil {
		total = int64(len(assets))
	}
	return assets, total, nil
}

func (p *Postgres) AgentByID(ctx context.Context, hostUUID string) (*Asset, error) {
	rows, err := p.pool.Query(ctx, assetSelect+" WHERE a.managed_agent AND a.host_uuid=$1", hostUUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	assets, err := scanAsset(rows)
	if err != nil {
		return nil, err
	}
	if len(assets) == 0 {
		return nil, pgx.ErrNoRows
	}
	return &assets[0], nil
}

func (p *Postgres) ScanRuns(ctx context.Context, params ScanQueryParams) ([]ScanRun, int64, error) {
	if params.Limit <= 0 || params.Limit > 500 {
		params.Limit = 50
	}
	args := []any{}
	where := " WHERE 1=1"
	add := func(clause string, value any) {
		args = append(args, value)
		where += clause + "$" + fmt.Sprint(len(args))
	}
	if params.HostUUID != "" {
		add(" AND sr.host_uuid=", params.HostUUID)
	}
	if params.Severity > 0 {
		add(" AND sr.max_severity>=", params.Severity)
	}
	if params.DateFrom != nil {
		add(" AND sr.scan_finished>=", *params.DateFrom)
	}
	if params.DateTo != nil {
		add(" AND sr.scan_finished<=", *params.DateTo)
	}
	if params.Search != "" {
		args = append(args, "%"+params.Search+"%")
		n := fmt.Sprint(len(args))
		where += " AND (a.hostname ILIKE $" + n + " OR sr.scan_id ILIKE $" + n + " OR sr.host_uuid ILIKE $" + n + ")"
	}
	allowedSort := map[string]string{"scan_finished": "sr.scan_finished", "hostname": "a.hostname", "max_severity": "sr.max_severity", "finding_count": "sr.finding_count", "status": "sr.status"}
	sortCol := allowedSort[params.Sort]
	if sortCol == "" {
		sortCol = "sr.scan_finished"
	}
	order := "DESC"
	if params.Order == "asc" {
		order = "ASC"
	}
	base := ` FROM scan_runs sr JOIN assets a ON a.host_uuid=sr.host_uuid` + where
	countArgs := append([]any(nil), args...)
	args = append(args, params.Limit, max(params.Offset, 0))
	limitPlaceholder, offsetPlaceholder := "$"+fmt.Sprint(len(args)-1), "$"+fmt.Sprint(len(args))
	rows, err := p.pool.Query(ctx, `SELECT sr.scan_id, sr.host_uuid, a.hostname, sr.agent_version, sr.os_name, sr.os_version, sr.observed_ip,
sr.scan_started, sr.scan_finished, sr.received_at, sr.status, sr.component_count, sr.finding_count, sr.critical_count, sr.high_count, sr.max_severity, sr.network_observation_count`+
		base+" ORDER BY "+sortCol+" "+order+", sr.scan_id LIMIT "+limitPlaceholder+" OFFSET "+offsetPlaceholder, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	scans := []ScanRun{}
	for rows.Next() {
		var s ScanRun
		if err := rows.Scan(&s.ScanID, &s.HostUUID, &s.Hostname, &s.AgentVersion, &s.OSName, &s.OSVersion, &s.ObservedIP,
			&s.ScanStarted, &s.ScanFinished, &s.ReceivedAt, &s.Status, &s.ComponentCount, &s.FindingCount, &s.CriticalCount,
			&s.HighCount, &s.MaxSeverity, &s.NetworkObservationCount); err != nil {
			return nil, 0, err
		}
		scans = append(scans, s)
	}
	var total int64
	if err := p.pool.QueryRow(ctx, "SELECT count(*)"+base, countArgs...).Scan(&total); err != nil {
		total = int64(len(scans))
	}
	return scans, total, rows.Err()
}

func (p *Postgres) ConnectionHistory(ctx context.Context, hostUUID string, params QueryParams) ([]ConnectionSession, int64, error) {
	if params.Limit <= 0 || params.Limit > 500 {
		params.Limit = 50
	}
	offset := max(params.Offset, 0)
	allowedSort := map[string]string{"connected_at": "connected_at", "disconnected_at": "disconnected_at", "last_seen": "last_seen", "observed_ip": "observed_ip", "agent_version": "agent_version", "status": "status"}
	sortCol := allowedSort[params.Sort]
	if sortCol == "" {
		sortCol = "connected_at"
	}
	order := "DESC"
	if params.Order == "asc" {
		order = "ASC"
	}
	args := []any{hostUUID}
	where := " WHERE host_uuid=$1"
	if params.Search != "" {
		args = append(args, "%"+params.Search+"%")
		n := fmt.Sprint(len(args))
		where += " AND (observed_ip ILIKE $" + n + " OR agent_version ILIKE $" + n + " OR status ILIKE $" + n + ")"
	}
	countArgs := append([]any(nil), args...)
	args = append(args, params.Limit, offset)
	rows, err := p.pool.Query(ctx, `SELECT session_id, host_uuid, connected_at, disconnected_at, last_seen, observed_ip, agent_version, status
FROM agent_connection_sessions`+where+` ORDER BY `+sortCol+` `+order+`, session_id LIMIT $`+fmt.Sprint(len(args)-1)+` OFFSET $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	sessions := []ConnectionSession{}
	for rows.Next() {
		var s ConnectionSession
		if err := rows.Scan(&s.SessionID, &s.HostUUID, &s.ConnectedAt, &s.DisconnectedAt, &s.LastSeen, &s.ObservedIP, &s.AgentVersion, &s.Status); err != nil {
			return nil, 0, err
		}
		sessions = append(sessions, s)
	}
	var total int64
	_ = p.pool.QueryRow(ctx, `SELECT count(*) FROM agent_connection_sessions`+where, countArgs...).Scan(&total)
	return sessions, total, rows.Err()
}

func (p *Postgres) ReportFindings(ctx context.Context, scanID string, params QueryParams) ([]Finding, int64, error) {
	if params.Limit <= 0 || params.Limit > 500 {
		params.Limit = 100
	}
	offset := max(params.Offset, 0)
	args := []any{scanID}
	where := " WHERE scan_id=$1"
	add := func(clause string, value any) {
		args = append(args, value)
		where += clause + "$" + fmt.Sprint(len(args))
	}
	if params.Search != "" {
		args = append(args, "%"+params.Search+"%")
		n := fmt.Sprint(len(args))
		where += " AND (title ILIKE $" + n + " OR description ILIKE $" + n + " OR asset_ref ILIKE $" + n + " OR algorithm ILIKE $" + n + " OR policy_rule_id ILIKE $" + n + ")"
	}
	if params.Algorithm != "" {
		add(" AND algorithm=", params.Algorithm)
	}
	if params.AssetRef != "" {
		add(" AND asset_ref=", params.AssetRef)
	}
	countArgs := append([]any(nil), args...)
	args = append(args, params.Limit, offset)
	rows, err := p.pool.Query(ctx, `SELECT occurrence_id, host_uuid, severity, title, description, asset_ref, algorithm, policy_rule_id,
migration_profile, 'historical', '', created_at, created_at, confidence
FROM finding_occurrences`+where+` ORDER BY severity DESC, created_at DESC LIMIT $`+fmt.Sprint(len(args)-1)+` OFFSET $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	findings := []Finding{}
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.FindingID, &f.HostUUID, &f.Severity, &f.Title, &f.Description, &f.AssetRef, &f.Algorithm,
			&f.PolicyRuleID, &f.MigrationProfile, &f.Status, &f.UpdatedBy, &f.UpdatedAt, &f.CreatedAt, &f.Confidence); err != nil {
			return nil, 0, err
		}
		findings = append(findings, f)
	}
	var total int64
	_ = p.pool.QueryRow(ctx, `SELECT count(*) FROM finding_occurrences`+where, countArgs...).Scan(&total)
	return findings, total, rows.Err()
}

func (p *Postgres) EnqueueAgentCommand(ctx context.Context, command *pb.MigrationCommand) error {
	raw, err := json.Marshal(command)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx, `INSERT INTO agent_commands (command_id,host_uuid,command_payload,status)
VALUES ($1,$2,$3::jsonb,'queued') ON CONFLICT (command_id) DO NOTHING`, command.CommandId, command.HostUuid, string(raw))
	return err
}

func (p *Postgres) DrainAgentCommands(ctx context.Context, hostUUID string) ([]*pb.MigrationCommand, error) {
	rows, err := p.pool.Query(ctx, `SELECT command_id,command_payload FROM agent_commands
WHERE host_uuid=$1 AND status='queued' ORDER BY queued_at`, hostUUID)
	if err != nil {
		return nil, err
	}
	var commands []*pb.MigrationCommand
	for rows.Next() {
		var id string
		var raw []byte
		if err := rows.Scan(&id, &raw); err != nil {
			rows.Close()
			return nil, err
		}
		var command pb.MigrationCommand
		if err := json.Unmarshal(raw, &command); err != nil {
			rows.Close()
			return nil, err
		}
		commands = append(commands, &command)
	}
	rows.Close()
	return commands, rows.Err()
}

func (p *Postgres) MarkAgentCommandDelivered(ctx context.Context, commandID string) error {
	_, err := p.pool.Exec(ctx, `UPDATE agent_commands SET status='delivered',delivered_at=now() WHERE command_id=$1`, commandID)
	return err
}

func (p *Postgres) MarkAgentCommandExecuting(ctx context.Context, commandID string) error {
	_, err := p.pool.Exec(ctx, `UPDATE agent_commands SET status='executing',delivered_at=COALESCE(delivered_at,now()) WHERE command_id=$1`, commandID)
	return err
}

func (p *Postgres) AgentCommand(ctx context.Context, hostUUID, commandID string) (*AgentCommand, error) {
	var command AgentCommand
	var payload []byte
	err := p.pool.QueryRow(ctx, `SELECT command_id,host_uuid,command_payload,status,queued_at,delivered_at,completed_at
FROM agent_commands WHERE host_uuid=$1 AND command_id=$2`, hostUUID, commandID).Scan(
		&command.CommandID, &command.HostUUID, &payload, &command.Status, &command.QueuedAt, &command.DeliveredAt, &command.CompletedAt)
	if err != nil {
		return nil, err
	}
	var directive pb.MigrationCommand
	if json.Unmarshal(payload, &directive) == nil {
		command.Command = directive.MigrationProfile
	}
	return &command, nil
}

func (p *Postgres) GetAgentScanConfig(ctx context.Context, hostUUID string) (*AgentScanConfig, error) {
	config := AgentScanConfig{
		HostUUID: hostUUID, ScanRoots: []string{}, ExcludeDirs: []string{},
		IncludeExtensions: []string{}, ScanIntervalSeconds: scanconfig.DefaultScanIntervalSeconds,
		MaxFileBytes: scanconfig.DefaultMaxFileBytes, MaxBinaryBytes: scanconfig.DefaultMaxBinaryBytes, NetworkTargets: []string{},
	}
	var raw []byte
	err := p.pool.QueryRow(ctx, `SELECT config FROM agent_scan_configs WHERE host_uuid=$1`, hostUUID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return &config, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, err
	}
	config.HostUUID = hostUUID
	config.Configured = true
	return &config, nil
}

func (p *Postgres) UpdateAgentScanConfig(ctx context.Context, config *AgentScanConfig) error {
	config.Configured = true
	raw, err := json.Marshal(config)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx, `INSERT INTO agent_scan_configs(host_uuid,config,updated_at) VALUES($1,$2::jsonb,now())
ON CONFLICT(host_uuid) DO UPDATE SET config=EXCLUDED.config,updated_at=now()`, config.HostUUID, string(raw))
	return err
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
SELECT cf.finding_id, cf.host_uuid, cf.severity, cf.title, cf.description, cf.asset_ref, cf.algorithm, cf.policy_rule_id, cf.migration_profile,
       COALESCE(cf.status,'open'), COALESCE(cf.updated_by,''), COALESCE(cf.updated_at, cf.created_at), cf.created_at, cf.confidence,
       cf.telemetry_id, a.hostname, a.agent_version, tp.scan_finished
FROM crypto_findings cf JOIN assets a ON a.host_uuid=cf.host_uuid JOIN telemetry_payloads tp ON tp.telemetry_id=cf.telemetry_id
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
			&f.TelemetryID, &f.Hostname, &f.AgentVersion, &f.ScanFinished,
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
	where := " WHERE 1=1"
	args := []any{}
	add := func(clause string, value any) {
		args = append(args, value)
		where += clause + "$" + fmt.Sprint(len(args))
	}
	if params.Search != "" {
		args = append(args, "%"+params.Search+"%")
		n := fmt.Sprint(len(args))
		where += ` AND (cf.title ILIKE $` + n + ` OR cf.description ILIKE $` + n + ` OR cf.asset_ref ILIKE $` + n + ` OR cf.algorithm ILIKE $` + n + ` OR cf.policy_rule_id ILIKE $` + n + ` OR a.hostname ILIKE $` + n + `)`
	}
	if params.HostUUID != "" {
		add(" AND cf.host_uuid=", params.HostUUID)
	}
	if params.ScanID != "" {
		add(" AND cf.telemetry_id=", params.ScanID)
	}
	if params.Algorithm != "" {
		add(" AND cf.algorithm=", params.Algorithm)
	}
	if params.AssetRef != "" {
		add(" AND cf.asset_ref=", params.AssetRef)
	}
	if params.DateFrom != nil {
		add(" AND tp.scan_finished>=", *params.DateFrom)
	}
	if params.DateTo != nil {
		add(" AND tp.scan_finished<=", *params.DateTo)
	}
	countArgs := append([]any(nil), args...)
	args = append(args, params.Limit, params.Offset)
	lp, op := "$"+fmt.Sprint(len(args)-1), "$"+fmt.Sprint(len(args))
	query := `SELECT cf.finding_id, cf.host_uuid, cf.severity, cf.title, cf.description, cf.asset_ref, cf.algorithm, cf.policy_rule_id, cf.migration_profile,
				 COALESCE(cf.status,'open'), COALESCE(cf.updated_by,''), COALESCE(cf.updated_at, cf.created_at), cf.created_at, cf.confidence,
				 cf.telemetry_id, a.hostname, a.agent_version, tp.scan_finished
			  FROM crypto_findings cf JOIN assets a ON a.host_uuid=cf.host_uuid JOIN telemetry_payloads tp ON tp.telemetry_id=cf.telemetry_id` + where +
		` ORDER BY cf.` + sortCol + ` ` + order + ` LIMIT ` + lp + ` OFFSET ` + op
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
			&f.TelemetryID, &f.Hostname, &f.AgentVersion, &f.ScanFinished,
		); err != nil {
			return nil, 0, err
		}
		findings = append(findings, f)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	countQuery := `SELECT count(*) FROM crypto_findings cf JOIN assets a ON a.host_uuid=cf.host_uuid JOIN telemetry_payloads tp ON tp.telemetry_id=cf.telemetry_id` + where
	var total int64
	if err := p.pool.QueryRow(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		total = int64(len(findings))
	}
	return findings, total, nil
}

func (p *Postgres) ComponentsPaginated(ctx context.Context, params QueryParams) ([]Component, int64, error) {
	if params.Limit <= 0 || params.Limit > 500 {
		params.Limit = 100
	}
	args := []any{}
	where := " WHERE 1=1"
	add := func(clause string, value any) {
		args = append(args, value)
		where += clause + "$" + fmt.Sprint(len(args))
	}
	if params.HostUUID != "" {
		add(" AND host_uuid=", params.HostUUID)
	}
	if params.ScanID != "" {
		add(" AND scan_id=", params.ScanID)
	}
	if params.AssetRef != "" {
		add(" AND (bom_ref=", params.AssetRef)
		where += " OR file_path=$" + fmt.Sprint(len(args)) + ")"
	}
	if params.Search != "" {
		args = append(args, "%"+params.Search+"%")
		n := fmt.Sprint(len(args))
		where += " AND (name ILIKE $" + n + " OR file_path ILIKE $" + n + " OR bom_ref ILIKE $" + n + ")"
	}
	countArgs := append([]any(nil), args...)
	args = append(args, params.Limit, max(params.Offset, 0))
	lp, op := "$"+fmt.Sprint(len(args)-1), "$"+fmt.Sprint(len(args))
	rows, err := p.pool.Query(ctx, `SELECT host_uuid,scan_id,bom_ref,name,version,component_type,file_path,language,algorithms,dependencies,reachable,extract(epoch from scan_finished)::bigint
FROM scan_components`+where+` ORDER BY scan_finished DESC LIMIT `+lp+` OFFSET `+op, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var components []Component
	for rows.Next() {
		var c Component
		var algorithms, dependencies []byte
		if err := rows.Scan(&c.HostUUID, &c.TelemetryID, &c.BomRef, &c.Name, &c.Version, &c.ComponentType, &c.FilePath, &c.Language, &algorithms, &dependencies, &c.Reachable, &c.ScanFinishedAt); err != nil {
			return nil, 0, err
		}
		_ = json.Unmarshal(algorithms, &c.Algorithms)
		_ = json.Unmarshal(dependencies, &c.Dependencies)
		components = append(components, c)
	}
	var total int64
	_ = p.pool.QueryRow(ctx, `SELECT count(*) FROM scan_components`+where, countArgs...).Scan(&total)
	return components, total, rows.Err()
}

func (p *Postgres) UpdateFindingStatus(ctx context.Context, findingID, status, updatedBy string) error {
	allowed := map[string]bool{"open": true, "accepted_risk": true, "false_positive": true, "remediated": true}
	if !allowed[status] {
		return errors.New("invalid status value")
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var fromStatus, hostUUID string
	if err := tx.QueryRow(ctx,
		`SELECT status, host_uuid FROM crypto_findings WHERE finding_id=$1`,
		findingID).Scan(&fromStatus, &hostUUID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errors.New("finding not found")
		}
		return err
	}

	if _, err := tx.Exec(ctx,
		`UPDATE crypto_findings SET status=$2, updated_by=$3, updated_at=now() WHERE finding_id=$1`,
		findingID, status, updatedBy); err != nil {
		return err
	}

	evt := &FindingLifecycleEvent{
		EventID:    uuid.New().String(),
		FindingID:  findingID,
		HostUUID:   hostUUID,
		EventType:  "status_change",
		FromStatus: fromStatus,
		ToStatus:   status,
		Actor:      updatedBy,
		Reason:     "",
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO finding_lifecycle_events (event_id, finding_id, host_uuid, event_type, from_status, to_status, actor, reason, occurred_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
ON CONFLICT (event_id) DO NOTHING`,
		evt.EventID, evt.FindingID, evt.HostUUID, evt.EventType,
		evt.FromStatus, evt.ToStatus, evt.Actor, evt.Reason); err != nil {
		return err
	}

	return tx.Commit(ctx)
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
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	metricsPresent := hb.MetricsPresent == nil || *hb.MetricsPresent
	_, err = tx.Exec(ctx, `
UPDATE assets
SET scan_progress = $2,
    current_scan_path = $3,
    cpu_usage = CASE WHEN $8 THEN $4 ELSE cpu_usage END,
    mem_usage = CASE WHEN $8 THEN $5 ELSE mem_usage END,
    status = $6,
    total_files_scanned = $7,
    last_seen = now()
WHERE host_uuid = $1`,
		hb.HostUUID, hb.ScanProgress, hb.CurrentScanPath, hb.CPUUsage, hb.MemUsage, hb.Status, hb.TotalFilesScanned, metricsPresent)
	if err != nil {
		return err
	}
	_, _ = tx.Exec(ctx, `UPDATE agent_connection_sessions SET last_seen=now(), status=$2 WHERE session_id=(
SELECT session_id FROM agent_connection_sessions WHERE host_uuid=$1 AND disconnected_at IS NULL ORDER BY connected_at DESC LIMIT 1)`, hb.HostUUID, hb.Status)
	_, err = tx.Exec(ctx, `INSERT INTO agent_progress_events
(event_id, host_uuid, progress, current_path, status, files_processed, cpu_usage, mem_usage)
SELECT $1,$2,$3,$4,$5,$6,$7,$8
WHERE NOT EXISTS (
  SELECT 1 FROM (
    SELECT progress, current_path, status, files_processed
    FROM agent_progress_events WHERE host_uuid=$2
    ORDER BY recorded_at DESC LIMIT 1
  ) latest
  WHERE latest.progress=$3 AND latest.current_path=$4 AND latest.status=$5 AND latest.files_processed=$6
)`,
		uuid.NewString(), hb.HostUUID, hb.ScanProgress, hb.CurrentScanPath, hb.Status, hb.TotalFilesScanned, hb.CPUUsage, hb.MemUsage)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
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

// ---------------------------------------------------------------------------
// LLM Analysis Jobs
// ---------------------------------------------------------------------------

func (p *Postgres) CreateAnalysisJob(ctx context.Context, job *LLMAnalysisJob) error {
	if job.JobID == "" {
		job.JobID = uuid.NewString()
	}
	_, err := p.pool.Exec(ctx, `
INSERT INTO llm_analysis_jobs (job_id, finding_id, job_type, status, error_msg, created_by, created_at)
VALUES ($1, $2, $3, $4, $5, $6, now())
ON CONFLICT (job_id) DO NOTHING`,
		job.JobID, job.FindingID, job.JobType, job.Status, job.ErrorMsg, job.CreatedBy)
	return err
}

func (p *Postgres) GetAnalysisJob(ctx context.Context, jobID string) (*LLMAnalysisJob, error) {
	var j LLMAnalysisJob
	err := p.pool.QueryRow(ctx, `
SELECT job_id, finding_id, job_type, status, error_msg, created_by, created_at, started_at, completed_at
FROM llm_analysis_jobs WHERE job_id = $1`, jobID).Scan(
		&j.JobID, &j.FindingID, &j.JobType, &j.Status, &j.ErrorMsg, &j.CreatedBy,
		&j.CreatedAt, &j.StartedAt, &j.CompletedAt)
	if err != nil {
		return nil, err
	}
	return &j, nil
}

func (p *Postgres) UpdateAnalysisJob(ctx context.Context, job *LLMAnalysisJob) error {
	_, err := p.pool.Exec(ctx, `
UPDATE llm_analysis_jobs SET status=$2, error_msg=$3, started_at=$4, completed_at=$5 WHERE job_id=$1`,
		job.JobID, job.Status, job.ErrorMsg, job.StartedAt, job.CompletedAt)
	return err
}

func (p *Postgres) ListAnalysisJobs(ctx context.Context, params QueryParams) ([]LLMAnalysisJob, int64, error) {
	if params.Limit <= 0 || params.Limit > 200 {
		params.Limit = 50
	}
	args := []any{}
	where := " WHERE 1=1"
	if params.Search != "" {
		args = append(args, params.Search)
		where += " AND (finding_id=$" + fmt.Sprint(len(args)) + " OR status=$" + fmt.Sprint(len(args)) + ")"
	}
	if params.HostUUID != "" {
		args = append(args, params.HostUUID)
		where += " AND finding_id IN (SELECT finding_id FROM crypto_findings WHERE host_uuid=$" + fmt.Sprint(len(args)) + ")"
	}
	countArgs := append([]any(nil), args...)
	args = append(args, params.Limit, max(params.Offset, 0))
	lp, op := "$"+fmt.Sprint(len(args)-1), "$"+fmt.Sprint(len(args))
	rows, err := p.pool.Query(ctx, `SELECT job_id, finding_id, job_type, status, error_msg, created_by, created_at, started_at, completed_at
FROM llm_analysis_jobs`+where+` ORDER BY created_at DESC LIMIT `+lp+` OFFSET `+op, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var jobs []LLMAnalysisJob
	for rows.Next() {
		var j LLMAnalysisJob
		if err := rows.Scan(&j.JobID, &j.FindingID, &j.JobType, &j.Status, &j.ErrorMsg, &j.CreatedBy,
			&j.CreatedAt, &j.StartedAt, &j.CompletedAt); err != nil {
			return nil, 0, err
		}
		jobs = append(jobs, j)
	}
	var total int64
	_ = p.pool.QueryRow(ctx, "SELECT count(*) FROM llm_analysis_jobs"+where, countArgs...).Scan(&total)
	return jobs, total, rows.Err()
}

// ---------------------------------------------------------------------------
// LLM Verdicts
// ---------------------------------------------------------------------------

func (p *Postgres) CreateVerdict(ctx context.Context, v *LLMVerdict) error {
	if v.VerdictID == "" {
		v.VerdictID = uuid.NewString()
	}
	cites, _ := json.Marshal(v.EvidenceCitations)
	_, err := p.pool.Exec(ctx, `
INSERT INTO llm_verdicts (verdict_id, job_id, finding_id, verdict, adjusted_severity, confidence, reasoning,
  evidence_citations, abstention_reason, model, prompt_version, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11,now())
ON CONFLICT (verdict_id) DO NOTHING`,
		v.VerdictID, v.JobID, v.FindingID, v.Verdict, v.AdjustedSeverity, v.Confidence,
		v.Reasoning, string(cites), v.AbstentionReason, v.Model, v.PromptVersion)
	return err
}

func (p *Postgres) GetVerdictByFinding(ctx context.Context, findingID string) (*LLMVerdict, error) {
	var v LLMVerdict
	var cites []byte
	err := p.pool.QueryRow(ctx, `
SELECT verdict_id, job_id, finding_id, verdict, adjusted_severity, confidence, reasoning,
  evidence_citations, abstention_reason, model, prompt_version, created_at
FROM llm_verdicts WHERE finding_id=$1 ORDER BY created_at DESC LIMIT 1`, findingID).Scan(
		&v.VerdictID, &v.JobID, &v.FindingID, &v.Verdict, &v.AdjustedSeverity, &v.Confidence,
		&v.Reasoning, &cites, &v.AbstentionReason, &v.Model, &v.PromptVersion, &v.CreatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(cites, &v.EvidenceCitations)
	return &v, nil
}

func (p *Postgres) GetVerdictByJob(ctx context.Context, jobID string) (*LLMVerdict, error) {
	var v LLMVerdict
	var cites []byte
	err := p.pool.QueryRow(ctx, `
SELECT verdict_id, job_id, finding_id, verdict, adjusted_severity, confidence, reasoning,
  evidence_citations, abstention_reason, model, prompt_version, created_at
FROM llm_verdicts WHERE job_id=$1`, jobID).Scan(
		&v.VerdictID, &v.JobID, &v.FindingID, &v.Verdict, &v.AdjustedSeverity, &v.Confidence,
		&v.Reasoning, &cites, &v.AbstentionReason, &v.Model, &v.PromptVersion, &v.CreatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(cites, &v.EvidenceCitations)
	return &v, nil
}

// ---------------------------------------------------------------------------
// LLM Provenance
// ---------------------------------------------------------------------------

func (p *Postgres) RecordProvenance(ctx context.Context, prov *LLMProvenance) error {
	if prov.ProvenanceID == "" {
		prov.ProvenanceID = uuid.NewString()
	}
	_, err := p.pool.Exec(ctx, `
INSERT INTO llm_provenance (provenance_id, job_id, finding_id, provider, model, prompt_name, prompt_version,
  input_hash, output_hash, tokens_in, tokens_out, latency_ms, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,now())`,
		prov.ProvenanceID, prov.JobID, prov.FindingID, prov.Provider, prov.Model,
		prov.PromptName, prov.PromptVersion, prov.InputHash, prov.OutputHash,
		prov.TokensIn, prov.TokensOut, prov.LatencyMS)
	return err
}

func (p *Postgres) ListProvenance(ctx context.Context, findingID string) ([]LLMProvenance, error) {
	rows, err := p.pool.Query(ctx, `
SELECT provenance_id, job_id, finding_id, provider, model, prompt_name, prompt_version,
  input_hash, output_hash, tokens_in, tokens_out, latency_ms, created_at
FROM llm_provenance WHERE finding_id=$1 ORDER BY created_at DESC`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []LLMProvenance
	for rows.Next() {
		var pr LLMProvenance
		if err := rows.Scan(&pr.ProvenanceID, &pr.JobID, &pr.FindingID, &pr.Provider, &pr.Model,
			&pr.PromptName, &pr.PromptVersion, &pr.InputHash, &pr.OutputHash,
			&pr.TokensIn, &pr.TokensOut, &pr.LatencyMS, &pr.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, pr)
	}
	return list, rows.Err()
}

// ---------------------------------------------------------------------------
// Agility Metrics
// ---------------------------------------------------------------------------

func (p *Postgres) UpsertAgilityMetrics(ctx context.Context, m *AgilityMetrics) error {
	if m.MetricID == "" {
		m.MetricID = uuid.NewString()
	}
	_, err := p.pool.Exec(ctx, `
INSERT INTO agility_metrics (metric_id, host_uuid, measurement_date, ttsa_days, hardcode_index,
  negotiation_coverage, profile_adoption_latency_days, blast_radius_score, measured_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())
ON CONFLICT (host_uuid, measurement_date) DO UPDATE SET
  ttsa_days = EXCLUDED.ttsa_days,
  hardcode_index = EXCLUDED.hardcode_index,
  negotiation_coverage = EXCLUDED.negotiation_coverage,
  profile_adoption_latency_days = EXCLUDED.profile_adoption_latency_days,
  blast_radius_score = EXCLUDED.blast_radius_score,
  measured_at = now()`,
		m.MetricID, m.HostUUID, m.MeasurementDate.Format("2006-01-02"),
		m.TTSADays, m.HardcodeIndex, m.NegotiationCoverage,
		m.ProfileAdoptionLatencyDays, m.BlastRadiusScore)
	return err
}

func (p *Postgres) GetAgilityMetrics(ctx context.Context, hostUUID string) (*AgilityMetrics, error) {
	var m AgilityMetrics
	err := p.pool.QueryRow(ctx, `
SELECT metric_id, host_uuid, measurement_date, ttsa_days, hardcode_index, negotiation_coverage,
  profile_adoption_latency_days, blast_radius_score, measured_at
FROM agility_metrics WHERE host_uuid=$1 ORDER BY measurement_date DESC LIMIT 1`, hostUUID).Scan(
		&m.MetricID, &m.HostUUID, &m.MeasurementDate, &m.TTSADays, &m.HardcodeIndex,
		&m.NegotiationCoverage, &m.ProfileAdoptionLatencyDays, &m.BlastRadiusScore, &m.MeasuredAt)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (p *Postgres) GetFleetAgilityMetrics(ctx context.Context) ([]AgilityMetrics, error) {
	rows, err := p.pool.Query(ctx, `
SELECT DISTINCT ON (host_uuid) metric_id, host_uuid, measurement_date, ttsa_days, hardcode_index,
  negotiation_coverage, profile_adoption_latency_days, blast_radius_score, measured_at
FROM agility_metrics ORDER BY host_uuid, measurement_date DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []AgilityMetrics
	for rows.Next() {
		var m AgilityMetrics
		if err := rows.Scan(&m.MetricID, &m.HostUUID, &m.MeasurementDate, &m.TTSADays, &m.HardcodeIndex,
			&m.NegotiationCoverage, &m.ProfileAdoptionLatencyDays, &m.BlastRadiusScore, &m.MeasuredAt); err != nil {
			return nil, err
		}
		list = append(list, m)
	}
	return list, rows.Err()
}

// ---------------------------------------------------------------------------
// Wave Plans
// ---------------------------------------------------------------------------

func (p *Postgres) CreateWavePlan(ctx context.Context, plan *WavePlan) error {
	if plan.PlanID == "" {
		plan.PlanID = uuid.NewString()
	}
	assetIDs, _ := json.Marshal(plan.AssetIDs)
	algTargets, _ := json.Marshal(plan.AlgorithmTargets)
	_, err := p.pool.Exec(ctx, `
INSERT INTO wave_plans (plan_id, name, description, wave_number, asset_ids, algorithm_targets,
  start_date, target_date, status, created_by, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7,$8,$9,$10,now(),now())
ON CONFLICT (plan_id) DO NOTHING`,
		plan.PlanID, plan.Name, plan.Description, plan.WaveNumber,
		string(assetIDs), string(algTargets),
		plan.StartDate, plan.TargetDate, plan.Status, plan.CreatedBy)
	return err
}

func (p *Postgres) GetWavePlans(ctx context.Context) ([]WavePlan, error) {
	rows, err := p.pool.Query(ctx, `
SELECT plan_id, name, description, wave_number, asset_ids, algorithm_targets,
  start_date, target_date, status, created_by, created_at, updated_at
FROM wave_plans ORDER BY wave_number, created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var plans []WavePlan
	for rows.Next() {
		var wp WavePlan
		var assetIDs, algTargets []byte
		if err := rows.Scan(&wp.PlanID, &wp.Name, &wp.Description, &wp.WaveNumber,
			&assetIDs, &algTargets, &wp.StartDate, &wp.TargetDate,
			&wp.Status, &wp.CreatedBy, &wp.CreatedAt, &wp.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(assetIDs, &wp.AssetIDs)
		_ = json.Unmarshal(algTargets, &wp.AlgorithmTargets)
		plans = append(plans, wp)
	}
	return plans, rows.Err()
}

func (p *Postgres) UpdateWavePlan(ctx context.Context, plan *WavePlan) error {
	assetIDs, _ := json.Marshal(plan.AssetIDs)
	algTargets, _ := json.Marshal(plan.AlgorithmTargets)
	_, err := p.pool.Exec(ctx, `
UPDATE wave_plans SET name=$2, description=$3, wave_number=$4, asset_ids=$5::jsonb,
  algorithm_targets=$6::jsonb, start_date=$7, target_date=$8, status=$9, updated_at=now()
WHERE plan_id=$1`,
		plan.PlanID, plan.Name, plan.Description, plan.WaveNumber,
		string(assetIDs), string(algTargets), plan.StartDate, plan.TargetDate, plan.Status)
	return err
}

func (p *Postgres) DeleteWavePlan(ctx context.Context, planID string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM wave_plans WHERE plan_id=$1`, planID)
	return err
}

func (p *Postgres) RecordLifecycleEvent(ctx context.Context, evt *FindingLifecycleEvent) error {
	_, err := p.pool.Exec(ctx, `
INSERT INTO finding_lifecycle_events (event_id, finding_id, host_uuid, event_type, from_status, to_status, actor, reason, occurred_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
ON CONFLICT (event_id) DO NOTHING`,
		evt.EventID, evt.FindingID, evt.HostUUID, evt.EventType,
		evt.FromStatus, evt.ToStatus, evt.Actor, evt.Reason)
	return err
}

func (p *Postgres) ListLifecycleEvents(ctx context.Context, findingID string) ([]FindingLifecycleEvent, error) {
	rows, err := p.pool.Query(ctx, `
SELECT event_id, finding_id, host_uuid, event_type, from_status, to_status, actor, reason, occurred_at
FROM finding_lifecycle_events
WHERE finding_id = $1
ORDER BY occurred_at ASC`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []FindingLifecycleEvent
	for rows.Next() {
		var e FindingLifecycleEvent
		if err := rows.Scan(&e.EventID, &e.FindingID, &e.HostUUID, &e.EventType,
			&e.FromStatus, &e.ToStatus, &e.Actor, &e.Reason, &e.OccurredAt); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

// ---------------------------------------------------------------------------
// TLS Certificate Health (WP-018)
// ---------------------------------------------------------------------------

func (p *Postgres) GetCertHealth(ctx context.Context) (*CertHealth, error) {
	var h CertHealth
	err := p.pool.QueryRow(ctx, `
SELECT
  COUNT(*) FILTER (WHERE not_after < now()) AS expired,
  COUNT(*) FILTER (WHERE not_after >= now() AND not_after < now() + interval '30 days') AS expiring_30,
  COUNT(*) FILTER (WHERE not_after >= now() AND not_after < now() + interval '90 days') AS expiring_90,
  COUNT(*) AS total
FROM tls_certificates`).Scan(&h.Expired, &h.Expiring30, &h.Expiring90, &h.TotalTracked)
	if err != nil {
		return nil, err
	}
	return &h, nil
}
