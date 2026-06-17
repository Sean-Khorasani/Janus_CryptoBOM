package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Default configuration values, used when neither an environment variable nor the
// optional config file provides a value. Resolution order is:
//
//	environment variable  >  config file (JANUS_CONFIG_FILE)  >  these constants
const (
	DefaultDatabaseURL             = "postgres://janus:janus@localhost:5432/janus?sslmode=disable"
	DefaultGRPCAddr                = "127.0.0.1:9443"
	DefaultHTTPAddr                = "127.0.0.1:8080"
	DefaultCORSOrigin              = "http://localhost:5173"
	DefaultLogLevel                = "info"
	DefaultDBMaxConns              = 25
	DefaultDBMinConns              = 5
	DefaultDBMaxConnLifetime       = 30 * time.Minute
	DefaultDBMaxConnIdleTime       = 5 * time.Minute
	DefaultAgentStallSeconds       = 300
	DefaultGRPCMaxRecvBytes        = 32 * 1024 * 1024
	DefaultGracefulShutdownSeconds = 30
	// DefaultAPIRateLimitPerMin caps requests per client IP per minute across the whole
	// REST API (OPS-002). Generous so normal dashboard polling/WS-fallback is unaffected;
	// set JANUS_API_RATE_LIMIT_PER_MIN=0 to disable. Auth endpoints keep a stricter 20/min.
	DefaultAPIRateLimitPerMin     = 600
	DefaultAgentAuthMode          = "shared"
	DefaultAgentAuthWindowSeconds = 300
	// DefaultTenant is the tenant a login (and pre-existing data) belongs to when no
	// per-role tenant is configured (WP-020 multi-tenancy, row-level).
	DefaultTenant              = "default"
	DefaultLLMAPIKeyEnv        = "JANUS_LLM_API_KEY"
	DefaultLLMModelAnalysis    = "gpt-4o-mini"
	DefaultLLMModelRemediation = "gpt-4o"
	DefaultLLMTimeoutSeconds   = 30
	DefaultLLMMaxRetries       = 2
	DefaultLLMMaxConcurrent    = 4
	DefaultLLMCapabilityMode   = "analysis_only"
	// Command-signing scheme defaults (consumed in cmd/janus-server/main.go via the
	// config resolver so JANUS_CONFIG_FILE covers them too).
	DefaultCommandSigScheme   = "hmac"
	DefaultCommandSigAlg      = "ML-DSA-65"
	DefaultCommandSigKeyLabel = "janus-command-mldsa"
)

// LLMConfig holds server-side LLM provider configuration.
// The API key is never stored as a value — only a file path or env var name is kept.
type LLMConfig struct {
	Enabled              bool
	BaseURL              string // JANUS_LLM_BASE_URL, validated as https:// or http://localhost
	APIKeyEnv            string // JANUS_LLM_API_KEY_ENV: name of env var holding the actual key
	APIKeyFile           string // JANUS_LLM_API_KEY_FILE: path to file containing the key (takes precedence)
	ModelAnalysis        string // JANUS_LLM_MODEL_ANALYSIS
	ModelRemediation     string // JANUS_LLM_MODEL_REMEDIATION
	TimeoutSeconds       int    // JANUS_LLM_TIMEOUT_SECONDS
	MaxRetries           int    // JANUS_LLM_MAX_RETRIES
	MaxConcurrent        int    // JANUS_LLM_MAX_CONCURRENT
	CapabilityMode       string // JANUS_LLM_CAPABILITY_MODE: "disabled" | "analysis_only" | "suggest_remediation"
	MaxTokensPerRequest  int    // JANUS_LLM_MAX_TOKENS_PER_REQUEST: per-call output token cap (0 = no limit)
	MaxRequestsPerMinute int    // JANUS_LLM_MAX_REQUESTS_PER_MINUTE: rate limit guard (0 = no limit)
}

// APIKey resolves the LLM API key at call time from file or env var.
// Returns empty string if not configured.
func (c *LLMConfig) APIKey() string {
	if c.APIKeyFile != "" {
		raw, err := os.ReadFile(c.APIKeyFile)
		if err != nil {
			return ""
		}
		return strings.TrimRight(string(raw), "\r\n")
	}
	if c.APIKeyEnv != "" {
		return os.Getenv(c.APIKeyEnv)
	}
	return ""
}

// validateLLMBaseURL checks that the URL is safe to use as an LLM provider endpoint.
// Requires https:// scheme, or http://localhost / http://127. for dev.
// Rejects private ranges and known metadata endpoints.
func validateLLMBaseURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("JANUS_LLM_BASE_URL must not be empty")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("JANUS_LLM_BASE_URL is not a valid URL: %w", err)
	}

	host := u.Hostname()
	lowerHost := strings.ToLower(host)

	// Block known metadata endpoints by name
	metadataHosts := []string{
		"metadata.google.internal",
		"169.254.169.254",
		"fd00:ec2::254",
	}
	for _, blocked := range metadataHosts {
		if lowerHost == blocked {
			return fmt.Errorf("JANUS_LLM_BASE_URL: metadata endpoint %q is not allowed", host)
		}
	}

	isLocalhost := lowerHost == "localhost" || strings.HasPrefix(host, "127.")

	if u.Scheme == "https" {
		// For HTTPS, additionally block private/loopback/link-local IPs (except localhost 127.x)
		ip := net.ParseIP(host)
		if ip != nil && !isLocalhost {
			if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				return fmt.Errorf("JANUS_LLM_BASE_URL: private/link-local IP %q is not allowed; use a public HTTPS endpoint", host)
			}
		}
		return nil
	}

	if u.Scheme == "http" {
		if isLocalhost {
			return nil
		}
		return fmt.Errorf("JANUS_LLM_BASE_URL: http scheme is only allowed for localhost; use https for remote providers")
	}

	return fmt.Errorf("JANUS_LLM_BASE_URL: unsupported scheme %q; use https", u.Scheme)
}

type Config struct {
	DatabaseURL       string
	GRPCAddr          string
	HTTPAddr          string
	TLSCertFile       string
	TLSKeyFile        string
	ClientCAFile      string
	CommandSigningKey []byte
	// JWTSecret signs dashboard session tokens (AUTH-03). It is separated from
	// CommandSigningKey so a leaked session secret cannot forge migration commands and
	// vice-versa. Defaults to CommandSigningKey when JANUS_JWT_SECRET is unset.
	JWTSecret []byte
	// RequireTLS/RequireMTLS fail startup if gRPC TLS / client-cert verification is not
	// configured (AUTH-01) — production profiles set these so a misconfigured deploy
	// cannot silently fall back to plaintext / unauthenticated agents.
	RequireTLS        bool
	RequireMTLS       bool
	DisableAuth       bool
	CORSOrigin        string
	DBMaxConns        int
	DBMinConns        int
	DBMaxConnLifetime time.Duration
	DBMaxConnIdleTime time.Duration
	LogLevel          string
	AgentStallSeconds int
	GRPCMaxRecvBytes  int
	// GracefulShutdownSeconds bounds how long the server waits for in-flight
	// HTTP requests, gRPC telemetry streams, and pending webhook dispatches to
	// drain on SIGTERM/SIGINT before forcing exit (OPS-001).
	GracefulShutdownSeconds int
	// APIRateLimitPerMin caps requests per client IP per minute across the REST API
	// (OPS-002). 0 disables the global limiter; auth endpoints keep their own stricter cap.
	APIRateLimitPerMin int
	// MetricsAddr, when set, serves /metrics on a dedicated listener (OPS-006) in
	// addition to the main HTTP server, so scraping can be isolated from the API.
	MetricsAddr string
	// MetricsToken, when set, requires scrapers to present it as a bearer token on
	// /metrics. Empty (default) keeps /metrics open for backward compatibility, so
	// deployments that expose the port publicly should set it (SEC).
	MetricsToken string
	// Per-agent authentication (WP-029 P1). AgentAuthMode is "shared" (legacy single
	// command-key agent token) or "per-agent" (per-agent HMAC keys derived from
	// AgentKeyMaster, with per-agent revocation). AgentKeyMaster is required in
	// per-agent mode; AgentAuthWindowSeconds bounds request-token freshness.
	AgentAuthMode          string
	AgentKeyMaster         []byte
	AgentAuthWindowSeconds int
	LLM                    LLMConfig
	// Notify holds operator notification-channel settings (OPS-003). All optional;
	// a channel is enabled only when its settings are present.
	Notify NotifyConfig
	// Credentials are the configured dashboard logins (S1). Loaded from env per
	// role; there are NO compiled-in default passwords. Empty + auth enabled means
	// login is disabled (fail closed) until an operator configures credentials.
	Credentials []Credential
}

// NotifyConfig carries operator notification-channel settings (OPS-003), resolved from
// JANUS_NOTIFY_* settings. It is intentionally dependency-free; cmd/janus-server maps it
// onto the notify package's Config when building the dispatcher.
type NotifyConfig struct {
	SlackWebhookURL string   // JANUS_NOTIFY_SLACK_WEBHOOK_URL
	SMTPAddr        string   // JANUS_NOTIFY_SMTP_ADDR (host:port)
	SMTPFrom        string   // JANUS_NOTIFY_SMTP_FROM
	SMTPTo          []string // JANUS_NOTIFY_SMTP_TO (comma-separated)
	SMTPUsername    string   // JANUS_NOTIFY_SMTP_USERNAME
	SMTPPassword    string   // JANUS_NOTIFY_SMTP_PASSWORD
	PagerDutyKey    string   // JANUS_NOTIFY_PAGERDUTY_ROUTING_KEY
	MinSeverity     int      // JANUS_NOTIFY_MIN_SEVERITY (default 5)
}

// Credential is one dashboard login: a username, its role, a bcrypt hash, and the tenant it
// belongs to (WP-020). TenantID scopes what fleet/finding data the login can see — it flows
// into the JWT tenant claim and every tenant-scoped query/broadcast; defaults to DefaultTenant.
type Credential struct {
	Username string
	Role     string
	Hash     []byte
	TenantID string
}

// loadCredentials reads per-role credentials from the environment (S1). For each
// role it prefers JANUS_<ROLE>_PASSWORD_HASH (a bcrypt hash, so no plaintext is
// ever in the environment); otherwise it accepts JANUS_<ROLE>_PASSWORD (plaintext,
// hashed at startup). Username defaults to the role name, overridable via
// JANUS_<ROLE>_USERNAME. Roles with neither variable set simply cannot log in.
func loadCredentials() []Credential {
	var creds []Credential
	for _, role := range []string{"admin", "operator", "viewer"} {
		up := strings.ToUpper(role)
		username := env("JANUS_"+up+"_USERNAME", role)
		tenant := env("JANUS_"+up+"_TENANT", DefaultTenant)
		if h := strings.TrimSpace(getStr("JANUS_" + up + "_PASSWORD_HASH")); h != "" {
			creds = append(creds, Credential{Username: username, Role: role, Hash: []byte(h), TenantID: tenant})
			continue
		}
		if p := getStr("JANUS_" + up + "_PASSWORD"); p != "" {
			hash, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
			if err != nil {
				panic(fmt.Sprintf("hash JANUS_%s_PASSWORD: %v", up, err))
			}
			creds = append(creds, Credential{Username: username, Role: role, Hash: hash, TenantID: tenant})
		}
	}
	return creds
}

// loadNotify reads operator notification-channel settings (OPS-003). Every channel is
// optional; absent settings leave the corresponding channel disabled.
func loadNotify() NotifyConfig {
	var to []string
	for _, addr := range strings.Split(getStr("JANUS_NOTIFY_SMTP_TO"), ",") {
		if a := strings.TrimSpace(addr); a != "" {
			to = append(to, a)
		}
	}
	return NotifyConfig{
		SlackWebhookURL: getStr("JANUS_NOTIFY_SLACK_WEBHOOK_URL"),
		SMTPAddr:        getStr("JANUS_NOTIFY_SMTP_ADDR"),
		SMTPFrom:        getStr("JANUS_NOTIFY_SMTP_FROM"),
		SMTPTo:          to,
		SMTPUsername:    getStr("JANUS_NOTIFY_SMTP_USERNAME"),
		SMTPPassword:    getStr("JANUS_NOTIFY_SMTP_PASSWORD"),
		PagerDutyKey:    getStr("JANUS_NOTIFY_PAGERDUTY_ROUTING_KEY"),
		MinSeverity:     intEnv("JANUS_NOTIFY_MIN_SEVERITY", 5),
	}
}

func FromEnv() Config {
	// Optional config file (JANUS_CONFIG_FILE): KEY=VALUE using the same keys as the
	// environment variables. Precedence is env var > config file > constant default.
	fileVals = loadConfigFile()
	fileValsLoaded = true

	commandSigningKey := []byte(getStr("JANUS_COMMAND_SIGNING_KEY"))
	if path := getStr("JANUS_COMMAND_SIGNING_KEY_FILE"); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			panic(fmt.Sprintf("read JANUS_COMMAND_SIGNING_KEY_FILE: %v", err))
		}
		commandSigningKey = []byte(strings.TrimRight(string(raw), "\r\n"))
	}

	// Session/JWT signing key (AUTH-03): distinct knob, defaults to the command key.
	jwtSecret := []byte(getStr("JANUS_JWT_SECRET"))
	if path := getStr("JANUS_JWT_SECRET_FILE"); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			panic(fmt.Sprintf("read JANUS_JWT_SECRET_FILE: %v", err))
		}
		jwtSecret = []byte(strings.TrimRight(string(raw), "\r\n"))
	}
	if len(jwtSecret) == 0 {
		jwtSecret = commandSigningKey
	}
	requireMTLS := getStr("JANUS_REQUIRE_MTLS") == "true"

	// Per-agent auth master key (WP-029 P1): derives per-agent HMAC keys. Optional
	// unless AgentAuthMode is "per-agent" (validated below).
	agentKeyMaster := []byte(getStr("JANUS_AGENT_KEY_MASTER"))
	if path := getStr("JANUS_AGENT_KEY_MASTER_FILE"); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			panic(fmt.Sprintf("read JANUS_AGENT_KEY_MASTER_FILE: %v", err))
		}
		agentKeyMaster = []byte(strings.TrimRight(string(raw), "\r\n"))
	}

	cfg := Config{
		DatabaseURL:             env("JANUS_DATABASE_URL", DefaultDatabaseURL),
		GRPCAddr:                env("JANUS_GRPC_ADDR", DefaultGRPCAddr),
		HTTPAddr:                env("JANUS_HTTP_ADDR", DefaultHTTPAddr),
		TLSCertFile:             getStr("JANUS_TLS_CERT_FILE"),
		TLSKeyFile:              getStr("JANUS_TLS_KEY_FILE"),
		ClientCAFile:            getStr("JANUS_CLIENT_CA_FILE"),
		CommandSigningKey:       commandSigningKey,
		JWTSecret:               jwtSecret,
		RequireTLS:              getStr("JANUS_REQUIRE_TLS") == "true" || requireMTLS,
		RequireMTLS:             requireMTLS,
		DisableAuth:             getStr("JANUS_DISABLE_AUTH") == "true",
		CORSOrigin:              env("JANUS_CORS_ORIGIN", DefaultCORSOrigin),
		DBMaxConns:              intEnv("JANUS_DB_MAX_CONNS", DefaultDBMaxConns),
		DBMinConns:              intEnv("JANUS_DB_MIN_CONNS", DefaultDBMinConns),
		DBMaxConnLifetime:       durationEnv("JANUS_DB_MAX_CONN_LIFETIME", DefaultDBMaxConnLifetime),
		DBMaxConnIdleTime:       durationEnv("JANUS_DB_MAX_CONN_IDLE_TIME", DefaultDBMaxConnIdleTime),
		LogLevel:                env("JANUS_LOG_LEVEL", DefaultLogLevel),
		AgentStallSeconds:       intEnv("JANUS_AGENT_STALL_SECONDS", DefaultAgentStallSeconds),
		GRPCMaxRecvBytes:        intEnv("JANUS_GRPC_MAX_RECV_BYTES", DefaultGRPCMaxRecvBytes),
		GracefulShutdownSeconds: intEnv("JANUS_GRACEFUL_SHUTDOWN_SECONDS", DefaultGracefulShutdownSeconds),
		APIRateLimitPerMin:      intEnv("JANUS_API_RATE_LIMIT_PER_MIN", DefaultAPIRateLimitPerMin),
		MetricsAddr:             getStr("JANUS_METRICS_ADDR"),
		MetricsToken:            getStr("JANUS_METRICS_TOKEN"),
		AgentAuthMode:           env("JANUS_AGENT_AUTH_MODE", DefaultAgentAuthMode),
		AgentKeyMaster:          agentKeyMaster,
		AgentAuthWindowSeconds:  intEnv("JANUS_AGENT_AUTH_WINDOW_SECONDS", DefaultAgentAuthWindowSeconds),
		Notify:                  loadNotify(),
		Credentials:             loadCredentials(),
	}

	// Validate command signing key is set (no default fallback — fail on startup)
	if len(cfg.CommandSigningKey) == 0 {
		panic("JANUS_COMMAND_SIGNING_KEY environment variable is required. Generate a strong 32-byte random key.")
	}
	if len(cfg.CommandSigningKey) < 16 {
		panic("JANUS_COMMAND_SIGNING_KEY must be at least 16 bytes (recommended: 32 bytes)")
	}
	if len(cfg.JWTSecret) < 16 {
		panic("JANUS_JWT_SECRET must be at least 16 bytes (recommended: 32 bytes)")
	}
	if cfg.GRPCMaxRecvBytes < 4*1024*1024 {
		panic("JANUS_GRPC_MAX_RECV_BYTES must be at least 4194304 (4 MiB)")
	}
	// Clamp graceful-shutdown window to a sane range (OPS-001). Zero or negative
	// disables draining entirely, which would defeat the purpose; cap the upper
	// bound so a misconfiguration cannot hang a rolling update indefinitely.
	if cfg.GracefulShutdownSeconds < 1 {
		cfg.GracefulShutdownSeconds = 1
	}
	if cfg.GracefulShutdownSeconds > 300 {
		cfg.GracefulShutdownSeconds = 300
	}
	// A negative rate limit is meaningless; treat it as "disabled" (0) (OPS-002).
	if cfg.APIRateLimitPerMin < 0 {
		cfg.APIRateLimitPerMin = 0
	}

	// Per-agent auth (WP-029 P1) requires a master key to derive per-agent keys.
	if cfg.AgentAuthMode != "shared" && cfg.AgentAuthMode != "per-agent" {
		panic("JANUS_AGENT_AUTH_MODE must be 'shared' or 'per-agent'")
	}
	if cfg.AgentAuthMode == "per-agent" && len(cfg.AgentKeyMaster) == 0 {
		panic("JANUS_AGENT_AUTH_MODE=per-agent requires JANUS_AGENT_KEY_MASTER (or JANUS_AGENT_KEY_MASTER_FILE)")
	}

	// LLM provider configuration — optional
	baseURL := getStr("JANUS_LLM_BASE_URL")
	if baseURL != "" {
		if err := validateLLMBaseURL(baseURL); err != nil {
			panic(err.Error())
		}
		apiKeyEnv := env("JANUS_LLM_API_KEY_ENV", DefaultLLMAPIKeyEnv)
		timeout := intEnv("JANUS_LLM_TIMEOUT_SECONDS", DefaultLLMTimeoutSeconds)
		if timeout < 5 {
			timeout = 5
		} else if timeout > 300 {
			timeout = 300
		}
		maxRetries := intEnv("JANUS_LLM_MAX_RETRIES", DefaultLLMMaxRetries)
		if maxRetries < 0 {
			maxRetries = 0
		} else if maxRetries > 5 {
			maxRetries = 5
		}
		maxConcurrent := intEnv("JANUS_LLM_MAX_CONCURRENT", DefaultLLMMaxConcurrent)
		if maxConcurrent < 1 {
			maxConcurrent = 1
		} else if maxConcurrent > 32 {
			maxConcurrent = 32
		}
		maxTokens := intEnv("JANUS_LLM_MAX_TOKENS_PER_REQUEST", 0)
		if maxTokens < 0 {
			maxTokens = 0
		}
		maxRPM := intEnv("JANUS_LLM_MAX_REQUESTS_PER_MINUTE", 0)
		if maxRPM < 0 {
			maxRPM = 0
		}
		cfg.LLM = LLMConfig{
			Enabled:              true,
			BaseURL:              baseURL,
			APIKeyEnv:            apiKeyEnv,
			APIKeyFile:           getStr("JANUS_LLM_API_KEY_FILE"),
			ModelAnalysis:        env("JANUS_LLM_MODEL_ANALYSIS", DefaultLLMModelAnalysis),
			ModelRemediation:     env("JANUS_LLM_MODEL_REMEDIATION", DefaultLLMModelRemediation),
			TimeoutSeconds:       timeout,
			MaxRetries:           maxRetries,
			MaxConcurrent:        maxConcurrent,
			CapabilityMode:       env("JANUS_LLM_CAPABILITY_MODE", DefaultLLMCapabilityMode),
			MaxTokensPerRequest:  maxTokens,
			MaxRequestsPerMinute: maxRPM,
		}
	}

	return cfg
}

// fileVals holds KEY=VALUE pairs from the optional config file (JANUS_CONFIG_FILE).
// FromEnv populates it; callers that resolve settings outside FromEnv (e.g. the hsm
// package, command-signing setup) trigger a lazy load via ensureFileVals so the config
// file applies to every setting, not just those read inside FromEnv.
var (
	fileVals       map[string]string
	fileValsLoaded bool
)

// ensureFileVals lazily loads the config file once if FromEnv has not already done so.
func ensureFileVals() {
	if fileValsLoaded {
		return
	}
	fileVals = loadConfigFile()
	fileValsLoaded = true
}

// ReloadFile forces a fresh read of JANUS_CONFIG_FILE into the file layer. FromEnv loads it
// implicitly; alternate entrypoints and tests call this to refresh after changing the env.
func ReloadFile() {
	fileValsLoaded = false
	ensureFileVals()
}

// Value resolves a config key with precedence env var > config file (JANUS_CONFIG_FILE) > "".
// Public so packages outside config (hsm, command-signing setup) honor the file too.
func Value(key string) string { return lookup(key) }

// ValueOr is Value with a default fallback when neither the env var nor the file sets key.
func ValueOr(key, def string) string { return env(key, def) }

// BoolValue resolves key as a boolean (strconv.ParseBool semantics: true/1/t/...). False when unset.
func BoolValue(key string) bool {
	b, _ := strconv.ParseBool(strings.TrimSpace(lookup(key)))
	return b
}

// loadConfigFile reads JANUS_CONFIG_FILE — a KEY=VALUE file using the same keys as the
// environment variables (`#` comments, optional `export ` prefix, and optional surrounding
// quotes are supported). Returns nil when the variable is unset; panics if the file is set
// but unreadable (a misconfiguration we want surfaced at startup).
func loadConfigFile() map[string]string {
	path := os.Getenv("JANUS_CONFIG_FILE")
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("read JANUS_CONFIG_FILE %q: %v", path, err))
	}
	return parseConfigFile(string(raw))
}

func parseConfigFile(s string) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		k := strings.TrimSpace(line[:eq])
		v := strings.TrimSpace(line[eq+1:])
		if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
			v = v[1 : len(v)-1]
		}
		if k != "" {
			m[k] = v
		}
	}
	return m
}

// lookup resolves a config key with precedence env var > config file > "".
// A non-empty environment variable always wins; an empty/unset one falls through to
// the config file (matching the prior `os.Getenv(key) != ""` semantics).
func lookup(key string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	ensureFileVals()
	if v, ok := fileVals[key]; ok {
		return v
	}
	return ""
}

// getStr returns the resolved value for key (env > file), or "" if neither sets it.
func getStr(key string) string { return lookup(key) }

func env(key, fallback string) string {
	if v := lookup(key); v != "" {
		return v
	}
	return fallback
}

func intEnv(key string, fallback int) int {
	if v := lookup(key); v != "" {
		var val int
		if _, err := fmt.Sscanf(v, "%d", &val); err == nil {
			return val
		}
	}
	return fallback
}

func durationEnv(key string, fallback time.Duration) time.Duration {
	if v := lookup(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
