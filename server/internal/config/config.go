package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
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
	DisableAuth       bool
	CORSOrigin        string
	DBMaxConns        int
	DBMinConns        int
	DBMaxConnLifetime time.Duration
	DBMaxConnIdleTime time.Duration
	LogLevel          string
	AgentStallSeconds int
	GRPCMaxRecvBytes  int
	LLM               LLMConfig
}

func FromEnv() Config {
	commandSigningKey := []byte(os.Getenv("JANUS_COMMAND_SIGNING_KEY"))
	if path := os.Getenv("JANUS_COMMAND_SIGNING_KEY_FILE"); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			panic(fmt.Sprintf("read JANUS_COMMAND_SIGNING_KEY_FILE: %v", err))
		}
		commandSigningKey = []byte(strings.TrimRight(string(raw), "\r\n"))
	}

	cfg := Config{
		DatabaseURL:       env("JANUS_DATABASE_URL", "postgres://janus:janus@localhost:5432/janus?sslmode=disable"),
		GRPCAddr:          env("JANUS_GRPC_ADDR", "127.0.0.1:9443"),
		HTTPAddr:          env("JANUS_HTTP_ADDR", "127.0.0.1:8080"),
		TLSCertFile:       os.Getenv("JANUS_TLS_CERT_FILE"),
		TLSKeyFile:        os.Getenv("JANUS_TLS_KEY_FILE"),
		ClientCAFile:      os.Getenv("JANUS_CLIENT_CA_FILE"),
		CommandSigningKey: commandSigningKey,
		DisableAuth:       os.Getenv("JANUS_DISABLE_AUTH") == "true",
		CORSOrigin:        env("JANUS_CORS_ORIGIN", "http://localhost:5173"),
		DBMaxConns:        intEnv("JANUS_DB_MAX_CONNS", 25),
		DBMinConns:        intEnv("JANUS_DB_MIN_CONNS", 5),
		DBMaxConnLifetime: durationEnv("JANUS_DB_MAX_CONN_LIFETIME", 30*time.Minute),
		DBMaxConnIdleTime: durationEnv("JANUS_DB_MAX_CONN_IDLE_TIME", 5*time.Minute),
		LogLevel:          env("JANUS_LOG_LEVEL", "info"),
		AgentStallSeconds: intEnv("JANUS_AGENT_STALL_SECONDS", 300),
		GRPCMaxRecvBytes:  intEnv("JANUS_GRPC_MAX_RECV_BYTES", 32*1024*1024),
	}

	// Validate command signing key is set (no default fallback — fail on startup)
	if len(cfg.CommandSigningKey) == 0 {
		panic("JANUS_COMMAND_SIGNING_KEY environment variable is required. Generate a strong 32-byte random key.")
	}
	if len(cfg.CommandSigningKey) < 16 {
		panic("JANUS_COMMAND_SIGNING_KEY must be at least 16 bytes (recommended: 32 bytes)")
	}
	if cfg.GRPCMaxRecvBytes < 4*1024*1024 {
		panic("JANUS_GRPC_MAX_RECV_BYTES must be at least 4194304 (4 MiB)")
	}

	// LLM provider configuration — optional
	baseURL := os.Getenv("JANUS_LLM_BASE_URL")
	if baseURL != "" {
		if err := validateLLMBaseURL(baseURL); err != nil {
			panic(err.Error())
		}
		apiKeyEnv := env("JANUS_LLM_API_KEY_ENV", "JANUS_LLM_API_KEY")
		timeout := intEnv("JANUS_LLM_TIMEOUT_SECONDS", 30)
		if timeout < 5 {
			timeout = 5
		} else if timeout > 300 {
			timeout = 300
		}
		maxRetries := intEnv("JANUS_LLM_MAX_RETRIES", 2)
		if maxRetries < 0 {
			maxRetries = 0
		} else if maxRetries > 5 {
			maxRetries = 5
		}
		maxConcurrent := intEnv("JANUS_LLM_MAX_CONCURRENT", 4)
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
			APIKeyFile:           os.Getenv("JANUS_LLM_API_KEY_FILE"),
			ModelAnalysis:        env("JANUS_LLM_MODEL_ANALYSIS", "gpt-4o-mini"),
			ModelRemediation:     env("JANUS_LLM_MODEL_REMEDIATION", "gpt-4o"),
			TimeoutSeconds:       timeout,
			MaxRetries:           maxRetries,
			MaxConcurrent:        maxConcurrent,
			CapabilityMode:       env("JANUS_LLM_CAPABILITY_MODE", "analysis_only"),
			MaxTokensPerRequest:  maxTokens,
			MaxRequestsPerMinute: maxRPM,
		}
	}

	return cfg
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func intEnv(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		var val int
		if _, err := fmt.Sscanf(v, "%d", &val); err == nil {
			return val
		}
	}
	return fallback
}

func durationEnv(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
