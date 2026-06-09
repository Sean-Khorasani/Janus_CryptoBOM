package config

import (
	"fmt"
	"os"
	"time"
)

type Config struct {
	DatabaseURL        string
	GRPCAddr           string
	HTTPAddr           string
	TLSCertFile        string
	TLSKeyFile         string
	ClientCAFile       string
	CommandSigningKey  []byte
	DisableAuth        bool
	CORSOrigin         string
	DBMaxConns         int
	DBMinConns         int
	DBMaxConnLifetime  time.Duration
	DBMaxConnIdleTime  time.Duration
	LogLevel           string
	AgentStallSeconds  int
}

func FromEnv() Config {
	cfg := Config{
		DatabaseURL:       env("JANUS_DATABASE_URL", "postgres://janus:janus@localhost:5432/janus?sslmode=disable"),
		GRPCAddr:          env("JANUS_GRPC_ADDR", "127.0.0.1:9443"),
		HTTPAddr:          env("JANUS_HTTP_ADDR", "127.0.0.1:8080"),
		TLSCertFile:       os.Getenv("JANUS_TLS_CERT_FILE"),
		TLSKeyFile:        os.Getenv("JANUS_TLS_KEY_FILE"),
		ClientCAFile:      os.Getenv("JANUS_CLIENT_CA_FILE"),
		CommandSigningKey: []byte(os.Getenv("JANUS_COMMAND_SIGNING_KEY")),
		DisableAuth:       os.Getenv("JANUS_DISABLE_AUTH") == "true",
		CORSOrigin:        env("JANUS_CORS_ORIGIN", "http://localhost:5173"),
		DBMaxConns:        intEnv("JANUS_DB_MAX_CONNS", 25),
		DBMinConns:        intEnv("JANUS_DB_MIN_CONNS", 5),
		DBMaxConnLifetime: durationEnv("JANUS_DB_MAX_CONN_LIFETIME", 30*time.Minute),
		DBMaxConnIdleTime: durationEnv("JANUS_DB_MAX_CONN_IDLE_TIME", 5*time.Minute),
		LogLevel:          env("JANUS_LOG_LEVEL", "info"),
		AgentStallSeconds: intEnv("JANUS_AGENT_STALL_SECONDS", 300),
	}

	// Validate command signing key is set (no default fallback — fail on startup)
	if len(cfg.CommandSigningKey) == 0 {
		panic("JANUS_COMMAND_SIGNING_KEY environment variable is required. Generate a strong 32-byte random key.")
	}
	if len(cfg.CommandSigningKey) < 16 {
		panic("JANUS_COMMAND_SIGNING_KEY must be at least 16 bytes (recommended: 32 bytes)")
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

