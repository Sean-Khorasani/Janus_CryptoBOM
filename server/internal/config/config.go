package config

import "os"

type Config struct {
	DatabaseURL       string
	GRPCAddr          string
	HTTPAddr          string
	TLSCertFile       string
	TLSKeyFile        string
	CommandSigningKey []byte
}

func FromEnv() Config {
	return Config{
		DatabaseURL:       env("JANUS_DATABASE_URL", "postgres://janus:janus@localhost:5432/janus?sslmode=disable"),
		GRPCAddr:          env("JANUS_GRPC_ADDR", "127.0.0.1:9443"),
		HTTPAddr:          env("JANUS_HTTP_ADDR", "127.0.0.1:8080"),
		TLSCertFile:       os.Getenv("JANUS_TLS_CERT_FILE"),
		TLSKeyFile:        os.Getenv("JANUS_TLS_KEY_FILE"),
		CommandSigningKey: []byte(env("JANUS_COMMAND_SIGNING_KEY", "local-development-command-signing-key")),
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

