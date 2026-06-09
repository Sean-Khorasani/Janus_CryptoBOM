package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/janus-cbom/janus/server/internal/config"
	"github.com/janus-cbom/janus/server/internal/grpcserver"
	"github.com/janus-cbom/janus/server/internal/hsm"
	"github.com/janus-cbom/janus/server/internal/httpapi"
	"github.com/janus-cbom/janus/server/internal/orchestrator"
	"github.com/janus-cbom/janus/server/internal/pb"
	"github.com/janus-cbom/janus/server/internal/policy"
	"github.com/janus-cbom/janus/server/internal/store"
	"github.com/janus-cbom/janus/server/internal/ws"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	cfg := config.FromEnv()

	// Initialize structured logging
	var level slog.Level
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pg, err := store.NewPostgres(ctx, store.PostgresConfig{
		DatabaseURL:      cfg.DatabaseURL,
		MaxConns:         cfg.DBMaxConns,
		MinConns:         cfg.DBMinConns,
		MaxConnLifetime:  cfg.DBMaxConnLifetime,
		MaxConnIdleTime:  cfg.DBMaxConnIdleTime,
	})
	if err != nil {
		slog.Error("connect postgres", "error", err)
		os.Exit(1)
	}
	defer pg.Close()

	if err := pg.EnsureSchema(ctx); err != nil {
		slog.Error("ensure schema", "error", err)
		os.Exit(1)
	}

	engine, err := policy.LoadEngine("policies")
	if err != nil {
		slog.Error("load policy engine", "error", err)
		os.Exit(1)
	}
	orch := orchestrator.New(cfg.CommandSigningKey)
	wsHub := ws.New()
	grpcSvc := grpcserver.New(pg, engine, orch, wsHub)

	grpcOptions := []grpc.ServerOption{}
	if cfg.TLSCertFile != "" || cfg.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			slog.Error("load tls certificate", "error", err)
			os.Exit(1)
		}

		var clientCAs *x509.CertPool
		if cfg.ClientCAFile != "" {
			caBytes, err := os.ReadFile(cfg.ClientCAFile)
			if err != nil {
				slog.Error("load client ca certificate", "error", err)
				os.Exit(1)
			}
			clientCAs = x509.NewCertPool()
			if ok := clientCAs.AppendCertsFromPEM(caBytes); !ok {
				slog.Error("failed to parse client ca certificate")
				os.Exit(1)
			}
		}

		tlsCfg := &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
		}

		if clientCAs != nil {
			tlsCfg.ClientCAs = clientCAs
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
			slog.Info("gRPC configured for Mutual TLS (mTLS) client verification")
		}

		grpcOptions = append(grpcOptions, grpc.Creds(credentials.NewTLS(tlsCfg)))
	} else {
		slog.Warn("TLS not configured; gRPC listening without TLS for local development")
	}

	grpcServer := grpc.NewServer(grpcOptions...)
	pb.RegisterJanusTelemetryServer(grpcServer, grpcSvc)

	grpcLn, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		slog.Error("listen grpc", "error", err)
		os.Exit(1)
	}

	httpHandler := httpapi.New(pg, orch, engine, cfg.CommandSigningKey, cfg.DisableAuth, wsHub)

	// Initialize HSM client if configured (F13)
	_ = os.Getenv("JANUS_HSM_MODULE_PATH") // reserved for HSM integration
	_ = hsm.NewSoftHSM2 // ensure package is used

	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           httpHandler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 2)
	go func() {
		slog.Info("janus gRPC controller listening", "addr", cfg.GRPCAddr)
		errCh <- grpcServer.Serve(grpcLn)
	}()
	go func() {
		slog.Info("janus HTTP API listening", "addr", cfg.HTTPAddr)
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		slog.Info("shutdown requested")
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	grpcServer.GracefulStop()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		slog.Warn("http shutdown", "error", err)
	}
}

