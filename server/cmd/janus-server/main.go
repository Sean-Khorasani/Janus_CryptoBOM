package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/janus-cbom/janus/server/internal/config"
	"github.com/janus-cbom/janus/server/internal/grpcserver"
	"github.com/janus-cbom/janus/server/internal/httpapi"
	"github.com/janus-cbom/janus/server/internal/orchestrator"
	"github.com/janus-cbom/janus/server/internal/pb"
	"github.com/janus-cbom/janus/server/internal/policy"
	"github.com/janus-cbom/janus/server/internal/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	cfg := config.FromEnv()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pg, err := store.NewPostgres(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("connect postgres: %v", err)
	}
	defer pg.Close()

	if err := pg.EnsureSchema(ctx); err != nil {
		log.Fatalf("ensure schema: %v", err)
	}

	engine, err := policy.LoadEngine("policies")
	if err != nil {
		log.Fatalf("load policy engine: %v", err)
	}
	orch := orchestrator.New(cfg.CommandSigningKey)
	grpcSvc := grpcserver.New(pg, engine, orch)

	grpcOptions := []grpc.ServerOption{}
	if cfg.TLSCertFile != "" || cfg.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			log.Fatalf("load tls certificate: %v", err)
		}
		tlsCfg := &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
		}
		grpcOptions = append(grpcOptions, grpc.Creds(credentials.NewTLS(tlsCfg)))
	} else {
		log.Printf("JANUS_TLS_CERT_FILE/JANUS_TLS_KEY_FILE not set; gRPC listening without TLS for local development")
	}

	grpcServer := grpc.NewServer(grpcOptions...)
	pb.RegisterJanusTelemetryServer(grpcServer, grpcSvc)

	grpcLn, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		log.Fatalf("listen grpc: %v", err)
	}

	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           httpapi.New(pg, orch, engine),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 2)
	go func() {
		log.Printf("janus gRPC controller listening on %s", cfg.GRPCAddr)
		errCh <- grpcServer.Serve(grpcLn)
	}()
	go func() {
		log.Printf("janus HTTP API listening on %s", cfg.HTTPAddr)
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		log.Printf("shutdown requested")
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	grpcServer.GracefulStop()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("http shutdown: %v", err)
	}
}

