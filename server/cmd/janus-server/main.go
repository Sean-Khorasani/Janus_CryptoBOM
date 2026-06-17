package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/janus-cbom/janus/server/internal/certmanager"
	"github.com/janus-cbom/janus/server/internal/config"
	"github.com/janus-cbom/janus/server/internal/grpcserver"
	"github.com/janus-cbom/janus/server/internal/hsm"
	"github.com/janus-cbom/janus/server/internal/httpapi"
	"github.com/janus-cbom/janus/server/internal/notify"
	"github.com/janus-cbom/janus/server/internal/orchestrator"
	"github.com/janus-cbom/janus/server/internal/pb"
	"github.com/janus-cbom/janus/server/internal/policy"
	"github.com/janus-cbom/janus/server/internal/store"
	"github.com/janus-cbom/janus/server/internal/version"
	"github.com/janus-cbom/janus/server/internal/ws"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

func main() {
	// Admin CLI subcommands (HSM key management, HMAC key gen) run and exit before the
	// server starts — `janus-server <subcommand> ...`.
	if runCLIIfRequested() {
		return
	}

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
	// Tag every line with the service + version so aggregated logs from multiple
	// components/replicas are filterable, and emit correlation-tagged JSON (OPS-004).
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})).
		With("service", "janus-server", "version", version.Version)
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pg, err := store.NewPostgres(ctx, store.PostgresConfig{
		DatabaseURL:     cfg.DatabaseURL,
		MaxConns:        cfg.DBMaxConns,
		MinConns:        cfg.DBMinConns,
		MaxConnLifetime: cfg.DBMaxConnLifetime,
		MaxConnIdleTime: cfg.DBMaxConnIdleTime,
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

	// Operator notification channels (OPS-003). Optional; enabled only when configured.
	// The Slack URL comes from server config (operator-trusted), so no SSRF validator here.
	notifier, nerr := notify.New(notify.Config{
		SlackWebhookURL: cfg.Notify.SlackWebhookURL,
		SMTPAddr:        cfg.Notify.SMTPAddr,
		SMTPFrom:        cfg.Notify.SMTPFrom,
		SMTPTo:          cfg.Notify.SMTPTo,
		SMTPUsername:    cfg.Notify.SMTPUsername,
		SMTPPassword:    cfg.Notify.SMTPPassword,
		PagerDutyKey:    cfg.Notify.PagerDutyKey,
		MinSeverity:     cfg.Notify.MinSeverity,
	}, nil, nil)
	if nerr != nil {
		slog.Error("notification config invalid", "error", nerr)
		os.Exit(1)
	}
	grpcSvc.SetNotifier(notifier)
	if notifier.Enabled() {
		slog.Info("operator notifications enabled", "channels", notifier.Channels())
	}

	grpcOptions := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(cfg.GRPCMaxRecvBytes),
		// REM-7: bound dead/idle streams so a wedged or vanished agent cannot hold a
		// server goroutine indefinitely. The server pings idle peers and drops them
		// when the ack times out; idle (no active RPC) connections are also reaped.
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:              60 * time.Second,
			Timeout:           20 * time.Second,
			MaxConnectionIdle: 15 * time.Minute,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             30 * time.Second,
			PermitWithoutStream: true,
		}),
	}
	// AUTH-01: fail fast if a production profile requires TLS / mTLS but it is not
	// configured, rather than silently serving plaintext or unauthenticated agents.
	if cfg.RequireTLS && (cfg.TLSCertFile == "" || cfg.TLSKeyFile == "") {
		slog.Error("JANUS_REQUIRE_TLS is set but JANUS_TLS_CERT_FILE and JANUS_TLS_KEY_FILE are not both configured")
		os.Exit(1)
	}
	if cfg.RequireMTLS && cfg.ClientCAFile == "" {
		slog.Error("JANUS_REQUIRE_MTLS is set but JANUS_CLIENT_CA_FILE is not configured")
		os.Exit(1)
	}
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

	// Per-agent gRPC authentication (WP-029 P1). No-op in the default "shared" mode;
	// when enabled, every RPC must carry valid janus-agent-{id,ts,auth} metadata.
	if cfg.AgentAuthMode == "per-agent" {
		window := int64(cfg.AgentAuthWindowSeconds)
		grpcOptions = append(grpcOptions,
			grpc.ChainUnaryInterceptor(grpcserver.PerAgentUnaryInterceptor(pg, cfg.AgentKeyMaster, window)),
			grpc.ChainStreamInterceptor(grpcserver.PerAgentStreamInterceptor(pg, cfg.AgentKeyMaster, window)),
		)
		slog.Info("per-agent gRPC authentication enabled")
	}

	grpcServer := grpc.NewServer(grpcOptions...)
	pb.RegisterJanusTelemetryServer(grpcServer, grpcSvc)

	grpcLn, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		slog.Error("listen grpc", "error", err)
		os.Exit(1)
	}

	// Session tokens use the (separable) JWT secret, not the command-signing key (AUTH-03).
	httpHandler, api := httpapi.New(pg, orch, engine, cfg.JWTSecret, cfg.DisableAuth, wsHub, cfg)

	// Optional dedicated metrics listener (OPS-006) — lets operators isolate Prometheus
	// scraping from the API surface. /metrics also remains on the main HTTP server.
	if cfg.MetricsAddr != "" {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", api.MetricsHandler())
		metricsSrv := &http.Server{Addr: cfg.MetricsAddr, Handler: metricsMux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			slog.Info("janus metrics listener", "addr", cfg.MetricsAddr)
			if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("metrics listener", "error", err)
			}
		}()
	}

	// Configurable HSM backend (HSM-01 + configurable HSM): JANUS_HSM_MODE selects
	// disabled | software | pkcs11. "software" (default) is a process-local keystore with
	// real ML-DSA signing; "pkcs11" uses a real token (SoftHSM2/hardware) and FAILS CLOSED
	// if it cannot be opened — so an operator who requires hardware-backed keys cannot
	// silently fall back to software.
	hsmCfg := hsm.LoadConfigFromEnv()
	hsmBackend, hsmErr := hsm.NewBackend(hsmCfg)
	if hsmErr != nil {
		slog.Error("HSM backend initialization failed", "mode", hsmCfg.Mode, "error", hsmErr)
		os.Exit(1)
	}
	if hsmBackend == nil {
		slog.Info("HSM disabled (JANUS_HSM_MODE=disabled); /api/hsm/* will return 501")
	} else {
		api.SetHSM(hsmBackend)
		slog.Info("HSM backend ready", "mode", hsmCfg.Mode)
	}

	// Baseline migration-command signing is HMAC-SHA256 (mandatory, quantum-resistant
	// symmetric MAC). Optionally the command key is held in the HSM (JANUS_HSM_SIGN_COMMANDS)
	// so it never sits in server memory; the wire value + agent verification are unchanged.
	// (Additional ML-DSA asymmetric command signing, with agent-side fingerprint-pinned
	// verification, is layered on top separately.)
	if hsmBackend != nil && hsmCfg.SignCommands {
		signer, ok := hsmBackend.(hsm.MACSigner)
		if !ok {
			slog.Error("JANUS_HSM_SIGN_COMMANDS is set but this HSM backend cannot compute a MAC", "mode", hsmCfg.Mode)
			os.Exit(1)
		}
		if err := signer.EnsureMACKey(hsmCfg.CommandKeyLabel, cfg.CommandSigningKey); err != nil {
			slog.Error("failed to provision the command-signing key in the HSM", "error", err)
			os.Exit(1)
		}
		orch.UseHSMSigner(signer, hsmCfg.CommandKeyLabel)
		slog.Info("migration-command signing is HSM-resident (HMAC)", "mode", hsmCfg.Mode, "key_label", hsmCfg.CommandKeyLabel)
	}

	// Optional additional layer: ML-DSA asymmetric command signing (JANUS_COMMAND_SIG_SCHEME=
	// ml-dsa). HMAC remains the mandatory baseline; this ADDS an ML-DSA signature that
	// agents verify after pinning the key's SHA-256 fingerprint. Prefers an HSM-resident
	// key (persistent), else a software key (ephemeral — fingerprint changes on restart).
	if strings.EqualFold(config.ValueOr("JANUS_COMMAND_SIG_SCHEME", config.DefaultCommandSigScheme), "ml-dsa") {
		alg := config.ValueOr("JANUS_COMMAND_SIG_ALG", config.DefaultCommandSigAlg)
		label := config.ValueOr("JANUS_COMMAND_SIG_KEY_LABEL", config.DefaultCommandSigKeyLabel)
		var pub []byte
		if ckm, ok := hsmBackend.(hsm.CommandKeyManager); ok {
			keyID, err := ckm.EnsureMLDSAKey(label, alg)
			if err != nil {
				slog.Error("ml-dsa command signing: provisioning the HSM key failed", "alg", alg, "error", err)
				os.Exit(1)
			}
			if pub, err = ckm.PublicKey(keyID); err != nil {
				slog.Error("ml-dsa command signing: reading the HSM public key failed", "error", err)
				os.Exit(1)
			}
			backend := hsmBackend
			orch.AddMLDSASigner(func(b []byte) ([]byte, error) { return backend.Sign(keyID, b) }, pub)
			fp := sha256.Sum256(pub)
			slog.Info("ML-DSA command signing enabled (HSM-resident key); pin this fingerprint on agents (command_pqc_fingerprint)",
				"alg", alg, "label", label, "fingerprint", hex.EncodeToString(fp[:]))
		} else {
			// Software signer: load a persistent key (required for a stable CA-chained
			// command cert) when JANUS_COMMAND_SIG_KEY_FILE is set, else generate ephemeral.
			var signer *orchestrator.MLDSACommandSigner
			var err error
			if keyFile := config.Value("JANUS_COMMAND_SIG_KEY_FILE"); keyFile != "" {
				keyBytes, lerr := loadPEMOrRaw(keyFile, "ML-DSA PRIVATE KEY")
				if lerr != nil {
					slog.Error("ml-dsa command signing: reading JANUS_COMMAND_SIG_KEY_FILE failed", "error", lerr)
					os.Exit(1)
				}
				signer, err = orchestrator.NewMLDSACommandSignerFromKey(alg, keyBytes)
			} else {
				signer, err = orchestrator.NewMLDSACommandSigner(alg)
			}
			if err != nil {
				slog.Error("ml-dsa command signing: software key setup failed", "alg", alg, "error", err)
				os.Exit(1)
			}
			pub, _ = signer.PublicKey()
			orch.AddMLDSASigner(signer.Sign, pub)
			fp := sha256.Sum256(pub)
			if config.Value("JANUS_COMMAND_SIG_KEY_FILE") != "" {
				slog.Info("ML-DSA command signing enabled (software key from file; stable across restarts)",
					"alg", alg, "fingerprint", hex.EncodeToString(fp[:]))
			} else {
				slog.Warn("ML-DSA command signing enabled (SOFTWARE key — fingerprint CHANGES on restart; use JANUS_HSM_MODE=pkcs11 or JANUS_COMMAND_SIG_KEY_FILE for a stable key); pin this fingerprint on agents",
					"alg", alg, "fingerprint", hex.EncodeToString(fp[:]))
			}
		}

		// CA-chained command trust (WP-029 P3, janus-sig-v2): when a command certificate is
		// provided, embed it in each command so agents verify the chain to the bundled root
		// (command_root_ca) instead of pinning a fingerprint. Fail closed if the cert's public
		// key does not match the signing key — a mismatch would make every command unverifiable.
		if certFile := config.Value("JANUS_COMMAND_SIG_CERT_FILE"); certFile != "" {
			leafDER, err := loadPEMOrRaw(certFile, "CERTIFICATE")
			if err != nil {
				slog.Error("ml-dsa command signing: reading JANUS_COMMAND_SIG_CERT_FILE failed", "error", err)
				os.Exit(1)
			}
			certPub, _, err := certmanager.MLDSAPublicKeyFromCert(leafDER)
			if err != nil {
				slog.Error("ml-dsa command signing: JANUS_COMMAND_SIG_CERT_FILE is not an ML-DSA certificate", "error", err)
				os.Exit(1)
			}
			certPubBytes, _ := certPub.MarshalBinary()
			if !bytes.Equal(certPubBytes, pub) {
				slog.Error("ml-dsa command signing: JANUS_COMMAND_SIG_CERT_FILE public key does not match the signing key; refusing to start")
				os.Exit(1)
			}
			orch.SetMLDSACommandCert(leafDER)
			slog.Info("ML-DSA command signing: CA-chained janus-sig-v2 enabled; bundle the command Root CA to agents (command_root_ca)")
		}
	}

	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           httpHandler,
		ReadHeaderTimeout: 5 * time.Second, // slowloris header defense
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MiB header cap
		// ReadTimeout/WriteTimeout are intentionally unset: a server-wide write
		// deadline would also apply to the hijacked, long-lived /api/ws connection.
		// Header slowloris is covered by ReadHeaderTimeout and bodies by bodyLimit.
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

	// Graceful shutdown (OPS-001). Bound the whole drain by the configured
	// window so a rolling update cannot hang indefinitely.
	gracePeriod := time.Duration(cfg.GracefulShutdownSeconds) * time.Second
	deadline := time.Now().Add(gracePeriod)
	slog.Info("draining", "grace_period", gracePeriod.String())

	// 1. Flip readiness to "draining" so new requests get 503 and load
	//    balancers stop routing traffic; in-flight requests keep going.
	api.BeginDraining()

	// 2. Stop accepting new gRPC streams and wait for in-flight telemetry
	//    stream handlers to return (their payloads persist before returning).
	grpcServer.GracefulStop()

	// 3. Drain pending critical-finding webhook dispatches.
	if remaining := time.Until(deadline); remaining > 0 {
		if ok := grpcSvc.WaitWebhooks(remaining); !ok {
			slog.Warn("webhook dispatch drain timed out; some notifications may be incomplete")
		}
	}

	// 4. Shut down the HTTP server, letting in-flight requests finish up to the
	//    remaining grace window.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), maxDuration(time.Until(deadline), time.Second))
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		slog.Warn("http shutdown", "error", err)
	}
	slog.Info("shutdown complete")
}

// maxDuration returns the larger of a and b. Used to guarantee a minimum HTTP
// shutdown window even if the grace period has already been consumed by earlier
// drain stages (OPS-001).
func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

// loadPEMOrRaw reads a file and returns the DER/raw bytes of the first PEM block whose type
// matches pemType; if the file is not PEM, the raw bytes are returned as-is. Used to load the
// ML-DSA command cert (CERTIFICATE) and key (ML-DSA PRIVATE KEY) for janus-sig-v2.
func loadPEMOrRaw(path, pemType string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rest := raw
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == pemType {
			return block.Bytes, nil
		}
		rest = next
	}
	return raw, nil
}
