package grpcserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/janus-cbom/janus/server/internal/orchestrator"
	"github.com/janus-cbom/janus/server/internal/pb"
	"github.com/janus-cbom/janus/server/internal/policy"
	"github.com/janus-cbom/janus/server/internal/store"
	"github.com/janus-cbom/janus/server/internal/version"
	"github.com/janus-cbom/janus/server/internal/ws"
	"google.golang.org/grpc/peer"
)

// webhookCircuit tracks failure state for circuit-breaking.
type webhookCircuit struct {
	mu            sync.Mutex
	failures      map[string]int       // url -> consecutive failure count
	cooldownUntil map[string]time.Time // url -> cooldown expiry
}

func (wc *webhookCircuit) recordFailure(url string) {
	wc.mu.Lock()
	defer wc.mu.Unlock()
	wc.failures[url]++
	if wc.failures[url] >= 5 {
		wc.cooldownUntil[url] = time.Now().Add(60 * time.Second)
	}
}

func (wc *webhookCircuit) recordSuccess(url string) {
	wc.mu.Lock()
	defer wc.mu.Unlock()
	delete(wc.failures, url)
	delete(wc.cooldownUntil, url)
}

func (wc *webhookCircuit) isOpen(url string) bool {
	wc.mu.Lock()
	defer wc.mu.Unlock()
	if cooldown, ok := wc.cooldownUntil[url]; ok && time.Now().Before(cooldown) {
		return true
	}
	return false
}

type Server struct {
	pb.UnimplementedJanusTelemetryServer
	store   store.Store
	policy  *policy.Engine
	orch    *orchestrator.Orchestrator
	circuit *webhookCircuit
	wsHub   *ws.Hub
}

func New(store store.Store, policy *policy.Engine, orch *orchestrator.Orchestrator, wsHub *ws.Hub) *Server {
	return &Server{
		store:  store,
		policy: policy,
		orch:   orch,
		wsHub:  wsHub,
		circuit: &webhookCircuit{
			failures:      make(map[string]int),
			cooldownUntil: make(map[string]time.Time),
		},
	}
}

func (s *Server) RegisterAgent(ctx context.Context, reg *pb.AgentRegistration) (*pb.AgentRegistrationAck, error) {
	if reg.HostUuid == "" || reg.Hostname == "" {
		return nil, fmt.Errorf("host_uuid and hostname are required")
	}
	if reg.HostUuid == "ci-cd-runner" {
		return nil, fmt.Errorf("ci-cd-runner is a reserved scan identity and cannot register as a managed agent")
	}
	observedIP := ""
	if remote, ok := peer.FromContext(ctx); ok {
		observedIP = remote.Addr.String()
		if host, _, err := net.SplitHostPort(observedIP); err == nil {
			observedIP = host
		}
	}
	if err := s.store.UpsertAgent(ctx, reg, observedIP); err != nil {
		return nil, err
	}
	s.wsHub.Broadcast("agent_registered", map[string]any{"host_uuid": reg.HostUuid, "hostname": reg.Hostname, "observed_ip": observedIP, "agent_version": reg.AgentVersion})
	return &pb.AgentRegistrationAck{
		HostUuid:      reg.HostUuid,
		Accepted:      true,
		ControllerId:  "janus-controller",
		PolicyVersion: s.policy.ProfileVersion(),
		EnabledCapabilities: []string{
			"cbom-intake",
			"pqc-policy-assessment",
			"signed-active-migration",
		},
		Message: "registered",
	}, nil
}

func (s *Server) StreamTelemetry(stream pb.JanusTelemetry_StreamTelemetryServer) error {
	var hostUUID string
	for {
		payload, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if payload.HostUuid == "" {
			return fmt.Errorf("payload host_uuid is required")
		}
		hostUUID = payload.HostUuid
		config, _ := s.store.GetAgentScanConfig(stream.Context(), payload.HostUuid)
		if config != nil && config.PolicyVersion != "" {
			s.policy.AssessWithVersion(payload, config.PolicyVersion)
		} else {
			s.policy.Assess(payload)
		}
		if err := s.store.InsertTelemetry(stream.Context(), payload); err != nil {
			return err
		}

		// Telemetry Webhook Dispatch Feature
		hasCritical := false
		for _, f := range payload.Findings {
			if f.Severity >= 5 { // Critical
				hasCritical = true
				break
			}
		}
		if hasCritical {
			go s.dispatchWebhooks(payload)
		}

		slog.Info("telemetry received",
			"host_uuid", payload.HostUuid,
			"components", len(payload.Components),
			"findings", len(payload.Findings),
			"network_obs", len(payload.NetworkObservations),
		)
		// Broadcast telemetry update to WebSocket clients
		s.wsHub.Broadcast("telemetry_update", map[string]interface{}{
			"host_uuid":   payload.HostUuid,
			"components":  len(payload.Components),
			"findings":    len(payload.Findings),
			"network_obs": len(payload.NetworkObservations),
			"critical":    hasCriticalFindings(payload),
		})

		for _, cmd := range s.orch.Drain(hostUUID) {
			if err := s.store.InsertMigrationCommand(stream.Context(), cmd); err != nil {
				return err
			}
			if err := stream.Send(cmd); err != nil {
				return err
			}
		}
		agentCommands, err := s.store.DrainAgentCommands(stream.Context(), hostUUID)
		if err != nil {
			return err
		}
		for _, cmd := range agentCommands {
			if err := stream.Send(cmd); err != nil {
				return err
			}
			if err := s.store.MarkAgentCommandDelivered(stream.Context(), cmd.CommandId); err != nil {
				return err
			}
		}
	}
}

func (s *Server) ReportMigrationStatus(stream pb.JanusTelemetry_ReportMigrationStatusServer) error {
	var lastCommandID string
	for {
		report, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&pb.MigrationStatusAck{
				CommandId: lastCommandID,
				Accepted:  true,
				Message:   "status reports accepted",
			})
		}
		if err != nil {
			return err
		}
		lastCommandID = report.CommandId
		if err := s.store.UpdateMigrationStatus(stream.Context(), report); err != nil {
			return err
		}
		slog.Info("migration status",
			"command_id", report.CommandId,
			"host_uuid", report.HostUuid,
			"state", report.State,
			"success", report.Success,
		)
		s.wsHub.Broadcast("migration_status", map[string]interface{}{
			"command_id": report.CommandId,
			"host_uuid":  report.HostUuid,
			"state":      report.State,
			"success":    report.Success,
		})
	}
}

// severityLabel maps a numeric severity to a human-readable label.
func severityLabel(sev int32) string {
	switch {
	case sev >= 5:
		return "critical"
	case sev == 4:
		return "high"
	case sev == 3:
		return "medium"
	case sev == 2:
		return "low"
	default:
		return "info"
	}
}

// buildSIEMEvent constructs a structured SIEM event map for a single critical finding.
func buildSIEMEvent(payload *pb.CbomTelemetryPayload, f *pb.CryptoFinding, prof policy.Profile) map[string]interface{} {
	remHint := ""
	if rule, ok := policy.GetRule(f.PolicyRuleId); ok {
		remHint = rule.RemediationHint
	}

	evidenceCtx := ""
	if len(f.EvidenceIds) > 0 {
		evidenceCtx = f.EvidenceIds[0]
	}

	return map[string]interface{}{
		"event_type":    "janus.finding.critical",
		"event_version": "1.0",
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
		"source": map[string]interface{}{
			"product":   "Janus CryptoBOM",
			"version":   version.Version,
			"host_uuid": payload.HostUuid,
		},
		"finding": map[string]interface{}{
			"finding_id":       f.FindingId,
			"rule_id":          f.PolicyRuleId,
			"title":            f.Title,
			"severity":         f.Severity,
			"severity_label":   severityLabel(f.Severity),
			"algorithm":        f.Algorithm,
			"asset_ref":        f.AssetRef,
			"confidence":       0,
			"status":           "open",
			"first_seen_at":    time.Now().UTC().Format(time.RFC3339),
			"evidence_context": evidenceCtx,
		},
		"remediation": map[string]interface{}{
			"rule_hint":            remHint,
			"migration_target_kem": prof.PreferredKEM,
			"migration_target_sig": prof.PreferredSignature,
		},
	}
}

func (s *Server) dispatchWebhooks(payload *pb.CbomTelemetryPayload) {
	webhooks, err := s.store.GetWebhooks(context.Background())
	if err != nil {
		slog.Error("failed to load webhooks for alerts", "error", err)
		return
	}
	if len(webhooks) == 0 {
		return
	}

	// Collect critical findings and build one SIEM event per finding.
	prof := s.policy.GetActiveProfile()
	var events [][]byte
	for _, f := range payload.Findings {
		if f.Severity < 5 {
			continue
		}
		evt := buildSIEMEvent(payload, f, prof)
		body, err := json.Marshal(evt)
		if err != nil {
			slog.Warn("failed to marshal SIEM event", "finding_id", f.FindingId, "error", err)
			continue
		}
		events = append(events, body)
	}
	if len(events) == 0 {
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}

	for _, wh := range webhooks {
		if !wh.Active {
			continue
		}
		// Circuit breaker check
		if s.circuit.isOpen(wh.URL) {
			slog.Warn("webhook circuit open, skipping dispatch", "url", wh.URL)
			continue
		}

		// Dispatch one request per critical finding event.
		for _, body := range events {
			// Retry up to 3 times with exponential backoff
			var lastErr error
			success := false
			for attempt := 0; attempt < 3; attempt++ {
				if attempt > 0 {
					backoff := time.Duration(1<<uint(attempt-1)) * time.Second
					time.Sleep(backoff)
				}

				req, reqErr := http.NewRequestWithContext(context.Background(), "POST", wh.URL, bytes.NewReader(body))
				if reqErr != nil {
					lastErr = reqErr
					continue
				}
				req.Header.Set("Content-Type", "application/json")
				if wh.SecretToken != "" {
					req.Header.Set("X-Janus-Token", wh.SecretToken)
				}

				resp, respErr := client.Do(req)
				if respErr != nil {
					lastErr = respErr
					continue
				}
				// Drain body for connection reuse
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()

				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					success = true
					break
				}
				lastErr = fmt.Errorf("webhook returned status %d", resp.StatusCode)
			}

			if success {
				s.circuit.recordSuccess(wh.URL)
			} else {
				slog.Error("failed to send webhook after 3 attempts", "url", wh.URL, "error", lastErr)
				s.circuit.recordFailure(wh.URL)
			}
		}
	}
}

// hasCriticalFindings checks if a payload contains any critical-severity findings.
func hasCriticalFindings(payload *pb.CbomTelemetryPayload) bool {
	for _, f := range payload.Findings {
		if f.Severity >= 5 {
			return true
		}
	}
	return false
}
