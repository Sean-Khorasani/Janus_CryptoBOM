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

func (s *Server) dispatchWebhooks(payload *pb.CbomTelemetryPayload) {
	webhooks, err := s.store.GetWebhooks(context.Background())
	if err != nil {
		slog.Error("failed to load webhooks for alerts", "error", err)
		return
	}
	if len(webhooks) == 0 {
		return
	}

	alert := map[string]interface{}{
		"event":      "janus-critical-compliance-finding",
		"timestamp":  time.Now().Format(time.RFC3339),
		"host_uuid":  payload.HostUuid,
		"findings":   len(payload.Findings),
		"components": len(payload.Components),
		"message":    fmt.Sprintf("Critical compliance findings reported for host %s", payload.HostUuid),
	}

	body, err := json.Marshal(alert)
	if err != nil {
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

			resp, err := client.Do(req)
			if err != nil {
				lastErr = err
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

// hasCriticalFindings checks if a payload contains any critical-severity findings.
func hasCriticalFindings(payload *pb.CbomTelemetryPayload) bool {
	for _, f := range payload.Findings {
		if f.Severity >= 5 {
			return true
		}
	}
	return false
}
