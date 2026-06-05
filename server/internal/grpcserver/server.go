package grpcserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/janus-cbom/janus/server/internal/orchestrator"
	"github.com/janus-cbom/janus/server/internal/pb"
	"github.com/janus-cbom/janus/server/internal/policy"
	"github.com/janus-cbom/janus/server/internal/store"
)

type Server struct {
	pb.UnimplementedJanusTelemetryServer
	store store.Store
	policy *policy.Engine
	orch  *orchestrator.Orchestrator
}

func New(store store.Store, policy *policy.Engine, orch *orchestrator.Orchestrator) *Server {
	return &Server{store: store, policy: policy, orch: orch}
}

func (s *Server) RegisterAgent(ctx context.Context, reg *pb.AgentRegistration) (*pb.AgentRegistrationAck, error) {
	if reg.HostUuid == "" || reg.Hostname == "" {
		return nil, fmt.Errorf("host_uuid and hostname are required")
	}
	if err := s.store.UpsertAgent(ctx, reg); err != nil {
		return nil, err
	}
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
		s.policy.Assess(payload)
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

		log.Printf("telemetry host=%s components=%d findings=%d network=%d", payload.HostUuid, len(payload.Components), len(payload.Findings), len(payload.NetworkObservations))

		for _, cmd := range s.orch.Drain(hostUUID) {
			if err := s.store.InsertMigrationCommand(stream.Context(), cmd); err != nil {
				return err
			}
			if err := stream.Send(cmd); err != nil {
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
		log.Printf("migration status command=%s host=%s state=%d success=%t", report.CommandId, report.HostUuid, report.State, report.Success)
	}
}

func (s *Server) dispatchWebhooks(payload *pb.CbomTelemetryPayload) {
	ctx := context.Background()
	webhooks, err := s.store.GetWebhooks(ctx)
	if err != nil {
		log.Printf("failed to load webhooks for alerts: %v", err)
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

	for _, wh := range webhooks {
		if !wh.Active {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, "POST", wh.URL, bytes.NewReader(body))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		if wh.SecretToken != "" {
			req.Header.Set("X-Janus-Token", wh.SecretToken)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Printf("failed to send webhook alert to %s: %v", wh.URL, err)
			continue
		}
		resp.Body.Close()
	}
}

