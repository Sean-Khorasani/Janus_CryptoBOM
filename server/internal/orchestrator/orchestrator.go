package orchestrator

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/janus-cbom/janus/server/internal/pb"
)

type Orchestrator struct {
	mu         sync.Mutex
	queues     map[string][]*pb.MigrationCommand
	signingKey []byte
}

func New(signingKey []byte) *Orchestrator {
	return &Orchestrator{
		queues:     make(map[string][]*pb.MigrationCommand),
		signingKey: append([]byte(nil), signingKey...),
	}
}

func (o *Orchestrator) BuildCommand(hostUUID, service, profile, configPath, patch, checksum string, dryRun bool) *pb.MigrationCommand {
	checklist := []string{"config-syntax", "daemon-reload", "tls13-handshake", "hybrid-mlkem-observed"}
	if checksum != "" {
		checklist = append(checklist, "checksum="+checksum)
	}
	cmd := &pb.MigrationCommand{
		CommandId:             uuid.NewString(),
		HostUuid:              hostUUID,
		TargetService:         service,
		MigrationProfile:      profile,
		TargetKem:             "X25519MLKEM768",
		TargetSignature:       "ML-DSA-65",
		ConfigPath:            configPath,
		ValidationChecklist:   checklist,
		RollbackWindowSeconds: 300,
		PatchUnifiedDiff:      patch,
		IssuedAtUnix:          time.Now().Unix(),
		DryRun:                dryRun,
	}
	cmd.SignedDirective = o.Sign(cmd)
	return cmd
}

func (o *Orchestrator) Enqueue(cmd *pb.MigrationCommand) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.queues[cmd.HostUuid] = append(o.queues[cmd.HostUuid], cmd)
}

func (o *Orchestrator) Drain(hostUUID string) []*pb.MigrationCommand {
	o.mu.Lock()
	defer o.mu.Unlock()
	pending := o.queues[hostUUID]
	delete(o.queues, hostUUID)
	return pending
}

func (o *Orchestrator) Sign(cmd *pb.MigrationCommand) []byte {
	mac := hmac.New(sha256.New, o.signingKey)
	_, _ = mac.Write([]byte(canonicalCommand(cmd)))
	return []byte(hex.EncodeToString(mac.Sum(nil)))
}

func (o *Orchestrator) Verify(cmd *pb.MigrationCommand) bool {
	expected := o.Sign(cmd)
	return hmac.Equal(expected, cmd.SignedDirective)
}

func canonicalCommand(cmd *pb.MigrationCommand) string {
	return fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%s\n%d\n%s\n%d\n%t",
		cmd.CommandId,
		cmd.HostUuid,
		cmd.TargetService,
		cmd.MigrationProfile,
		cmd.TargetKem,
		cmd.TargetSignature,
		cmd.ConfigPath,
		cmd.RollbackWindowSeconds,
		cmd.PatchUnifiedDiff,
		cmd.IssuedAtUnix,
		cmd.DryRun,
	)
}

