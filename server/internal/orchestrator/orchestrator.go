package orchestrator

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/janus-cbom/janus/server/internal/pb"
)

// CommandMAC is the optional HSM-resident MAC used for migration-command signing
// (configurable). It is satisfied by hsm.MACSigner; the orchestrator declares only the
// method it needs so it does not import the hsm package. HMAC-SHA256 over the same key is
// identical whether computed in-process or in the HSM, so the agent's verification is
// unchanged — the HSM mode only moves the key out of server memory.
type CommandMAC interface {
	MAC(label string, data []byte) ([]byte, error)
}

type Orchestrator struct {
	mu         sync.Mutex
	queues     map[string][]*pb.MigrationCommand
	signingKey []byte     // in-process HMAC key; retained for the default (non-HSM) path
	hsmMAC     CommandMAC // when set, HMAC command signing is HSM-resident
	macLabel   string
	// mldsaSign/mldsaPub, when set, ADD an ML-DSA signature alongside the mandatory HMAC
	// (defense in depth). SignedDirective then carries a structured envelope (see Sign)
	// holding the HMAC, the ML-DSA signature, and the public key. Agents that pin the
	// key's fingerprint verify both; HMAC always remains the baseline.
	mldsaSign    func([]byte) ([]byte, error)
	mldsaPub     []byte
	mldsaCertDER []byte
}

// commandSigEnvelopeV1 marks a dual-signed SignedDirective. Lines after it:
//
//	line 0: janus-sig-v1
//	line 1: <hmac hex>
//	line 2: <base64 ML-DSA signature>
//	line 3: <base64 ML-DSA public key>
//
// A SignedDirective WITHOUT this prefix is the legacy HMAC-hex form (HMAC only).
const commandSigEnvelopeV1 = "janus-sig-v1"

// commandSigEnvelopeV2 marks a CA-chained dual-signed SignedDirective (WP-029 P3). Identical
// to v1 except line 3 carries the leaf command-signing certificate (base64 DER), chained to
// the bundled ML-DSA root, instead of a bare public key. Agents verify the chain to their
// trust anchor (no fingerprint pinning); the leaf's public key then verifies the ML-DSA sig.
//
//	line 0: janus-sig-v2
//	line 1: <hmac hex>
//	line 2: <base64 ML-DSA signature>
//	line 3: <base64 ML-DSA leaf command cert DER>
const commandSigEnvelopeV2 = "janus-sig-v2"

func New(signingKey []byte) *Orchestrator {
	return &Orchestrator{
		queues:     make(map[string][]*pb.MigrationCommand),
		signingKey: append([]byte(nil), signingKey...),
	}
}

// UseHSMSigner routes migration-command HMAC signing through an HSM-resident key
// (JANUS_HSM_SIGN_COMMANDS). The in-process key is dropped so it no longer lives in
// server memory; signing fails closed if the HSM is unreachable.
func (o *Orchestrator) UseHSMSigner(mac CommandMAC, label string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.hsmMAC = mac
	o.macLabel = label
	o.signingKey = nil
}

// AddMLDSASigner adds an ML-DSA signature alongside the mandatory HMAC (additive, not a
// replacement). sign() takes the canonical command bytes and returns the raw ML-DSA
// signature; pub is the FIPS 204 public key embedded in each command so agents can
// fingerprint-pin and verify it. Signing fails closed if sign() errors. The signer may be
// software (circl) or an HSM-resident ML-DSA key.
func (o *Orchestrator) AddMLDSASigner(sign func([]byte) ([]byte, error), pub []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.mldsaSign = sign
	o.mldsaPub = append([]byte(nil), pub...)
}

// SetMLDSACommandCert switches the ML-DSA envelope to janus-sig-v2 (WP-029 P3): each command
// carries the leaf command-signing certificate (DER, chained to the bundled ML-DSA root)
// instead of a bare public key, so agents verify the chain to their trust anchor rather than
// pinning a key fingerprint. The leaf cert MUST correspond to the key used by the
// AddMLDSASigner sign func. Passing nil reverts to the v1 (fingerprint-pin) envelope.
func (o *Orchestrator) SetMLDSACommandCert(certDER []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if certDER == nil {
		o.mldsaCertDER = nil
		return
	}
	o.mldsaCertDER = append([]byte(nil), certDER...)
}

func (o *Orchestrator) BuildCommand(hostUUID, service, profile, configPath, patch, checksum string, dryRun bool, preferredKEM, preferredSignature string) *pb.MigrationCommand {
	kem := preferredKEM
	if kem == "" {
		kem = "X25519MLKEM768"
	}
	sig := preferredSignature
	if sig == "" {
		sig = "ML-DSA-65"
	}
	checklist := []string{"config-syntax", "daemon-reload", "tls13-handshake", "hybrid-mlkem-observed"}
	if checksum != "" {
		checklist = append(checklist, "checksum="+checksum)
	}
	cmd := &pb.MigrationCommand{
		CommandId:             uuid.NewString(),
		HostUuid:              hostUUID,
		TargetService:         service,
		MigrationProfile:      profile,
		TargetKem:             kem,
		TargetSignature:       sig,
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
	canonical := []byte(canonicalCommand(cmd))
	hmacHex, err := o.hmacHex(canonical)
	if err != nil {
		// Fail closed: empty signature → the agent rejects, rather than emitting an
		// unverifiable directive.
		slog.Error("command HMAC signing failed; emitting unsigned (agent will reject)",
			"error", err, "command_id", cmd.CommandId)
		return nil
	}
	if o.mldsaSign == nil {
		return []byte(hmacHex) // legacy HMAC-only form
	}
	// Dual-signed: add the ML-DSA signature + public key in a structured envelope.
	sig, err := o.mldsaSign(canonical)
	if err != nil {
		slog.Error("ml-dsa command signing failed; emitting unsigned (agent will reject)",
			"error", err, "command_id", cmd.CommandId)
		return nil
	}
	// v2 (CA-chained): carry the leaf command cert instead of the bare public key.
	if o.mldsaCertDER != nil {
		env := strings.Join([]string{
			commandSigEnvelopeV2,
			hmacHex,
			base64.StdEncoding.EncodeToString(sig),
			base64.StdEncoding.EncodeToString(o.mldsaCertDER),
		}, "\n")
		return []byte(env)
	}
	env := strings.Join([]string{
		commandSigEnvelopeV1,
		hmacHex,
		base64.StdEncoding.EncodeToString(sig),
		base64.StdEncoding.EncodeToString(o.mldsaPub),
	}, "\n")
	return []byte(env)
}

// hmacHex computes the baseline HMAC-SHA256 (hex) over canonical, using the HSM-resident
// key when configured, else the in-process key.
func (o *Orchestrator) hmacHex(canonical []byte) (string, error) {
	if o.hsmMAC != nil {
		raw, err := o.hsmMAC.MAC(o.macLabel, canonical)
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(raw), nil
	}
	mac := hmac.New(sha256.New, o.signingKey)
	_, _ = mac.Write(canonical)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// Verify checks the baseline HMAC. For dual-signed (ML-DSA) commands it verifies the HMAC
// portion of the envelope; the ML-DSA signature is verified by the agent with the pinned
// public key (re-signing here would differ). Verify is not used on the server command
// path — agents are the verifiers.
func (o *Orchestrator) Verify(cmd *pb.MigrationCommand) bool {
	canonical := []byte(canonicalCommand(cmd))
	expected, err := o.hmacHex(canonical)
	if err != nil {
		return false
	}
	got := string(cmd.SignedDirective)
	if strings.HasPrefix(got, commandSigEnvelopeV1+"\n") || strings.HasPrefix(got, commandSigEnvelopeV2+"\n") {
		parts := strings.Split(got, "\n")
		if len(parts) < 2 {
			return false
		}
		got = parts[1]
	}
	return hmac.Equal([]byte(expected), []byte(got))
}

func canonicalCommand(cmd *pb.MigrationCommand) string {
	checklist, _ := json.Marshal(cmd.ValidationChecklist)
	return fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%d\n%s\n%d\n%t",
		cmd.CommandId,
		cmd.HostUuid,
		cmd.TargetService,
		cmd.MigrationProfile,
		cmd.TargetKem,
		cmd.TargetSignature,
		cmd.ConfigPath,
		checklist,
		cmd.RollbackWindowSeconds,
		cmd.PatchUnifiedDiff,
		cmd.IssuedAtUnix,
		cmd.DryRun,
	)
}
