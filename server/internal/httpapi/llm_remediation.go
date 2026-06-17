package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/janus-cbom/janus/server/internal/llm"
	"github.com/janus-cbom/janus/server/internal/pb"
	"github.com/janus-cbom/janus/server/internal/store"
)

// llmSuggestion serves remediation suggestions (LLM-011):
//
//	GET  /api/llm/suggestions/{finding_id}        — latest suggestion for a finding
//	POST /api/llm/suggestions/{suggestion_id}/review — operator/admin approve/reject
//
// Reviewing a suggestion is advisory only: it records an audit decision and never
// applies the patch (authority inversion — applying a change stays an explicit
// operator action through the normal migration path, gated on the security phase).
func (a *API) llmSuggestion(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/llm/suggestions/")
	if strings.HasSuffix(rest, "/review") {
		a.reviewSuggestion(w, r, strings.TrimSuffix(rest, "/review"))
		return
	}
	// POST /api/llm/suggestions/{id}/apply — LLM-014: convert an approved + validated
	// suggestion into a signed migration command and enqueue it (manual, operator-gated).
	if strings.HasSuffix(rest, "/apply") {
		a.applySuggestion(w, r, strings.TrimSuffix(rest, "/apply"))
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	findingID := rest
	if findingID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "finding_id is required"})
		return
	}
	suggestion, err := a.store.GetSuggestionByFinding(r.Context(), findingID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, suggestion)
}

func (a *API) reviewSuggestion(w http.ResponseWriter, r *http.Request, suggestionID string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if role, _ := r.Context().Value(RoleContextKey).(string); role != "operator" && role != "admin" {
		http.Error(w, "forbidden: operator or admin role required", http.StatusForbidden)
		return
	}
	if suggestionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "suggestion_id is required"})
		return
	}
	var body struct {
		Decision string `json:"decision"`
		Note     string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if !validReviewDecision(body.Decision) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "decision must be 'approved' or 'rejected'"})
		return
	}
	reviewer, _ := r.Context().Value(UserContextKey).(string)
	suggestion, err := a.store.SetSuggestionReview(r.Context(), suggestionID, body.Decision, reviewer, body.Note)
	if errors.Is(err, store.ErrSuggestionNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "suggestion not found"})
		return
	}
	if err != nil {
		writeError(w, err)
		return
	}
	_ = a.store.InsertAuditLog(r.Context(), &store.AuditLog{
		Username: reviewer,
		Action:   "LLM_SUGGESTION_REVIEW",
		Details:  fmt.Sprintf("suggestion %s %s", suggestionID, body.Decision),
	})
	writeJSON(w, http.StatusOK, suggestion)
}

// applySuggestion (LLM-014) converts an approved, validated suggestion into a signed
// migration command and enqueues it through the existing orchestrator path. It is
// operator-gated (manual). Two independent agent-side gates still apply downstream: the
// agent only mutates in active (non-passive) mode, and only allowlisted config file
// types — so this enqueue is safe even before those run. Defaults to dry-run.
func (a *API) applySuggestion(w http.ResponseWriter, r *http.Request, suggestionID string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if role, _ := r.Context().Value(RoleContextKey).(string); role != "operator" && role != "admin" {
		http.Error(w, "forbidden: operator or admin role required", http.StatusForbidden)
		return
	}
	var body struct {
		DryRun        *bool  `json:"dry_run"`
		TargetService string `json:"target_service"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body) // body is optional; defaults below

	s, err := a.store.GetSuggestionByID(r.Context(), suggestionID)
	if errors.Is(err, store.ErrSuggestionNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "suggestion not found"})
		return
	}
	if err != nil {
		writeError(w, err)
		return
	}

	username, _ := r.Context().Value(UserContextKey).(string)
	cmd, status, reason := a.enqueueSuggestionCommand(r.Context(), s, body.TargetService, body.DryRun, "manual", username)
	if cmd == nil {
		writeJSON(w, status, map[string]string{"error": reason})
		return
	}
	writeJSON(w, http.StatusAccepted, cmd)
}

// enqueueSuggestionCommand is the shared LLM-014 core for both manual apply and
// autonomous (LLM-017) remediation. It validates the suggestion is actionable, confirms
// the agent would actually apply the patch (extension allowlist), builds an HMAC-signed
// migration command from the existing orchestrator, and enqueues + persists it. mode is
// "manual" (requires human approval recorded on the suggestion) or "autonomous" (the
// governor is the authority — approval is not required, controls gate it upstream).
// Returns (nil, httpStatus, reason) on refusal; (cmd, 202, "") on success.
func (a *API) enqueueSuggestionCommand(ctx context.Context, s *store.LLMSuggestion, targetService string, dryRunReq *bool, mode, actor string) (*pb.MigrationCommand, int, string) {
	if mode == "manual" && s.ReviewDecision != "approved" {
		return nil, http.StatusConflict, "suggestion must be approved before it can be applied"
	}
	if s.ValidationStatus != "passed" || s.CandidatePatch == "" {
		return nil, http.StatusUnprocessableEntity, "suggestion has no deterministically-validated candidate patch to apply"
	}
	target, ok, reason := llm.AgentWillApplyPatch(s.CandidatePatch)
	if !ok {
		return nil, http.StatusUnprocessableEntity, reason
	}

	f, found := a.findFindingByID(ctx, s.FindingID)
	if !found {
		return nil, http.StatusNotFound, "finding for this suggestion was not found"
	}
	if f.HostUUID == "" {
		return nil, http.StatusUnprocessableEntity, "finding has no host to target"
	}

	configPath := stripLineSuffix(f.AssetRef)
	if configPath == "" {
		configPath = target
	}
	service := targetService
	if service == "" {
		service = deriveService(configPath)
	}
	dryRun := true // safe default; an explicit false is required to apply for real
	if dryRunReq != nil {
		dryRun = *dryRunReq
	}
	profile := f.MigrationProfile
	if profile == "" {
		profile = "llm-remediation"
	}

	// Drift checksum is best-effort: a first-time apply may have no prior hash.
	hash, _ := a.store.GetLatestConfigHash(ctx, f.HostUUID, configPath)
	ap := a.engine.GetActiveProfile()
	cmd := a.orch.BuildCommand(f.HostUUID, service, profile, configPath, s.CandidatePatch, hash, dryRun, ap.PreferredKEM, ap.PreferredSignature)
	a.orch.Enqueue(cmd)
	if err := a.store.InsertMigrationCommand(ctx, cmd); err != nil {
		slog.Error("llm remediation: persist migration command", "error", err, "suggestion_id", s.SuggestionID)
		return nil, http.StatusInternalServerError, "internal server error"
	}

	_ = a.store.InsertAuditLog(ctx, &store.AuditLog{
		Username: actor,
		Action:   "LLM_APPLY_REMEDIATION",
		Details: fmt.Sprintf("mode=%s suggestion=%s finding=%s host=%s command=%s dry_run=%t target=%s",
			mode, s.SuggestionID, s.FindingID, f.HostUUID, cmd.CommandId, dryRun, target),
	})
	a.wsHub.Broadcast("migration_enqueued", map[string]string{
		"command_id":     cmd.CommandId,
		"host_uuid":      cmd.HostUuid,
		"target_service": cmd.TargetService,
		"source":         "llm_remediation_" + mode,
	})
	return cmd, http.StatusAccepted, ""
}

// autoApplyRemediation is the RemediationEnqueuer injected into the LLM service for
// autonomous remediation (LLM-017). The governor has already authorized; this builds and
// enqueues the signed command with a non-human actor (separation of duties). Refusals
// (e.g. a non-allowlisted patch the governor's own check also catches) are logged, not
// fatal — the suggestion still stands for manual handling.
func (a *API) autoApplyRemediation(ctx context.Context, s *store.LLMSuggestion, dryRun bool) error {
	cmd, status, reason := a.enqueueSuggestionCommand(ctx, s, "", &dryRun, "autonomous", "system:autoremediation")
	if cmd == nil {
		slog.Warn("autonomous remediation skipped", "suggestion_id", s.SuggestionID, "status", status, "reason", reason)
		return fmt.Errorf("autonomous enqueue refused: %s", reason)
	}
	slog.Info("autonomous remediation enqueued", "suggestion_id", s.SuggestionID, "command_id", cmd.CommandId, "dry_run", dryRun)
	return nil
}

// stripLineSuffix removes a trailing ":<line>" from an asset reference ("path:42" ->
// "path") while leaving Windows drive letters ("C:\\x") and plain paths intact.
func stripLineSuffix(assetRef string) string {
	i := strings.LastIndexByte(assetRef, ':')
	if i <= 1 { // no colon, or a drive-letter colon at index 1
		return assetRef
	}
	suffix := assetRef[i+1:]
	if suffix == "" {
		return assetRef[:i]
	}
	for _, c := range suffix {
		if c < '0' || c > '9' {
			return assetRef // not a line number — leave as-is
		}
	}
	return assetRef[:i]
}

// deriveService maps a config file path to the migration engine's service label so the
// agent picks the right validate/reload routine. Falls back to a generic label.
func deriveService(configPath string) string {
	lower := strings.ToLower(configPath)
	switch {
	case strings.Contains(lower, "nginx"):
		return "nginx"
	case strings.Contains(lower, "apache"), strings.Contains(lower, "httpd"):
		return "apache"
	case strings.Contains(lower, "sshd_config"), strings.Contains(lower, "ssh_config"):
		return "ssh"
	case strings.Contains(lower, "postgres"):
		return "postgresql"
	default:
		return "generic"
	}
}
