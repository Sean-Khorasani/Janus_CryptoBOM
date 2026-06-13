package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"

	pb "github.com/janus-cbom/janus/server/internal/pb"
	"github.com/janus-cbom/janus/server/internal/store"
)

// agentRoutes serves /api/agents/{id}[/sub] — the per-agent detail, scan history,
// connection history, scan config, and command (Rescan) endpoints the fleet UI
// relies on (UX-002). These were never registered, so the Rescan button, Configure
// modal, and agent-detail drawer 404'd end-to-end. Every handler is backed by an
// existing Store interface method; no schema or store changes are needed.
//
// Routing (stdlib mux gives us the "/api/agents/" subtree):
//
//	GET  /api/agents/{id}                      -> agent detail
//	GET  /api/agents/{id}/scans                -> scan history
//	GET  /api/agents/{id}/connections          -> connection sessions
//	GET  /api/agents/{id}/config               -> per-agent scan config
//	PUT  /api/agents/{id}/config               -> update per-agent scan config
//	POST /api/agents/{id}/commands             -> enqueue a command (scan-now)
//	GET  /api/agents/{id}/commands/{commandId} -> command status
func (a *API) agentRoutes(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/agents/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "agent id required"})
		return
	}
	hostUUID := parts[0]
	sub := ""
	if len(parts) > 1 {
		sub = parts[1]
	}

	switch sub {
	case "":
		a.agentDetail(w, r, hostUUID)
	case "scans":
		a.agentScans(w, r, hostUUID)
	case "connections":
		a.agentConnections(w, r, hostUUID)
	case "config":
		a.agentConfig(w, r, hostUUID)
	case "commands":
		if len(parts) >= 3 && parts[2] != "" {
			a.agentCommandStatus(w, r, hostUUID, parts[2])
			return
		}
		a.agentEnqueueCommand(w, r, hostUUID)
	default:
		http.NotFound(w, r)
	}
}

// agentMutationAllowed gates state-changing agent operations (rescan, config save)
// to operator/admin, mirroring the RequireRole policy used elsewhere.
func agentMutationAllowed(r *http.Request) bool {
	role, _ := r.Context().Value(RoleContextKey).(string)
	return role == "admin" || role == "operator"
}

func (a *API) agentDetail(w http.ResponseWriter, r *http.Request, hostUUID string) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	asset, err := a.store.AgentByID(r.Context(), hostUUID)
	if err != nil {
		writeError(w, err)
		return
	}
	if asset == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
		return
	}
	writeJSON(w, http.StatusOK, asset)
}

func (a *API) agentScans(w http.ResponseWriter, r *http.Request, hostUUID string) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	params := store.ScanQueryParams{
		QueryParams: store.QueryParams{Limit: intParam(r, "limit", 50), Offset: intParam(r, "offset", 0)},
		HostUUID:    hostUUID,
	}
	scans, total, err := a.store.ScanRuns(r.Context(), params)
	if err != nil {
		writeError(w, err)
		return
	}
	if scans == nil {
		scans = []store.ScanRun{}
	}
	w.Header().Set("X-Total-Count", intStr(total))
	writeJSON(w, http.StatusOK, scans)
}

func (a *API) agentConnections(w http.ResponseWriter, r *http.Request, hostUUID string) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	params := store.QueryParams{Limit: intParam(r, "limit", 50), Offset: intParam(r, "offset", 0)}
	sessions, total, err := a.store.ConnectionHistory(r.Context(), hostUUID, params)
	if err != nil {
		writeError(w, err)
		return
	}
	if sessions == nil {
		sessions = []store.ConnectionSession{}
	}
	w.Header().Set("X-Total-Count", intStr(total))
	writeJSON(w, http.StatusOK, sessions)
}

func (a *API) agentConfig(w http.ResponseWriter, r *http.Request, hostUUID string) {
	switch r.Method {
	case http.MethodGet:
		cfg, err := a.store.GetAgentScanConfig(r.Context(), hostUUID)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, cfg)
	case http.MethodPut:
		if !agentMutationAllowed(r) {
			http.Error(w, "forbidden: operator or admin role required", http.StatusForbidden)
			return
		}
		var cfg store.AgentScanConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		cfg.HostUUID = hostUUID
		cfg.Configured = true
		if err := a.store.UpdateAgentScanConfig(r.Context(), &cfg); err != nil {
			writeError(w, err)
			return
		}
		username, _ := r.Context().Value(UserContextKey).(string)
		_ = a.store.InsertAuditLog(r.Context(), &store.AuditLog{
			Username: username, Action: "AGENT_CONFIG_UPDATE", Details: "host_uuid=" + hostUUID,
		})
		writeJSON(w, http.StatusOK, cfg)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// agentEnqueueCommand queues a command for the agent to drain over gRPC. Only the
// "scan-now" command is supported; the agent recognizes it by
// target_service="janus-agent" + migration_profile="scan-now" and triggers a scan
// without requiring an HMAC signature (it never reaches the mutation path).
func (a *API) agentEnqueueCommand(w http.ResponseWriter, r *http.Request, hostUUID string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !agentMutationAllowed(r) {
		http.Error(w, "forbidden: operator or admin role required", http.StatusForbidden)
		return
	}
	var req struct {
		Command string `json:"command"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Command != "scan-now" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported command; only scan-now is allowed"})
		return
	}
	commandID := uuid.NewString()
	cmd := &pb.MigrationCommand{
		CommandId:        commandID,
		HostUuid:         hostUUID,
		TargetService:    "janus-agent",
		MigrationProfile: "scan-now",
		DryRun:           false,
	}
	if err := a.store.EnqueueAgentCommand(r.Context(), cmd); err != nil {
		writeError(w, err)
		return
	}
	username, _ := r.Context().Value(UserContextKey).(string)
	_ = a.store.InsertAuditLog(r.Context(), &store.AuditLog{
		Username: username, Action: "AGENT_SCAN_REQUEST", Details: "host_uuid=" + hostUUID + " command_id=" + commandID,
	})
	writeJSON(w, http.StatusAccepted, map[string]string{
		"command_id": commandID,
		"message":    "Scan queued for delivery to the agent",
	})
}

func (a *API) agentCommandStatus(w http.ResponseWriter, r *http.Request, hostUUID, commandID string) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	cmd, err := a.store.AgentCommand(r.Context(), hostUUID, commandID)
	if err != nil {
		writeError(w, err)
		return
	}
	if cmd == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "command not found"})
		return
	}
	writeJSON(w, http.StatusOK, cmd)
}
