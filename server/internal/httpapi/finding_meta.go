package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/janus-cbom/janus/server/internal/store"
)

// UX-003: finding comments + assignment endpoints, routed from findingsDispatch:
//   GET/POST /api/findings/{id}/comments
//   POST     /api/findings/{id}/assign

func findingIDFromPath(path, suffix string) string {
	trimmed := strings.TrimPrefix(path, "/api/findings/")
	return strings.TrimSuffix(trimmed, "/"+suffix)
}

// findingComments handles GET (list) and POST (add) for a finding's comments.
func (a *API) findingComments(w http.ResponseWriter, r *http.Request) {
	id := findingIDFromPath(r.URL.Path, "comments")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		comments, err := a.store.ListFindingComments(r.Context(), id)
		if err != nil {
			writeError(w, err)
			return
		}
		if comments == nil {
			comments = []store.FindingComment{}
		}
		writeJSON(w, http.StatusOK, comments)
	case http.MethodPost:
		if !requireWriteRole(w, r) {
			return
		}
		var body struct {
			Body string `json:"body"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, err)
			return
		}
		if strings.TrimSpace(body.Body) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "comment body is required"})
			return
		}
		actor, _ := r.Context().Value(UserContextKey).(string)
		if actor == "" {
			actor = "operator"
		}
		c := &store.FindingComment{FindingID: id, Actor: actor, Body: strings.TrimSpace(body.Body)}
		if err := a.store.AddFindingComment(r.Context(), c); err != nil {
			writeError(w, err)
			return
		}
		a.wsHub.BroadcastTenant(TenantFromContext(r.Context()), "finding_comment", map[string]string{"finding_id": id, "actor": actor})
		writeJSON(w, http.StatusCreated, c)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// findingAssign handles GET (current assignment) and POST (set assignment) for
// /api/findings/{id}/assign.
func (a *API) findingAssign(w http.ResponseWriter, r *http.Request) {
	id := findingIDFromPath(r.URL.Path, "assign")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodGet {
		asn, err := a.store.GetFindingAssignment(r.Context(), id)
		if err != nil {
			writeError(w, err)
			return
		}
		if asn == nil {
			asn = &store.FindingAssignment{FindingID: id}
		}
		writeJSON(w, http.StatusOK, asn)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !requireWriteRole(w, r) {
		return
	}
	var body struct {
		AssignedTo string `json:"assigned_to"`
		DueDate    string `json:"due_date"` // YYYY-MM-DD, optional
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, err)
		return
	}
	asn := &store.FindingAssignment{FindingID: id, AssignedTo: body.AssignedTo}
	if body.DueDate != "" {
		d, err := time.Parse("2006-01-02", body.DueDate)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "due_date must be YYYY-MM-DD"})
			return
		}
		asn.DueDate = &d
	}
	if err := a.store.UpsertFindingAssignment(r.Context(), asn); err != nil {
		writeError(w, err)
		return
	}
	actor, _ := r.Context().Value(UserContextKey).(string)
	if actor == "" {
		actor = "operator"
	}
	_ = a.store.InsertAuditLog(r.Context(), &store.AuditLog{
		Username: actor, Action: "FINDING_ASSIGN",
		Details: "finding_id=" + id + " assigned_to=" + body.AssignedTo + " due=" + body.DueDate,
	})
	a.wsHub.BroadcastTenant(TenantFromContext(r.Context()), "finding_assigned", map[string]string{"finding_id": id, "assigned_to": body.AssignedTo})
	writeJSON(w, http.StatusOK, asn)
}
