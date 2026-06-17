package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/janus-cbom/janus/server/internal/store"
)

// revocationCache tracks, per username, the unix time of the most recent password
// change. AuthMiddleware rejects any JWT whose `iat` predates that cutoff, so a
// password change invalidates sessions issued before it (AUTH-002).
//
// It is seeded from the credential_overrides table at startup and updated in-process
// on each change. In a multi-replica deployment, a replica only learns of a change it
// did not serve at its next restart/reseed; that staleness window is acceptable for
// the current single-control-plane posture (documented in GUIDE.md §5 / ARCHITECTURE
// §9.2) and bounded by the JWT TTL.
type revocationCache struct {
	mu sync.RWMutex
	m  map[string]int64
}

func newRevocationCache() *revocationCache { return &revocationCache{m: map[string]int64{}} }

// before returns the unix cutoff for a user (0 if none): tokens with iat < cutoff
// are invalid.
func (c *revocationCache) before(username string) int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.m[username]
}

func (c *revocationCache) set(username string, cutoffUnix int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[username] = cutoffUnix
}

func (c *revocationCache) seedFromTimes(in map[string]time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for u, t := range in {
		c.m[u] = t.Unix()
	}
}

// minPasswordLength is the floor for runtime password changes (AUTH-002). A length
// floor (rather than character-class rules) follows current NIST 800-63B guidance and
// avoids pushing users toward weak-but-compliant patterns.
const minPasswordLength = 12

func validateNewPassword(newPassword, currentPassword string) error {
	if len(newPassword) < minPasswordLength {
		return fmt.Errorf("new password must be at least %d characters", minPasswordLength)
	}
	if newPassword == currentPassword {
		return errors.New("new password must differ from the current password")
	}
	return nil
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// changePassword lets an authenticated user change their own password. The acting
// username is taken from the verified JWT (never the request body). The new bcrypt
// hash is persisted to credential_overrides — which login then prefers over the
// env-configured hash — and the revocation cache is advanced so the user's existing
// tokens stop working (AUTH-002).
func (a *API) changePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	username, _ := r.Context().Value(UserContextKey).(string)
	if username == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req changePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Resolve the current hash: a prior override supersedes the env-configured hash.
	var currentHash []byte
	for i := range a.creds {
		if a.creds[i].Username == username {
			currentHash = a.creds[i].Hash
			break
		}
	}
	if oh, _, ok, err := a.store.GetCredentialOverride(r.Context(), username); err == nil && ok {
		currentHash = oh
	}
	if currentHash == nil {
		// No password is configured for this account (e.g. auth disabled / dev-admin).
		http.Error(w, "password change is not available for this account", http.StatusBadRequest)
		return
	}

	if err := bcrypt.CompareHashAndPassword(currentHash, []byte(req.CurrentPassword)); err != nil {
		http.Error(w, "current password is incorrect", http.StatusUnauthorized)
		return
	}
	if err := validateNewPassword(req.NewPassword, req.CurrentPassword); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "could not process password", http.StatusInternalServerError)
		return
	}
	updated, err := a.store.SetCredentialOverride(r.Context(), username, newHash)
	if err != nil {
		http.Error(w, "could not save new password", http.StatusInternalServerError)
		return
	}

	// Invalidate this user's existing sessions: tokens with iat < updated are rejected.
	a.revoked.set(username, updated.Unix())
	_ = a.store.InsertAuditLog(r.Context(), &store.AuditLog{
		Username: username,
		Action:   "PASSWORD_CHANGE",
		Details:  "password changed; prior sessions invalidated",
	})

	w.WriteHeader(http.StatusNoContent)
}
