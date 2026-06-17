package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

// wsTicketTTL bounds how long a freshly minted WebSocket ticket is valid before
// it must be redeemed. Short by design — the dashboard requests one immediately
// before connecting.
const wsTicketTTL = 30 * time.Second

// wsTicketStore issues short-lived, single-use tickets that authorize exactly
// one /api/ws upgrade (SEC). Browsers cannot set an Authorization header on a
// WebSocket, so the alternative was putting the session JWT in the query string
// where it leaks into proxy/access logs and browser history. Instead the client
// calls POST /api/ws/ticket with its bearer token (header-authed) and connects
// with ?ticket=. Tickets are consumed on first use and expire quickly.
type wsTicketStore struct {
	mu      sync.Mutex
	tickets map[string]wsTicket
}

type wsTicket struct {
	user    string
	role    string
	tenant  string
	expires time.Time
}

func newWSTicketStore() *wsTicketStore {
	return &wsTicketStore{tickets: make(map[string]wsTicket)}
}

// issue mints a new random ticket bound to the caller's identity.
func (s *wsTicketStore) issue(user, role, tenant string, now time.Time) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	id := hex.EncodeToString(buf)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(now)
	s.tickets[id] = wsTicket{user: user, role: role, tenant: tenant, expires: now.Add(wsTicketTTL)}
	return id, nil
}

// consume validates and removes a ticket, returning its (user, role, tenant) on success.
// A ticket is valid at most once, so a leaked URL cannot be replayed.
func (s *wsTicketStore) consume(id string, now time.Time) (user, role, tenant string, ok bool) {
	if id == "" {
		return "", "", "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t, found := s.tickets[id]
	if !found {
		return "", "", "", false
	}
	delete(s.tickets, id)
	if now.After(t.expires) {
		return "", "", "", false
	}
	return t.user, t.role, t.tenant, true
}

// sweep drops expired tickets. Caller must hold the lock.
func (s *wsTicketStore) sweep(now time.Time) {
	for id, t := range s.tickets {
		if now.After(t.expires) {
			delete(s.tickets, id)
		}
	}
}

// wsTicketIssue (POST /api/ws/ticket) returns a single-use ticket for the
// authenticated caller. It runs behind AuthMiddleware, so the bearer JWT is read
// from the Authorization header — never the URL.
func (a *API) wsTicketIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, _ := r.Context().Value(UserContextKey).(string)
	role, _ := r.Context().Value(RoleContextKey).(string)
	tenant := TenantFromContext(r.Context())
	id, err := a.wsTickets.issue(user, role, tenant, time.Now())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ticket":     id,
		"expires_in": int(wsTicketTTL.Seconds()),
	})
}

// serveWS validates the single-use ticket from ?ticket= and hands off to the
// hub. /api/ws bypasses JWT auth in AuthMiddleware precisely because the ticket
// is the credential here.
func (a *API) serveWS(w http.ResponseWriter, r *http.Request) {
	_, _, tenant, ok := a.wsTickets.consume(r.URL.Query().Get("ticket"), time.Now())
	if !ok {
		http.Error(w, "invalid or expired websocket ticket", http.StatusUnauthorized)
		return
	}
	a.wsHub.ServeWS(w, r, tenant)
}
