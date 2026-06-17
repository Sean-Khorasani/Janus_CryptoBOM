package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/janus-cbom/janus/server/internal/agentauth"
	"github.com/janus-cbom/janus/server/internal/config"
	"github.com/janus-cbom/janus/server/internal/store"
)

type contextKey string

const (
	RoleContextKey   contextKey = "user_role"
	UserContextKey   contextKey = "user_name"
	TenantContextKey contextKey = "tenant_id"
)

// TenantFromContext returns the authenticated request's tenant (WP-020), or the default
// tenant when none is present (e.g. auth disabled or a pre-tenancy token).
func TenantFromContext(ctx context.Context) string {
	if t, ok := ctx.Value(TenantContextKey).(string); ok && t != "" {
		return t
	}
	return config.DefaultTenant
}

type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type JWTPayload struct {
	Sub    string `json:"sub"`
	Role   string `json:"role"`
	Tenant string `json:"tenant,omitempty"`
	Iat    int64  `json:"iat"`
	Exp    int64  `json:"exp"`
}

// jwtTTL returns the access-token lifetime. Configurable via JANUS_JWT_TTL (a Go
// duration like "8h" or "30m"); defaults to 24h and is clamped to [5m, 720h] so a
// typo can't mint effectively-immortal or instantly-expiring tokens (AUTH-001).
// Shorter tokens shrink the exposure window of a leaked token (relates to S3).
func jwtTTL() time.Duration {
	ttl := 24 * time.Hour
	if v := os.Getenv("JANUS_JWT_TTL"); v != "" {
		if parsed, err := time.ParseDuration(v); err == nil {
			ttl = parsed
		}
	}
	if ttl < 5*time.Minute {
		ttl = 5 * time.Minute
	}
	if ttl > 720*time.Hour {
		ttl = 720 * time.Hour
	}
	return ttl
}

func GenerateToken(username, role, tenant string, secret []byte) (string, error) {
	header := JWTHeader{Alg: "HS256", Typ: "JWT"}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)

	if tenant == "" {
		tenant = config.DefaultTenant
	}
	now := time.Now()
	payload := JWTPayload{
		Sub:    username,
		Role:   role,
		Tenant: tenant,
		Iat:    now.Unix(),
		Exp:    now.Add(jwtTTL()).Unix(),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	signingInput := headerB64 + "." + payloadB64
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	signatureBytes := mac.Sum(nil)
	signatureB64 := base64.RawURLEncoding.EncodeToString(signatureBytes)

	return signingInput + "." + signatureB64, nil
}

// VerifyToken validates the signature and expiry and returns (subject, role,
// issued-at unix, error). The issued-at is used by AuthMiddleware to honor
// password-change session invalidation (AUTH-002).
func VerifyToken(tokenStr string, secret []byte) (string, string, string, int64, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return "", "", "", 0, errors.New("invalid token format")
	}

	headerB64, payloadB64, signatureB64 := parts[0], parts[1], parts[2]
	signingInput := headerB64 + "." + payloadB64

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	expectedSignature := mac.Sum(nil)
	expectedSignatureB64 := base64.RawURLEncoding.EncodeToString(expectedSignature)

	if !hmac.Equal([]byte(signatureB64), []byte(expectedSignatureB64)) {
		return "", "", "", 0, errors.New("invalid signature")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return "", "", "", 0, err
	}

	var payload JWTPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return "", "", "", 0, err
	}

	if time.Now().Unix() > payload.Exp {
		return "", "", "", 0, errors.New("token expired")
	}

	tenant := payload.Tenant
	if tenant == "" {
		tenant = config.DefaultTenant // back-compat: tokens minted before tenancy
	}
	return payload.Sub, payload.Role, tenant, payload.Iat, nil
}

// AuthMiddleware verifies the bearer JWT. revokedBefore, if non-nil, returns the
// unix cutoff before which a user's tokens are invalid (a password change advances
// it) — a token with iat < cutoff is rejected so the change ends prior sessions
// (AUTH-002). Pass nil to disable the check.
// AuthMiddleware verifies dashboard JWTs with `secret` (the session/JWT key) and agent
// tokens with `agentSecret` (the command-signing key). Keeping them distinct (AUTH-03)
// means a leaked session secret cannot mint valid agent tokens, and vice-versa; they may
// be the same value when JANUS_JWT_SECRET is unset.
func AuthMiddleware(secret []byte, agentSecret []byte, disableAuth bool, revokedBefore func(string) int64, agentVerify func(*http.Request) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if disableAuth {
				// Inject admin role by default if authentication is disabled
				ctx := context.WithValue(r.Context(), UserContextKey, "dev-admin")
				ctx = context.WithValue(ctx, RoleContextKey, "admin")
				ctx = context.WithValue(ctx, TenantContextKey, config.DefaultTenant)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			if r.URL.Path == "/api/agent/config" || r.URL.Path == "/api/agent/scan-command" {
				if agentVerify != nil {
					// Per-agent mode (WP-029 P1): verify the per-agent HMAC request token.
					if !agentVerify(r) {
						http.Error(w, "invalid agent authentication", http.StatusUnauthorized)
						return
					}
					next.ServeHTTP(w, r)
					return
				}
				// Shared mode (legacy): HMAC(command signing key, host_uuid).
				hostUUID := r.URL.Query().Get("host_uuid")
				mac := hmac.New(sha256.New, agentSecret)
				_, _ = mac.Write([]byte(hostUUID))
				expected := fmt.Sprintf("%x", mac.Sum(nil))
				if hostUUID == "" || !hmac.Equal([]byte(expected), []byte(r.Header.Get("X-Janus-Agent-Token"))) {
					http.Error(w, "invalid agent authentication", http.StatusUnauthorized)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// Heartbeat remains public for compatibility with older agents.
			// CSR generation (AUTH-003) is operator/admin-only — removed from the public allowlist.
			// /api/ws bypasses JWT here because it is authorized by a single-use
			// ticket validated in serveWS (SEC: keeps the session JWT out of the URL).
			if r.URL.Path == "/api/agent/heartbeat" || r.URL.Path == "/api/health" || r.URL.Path == "/api/auth/login" || r.URL.Path == "/metrics" || r.URL.Path == "/api/ws" {
				next.ServeHTTP(w, r)
				return
			}

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "missing authorization header", http.StatusUnauthorized)
				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				http.Error(w, "invalid authorization format", http.StatusUnauthorized)
				return
			}

			username, role, tenant, iat, err := VerifyToken(parts[1], secret)
			if err != nil {
				http.Error(w, fmt.Sprintf("unauthorized: %v", err), http.StatusUnauthorized)
				return
			}

			if revokedBefore != nil {
				if cutoff := revokedBefore(username); cutoff > 0 && iat < cutoff {
					http.Error(w, "unauthorized: session invalidated by a password change, please log in again", http.StatusUnauthorized)
					return
				}
			}

			ctx := context.WithValue(r.Context(), UserContextKey, username)
			ctx = context.WithValue(ctx, RoleContextKey, role)
			ctx = context.WithValue(ctx, TenantContextKey, tenant)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// verifyAgentRequest authenticates a per-agent request (WP-029 P1): it checks the
// X-Janus-Agent-{Id,Ts,Auth} headers against the agent's stored credential (which must
// be active), using a key derived from the master with a replay window, and best-effort
// bumps last_auth_at. Used only when AgentAuthMode=per-agent.
func (a *API) verifyAgentRequest(r *http.Request) bool {
	agentID := r.Header.Get("X-Janus-Agent-Id")
	tsStr := r.Header.Get("X-Janus-Agent-Ts")
	token := r.Header.Get("X-Janus-Agent-Auth")
	if agentID == "" || tsStr == "" || token == "" {
		return false
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false
	}
	cred, err := a.store.GetAgentCredential(r.Context(), agentID)
	if err != nil || cred == nil || cred.Status != "active" {
		return false
	}
	if cred.KeyMode != "derived" && cred.KeyMode != "" {
		// 'stored'-key mode is not enforced by this build's verifier yet.
		return false
	}
	key, err := agentauth.DeriveKey(a.cfg.AgentKeyMaster, agentID)
	if err != nil {
		return false
	}
	if !agentauth.Verify(key, agentID, r.Method, r.URL.Path, ts, time.Now().Unix(), int64(a.cfg.AgentAuthWindowSeconds), token) {
		return false
	}
	_ = a.store.TouchAgentCredential(r.Context(), agentID)
	return true
}

// requireWriteRole gates the mutating branch of a read/write multiplexed handler to
// operator/admin (REM-1 / FEAT-ROLE-COVERAGE). It writes 403 and returns false when the
// caller lacks the role, so reads can stay open while writes are restricted. Returns true
// when auth is disabled (dev) since the middleware injects an admin context.
func requireWriteRole(w http.ResponseWriter, r *http.Request) bool {
	role, _ := r.Context().Value(RoleContextKey).(string)
	if role != "operator" && role != "admin" {
		http.Error(w, "forbidden: operator or admin role required", http.StatusForbidden)
		return false
	}
	return true
}

func RequireRole(allowedRoles []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			roleVal := r.Context().Value(RoleContextKey)
			if roleVal == nil {
				http.Error(w, "forbidden: user context missing", http.StatusForbidden)
				return
			}
			userRole := roleVal.(string)

			matched := false
			for _, r := range allowedRoles {
				if r == userRole {
					matched = true
					break
				}
			}

			// hierarchy check: admin has access to everything
			if userRole == "admin" {
				matched = true
			}

			if !matched {
				http.Error(w, "forbidden: insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
	Role  string `json:"role"`
}

// dummyBcryptHash is a valid bcrypt hash of a random value, compared against when
// no user matches so login timing doesn't leak username existence (S1).
var dummyBcryptHash = []byte("$2a$10$N9qo8uLOickgx2ZMRZoMy.Mrq4kZpaX3y0kF1cV1q1qFp9q1q1q1q")

// LoginHandler authenticates against the env-configured credentials, preferring a
// persisted password override (from a prior /api/auth/change-password) when one
// exists for the matched user (AUTH-002). st may be nil (no override lookup).
func LoginHandler(secret []byte, disableAuth bool, creds []config.Credential, st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req LoginRequest
		// Body is optional when auth is disabled — ignore parse errors.
		_ = json.NewDecoder(r.Body).Decode(&req)

		var role, tenant string
		tenant = config.DefaultTenant
		if disableAuth {
			// Auth disabled: any credentials (or none) get admin access.
			// The username defaults to "dev-admin" when not provided.
			if req.Username == "" {
				req.Username = "dev-admin"
			}
			role = "admin"
		} else {
			// Credentials come from config (env), bcrypt-hashed — no compiled-in
			// passwords (S1). Always run one bcrypt compare (against a dummy hash on
			// miss) to avoid leaking which usernames exist.
			var matched *config.Credential
			for i := range creds {
				if subtle.ConstantTimeCompare([]byte(creds[i].Username), []byte(req.Username)) == 1 {
					matched = &creds[i]
					break
				}
			}
			hash := dummyBcryptHash
			if matched != nil {
				hash = matched.Hash
				// A runtime password change persists a new hash that supersedes the
				// env-configured one (AUTH-002).
				if st != nil {
					if oh, _, ok, err := st.GetCredentialOverride(r.Context(), matched.Username); err == nil && ok {
						hash = oh
					}
				}
			}
			if err := bcrypt.CompareHashAndPassword(hash, []byte(req.Password)); err != nil || matched == nil {
				http.Error(w, "invalid username or password", http.StatusUnauthorized)
				return
			}
			role = matched.Role
			if matched.TenantID != "" {
				tenant = matched.TenantID
			}
		}

		token, err := GenerateToken(req.Username, role, tenant, secret)
		if err != nil {
			writeError(w, err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(LoginResponse{
			Token: token,
			Role:  role,
		})
	}
}
