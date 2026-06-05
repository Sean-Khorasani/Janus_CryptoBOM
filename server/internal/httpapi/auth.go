package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type contextKey string

const (
	RoleContextKey contextKey = "user_role"
	UserContextKey contextKey = "user_name"
)

type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type JWTPayload struct {
	Sub  string `json:"sub"`
	Role string `json:"role"`
	Exp  int64  `json:"exp"`
}

func GenerateToken(username, role string, secret []byte) (string, error) {
	header := JWTHeader{Alg: "HS256", Typ: "JWT"}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)

	payload := JWTPayload{
		Sub:  username,
		Role: role,
		Exp:  time.Now().Add(24 * time.Hour).Unix(),
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

func VerifyToken(tokenStr string, secret []byte) (string, string, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return "", "", errors.New("invalid token format")
	}

	headerB64, payloadB64, signatureB64 := parts[0], parts[1], parts[2]
	signingInput := headerB64 + "." + payloadB64

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	expectedSignature := mac.Sum(nil)
	expectedSignatureB64 := base64.RawURLEncoding.EncodeToString(expectedSignature)

	if !hmac.Equal([]byte(signatureB64), []byte(expectedSignatureB64)) {
		return "", "", errors.New("invalid signature")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return "", "", err
	}

	var payload JWTPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return "", "", err
	}

	if time.Now().Unix() > payload.Exp {
		return "", "", errors.New("token expired")
	}

	return payload.Sub, payload.Role, nil
}

func AuthMiddleware(secret []byte, disableAuth bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if disableAuth {
				// Inject admin role by default if authentication is disabled
				ctx := context.WithValue(r.Context(), UserContextKey, "dev-admin")
				ctx = context.WithValue(ctx, RoleContextKey, "admin")
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Heartbeat endpoint and CSR creation endpoints are public/agent-only
			if r.URL.Path == "/api/agent/heartbeat" || r.URL.Path == "/api/certificates/csr" || r.URL.Path == "/api/health" || r.URL.Path == "/api/auth/login" {
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

			username, role, err := VerifyToken(parts[1], secret)
			if err != nil {
				http.Error(w, fmt.Sprintf("unauthorized: %v", err), http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), UserContextKey, username)
			ctx = context.WithValue(ctx, RoleContextKey, role)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
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

func LoginHandler(secret []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Simple static credentials mapping
		var role string
		if req.Username == "admin" && req.Password == "janus-admin-pass" {
			role = "admin"
		} else if req.Username == "operator" && req.Password == "janus-operator-pass" {
			role = "operator"
		} else if req.Username == "viewer" && req.Password == "janus-viewer-pass" {
			role = "viewer"
		} else {
			http.Error(w, "invalid username or password", http.StatusUnauthorized)
			return
		}

		token, err := GenerateToken(req.Username, role, secret)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(LoginResponse{
			Token: token,
			Role:  role,
		})
	}
}
