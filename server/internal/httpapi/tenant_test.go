package httpapi

import (
	"context"
	"strings"
	"testing"

	"github.com/janus-cbom/janus/server/internal/config"
)

// WP-020: the session token carries the login's tenant, and the auth layer surfaces it via
// TenantFromContext (defaulting safely when absent).
func TestJWTCarriesTenant(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	tok, err := GenerateToken("alice", "operator", "acme", secret)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	sub, role, tenant, _, err := VerifyToken(tok, secret)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if sub != "alice" || role != "operator" || tenant != "acme" {
		t.Fatalf("claims = (%q,%q,%q), want (alice,operator,acme)", sub, role, tenant)
	}

	// An empty tenant at mint time defaults to the default tenant (never empty on the wire).
	tok2, _ := GenerateToken("bob", "viewer", "", secret)
	if _, _, tn, _, _ := VerifyToken(tok2, secret); tn != config.DefaultTenant {
		t.Fatalf("empty tenant should default to %q, got %q", config.DefaultTenant, tn)
	}
}

// WP-020: tenant IDs are slugs (used in JWT claims, row filters, config keys), so the create
// endpoint must reject anything outside a safe character set.
func TestTenantIDValidation(t *testing.T) {
	valid := []string{"default", "acme", "team-1", "t_2", "a"}
	for _, v := range valid {
		if !tenantIDPattern.MatchString(v) {
			t.Errorf("%q should be a valid tenant_id", v)
		}
	}
	invalid := []string{"", "Acme", "has space", "has/slash", "-leading", "x'; DROP TABLE", strings.Repeat("a", 64)}
	for _, v := range invalid {
		if tenantIDPattern.MatchString(v) {
			t.Errorf("%q should be rejected", v)
		}
	}
}

func TestTenantFromContext(t *testing.T) {
	// Absent → default (safe fallback).
	if got := TenantFromContext(context.Background()); got != config.DefaultTenant {
		t.Errorf("absent tenant = %q, want %q", got, config.DefaultTenant)
	}
	// Present → that tenant.
	ctx := context.WithValue(context.Background(), TenantContextKey, "acme")
	if got := TenantFromContext(ctx); got != "acme" {
		t.Errorf("context tenant = %q, want acme", got)
	}
}
