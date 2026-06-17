package grpcserver

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/janus-cbom/janus/server/internal/agentauth"
	"github.com/janus-cbom/janus/server/internal/store"
)

// agentAuthTestStore implements only the two credential methods verifyAgentMD touches.
// The embedded nil Store panics if any other method is reached — which would itself be
// a useful failure signal, since verifyAgentMD must not call anything else.
type agentAuthTestStore struct {
	store.Store
	cred    *store.AgentCredential
	getErr  error
	touched bool
}

var errProbe = errors.New("probe")

func (s *agentAuthTestStore) GetAgentCredential(_ context.Context, _ string) (*store.AgentCredential, error) {
	return s.cred, s.getErr
}

func (s *agentAuthTestStore) TouchAgentCredential(_ context.Context, _ string) error {
	s.touched = true
	return nil
}

func mdCtx(id, ts, auth string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.New(map[string]string{
		"janus-agent-id":   id,
		"janus-agent-ts":   ts,
		"janus-agent-auth": auth,
	}))
}

func TestVerifyAgentMD(t *testing.T) {
	master := []byte("0123456789abcdef0123456789abcdef")
	const agentID = "agent-xyz"
	key, err := agentauth.DeriveKey(master, agentID)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	const ts int64 = 1_700_000_000
	tsStr := strconv.FormatInt(ts, 10)
	good := agentauth.Token(key, agentID, agentauth.GRPCMethod, agentauth.GRPCPath, ts)
	active := &store.AgentCredential{Status: "active", KeyMode: "derived"}

	cases := []struct {
		name    string
		ctx     context.Context
		store   *agentAuthTestStore
		want    bool
		touched bool
	}{
		{"valid", mdCtx(agentID, tsStr, good), &agentAuthTestStore{cred: active}, true, true},
		{"revoked", mdCtx(agentID, tsStr, good), &agentAuthTestStore{cred: &store.AgentCredential{Status: "revoked", KeyMode: "derived"}}, false, false},
		{"wrong-token", mdCtx(agentID, tsStr, good+"00"), &agentAuthTestStore{cred: active}, false, false},
		{"unknown-agent", mdCtx(agentID, tsStr, good), &agentAuthTestStore{cred: nil}, false, false},
		{"missing-headers", context.Background(), &agentAuthTestStore{cred: active}, false, false},
		{"bad-ts", mdCtx(agentID, "not-a-number", good), &agentAuthTestStore{cred: active}, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// window=0 disables the freshness check so a fixed token stays deterministic.
			got := verifyAgentMD(c.ctx, c.store, master, 0)
			if got != c.want {
				t.Fatalf("verifyAgentMD = %v, want %v", got, c.want)
			}
			if c.store.touched != c.touched {
				t.Fatalf("touched = %v, want %v", c.store.touched, c.touched)
			}
		})
	}
}

func TestResolveAgentTenant(t *testing.T) {
	cases := []struct {
		name  string
		ctx   context.Context
		store *agentAuthTestStore
		want  string
	}{
		{"no-metadata", context.Background(), &agentAuthTestStore{}, "default"},
		{"id-but-no-cred", mdCtx("agent-1", "", ""), &agentAuthTestStore{cred: nil}, "default"},
		{"cred-empty-tenant", mdCtx("agent-1", "", ""), &agentAuthTestStore{cred: &store.AgentCredential{}}, "default"},
		{"cred-with-tenant", mdCtx("agent-1", "", ""), &agentAuthTestStore{cred: &store.AgentCredential{TenantID: "acme"}}, "acme"},
		{"get-error", mdCtx("agent-1", "", ""), &agentAuthTestStore{getErr: errProbe}, "default"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &Server{store: c.store}
			if got := s.resolveAgentTenant(c.ctx); got != c.want {
				t.Fatalf("resolveAgentTenant = %q, want %q", got, c.want)
			}
		})
	}
}

func TestPerAgentUnaryInterceptor(t *testing.T) {
	master := []byte("0123456789abcdef0123456789abcdef")
	const agentID = "agent-xyz"
	key, _ := agentauth.DeriveKey(master, agentID)
	const ts int64 = 1_700_000_000
	tok := agentauth.Token(key, agentID, agentauth.GRPCMethod, agentauth.GRPCPath, ts)
	active := &agentAuthTestStore{cred: &store.AgentCredential{Status: "active", KeyMode: "derived"}}

	called := false
	handler := func(_ context.Context, _ any) (any, error) {
		called = true
		return "ok", nil
	}
	interceptor := PerAgentUnaryInterceptor(active, master, 0)

	// Authenticated call reaches the handler.
	if _, err := interceptor(mdCtx(agentID, strconv.FormatInt(ts, 10), tok), nil, &grpc.UnaryServerInfo{}, handler); err != nil {
		t.Fatalf("authenticated call errored: %v", err)
	}
	if !called {
		t.Fatal("handler was not invoked for an authenticated call")
	}

	// Unauthenticated call is rejected before the handler with codes.Unauthenticated.
	called = false
	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{}, handler)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("want Unauthenticated, got %v", err)
	}
	if called {
		t.Fatal("handler ran for an unauthenticated call")
	}
}
