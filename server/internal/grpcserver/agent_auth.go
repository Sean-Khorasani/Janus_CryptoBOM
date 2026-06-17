package grpcserver

import (
	"context"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/janus-cbom/janus/server/internal/agentauth"
	"github.com/janus-cbom/janus/server/internal/store"
)

// verifyAgentMD authenticates a gRPC call in per-agent mode (WP-029 P1): the client
// sends janus-agent-{id,ts,auth} metadata, where auth = HMAC over
// agentID + GRPCMethod + GRPCPath + ts with the per-agent key. The credential must be
// active and the timestamp within the freshness window.
func verifyAgentMD(ctx context.Context, st store.Store, master []byte, window int64) bool {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	get := func(k string) string {
		if v := md.Get(k); len(v) > 0 {
			return v[0]
		}
		return ""
	}
	agentID, tsStr, token := get("janus-agent-id"), get("janus-agent-ts"), get("janus-agent-auth")
	if agentID == "" || tsStr == "" || token == "" {
		return false
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false
	}
	cred, err := st.GetAgentCredential(ctx, agentID)
	if err != nil || cred == nil || cred.Status != "active" {
		return false
	}
	if cred.KeyMode != "derived" && cred.KeyMode != "" {
		return false
	}
	key, err := agentauth.DeriveKey(master, agentID)
	if err != nil {
		return false
	}
	if !agentauth.Verify(key, agentID, agentauth.GRPCMethod, agentauth.GRPCPath, ts, time.Now().Unix(), window, token) {
		return false
	}
	_ = st.TouchAgentCredential(ctx, agentID)
	return true
}

// PerAgentUnaryInterceptor rejects unary calls from agents that fail per-agent auth.
func PerAgentUnaryInterceptor(st store.Store, master []byte, window int64) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !verifyAgentMD(ctx, st, master, window) {
			return nil, status.Error(codes.Unauthenticated, "per-agent authentication failed")
		}
		return handler(ctx, req)
	}
}

// PerAgentStreamInterceptor rejects streams from agents that fail per-agent auth (checked
// once at stream open).
func PerAgentStreamInterceptor(st store.Store, master []byte, window int64) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if !verifyAgentMD(ss.Context(), st, master, window) {
			return status.Error(codes.Unauthenticated, "per-agent authentication failed")
		}
		return handler(srv, ss)
	}
}
