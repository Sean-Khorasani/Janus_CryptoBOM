package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/janus-cbom/janus/server/internal/agentauth"
	"github.com/janus-cbom/janus/server/internal/config"
	"github.com/janus-cbom/janus/server/internal/store"
)

// runAgentCLI dispatches `janus-server agent <enroll|revoke|disable|activate|list>` to manage
// per-agent identities (WP-029 P1). Uses JANUS_DATABASE_URL; enroll (derived mode) needs the
// master key in JANUS_AGENT_KEY_MASTER (hex) or JANUS_AGENT_KEY_MASTER_FILE — the master stays
// server-side, each agent receives only its own derived key.
func runAgentCLI(args []string) {
	if len(args) == 0 {
		agentUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "enroll":
		agentEnroll(args[1:])
	case "revoke":
		agentSetStatus(args[1:], "revoked")
	case "disable":
		agentSetStatus(args[1:], "disabled")
	case "activate":
		agentSetStatus(args[1:], "active")
	case "list":
		agentList()
	default:
		agentUsage()
		os.Exit(2)
	}
}

func agentUsage() {
	fmt.Fprintln(os.Stderr, `usage: janus-server agent <sub> [flags]
  enroll   --label <name> [--host-uuid <uuid>] [--tenant <id>]   create an identity; prints agent_id + derived key
  revoke   --id <agent_id> [--reason <text>]     revoke an agent (instant, isolated)
  disable  --id <agent_id>                        pause an agent (reversible)
  activate --id <agent_id>                        re-enable a disabled agent
  list                                            list agent identities
Env: JANUS_DATABASE_URL; enroll needs JANUS_AGENT_KEY_MASTER (hex) or JANUS_AGENT_KEY_MASTER_FILE.`)
}

func agentStore() (*store.Postgres, context.Context) {
	dbURL := os.Getenv("JANUS_DATABASE_URL")
	if dbURL == "" {
		dbURL = config.DefaultDatabaseURL
	}
	ctx := context.Background()
	pg, err := store.NewPostgres(ctx, store.PostgresConfig{
		DatabaseURL: dbURL,
		MaxConns:    config.DefaultDBMaxConns,
		MinConns:    config.DefaultDBMinConns,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "agent: connect postgres:", err)
		os.Exit(1)
	}
	if err := pg.EnsureSchema(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "agent: ensure schema:", err)
		os.Exit(1)
	}
	return pg, ctx
}

func agentMasterKey() []byte {
	if path := os.Getenv("JANUS_AGENT_KEY_MASTER_FILE"); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "agent enroll: read JANUS_AGENT_KEY_MASTER_FILE:", err)
			os.Exit(1)
		}
		return []byte(strings.TrimSpace(string(raw)))
	}
	m := strings.TrimSpace(os.Getenv("JANUS_AGENT_KEY_MASTER"))
	if m == "" {
		fmt.Fprintln(os.Stderr, "agent enroll: set JANUS_AGENT_KEY_MASTER (hex) or JANUS_AGENT_KEY_MASTER_FILE")
		os.Exit(1)
	}
	return []byte(m)
}

func agentEnroll(args []string) {
	fs := flag.NewFlagSet("agent enroll", flag.ExitOnError)
	label := fs.String("label", "", "human label for the agent")
	hostUUID := fs.String("host-uuid", "", "optional asset host_uuid to bind")
	tenant := fs.String("tenant", "default", "tenant the agent's assets belong to (WP-020)")
	_ = fs.Parse(args)

	master := agentMasterKey()
	agentID := uuid.NewString()
	key, err := agentauth.DeriveKey(master, agentID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agent enroll: derive key:", err)
		os.Exit(1)
	}
	pg, ctx := agentStore()
	defer pg.Close()
	if err := pg.UpsertAgentCredential(ctx, &store.AgentCredential{
		AgentID: agentID, HostUUID: *hostUUID, KeyMode: "derived", Status: "active", Label: *label, TenantID: *tenant, EnrolledBy: "cli",
	}); err != nil {
		fmt.Fprintln(os.Stderr, "agent enroll:", err)
		os.Exit(1)
	}
	fmt.Println("# Per-agent identity enrolled — put these in the agent package (janus-agent.toml):")
	fmt.Printf("agent_id  = %q\n", agentID)
	fmt.Printf("agent_key = %q\n", hex.EncodeToString(key))
}

func agentSetStatus(args []string, status string) {
	fs := flag.NewFlagSet("agent "+status, flag.ExitOnError)
	id := fs.String("id", "", "agent_id")
	reason := fs.String("reason", "", "reason (recorded on revoke)")
	_ = fs.Parse(args)
	if *id == "" {
		fmt.Fprintln(os.Stderr, "agent: --id is required")
		os.Exit(2)
	}
	pg, ctx := agentStore()
	defer pg.Close()
	if err := pg.SetAgentCredentialStatus(ctx, *id, status, *reason); err != nil {
		fmt.Fprintln(os.Stderr, "agent:", err)
		os.Exit(1)
	}
	fmt.Printf("agent %s -> %s\n", *id, status)
}

func agentList() {
	pg, ctx := agentStore()
	defer pg.Close()
	creds, err := pg.ListAgentCredentials(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agent list:", err)
		os.Exit(1)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "AGENT_ID\tSTATUS\tTENANT\tLABEL\tENROLLED\tLAST_AUTH")
	for _, c := range creds {
		last := "-"
		if c.LastAuthAt != nil {
			last = c.LastAuthAt.Format(time.RFC3339)
		}
		tenant := c.TenantID
		if tenant == "" {
			tenant = "default"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", c.AgentID, c.Status, tenant, c.Label, c.EnrolledAt.Format("2006-01-02"), last)
	}
	_ = w.Flush()
}
