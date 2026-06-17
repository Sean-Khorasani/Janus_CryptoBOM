package config

import "testing"

// WP-020: each dashboard login is assigned a tenant — JANUS_<ROLE>_TENANT, defaulting to
// DefaultTenant — so fleet/finding data can later be scoped per tenant.
func TestCredentialTenantAssignment(t *testing.T) {
	t.Setenv("JANUS_ADMIN_PASSWORD", "admin-pw")
	t.Setenv("JANUS_ADMIN_TENANT", "acme")
	t.Setenv("JANUS_OPERATOR_PASSWORD", "op-pw") // no tenant set -> default
	t.Cleanup(func() { fileVals = nil; fileValsLoaded = false })

	creds := loadCredentials()
	byRole := map[string]Credential{}
	for _, c := range creds {
		byRole[c.Role] = c
	}
	if byRole["admin"].TenantID != "acme" {
		t.Errorf("admin tenant = %q, want acme", byRole["admin"].TenantID)
	}
	if byRole["operator"].TenantID != DefaultTenant {
		t.Errorf("operator tenant = %q, want %q", byRole["operator"].TenantID, DefaultTenant)
	}
}

func TestParseConfigFile(t *testing.T) {
	m := parseConfigFile("# a comment\n" +
		"JANUS_GRPC_ADDR=0.0.0.0:9443\n" +
		"export JANUS_LOG_LEVEL = debug\n" +
		"QUOTED=\"a b c\"\n" +
		"SINGLE='x y'\n" +
		"\n" +
		"NOEQUALS\n")
	if m["JANUS_GRPC_ADDR"] != "0.0.0.0:9443" {
		t.Fatalf("grpc_addr = %q", m["JANUS_GRPC_ADDR"])
	}
	if m["JANUS_LOG_LEVEL"] != "debug" {
		t.Fatalf("export-prefixed log_level = %q", m["JANUS_LOG_LEVEL"])
	}
	if m["QUOTED"] != "a b c" {
		t.Fatalf("double-quoted = %q", m["QUOTED"])
	}
	if m["SINGLE"] != "x y" {
		t.Fatalf("single-quoted = %q", m["SINGLE"])
	}
	if _, ok := m["NOEQUALS"]; ok {
		t.Fatal("line without '=' should be skipped")
	}
}

func TestConfigPrecedenceEnvOverFileOverDefault(t *testing.T) {
	fileVals = map[string]string{"JANUS_TEST_KEY": "from-file", "JANUS_TEST_NUM": "42", "JANUS_TEST_BOOL": "true"}
	fileValsLoaded = true // prevent the lazy loader from clobbering the manual map
	t.Cleanup(func() { fileVals = nil; fileValsLoaded = false })

	// Public resolvers (used by the hsm package + command-signing setup) read the same layer.
	if got := Value("JANUS_TEST_KEY"); got != "from-file" {
		t.Fatalf("Value file layer: got %q", got)
	}
	if got := ValueOr("JANUS_NOT_SET_ANYWHERE", "the-default"); got != "the-default" {
		t.Fatalf("ValueOr default: got %q", got)
	}
	if !BoolValue("JANUS_TEST_BOOL") {
		t.Fatal("BoolValue should read 'true' from the file layer")
	}
	if BoolValue("JANUS_NOT_SET_ANYWHERE") {
		t.Fatal("BoolValue should be false when unset")
	}

	// File value is used when the env var is unset.
	if got := lookup("JANUS_TEST_KEY"); got != "from-file" {
		t.Fatalf("file layer: got %q, want from-file", got)
	}
	// Env var wins over the file.
	t.Setenv("JANUS_TEST_KEY", "from-env")
	if got := lookup("JANUS_TEST_KEY"); got != "from-env" {
		t.Fatalf("env over file: got %q, want from-env", got)
	}
	// Unknown key resolves to "".
	if got := lookup("JANUS_NOT_SET_ANYWHERE"); got != "" {
		t.Fatalf("unknown key: got %q, want empty", got)
	}
	// env() falls back to the constant default when neither env nor file set it.
	if got := env("JANUS_NOT_SET_ANYWHERE", "the-default"); got != "the-default" {
		t.Fatalf("default fallback: got %q", got)
	}
	// intEnv reads from the file layer.
	if got := intEnv("JANUS_TEST_NUM", 7); got != 42 {
		t.Fatalf("intEnv file layer: got %d, want 42", got)
	}
}
