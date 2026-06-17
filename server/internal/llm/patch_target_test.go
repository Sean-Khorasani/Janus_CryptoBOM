package llm

import "testing"

func TestAgentWillApplyPatch(t *testing.T) {
	cfgPatch := func(p string) string {
		return "--- a/" + p + "\n+++ b/" + p + "\n@@ -1 +1 @@\n-old\n+new\n"
	}
	cases := []struct {
		name    string
		patch   string
		wantOK  bool
		wantTgt string
	}{
		{"config ext .conf", cfgPatch("etc/nginx/nginx.conf"), true, "etc/nginx/nginx.conf"},
		{"config ext .yaml", cfgPatch("k8s/tls.yaml"), true, "k8s/tls.yaml"},
		{"extensionless sshd_config", cfgPatch("etc/ssh/sshd_config"), true, "etc/ssh/sshd_config"},
		{"source .go rejected", cfgPatch("internal/crypto/rsa.go"), false, "internal/crypto/rsa.go"},
		{"source .java rejected", cfgPatch("src/Main.java"), false, "src/Main.java"},
		{"extensionless unknown rejected", cfgPatch("usr/local/bin/run"), false, "usr/local/bin/run"},
		{"empty patch", "", false, ""},
		{"no +++ header", "@@ -1 +1 @@\n-a\n+b\n", false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tgt, ok, reason := AgentWillApplyPatch(c.patch)
			if ok != c.wantOK {
				t.Fatalf("ok=%v want %v (reason=%q)", ok, c.wantOK, reason)
			}
			if tgt != c.wantTgt {
				t.Fatalf("target=%q want %q", tgt, c.wantTgt)
			}
			if !ok && reason == "" {
				t.Error("rejection must carry a reason")
			}
		})
	}
}

func TestPatchTargetPathSkipsDevNull(t *testing.T) {
	// A new-file diff (--- /dev/null) must resolve to the real +++ target.
	patch := "--- /dev/null\n+++ b/etc/app/config.toml\n@@ -0,0 +1 @@\n+x=1\n"
	if got := PatchTargetPath(patch); got != "etc/app/config.toml" {
		t.Fatalf("got %q", got)
	}
}
