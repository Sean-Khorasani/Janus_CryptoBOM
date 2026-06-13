package orchestrator

import "testing"

func TestVerifyRejectsModifiedValidationChecklist(t *testing.T) {
	orch := New([]byte("test-signing-key-with-sufficient-length"))
	cmd := orch.BuildCommand(
		"host-1",
		"nginx",
		"hybrid",
		"/etc/nginx/nginx.conf",
		"patch",
		"original-checksum",
		true,
		"",
		"",
	)

	if !orch.Verify(cmd) {
		t.Fatal("freshly signed command did not verify")
	}

	cmd.ValidationChecklist[len(cmd.ValidationChecklist)-1] = "checksum=attacker-controlled"
	if orch.Verify(cmd) {
		t.Fatal("command verified after validation checklist modification")
	}
}

func TestVerifyRejectsModifiedTargetHost(t *testing.T) {
	orch := New([]byte("test-signing-key-with-sufficient-length"))
	cmd := orch.BuildCommand("host-1", "nginx", "hybrid", "/etc/nginx/nginx.conf", "patch", "", true, "", "")

	cmd.HostUuid = "host-2"
	if orch.Verify(cmd) {
		t.Fatal("command verified after target host modification")
	}
}
