package agentauth

import "testing"

func TestDeriveKeyDeterministicAndPerAgent(t *testing.T) {
	master := []byte("server-master-key-32-bytes-long!!")
	k1, err := DeriveKey(master, "agent-a")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(k1) != KeyLen {
		t.Fatalf("key len = %d, want %d", len(k1), KeyLen)
	}
	// Deterministic for the same inputs.
	k1b, _ := DeriveKey(master, "agent-a")
	if string(k1) != string(k1b) {
		t.Fatal("derivation must be deterministic")
	}
	// Distinct per agent id.
	k2, _ := DeriveKey(master, "agent-b")
	if string(k1) == string(k2) {
		t.Fatal("different agent ids must derive different keys")
	}
	// Distinct per master.
	k3, _ := DeriveKey([]byte("a-different-master-key-32-bytes!"), "agent-a")
	if string(k1) == string(k3) {
		t.Fatal("different masters must derive different keys")
	}
	if _, err := DeriveKey(nil, "agent-a"); err == nil {
		t.Fatal("empty master must error")
	}
}

func TestTokenVerify(t *testing.T) {
	key, _ := DeriveKey([]byte("server-master-key-32-bytes-long!!"), "agent-a")
	const now = int64(1_700_000_000)
	tok := Token(key, "agent-a", "POST", "/api/agent/config", now)

	if !Verify(key, "agent-a", "POST", "/api/agent/config", now, now, 300, tok) {
		t.Fatal("valid token must verify")
	}
	// Wrong key / id / method / path / token => reject.
	other, _ := DeriveKey([]byte("server-master-key-32-bytes-long!!"), "agent-b")
	if Verify(other, "agent-a", "POST", "/api/agent/config", now, now, 300, tok) {
		t.Fatal("wrong key must fail")
	}
	if Verify(key, "agent-b", "POST", "/api/agent/config", now, now, 300, tok) {
		t.Fatal("wrong agent id must fail")
	}
	if Verify(key, "agent-a", "GET", "/api/agent/config", now, now, 300, tok) {
		t.Fatal("wrong method must fail")
	}
	if Verify(key, "agent-a", "POST", "/api/agent/scan-command", now, now, 300, tok) {
		t.Fatal("wrong path must fail")
	}
	if Verify(key, "agent-a", "POST", "/api/agent/config", now, now, 300, "00") {
		t.Fatal("garbage token must fail")
	}
	// Stale / future timestamp beyond the window => reject.
	if Verify(key, "agent-a", "POST", "/api/agent/config", now, now+1000, 300, tok) {
		t.Fatal("stale ts must fail")
	}
	if Verify(key, "agent-a", "POST", "/api/agent/config", now+1000, now, 300, tok) {
		t.Fatal("future ts must fail")
	}
	// Window 0 disables the freshness check.
	if !Verify(key, "agent-a", "POST", "/api/agent/config", now, now+99999, 0, tok) {
		t.Fatal("window=0 should skip freshness")
	}
}
