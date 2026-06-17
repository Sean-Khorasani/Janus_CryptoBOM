package httpapi

import "testing"

func TestValidateWebhookURL(t *testing.T) {
	ok := []string{
		"https://siem.example.com/ingest",
		"https://hooks.example.com:8443/x",
		"http://localhost:9000/hook",
		"http://127.0.0.1:9000/hook",
	}
	for _, u := range ok {
		if err := validateWebhookURL(u); err != nil {
			t.Errorf("expected %q to be allowed, got %v", u, err)
		}
	}

	bad := []string{
		"",                                  // unparseable host
		"ftp://example.com/x",               // bad scheme
		"http://siem.example.com/x",         // plain http to a remote host
		"https://169.254.169.254/latest",    // cloud metadata
		"https://metadata.google.internal/", // metadata by name
		"https://10.0.0.5/ingest",           // private IP
		"https://192.168.1.10/ingest",       // private IP
		"https://[::1]/ingest",              // loopback v6
	}
	for _, u := range bad {
		if err := validateWebhookURL(u); err == nil {
			t.Errorf("expected %q to be rejected", u)
		}
	}
}
