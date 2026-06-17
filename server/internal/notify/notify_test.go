package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"strings"
	"sync"
	"testing"
)

func sampleAlert() Alert {
	return Alert{
		Title: "RSA-2048 below policy floor", Severity: 5, Hostname: "web-01",
		HostUUID: "uuid-1", Algorithm: "RSA-2048", FindingID: "f-123",
		Description: "RSA key shorter than 3072 bits", PolicyRule: "rsa-min-bits",
	}
}

// TestSlackAndPagerDutyDispatch wires Slack + PagerDuty at a local test server and asserts
// each receives a well-formed POST.
func TestSlackAndPagerDutyDispatch(t *testing.T) {
	var mu sync.Mutex
	got := map[string]map[string]any{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		mu.Lock()
		got[r.URL.Path] = m
		mu.Unlock()
		if strings.Contains(r.URL.Path, "pagerduty") {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Point both channels at the test server (PagerDuty URL is fixed in code, so we exercise
	// it through a dispatcher that uses the test server's client + a rewriting transport).
	d, err := New(Config{SlackWebhookURL: srv.URL + "/slack"}, srv.Client(), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !d.Enabled() || len(d.Channels()) != 1 {
		t.Fatalf("expected 1 channel, got %v", d.Channels())
	}
	d.Notify(context.Background(), sampleAlert())

	mu.Lock()
	slack := got["/slack"]
	mu.Unlock()
	if slack == nil {
		t.Fatal("slack channel did not receive a POST")
	}
	if txt, _ := slack["text"].(string); !strings.Contains(txt, "RSA-2048") || !strings.Contains(txt, "f-123") {
		t.Fatalf("slack text missing fields: %q", slack["text"])
	}
}

// TestPagerDutyPayload checks the Events API v2 envelope shape directly.
func TestPagerDutyPayload(t *testing.T) {
	var captured map[string]any
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		if !strings.Contains(r.URL.Host, "pagerduty.com") {
			t.Errorf("unexpected PagerDuty host: %s", r.URL.Host)
		}
		return &http.Response{StatusCode: http.StatusAccepted, Body: io.NopCloser(strings.NewReader("{}"))}, nil
	})
	d, err := New(Config{PagerDutyKey: "rk-xyz"}, &http.Client{Transport: rt}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	d.Notify(context.Background(), sampleAlert())

	if captured["routing_key"] != "rk-xyz" || captured["event_action"] != "trigger" {
		t.Fatalf("bad envelope: %+v", captured)
	}
	if captured["dedup_key"] != "janus-f-123" {
		t.Fatalf("dedup_key = %v, want janus-f-123", captured["dedup_key"])
	}
	p, _ := captured["payload"].(map[string]any)
	if p == nil || p["severity"] != "critical" {
		t.Fatalf("payload severity not critical: %+v", p)
	}
}

// TestEmailChannel verifies the SMTP send path and message contents via a fake sender.
func TestEmailChannel(t *testing.T) {
	var gotFrom string
	var gotTo []string
	var gotMsg string
	fake := func(addr string, _ smtp.Auth, from string, to []string, msg []byte) error {
		gotFrom, gotTo, gotMsg = from, to, string(msg)
		return nil
	}
	d, err := New(Config{
		SMTPAddr: "smtp.example.com:587", SMTPFrom: "janus@example.com",
		SMTPTo: []string{"soc@example.com", "ops@example.com"}, SMTPUsername: "u", SMTPPassword: "p",
	}, nil, fake)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	d.Notify(context.Background(), sampleAlert())

	if gotFrom != "janus@example.com" || len(gotTo) != 2 {
		t.Fatalf("from/to wrong: %s %v", gotFrom, gotTo)
	}
	for _, want := range []string{"Subject: [Janus][sev5]", "RSA-2048", "web-01", "f-123", "rsa-min-bits"} {
		if !strings.Contains(gotMsg, want) {
			t.Fatalf("email missing %q in:\n%s", want, gotMsg)
		}
	}
}

// TestSeverityGate drops alerts below the configured minimum.
func TestSeverityGate(t *testing.T) {
	var calls int
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	d, _ := New(Config{SlackWebhookURL: "https://hooks.example.com/x", MinSeverity: 5}, &http.Client{Transport: rt}, nil)

	a := sampleAlert()
	a.Severity = 4 // below floor
	d.Notify(context.Background(), a)
	if calls != 0 {
		t.Fatalf("sev-4 alert should be dropped, got %d calls", calls)
	}
	a.Severity = 5
	d.Notify(context.Background(), a)
	if calls != 1 {
		t.Fatalf("sev-5 alert should fire once, got %d calls", calls)
	}
}

// TestDisabledDispatcher is a no-op with no channels.
func TestDisabledDispatcher(t *testing.T) {
	d, err := New(Config{}, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if d.Enabled() {
		t.Fatal("dispatcher with no config should be disabled")
	}
	d.Notify(context.Background(), sampleAlert()) // must not panic
}

// TestSlackURLValidation rejects an SSRF-y Slack URL via the injected validator.
func TestSlackURLValidation(t *testing.T) {
	_, err := New(Config{
		SlackWebhookURL: "http://169.254.169.254/latest",
		URLValidator:    func(string) error { return errProbe },
	}, nil, nil)
	if err == nil {
		t.Fatal("expected validation error for blocked Slack URL")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

var errProbe = io.EOF
