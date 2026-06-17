// Package notify delivers critical-finding alerts to operator notification channels
// (OPS-003): Slack incoming webhooks, email (SMTP), and PagerDuty Events API v2. It is
// independent of the SIEM webhook dispatcher (those carry raw machine events for ingestion;
// these are human-facing alerts). Every channel is optional and enabled purely by
// configuration — a Dispatcher with no configured channels is a no-op.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/smtp"
	"strings"
	"sync"
	"time"
)

// Alert is a single human-facing notification about a critical cryptographic finding.
type Alert struct {
	Title       string
	Severity    int
	Hostname    string
	HostUUID    string
	Algorithm   string
	FindingID   string
	Description string
	PolicyRule  string
}

// dedupKey identifies an alert for PagerDuty deduplication / general identity.
func (a Alert) dedupKey() string {
	if a.FindingID != "" {
		return "janus-" + a.FindingID
	}
	return fmt.Sprintf("janus-%s-%s", a.HostUUID, a.Algorithm)
}

func (a Alert) summary() string {
	host := a.Hostname
	if host == "" {
		host = a.HostUUID
	}
	return fmt.Sprintf("[Janus][sev%d] %s on %s (%s)", a.Severity, a.Algorithm, host, a.Title)
}

// Channel is one delivery target. Send must be safe for concurrent use.
type Channel interface {
	Name() string
	Send(ctx context.Context, a Alert) error
}

// Config is the notification configuration, resolved from JANUS_NOTIFY_* settings.
// A zero Config produces a Dispatcher with no channels (notifications disabled).
type Config struct {
	SlackWebhookURL string
	SMTPAddr        string // host:port
	SMTPFrom        string
	SMTPTo          []string
	SMTPUsername    string
	SMTPPassword    string
	PagerDutyKey    string // Events API v2 routing key
	MinSeverity     int    // alerts below this severity are dropped (default 5)
	URLValidator    func(string) error
}

// Dispatcher fans an alert out to all enabled channels. Best-effort: a channel failure is
// logged and never blocks the others.
type Dispatcher struct {
	channels    []Channel
	minSeverity int
}

// New builds a Dispatcher from cfg, wiring only the channels whose settings are present.
// httpClient and smtpSend are injectable for testing; pass nil to use the defaults.
func New(cfg Config, httpClient *http.Client, smtpSend SMTPSendFunc) (*Dispatcher, error) {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	if smtpSend == nil {
		smtpSend = defaultSMTPSend
	}
	validate := cfg.URLValidator
	min := cfg.MinSeverity
	if min <= 0 {
		min = 5
	}
	d := &Dispatcher{minSeverity: min}

	if cfg.SlackWebhookURL != "" {
		if validate != nil {
			if err := validate(cfg.SlackWebhookURL); err != nil {
				return nil, fmt.Errorf("slack webhook URL: %w", err)
			}
		}
		d.channels = append(d.channels, &slackChannel{url: cfg.SlackWebhookURL, client: httpClient})
	}
	if cfg.PagerDutyKey != "" {
		d.channels = append(d.channels, &pagerDutyChannel{routingKey: cfg.PagerDutyKey, client: httpClient})
	}
	if cfg.SMTPAddr != "" && cfg.SMTPFrom != "" && len(cfg.SMTPTo) > 0 {
		d.channels = append(d.channels, &emailChannel{
			addr: cfg.SMTPAddr, from: cfg.SMTPFrom, to: cfg.SMTPTo,
			username: cfg.SMTPUsername, password: cfg.SMTPPassword, send: smtpSend,
		})
	}
	return d, nil
}

// Enabled reports whether any channel is configured.
func (d *Dispatcher) Enabled() bool { return d != nil && len(d.channels) > 0 }

// Channels returns the names of the configured channels (for startup logging).
func (d *Dispatcher) Channels() []string {
	if d == nil {
		return nil
	}
	out := make([]string, 0, len(d.channels))
	for _, c := range d.channels {
		out = append(out, c.Name())
	}
	return out
}

// Notify delivers an alert to every configured channel, dropping it if below MinSeverity.
// Channels run concurrently; individual failures are logged, not returned.
func (d *Dispatcher) Notify(ctx context.Context, a Alert) {
	if !d.Enabled() || a.Severity < d.minSeverity {
		return
	}
	var wg sync.WaitGroup
	for _, ch := range d.channels {
		wg.Add(1)
		go func(c Channel) {
			defer wg.Done()
			if err := c.Send(ctx, a); err != nil {
				slog.Warn("notification channel failed", "channel", c.Name(), "finding_id", a.FindingID, "error", err)
			}
		}(ch)
	}
	wg.Wait()
}

// --- Slack ------------------------------------------------------------------

type slackChannel struct {
	url    string
	client *http.Client
}

func (s *slackChannel) Name() string { return "slack" }

func (s *slackChannel) Send(ctx context.Context, a Alert) error {
	host := a.Hostname
	if host == "" {
		host = a.HostUUID
	}
	text := fmt.Sprintf(":rotating_light: *%s*\n*Host:* %s\n*Algorithm:* %s\n*Rule:* %s\n*Finding:* `%s`\n%s",
		a.Title, host, a.Algorithm, a.PolicyRule, a.FindingID, a.Description)
	body, _ := json.Marshal(map[string]string{"text": text})
	return postJSON(ctx, s.client, s.url, body, nil)
}

// --- PagerDuty (Events API v2) ----------------------------------------------

type pagerDutyChannel struct {
	routingKey string
	client     *http.Client
}

func (p *pagerDutyChannel) Name() string { return "pagerduty" }

func (p *pagerDutyChannel) Send(ctx context.Context, a Alert) error {
	payload := map[string]any{
		"routing_key":  p.routingKey,
		"event_action": "trigger",
		"dedup_key":    a.dedupKey(),
		"payload": map[string]any{
			"summary":   a.summary(),
			"source":    firstNonEmpty(a.Hostname, a.HostUUID, "janus"),
			"severity":  "critical",
			"component": a.Algorithm,
			"group":     a.PolicyRule,
			"class":     "cryptographic-finding",
			"custom_details": map[string]any{
				"finding_id":  a.FindingID,
				"description": a.Description,
				"policy_rule": a.PolicyRule,
			},
		},
	}
	body, _ := json.Marshal(payload)
	return postJSON(ctx, p.client, "https://events.pagerduty.com/v2/enqueue", body, func(code int) bool {
		return code == http.StatusAccepted || (code >= 200 && code < 300)
	})
}

// --- Email (SMTP) -----------------------------------------------------------

// SMTPSendFunc matches net/smtp.SendMail so tests can substitute a fake sender.
type SMTPSendFunc func(addr string, auth smtp.Auth, from string, to []string, msg []byte) error

func defaultSMTPSend(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	return smtp.SendMail(addr, auth, from, to, msg)
}

type emailChannel struct {
	addr, from, username, password string
	to                             []string
	send                           SMTPSendFunc
}

func (e *emailChannel) Name() string { return "email" }

func (e *emailChannel) Send(_ context.Context, a Alert) error {
	var auth smtp.Auth
	if e.username != "" {
		host := e.addr
		if i := strings.LastIndex(e.addr, ":"); i > 0 {
			host = e.addr[:i]
		}
		auth = smtp.PlainAuth("", e.username, e.password, host)
	}
	msg := buildEmail(e.from, e.to, a)
	return e.send(e.addr, auth, e.from, e.to, msg)
}

// buildEmail renders an RFC 5322 message for the alert.
func buildEmail(from string, to []string, a Alert) []byte {
	host := a.Hostname
	if host == "" {
		host = a.HostUUID
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", a.summary())
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
	fmt.Fprintf(&b, "Critical cryptographic finding detected by Janus CryptoBOM.\r\n\r\n")
	fmt.Fprintf(&b, "Title:       %s\r\n", a.Title)
	fmt.Fprintf(&b, "Severity:    %d\r\n", a.Severity)
	fmt.Fprintf(&b, "Host:        %s\r\n", host)
	fmt.Fprintf(&b, "Algorithm:   %s\r\n", a.Algorithm)
	fmt.Fprintf(&b, "Policy rule: %s\r\n", a.PolicyRule)
	fmt.Fprintf(&b, "Finding ID:  %s\r\n", a.FindingID)
	fmt.Fprintf(&b, "\r\n%s\r\n", a.Description)
	return b.Bytes()
}

// --- helpers ----------------------------------------------------------------

func postJSON(ctx context.Context, client *http.Client, url string, body []byte, accept func(int) bool) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	if accept != nil {
		ok = accept(resp.StatusCode)
	}
	if !ok {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
