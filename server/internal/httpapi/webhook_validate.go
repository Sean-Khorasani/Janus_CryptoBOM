package httpapi

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// validateWebhookURL applies SSRF protections to operator-supplied webhook
// destinations (HTTP-02), mirroring the LLM base-URL guard: only http/https, no
// cloud-metadata endpoints, and no private/loopback/link-local IP literals. Plain
// http is permitted only for localhost (local testing); remote endpoints must be https.
func validateWebhookURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid webhook URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported webhook scheme %q; use https", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("webhook URL must include a host")
	}
	lowerHost := strings.ToLower(host)

	for _, blocked := range []string{"metadata.google.internal", "169.254.169.254", "fd00:ec2::254"} {
		if lowerHost == blocked {
			return fmt.Errorf("metadata endpoint %q is not allowed", host)
		}
	}

	isLocalhost := lowerHost == "localhost" || strings.HasPrefix(host, "127.")
	if ip := net.ParseIP(host); ip != nil && !isLocalhost {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return fmt.Errorf("private/link-local IP %q is not allowed; use a public endpoint", host)
		}
	}
	if u.Scheme == "http" && !isLocalhost {
		return fmt.Errorf("http is only allowed for localhost; use https for remote webhooks")
	}
	return nil
}
