package metrics

import (
	"strings"
	"testing"
)

func TestProcessMetricsExposition(t *testing.T) {
	ObserveHTTP("GET", "/api/overview", 200, 0.02)
	ObserveHTTP("GET", "/api/overview", 200, 0.3)
	ObserveHTTP("POST", "/api/auth/login", 401, 0.001)
	ObserveWebhook("success")
	ObserveWebhook("failed")

	var sb strings.Builder
	WriteProcessMetrics(&sb)
	out := sb.String()

	want := []string{
		"# TYPE janus_http_requests_total counter",
		`janus_http_requests_total{method="GET",path="/api/overview",status="200"} 2`,
		`janus_http_requests_total{method="POST",path="/api/auth/login",status="401"} 1`,
		"# TYPE janus_http_request_duration_seconds histogram",
		`janus_http_request_duration_seconds_count{path="/api/overview"} 2`,
		`janus_http_request_duration_seconds_bucket{path="/api/overview",le="+Inf"} 2`,
		// cumulative buckets: 0.02 falls in le>=0.025; 0.3 falls in le>=0.5
		`janus_http_request_duration_seconds_bucket{path="/api/overview",le="0.025"} 1`,
		`janus_http_request_duration_seconds_bucket{path="/api/overview",le="0.5"} 2`,
		`janus_webhook_dispatches_total{status="success"} 1`,
		`janus_webhook_dispatches_total{status="failed"} 1`,
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("metrics output missing line:\n  %s\n--- full output ---\n%s", w, out)
		}
	}
}
