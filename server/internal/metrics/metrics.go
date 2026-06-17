// Package metrics is a tiny, dependency-free Prometheus-text registry for the
// in-process counters and latency histogram that can't be derived at scrape time
// (OPS-006). Scrape-time gauges (findings, agents, DB pool) are rendered by the
// HTTP /metrics handler; this package owns the request/webhook series that must be
// accumulated as events happen. Kept hand-rolled (no prometheus/client_golang) to
// match the existing /metrics endpoint and avoid a new dependency.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// latencyBuckets are cumulative upper bounds (seconds) for the request histogram.
var latencyBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type httpKey struct {
	method, path, status string
}

var (
	mu        sync.Mutex
	httpReqs  = map[httpKey]uint64{}
	durBucket = map[string][]uint64{} // path -> per-bucket cumulative counts
	durSum    = map[string]float64{}
	durCount  = map[string]uint64{}
	webhook   = map[string]uint64{} // status -> count

	webhookLatSum   float64 // FEAT-METRICS: webhook dispatch duration summary
	webhookLatCount uint64

	migrationDurSum   = map[string]float64{} // FEAT-METRICS: migration duration by terminal state
	migrationDurCount = map[string]uint64{}
)

// ObserveHTTP records one served HTTP request: bumps the request counter and the
// per-path latency histogram. path should be a low-cardinality route template.
func ObserveHTTP(method, path string, status int, seconds float64) {
	mu.Lock()
	defer mu.Unlock()
	httpReqs[httpKey{method, path, strconv.Itoa(status)}]++
	b := durBucket[path]
	if b == nil {
		b = make([]uint64, len(latencyBuckets))
	}
	for i, ub := range latencyBuckets {
		if seconds <= ub {
			b[i]++ // cumulative: an observation counts in every bucket whose le >= it
		}
	}
	durBucket[path] = b
	durSum[path] += seconds
	durCount[path]++
}

// ObserveWebhook records one webhook dispatch outcome (success|failed|skipped).
func ObserveWebhook(status string) {
	mu.Lock()
	webhook[status]++
	mu.Unlock()
}

// ObserveWebhookLatency records the wall-clock duration (seconds) of one webhook
// dispatch, including retries (FEAT-METRICS). Exposed as a Prometheus summary.
func ObserveWebhookLatency(seconds float64) {
	mu.Lock()
	webhookLatSum += seconds
	webhookLatCount++
	mu.Unlock()
}

// ObserveMigration records the duration (seconds) of a migration that reached a
// terminal state ("succeeded"|"failed"), as a per-state summary (FEAT-METRICS).
func ObserveMigration(state string, seconds float64) {
	if seconds < 0 {
		seconds = 0
	}
	mu.Lock()
	migrationDurSum[state] += seconds
	migrationDurCount[state]++
	mu.Unlock()
}

// escapeLabel escapes a Prometheus label value (backslash, quote, newline).
func escapeLabel(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

func formatFloat(f float64) string { return strconv.FormatFloat(f, 'g', -1, 64) }

// WriteProcessMetrics writes the accumulated counters/histogram in Prometheus text
// exposition format. Output is deterministically ordered so diffs/tests are stable.
func WriteProcessMetrics(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()

	fmt.Fprint(w, "# HELP janus_http_requests_total Total HTTP requests handled.\n")
	fmt.Fprint(w, "# TYPE janus_http_requests_total counter\n")
	hkeys := make([]httpKey, 0, len(httpReqs))
	for k := range httpReqs {
		hkeys = append(hkeys, k)
	}
	sort.Slice(hkeys, func(i, j int) bool {
		if hkeys[i].path != hkeys[j].path {
			return hkeys[i].path < hkeys[j].path
		}
		if hkeys[i].method != hkeys[j].method {
			return hkeys[i].method < hkeys[j].method
		}
		return hkeys[i].status < hkeys[j].status
	})
	for _, k := range hkeys {
		fmt.Fprintf(w, "janus_http_requests_total{method=\"%s\",path=\"%s\",status=\"%s\"} %d\n",
			escapeLabel(k.method), escapeLabel(k.path), escapeLabel(k.status), httpReqs[k])
	}

	fmt.Fprint(w, "\n# HELP janus_http_request_duration_seconds HTTP request latency.\n")
	fmt.Fprint(w, "# TYPE janus_http_request_duration_seconds histogram\n")
	paths := make([]string, 0, len(durCount))
	for p := range durCount {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		pl := escapeLabel(p)
		b := durBucket[p]
		for i, ub := range latencyBuckets {
			fmt.Fprintf(w, "janus_http_request_duration_seconds_bucket{path=\"%s\",le=\"%s\"} %d\n", pl, formatFloat(ub), b[i])
		}
		fmt.Fprintf(w, "janus_http_request_duration_seconds_bucket{path=\"%s\",le=\"+Inf\"} %d\n", pl, durCount[p])
		fmt.Fprintf(w, "janus_http_request_duration_seconds_sum{path=\"%s\"} %s\n", pl, formatFloat(durSum[p]))
		fmt.Fprintf(w, "janus_http_request_duration_seconds_count{path=\"%s\"} %d\n", pl, durCount[p])
	}

	fmt.Fprint(w, "\n# HELP janus_webhook_dispatches_total Webhook dispatch outcomes.\n")
	fmt.Fprint(w, "# TYPE janus_webhook_dispatches_total counter\n")
	wkeys := make([]string, 0, len(webhook))
	for s := range webhook {
		wkeys = append(wkeys, s)
	}
	sort.Strings(wkeys)
	for _, s := range wkeys {
		fmt.Fprintf(w, "janus_webhook_dispatches_total{status=\"%s\"} %d\n", escapeLabel(s), webhook[s])
	}

	fmt.Fprint(w, "\n# HELP janus_webhook_dispatch_duration_seconds Webhook dispatch duration including retries.\n")
	fmt.Fprint(w, "# TYPE janus_webhook_dispatch_duration_seconds summary\n")
	fmt.Fprintf(w, "janus_webhook_dispatch_duration_seconds_sum %s\n", formatFloat(webhookLatSum))
	fmt.Fprintf(w, "janus_webhook_dispatch_duration_seconds_count %d\n", webhookLatCount)

	fmt.Fprint(w, "\n# HELP janus_migration_duration_seconds Migration duration by terminal state.\n")
	fmt.Fprint(w, "# TYPE janus_migration_duration_seconds summary\n")
	mkeys := make([]string, 0, len(migrationDurCount))
	for st := range migrationDurCount {
		mkeys = append(mkeys, st)
	}
	sort.Strings(mkeys)
	for _, st := range mkeys {
		fmt.Fprintf(w, "janus_migration_duration_seconds_sum{state=\"%s\"} %s\n", escapeLabel(st), formatFloat(migrationDurSum[st]))
		fmt.Fprintf(w, "janus_migration_duration_seconds_count{state=\"%s\"} %d\n", escapeLabel(st), migrationDurCount[st])
	}
}
