package httpapi

import (
	"context"
	"net/http"
	"regexp"

	"github.com/google/uuid"
)

// CorrelationIDContextKey carries the per-request correlation ID through the
// request context so handlers, the request logger, and writeError can tag their
// output with it (OPS-004).
const CorrelationIDContextKey contextKey = "correlation_id"

// CorrelationHeader is the request/response header carrying the ID. We accept the
// common X-Correlation-ID and X-Request-ID on input and always echo X-Correlation-ID.
const CorrelationHeader = "X-Correlation-ID"

// safeCorrelationID bounds an inbound ID to a safe shape so a caller can't inject
// newlines/control chars into structured logs or smuggle oversized headers.
var safeCorrelationID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// correlationMiddleware assigns each request a correlation ID — reusing a
// client-supplied X-Correlation-ID/X-Request-ID when it is well-formed, otherwise
// minting a UUID — stores it in the request context, and echoes it on the response
// header. It is the outermost middleware so the ID exists for every downstream layer
// (OPS-004).
func correlationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(CorrelationHeader)
		if id == "" {
			id = r.Header.Get("X-Request-ID")
		}
		if !safeCorrelationID.MatchString(id) {
			id = uuid.NewString()
		}
		// Echo it before next runs so writeError can read it back off the response
		// header without every handler having to thread the context.
		w.Header().Set(CorrelationHeader, id)
		ctx := context.WithValue(r.Context(), CorrelationIDContextKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// correlationID returns the request's correlation ID, or "" if none was set.
func correlationID(ctx context.Context) string {
	if v, ok := ctx.Value(CorrelationIDContextKey).(string); ok {
		return v
	}
	return ""
}
