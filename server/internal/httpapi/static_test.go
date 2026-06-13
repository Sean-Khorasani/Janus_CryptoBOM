package httpapi

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestSPAHandler(t *testing.T) {
	const (
		indexBody = "<html>Janus UI</html>"
		assetBody = "console.log('janus');"
	)

	uiDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(uiDir, "index.html"), []byte(indexBody), 0o600); err != nil {
		t.Fatalf("write index: %v", err)
	}
	assetsDir := filepath.Join(uiDir, "assets")
	if err := os.Mkdir(assetsDir, 0o700); err != nil {
		t.Fatalf("create assets directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(assetsDir, "app.js"), []byte(assetBody), 0o600); err != nil {
		t.Fatalf("write asset: %v", err)
	}

	tests := []struct {
		name       string
		root       string
		method     string
		path       string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "missing UI directory returns 404",
			root:       filepath.Join(t.TempDir(), "missing"),
			method:     http.MethodGet,
			path:       "/",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "root serves index",
			root:       uiDir,
			method:     http.MethodGet,
			path:       "/",
			wantStatus: http.StatusOK,
			wantBody:   indexBody,
		},
		{
			name:       "existing asset is served",
			root:       uiDir,
			method:     http.MethodGet,
			path:       "/assets/app.js",
			wantStatus: http.StatusOK,
			wantBody:   assetBody,
		},
		{
			name:       "unknown SPA route falls back to index",
			root:       uiDir,
			method:     http.MethodGet,
			path:       "/findings/critical",
			wantStatus: http.StatusOK,
			wantBody:   indexBody,
		},
		{
			name:       "non-GET returns 404",
			root:       uiDir,
			method:     http.MethodPost,
			path:       "/",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()

			spaHandler(tt.root).ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantBody != "" && rec.Body.String() != tt.wantBody {
				t.Fatalf("body = %q, want %q", rec.Body.String(), tt.wantBody)
			}
		})
	}
}
