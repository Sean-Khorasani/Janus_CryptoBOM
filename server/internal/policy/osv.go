package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// OSVClient provides live vulnerability lookups against the OSV.dev API.
// Results are cached to avoid redundant network calls within the same assessment cycle.
type OSVClient struct {
	mu      sync.RWMutex
	cache   map[string][]OSVVulnerability
	client  *http.Client
	enabled bool
	baseURL string
}

type OSVVulnerability struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Details  string        `json:"details"`
	Severity []OSVSeverity `json:"severity"`
	Affected []OSVAffected `json:"affected"`
}

type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type OSVAffected struct {
	Package OSVPackage `json:"package"`
	Ranges  []OSVRange `json:"ranges"`
}

type OSVPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	Purl      string `json:"purl"`
}

type OSVRange struct {
	Type   string     `json:"type"`
	Events []OSVEvent `json:"events"`
}

type OSVEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type osvQueryRequest struct {
	Package *osvQueryPackage `json:"package,omitempty"`
	Version string           `json:"version,omitempty"`
}

type osvQueryPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvQueryResponse struct {
	Vulns []OSVVulnerability `json:"vulns"`
}

// NewOSVClient creates a new OSV.dev API client.
// If enabled is false, all queries return empty results (for air-gapped environments).
func NewOSVClient(enabled bool) *OSVClient {
	return &OSVClient{
		cache:   make(map[string][]OSVVulnerability),
		client:  &http.Client{Timeout: 10 * time.Second},
		enabled: enabled,
		baseURL: "https://api.osv.dev/v1",
	}
}

// QueryPackage looks up known vulnerabilities for a specific package and version.
// Results are cached by package+version to avoid redundant API calls.
func (c *OSVClient) QueryPackage(ecosystem, name, version string) ([]OSVVulnerability, error) {
	if !c.enabled {
		return nil, nil
	}

	cacheKey := fmt.Sprintf("%s/%s@%s", ecosystem, name, version)

	c.mu.RLock()
	if cached, ok := c.cache[cacheKey]; ok {
		c.mu.RUnlock()
		return cached, nil
	}
	c.mu.RUnlock()

	// Map Janus ecosystem names to OSV ecosystem names
	osvEcosystem := mapEcosystem(ecosystem)
	if osvEcosystem == "" {
		return nil, nil
	}

	query := osvQueryRequest{
		Package: &osvQueryPackage{
			Name:      name,
			Ecosystem: osvEcosystem,
		},
		Version: version,
	}

	body, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("osv: marshal query: %w", err)
	}

	resp, err := c.client.Post(c.baseURL+"/query", "application/json", bytes.NewReader(body))
	if err != nil {
		// Network errors are non-fatal; fall back to local advisories
		return nil, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, nil
	}

	var result osvQueryResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, nil
	}

	// Cache the result
	c.mu.Lock()
	c.cache[cacheKey] = result.Vulns
	c.mu.Unlock()

	return result.Vulns, nil
}

// FilterCryptoRelevant returns only vulnerabilities that are related to cryptographic issues.
func FilterCryptoRelevant(vulns []OSVVulnerability) []OSVVulnerability {
	var relevant []OSVVulnerability
	cryptoKeywords := []string{
		"crypto", "tls", "ssl", "certificate", "cipher", "encrypt",
		"decrypt", "hash", "sign", "key", "rsa", "ecdsa", "aes",
		"pkcs", "x509", "handshake", "padding", "oracle", "timing",
		"rng", "random", "nonce", "iv", "salt",
	}

	for _, v := range vulns {
		text := strings.ToLower(v.Summary + " " + v.Details + " " + v.ID)
		for _, kw := range cryptoKeywords {
			if strings.Contains(text, kw) {
				relevant = append(relevant, v)
				break
			}
		}
	}
	return relevant
}

// mapEcosystem converts Janus ecosystem names to OSV.dev ecosystem identifiers.
func mapEcosystem(ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case "go", "golang":
		return "Go"
	case "npm", "node":
		return "npm"
	case "pypi", "python":
		return "PyPI"
	case "maven", "jvm", "java":
		return "Maven"
	case "nuget", ".net", "csharp":
		return "NuGet"
	case "crates.io", "rust":
		return "crates.io"
	case "rubygems", "ruby":
		return "RubyGems"
	case "packagist", "php":
		return "Packagist"
	default:
		return ""
	}
}

// OSVSeverityToJanus converts OSV CVSS severity to Janus severity scale.
func OSVSeverityToJanus(vulnSeverity []OSVSeverity) int32 {
	for _, s := range vulnSeverity {
		if s.Type == "CVSS_V3" {
			// Parse CVSS score — the Score field contains the base score as a string
			if s.Score != "" {
				if score, err := strconv.ParseFloat(s.Score, 64); err == nil {
					return cvssScoreToJanus(score)
				}
			}
			// Try CVSS_V4
		}
		if s.Type == "CVSS_V4" {
			if s.Score != "" {
				if score, err := strconv.ParseFloat(s.Score, 64); err == nil {
					return cvssScoreToJanus(score)
				}
			}
		}
	}
	return 3 // Medium default when no parseable severity found
}

// cvssScoreToJanus maps a CVSS base score (0.0-10.0) to Janus severity.
func cvssScoreToJanus(score float64) int32 {
	switch {
	case score >= 9.0:
		return 5 // Critical
	case score >= 7.0:
		return 4 // High
	case score >= 4.0:
		return 3 // Medium
	default:
		return 2 // Low
	}
}

// GetFixedVersion extracts the fixed version from an OSV vulnerability's affected ranges.
func GetFixedVersion(vuln OSVVulnerability) string {
	for _, aff := range vuln.Affected {
		for _, r := range aff.Ranges {
			for _, ev := range r.Events {
				if ev.Fixed != "" {
					return ev.Fixed
				}
			}
		}
	}
	return "unknown"
}

// ---------------------------------------------------------------------------
// NVD Client (NIST NVD API)
