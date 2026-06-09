import { useState, useEffect, useMemo } from "react";
import { X, ChevronDown, ChevronUp } from "lucide-react";
import { Finding, ComponentRecord } from "../hooks/useApi";
import { FocusTrap } from "../a11y/FocusTrap";

export function SeverityBadge({ severity }: { severity: number }) {
  const label = severity >= 5 ? "Critical" : severity === 4 ? "High" : severity === 3 ? "Medium" : severity === 2 ? "Low" : "Info";
  const color = severity >= 5 ? "bg-[#d33f49] text-white" : severity === 4 ? "bg-[#e07a2f] text-white" : severity === 3 ? "bg-[#ffd166] text-[#3a2a00]" : "bg-[#edf1ea] text-[#4d594f] dark:bg-[#22302a] dark:text-[#6b7e6f]";
  return <span className={`rounded px-2 py-1 text-xs font-medium ${color}`}>{label}</span>;
}

export function UsageContextBadge({ description }: { description: string }) {
  const desc = (description || "").toLowerCase();
  let label = "";
  let color = "";
  if (desc.includes("usage context: verify") || desc.includes("usage context: parse")) {
    label = "Verify-Only";
    color = "bg-sky-100 text-sky-800 dark:bg-[#152238] dark:text-[#60a5fa]";
  } else if (desc.includes("usage context: negotiate")) {
    label = "Negotiation";
    color = "bg-violet-100 text-violet-800 dark:bg-[#1e1338] dark:text-[#a78bfa]";
  }
  if (!label) return null;
  return <span className={`rounded px-1.5 py-0.5 text-[10px] font-semibold ${color}`}>{label}</span>;
}

export function Empty({ label }: { label: string }) {
  return <div className="py-8 text-center text-sm text-[#697469] dark:text-[#8fa991]">{label}</div>;
}

export function formatDate(value: string) {
  if (!value) return "n/a";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString();
}

function getResolutionDetails(ruleId: string, algorithm: string, description: string) {
  switch (ruleId) {
    case "JANUS-PQC-001":
      return {
        recommendation: "Migrate signature scheme to post-quantum signature standards.",
        steps: [
          "Re-evaluate signing key requirements in your certificates, trust stores, and application signatures.",
          "Issue new host or application certificates signed using ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).",
          "Ensure client trust stores are pre-loaded with corresponding PQC root and intermediate CAs."
        ],
        code: `# Go CSR Generation Profile (ML-DSA)
{
  "common_name": "secure-service.local",
  "target_signature": "ML-DSA-65",
  "hybrid_compatibility": true
}`
      };
    case "JANUS-PQC-002":
      return {
        recommendation: "Increase key length to the Transitional Safety Threshold (minimum 3072 bits) or migrate to PQC.",
        steps: [
          "Identify where the key pair is generated (e.g., configurations, environment scripts).",
          "Replace the parameters in key generation commands to specify at least 3072 key bits.",
          "For RSA keys, replace with: openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072",
          "Ideally, initiate transition to ML-DSA signatures to avoid legacy thresholds altogether."
        ],
        code: `# Correct OpenSSL keygen parameters for RSA-3072
$ openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out private.pem

# Or migrate directly to ML-DSA key generation
$ openssl genpkey -algorithm ML-DSA-65 -out pq_private.pem`
      };
    case "JANUS-PQC-007":
    case "JANUS-PQC-005":
      return {
        recommendation: "Transition key exchange mechanisms to post-quantum hybrid KEM standards (ML-KEM).",
        steps: [
          "Ensure your web server or proxy supports TLS 1.3.",
          "Configure the service to prefer hybrid key-exchange groups (e.g., X25519MLKEM768 or SecP256r1MLKEM768).",
          "Verify configuration using the Janus Agent active probe."
        ],
        code: `# Nginx TLS v1.3 configuration with hybrid groups
ssl_protocols TLSv1.3;
# Instruct openssl to use hybrid groups
ssl_conf_command Groups X25519MLKEM768:X25519:P-256;`
      };
    case "JANUS-CLASSICAL-003":
      return {
        recommendation: "Replace deprecated hash functions (MD5/SHA-1) with secure hashing standards.",
        steps: [
          "Scan source files to locate references to cryptographic APIs invoking MD5 or SHA-1.",
          "Upgrade APIs to invoke SHA-256, SHA-384, or SHA-3 according to package standards.",
          "Where compatibility requires it, wrap legacy objects in HMAC-SHA-256 signatures."
        ],
        code: `// Vulnerable Code:
// hasher := md5.New()

// Remediated Code:
import "crypto/sha256"
hasher := sha256.New()`
      };
    case "JANUS-PQC-004":
      return {
        recommendation: "Upgrade symmetric key lengths to AES-256 for long-term confidentiality.",
        steps: [
          "Update application environment variables, configuration parameters, or database schemas to request 256-bit keys.",
          "Ensure cipher block modes are authenticated (e.g., GCM, ChaCha20-Poly1305) to protect against bit-flipping attacks."
        ],
        code: `// Secure symmetric configuration using AES-256-GCM
block, err := aes.NewCipher(key256)
aesgcm, err := cipher.NewGCM(block)`
      };
    case "JANUS-NET-001":
      return {
        recommendation: "Disable cleartext communication and enforce secure TLS configurations.",
        steps: [
          "Expose services only on secure ports (e.g. 443, 8443, 9443).",
          "Add redirect headers (HTTP 301/308) in cleartext configurations pointing to HTTPS endpoints.",
          "Inject HTTP Strict Transport Security (HSTS) headers."
        ],
        code: `# Nginx Cleartext Redirect & TLS Configuration
server {
    listen 80;
    server_name example.com;
    return 301 https://$host$request_uri;
}`
      };
    case "JANUS-NET-002":
      return {
        recommendation: "Upgrade server configurations to enforce TLS 1.3 exclusively.",
        steps: [
          "Deprecate TLS 1.0, 1.1, and 1.2 versions in server configuration settings.",
          "Ensure standard cryptography libraries on the server (e.g., OpenSSL, SChannel) support TLS 1.3."
        ],
        code: `# Enforce TLS 1.3 on Apache HTTP Server
SSLProtocol -all +TLSv1.3
SSLCipherSuite HIGH:!aNULL:!MD5`
      };
    default:
      return {
        recommendation: "Review and modernize cryptographic algorithm parameters.",
        steps: [
          "Inspect the calling module or protocol config.",
          "Compare configuration with current PQC Baseline (NIST FIPS 203, 204, 205).",
          "Configure standard cryptographically agile libraries."
        ],
        code: `# Generic Remediation Instruction
1. Identify implementation location: "${description}"
2. Review company cryptographic agility baseline.
3. Migrate configurations to transitional hybrid protocols.`
      };
  }
}

interface FindingTableProps {
  findings: Finding[];
  components: ComponentRecord[];
  statuses: Record<string, string>;
  updateStatus: (id: string, status: string) => void;
}

export function FindingTable({ findings, components, statuses, updateStatus }: FindingTableProps) {
  const [selected, setSelected] = useState<Finding | null>(null);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [sortCol, setSortCol] = useState<"severity" | "algorithm" | null>(null);
  const [sortDir, setSortDir] = useState<"asc" | "desc" | null>(null);

  useEffect(() => {
    setPage(1);
  }, [search]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setSelected(null);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  const currentSelected = useMemo(() => {
    if (!selected) return null;
    return findings.find(f => f.finding_id === selected.finding_id) || selected;
  }, [selected, findings]);

  const currentSelectedFilePath = useMemo(() => {
    if (!currentSelected) return null;
    const comp = components.find(c => c.bom_ref === currentSelected.asset_ref);
    return comp ? comp.file_path : null;
  }, [currentSelected, components]);

  const handleSort = (col: "severity" | "algorithm") => {
    if (sortCol !== col) {
      setSortCol(col);
      setSortDir("asc");
    } else {
      if (sortDir === "asc") {
        setSortDir("desc");
      } else if (sortDir === "desc") {
        setSortCol(null);
        setSortDir(null);
      } else {
        setSortDir("asc");
      }
    }
  };

  const sortedFindings = useMemo(() => {
    if (!sortCol || !sortDir) return findings;
    const sorted = [...findings];
    sorted.sort((a, b) => {
      if (sortCol === "severity") {
        return sortDir === "asc" ? a.severity - b.severity : b.severity - a.severity;
      } else {
        const strA = String(a.algorithm || "").toLowerCase();
        const strB = String(b.algorithm || "").toLowerCase();
        if (strA < strB) return sortDir === "asc" ? -1 : 1;
        if (strA > strB) return sortDir === "asc" ? 1 : -1;
        return 0;
      }
    });
    return sorted;
  }, [findings, sortCol, sortDir]);

  const filteredFindings = useMemo(() => {
    return sortedFindings.filter((f) => {
      if (!search) return true;
      const s = search.toLowerCase();
      return (
        (f.title && f.title.toLowerCase().includes(s)) ||
        (f.description && f.description.toLowerCase().includes(s)) ||
        (f.algorithm && f.algorithm.toLowerCase().includes(s)) ||
        (f.asset_ref && f.asset_ref.toLowerCase().includes(s)) ||
        (f.policy_rule_id && f.policy_rule_id.toLowerCase().includes(s))
      );
    });
  }, [sortedFindings, search]);

  const itemsPerPage = 25;
  const totalPages = Math.max(1, Math.ceil(filteredFindings.length / itemsPerPage));
  const startIndex = (page - 1) * itemsPerPage;
  const paginatedFindings = filteredFindings.slice(startIndex, startIndex + itemsPerPage);

  const downloadCSV = () => {
    const headers = ["id", "title", "severity", "algorithm", "asset"];
    const rows = filteredFindings.map((f) => [
      f.finding_id,
      f.title,
      f.severity,
      f.algorithm || "unknown",
      f.asset_ref
    ]);
    const csvContent = [
      headers.join(","),
      ...rows.map(r => r.map(val => `"${String(val).replace(/"/g, '""')}"`).join(","))
    ].join("\n");

    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", "findings.csv");
    link.style.visibility = "hidden";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const downloadJSON = () => {
    const cbom = {
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      components: components || []
    };
    const jsonContent = JSON.stringify(cbom, null, 2);
    const blob = new Blob([jsonContent], { type: "application/json;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", "cbom.json");
    link.style.visibility = "hidden";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const resolution = currentSelected ? getResolutionDetails(currentSelected.policy_rule_id, currentSelected.algorithm, currentSelected.description) : null;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-4 pb-2">
        <div className="relative">
          <input
            type="text"
            className="search-bar w-80 rounded-md border border-[#dfe5dc] px-3 py-1.5 text-sm placeholder-[#697469] focus:border-[#2f6fed] focus:outline-none dark:border-[#2a3a30] dark:bg-[#0d1210] dark:text-[#e8ede9] dark:placeholder-[#6b7e6f]"
            placeholder="Search findings..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            data-testid="search-input"
            aria-label="Search findings"
          />
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={downloadCSV}
            data-action="download-csv"
            disabled={filteredFindings.length === 0}
            className="h-9 px-3 rounded border border-[#dfe5dc] bg-white text-xs font-medium text-[#4d594f] hover:bg-[#edf1ea] disabled:opacity-50 disabled:cursor-not-allowed dark:border-[#2a3a30] dark:bg-[#1a2620] dark:text-[#6b7e6f] dark:hover:bg-[#22302a]"
            type="button"
            aria-label="Download findings as CSV"
          >
            Download Findings CSV
          </button>
          <button
            onClick={downloadJSON}
            data-action="download-json"
            disabled={!components || components.length === 0}
            className="h-9 px-3 rounded border border-[#dfe5dc] bg-white text-xs font-medium text-[#4d594f] hover:bg-[#edf1ea] disabled:opacity-50 disabled:cursor-not-allowed dark:border-[#2a3a30] dark:bg-[#1a2620] dark:text-[#6b7e6f] dark:hover:bg-[#22302a]"
            type="button"
            aria-label="Download CBOM as JSON"
          >
            Download CBOM JSON
          </button>
          <a
            href="/report.html"
            className="flex h-9 items-center justify-center px-3 rounded border border-[#dfe5dc] bg-white text-xs font-medium text-[#4d594f] hover:bg-[#edf1ea] dark:border-[#2a3a30] dark:bg-[#1a2620] dark:text-[#6b7e6f] dark:hover:bg-[#22302a]"
            aria-label="Open HTML report"
          >
            Open HTML Report
          </a>
        </div>
      </div>

      <div className="overflow-auto">
        <table className="w-full min-w-[820px] text-left text-sm" role="table">
          <thead className="border-b border-[#dfe5dc] text-xs uppercase text-[#697469] dark:border-[#2a3a30] dark:text-[#8fa991]">
            <tr>
              <th
                onClick={() => handleSort("severity")}
                className={`py-2 pr-3 cursor-pointer select-none hover:text-[#17211c] dark:hover:text-[#e8ede9] ${
                  sortCol === "severity"
                    ? (sortDir === "asc" ? "sorted asc ascending" : "sorted desc descending")
                    : ""
                }`}
                data-sort-col="severity"
                scope="col"
                aria-sort={sortCol === "severity" ? (sortDir === "asc" ? "ascending" : "descending") : "none"}
              >
                Severity {sortCol === "severity" ? (sortDir === "asc" ? <ChevronUp size={12} className="inline" /> : <ChevronDown size={12} className="inline" />) : null}
              </th>
              <th className="py-2 pr-3" scope="col">Finding</th>
              <th className="py-2 pr-3" scope="col">Asset</th>
              <th
                onClick={() => handleSort("algorithm")}
                className={`py-2 pr-3 cursor-pointer select-none hover:text-[#17211c] dark:hover:text-[#e8ede9] ${
                  sortCol === "algorithm"
                    ? (sortDir === "asc" ? "sorted asc ascending" : "sorted desc descending")
                    : ""
                }`}
                data-sort-col="algorithm"
                scope="col"
                aria-sort={sortCol === "algorithm" ? (sortDir === "asc" ? "ascending" : "descending") : "none"}
              >
                Algorithm {sortCol === "algorithm" ? (sortDir === "asc" ? <ChevronUp size={12} className="inline" /> : <ChevronDown size={12} className="inline" />) : null}
              </th>
              <th className="py-2 pr-3" scope="col">Rule</th>
            </tr>
          </thead>
          <tbody>
            {paginatedFindings.map((finding) => {
              const status = statuses[finding.finding_id];
              let rowClass = "border-b border-[#edf1ea] hover:bg-[#edf1ea]/40 cursor-pointer transition-colors dark:border-[#2a3a30] dark:hover:bg-[#22302a]/40";
              if (status === "accepted") {
                rowClass += " opacity-50 muted accepted";
              } else if (status === "remediated") {
                rowClass += " opacity-50 muted remediated";
              } else if (status === "false-positive") {
                rowClass += " opacity-50 muted false-positive";
              }

              const comp = components.find(c => c.bom_ref === finding.asset_ref);
              const filePath = comp ? comp.file_path : null;

              return (
                <tr
                  key={finding.finding_id}
                  className={rowClass}
                  onClick={() => setSelected(finding)}
                  tabIndex={0}
                  onKeyDown={(e) => { if (e.key === "Enter") setSelected(finding); }}
                  role="button"
                  aria-label={`Finding: ${finding.title}, severity: ${finding.severity}`}
                >
                  <td className="py-2 pr-3"><SeverityBadge severity={finding.severity} /></td>
                  <td className="py-2 pr-3">
                    <div className="flex items-center gap-2">
                      <span className="font-medium dark:text-[#e8ede9]">{finding.title}</span>
                      <UsageContextBadge description={finding.description} />
                      {status === "accepted" && <span className="badge bg-[#edf1ea] text-[#4d594f] text-xs px-2 py-0.5 rounded font-medium dark:bg-[#22302a] dark:text-[#6b7e6f]">Accepted</span>}
                      {status === "false-positive" && <span className="badge bg-[#edf1ea] text-[#4d594f] text-xs px-2 py-0.5 rounded font-medium dark:bg-[#22302a] dark:text-[#6b7e6f]">False Positive</span>}
                      {status === "remediated" && <span className="badge bg-[#edf1ea] text-[#4d594f] text-xs px-2 py-0.5 rounded font-medium dark:bg-[#22302a] dark:text-[#6b7e6f]">Remediated</span>}
                    </div>
                    <div className="max-w-[420px] truncate text-xs text-[#697469] dark:text-[#8fa991]">{finding.description}</div>
                    {filePath && (
                      <div className="text-[11px] font-mono text-[#11845b] mt-0.5 truncate max-w-[420px] dark:text-[#3da06a]" title={filePath}>
                        {filePath}
                      </div>
                    )}
                  </td>
                  <td className="py-2 pr-3 max-w-[240px] truncate dark:text-[#8fa991]">{finding.asset_ref}</td>
                  <td className="py-2 pr-3 dark:text-[#e8ede9]">{finding.algorithm || "unknown"}</td>
                  <td className="py-2 pr-3 font-mono text-xs dark:text-[#8fa991]">{finding.policy_rule_id}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {filteredFindings.length === 0 && <Empty label="No findings found" />}

      {filteredFindings.length > 0 && (
        <div className="flex items-center justify-between border-t border-[#dfe5dc] pt-4 mt-4 dark:border-[#2a3a30]">
          <span className="text-xs text-[#697469] dark:text-[#8fa991]">
            Showing {startIndex + 1} to {Math.min(startIndex + itemsPerPage, filteredFindings.length)} of {filteredFindings.length} findings
          </span>
          <div className="flex gap-2">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1}
              data-action="prev-page"
              className="h-8 px-3 rounded border border-[#dfe5dc] bg-white text-xs font-medium text-[#4d594f] hover:bg-[#edf1ea] disabled:opacity-50 disabled:cursor-not-allowed dark:border-[#2a3a30] dark:bg-[#1a2620] dark:text-[#6b7e6f] dark:hover:bg-[#22302a]"
              type="button"
              aria-label="Previous page"
            >
              Previous
            </button>
            <button
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              data-action="next-page"
              className="h-8 px-3 rounded border border-[#dfe5dc] bg-white text-xs font-medium text-[#4d594f] hover:bg-[#edf1ea] disabled:opacity-50 disabled:cursor-not-allowed dark:border-[#2a3a30] dark:bg-[#1a2620] dark:text-[#6b7e6f] dark:hover:bg-[#22302a]"
              type="button"
              aria-label="Next page"
            >
              Next
            </button>
          </div>
        </div>
      )}

      {currentSelected && resolution && (
        <FocusTrap active={!!currentSelected} onEscape={() => setSelected(null)}>
          <div className="finding-drawer fixed inset-y-0 inset-0 z-50 flex justify-end bg-black/40 backdrop-blur-sm transition-opacity dark:bg-black/55" data-testid="finding-drawer" onClick={() => setSelected(null)} role="dialog" aria-modal="true" aria-labelledby="finding-drawer-title">
            <div className="h-full w-full max-w-xl bg-white p-6 shadow-2xl overflow-y-auto animate-slide-in flex flex-col text-[#17211c] dark:bg-[#1a2620] dark:text-[#e8ede9]" onClick={(e) => e.stopPropagation()}>
              <div className="flex items-start justify-between border-b border-[#dfe5dc] pb-4 mb-4 dark:border-[#2a3a30]">
                <div>
                  <h3 id="finding-drawer-title" className="text-lg font-bold tracking-tight">{currentSelected.title}</h3>
                  <div className="flex gap-2 items-center mt-2">
                    <SeverityBadge severity={currentSelected.severity} />
                    <span className="font-mono text-xs text-[#697469] dark:text-[#8fa991]">{currentSelected.policy_rule_id}</span>
                  </div>
                </div>
                <button
                  onClick={() => setSelected(null)}
                  className="p-1 rounded-md text-[#4d594f] hover:bg-[#edf1ea] dark:text-[#6b7e6f] dark:hover:bg-[#22302a]"
                  type="button"
                  aria-label="Close finding drawer"
                >
                  <X size={20} aria-hidden="true" />
                </button>
              </div>

              <div className="space-y-4 flex-1">
                <div>
                  <span className="block text-xs font-semibold text-[#697469] uppercase tracking-wider mb-1 dark:text-[#8fa991]">Impacted Asset</span>
                  <span className="font-mono text-sm block bg-[#f7f8f5] p-2 rounded border border-[#dfe5dc] max-w-full overflow-x-auto dark:bg-[#0d1210] dark:border-[#2a3a30] dark:text-[#e8ede9]">{currentSelected.asset_ref}</span>
                </div>

                {currentSelectedFilePath && (
                  <div>
                    <span className="block text-xs font-semibold text-[#697469] uppercase tracking-wider mb-1 dark:text-[#8fa991]">Source File Path</span>
                    <span className="font-mono text-sm block bg-[#f7f8f5] p-2 rounded border border-[#dfe5dc] max-w-full overflow-x-auto text-[#11845b] dark:bg-[#0d1210] dark:border-[#2a3a30] dark:text-[#3da06a]">{currentSelectedFilePath}</span>
                  </div>
                )}

                <div>
                  <span className="block text-xs font-semibold text-[#697469] uppercase tracking-wider mb-1 dark:text-[#8fa991]">Algorithm Observed</span>
                  <span className="font-medium text-sm dark:text-[#e8ede9]">{currentSelected.algorithm || "unknown"}</span>
                </div>

                <div>
                  <span className="block text-xs font-semibold text-[#697469] uppercase tracking-wider mb-1 dark:text-[#8fa991]">Scanner Confidence Rating</span>
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-sm dark:text-[#e8ede9]" data-testid="confidence-rating">
                      {currentSelected.confidence ? (currentSelected.confidence * 100).toFixed(0) : "82"}%
                    </span>
                    {currentSelected.confidence && currentSelected.confidence >= 0.85 ? (
                      <span className="inline-block rounded bg-green-100 text-green-800 text-[10px] px-1.5 py-0.5 font-semibold dark:bg-[#0f2a1a] dark:text-[#4ade80]">
                        AST-Aware (High Confidence)
                      </span>
                    ) : currentSelected.confidence && currentSelected.confidence >= 0.5 ? (
                      <span className="inline-block rounded bg-sky-100 text-sky-800 text-[10px] px-1.5 py-0.5 font-semibold dark:bg-[#152238] dark:text-[#60a5fa]">
                        Context-Adjusted (Medium Confidence)
                      </span>
                    ) : (
                      <span className="inline-block rounded bg-amber-100 text-amber-800 text-[10px] px-1.5 py-0.5 font-semibold dark:bg-[#2d2010] dark:text-[#fbbf24]">
                        Regex/Pattern (Low Confidence)
                      </span>
                    )}
                  </div>
                  <UsageContextBadge description={currentSelected.description} />
                </div>

                <div>
                  <span className="block text-xs font-semibold text-[#697469] uppercase tracking-wider mb-1 dark:text-[#8fa991]">Telemetry Context</span>
                  <p className="text-sm text-[#4d594f] mt-1 dark:text-[#6b7e6f]">{currentSelected.description}</p>
                </div>

                <div className="border-t border-[#dfe5dc] pt-4 dark:border-[#2a3a30]">
                  <span className="block text-xs font-semibold text-[#697469] uppercase tracking-wider mb-2 dark:text-[#8fa991]">Remediation Blueprint</span>
                  <div className="bg-[#eef2ec] border border-[#cbd5c7] rounded-md p-3 text-sm font-medium mb-3 text-[#17211c] dark:bg-[#22302a] dark:border-[#2a3a30] dark:text-[#e8ede9]">
                    {resolution.recommendation}
                  </div>
                  <span className="block text-xs font-semibold text-[#697469] uppercase tracking-wider mb-2 dark:text-[#8fa991]">Resolution Steps</span>
                  <ul className="list-disc pl-5 text-sm text-[#4d594f] space-y-2 dark:text-[#6b7e6f]">
                    {resolution.steps.map((step, idx) => (
                      <li key={idx}>{step}</li>
                    ))}
                  </ul>
                </div>

                <div>
                  <span className="block text-xs font-semibold text-[#697469] uppercase tracking-wider mb-2 dark:text-[#8fa991]">Remediation Example</span>
                  <pre className="bg-[#17211c] text-white p-3 rounded-md font-mono text-xs overflow-x-auto leading-relaxed dark:bg-[#0d1210]">
                    <code>{resolution.code}</code>
                  </pre>
                </div>
              </div>

              <div className="border-t border-[#dfe5dc] pt-4 mt-6 flex flex-wrap gap-2 justify-between items-center dark:border-[#2a3a30]">
                <div className="flex gap-2">
                  <button
                    onClick={() => {
                      updateStatus(currentSelected.finding_id, "accepted");
                      setSelected(null);
                    }}
                    data-action="accept-risk"
                    className="h-9 px-3 rounded bg-amber-500 text-white text-xs font-medium hover:bg-amber-600"
                    type="button"
                    aria-label="Accept risk for this finding"
                  >
                    Accept Risk
                  </button>
                  <button
                    onClick={() => {
                      updateStatus(currentSelected.finding_id, "false-positive");
                      setSelected(null);
                    }}
                    data-action="false-positive"
                    className="h-9 px-3 rounded bg-blue-500 text-white text-xs font-medium hover:bg-blue-600"
                    type="button"
                    aria-label="Mark finding as false positive"
                  >
                    Mark False Positive
                  </button>
                  <button
                    onClick={() => {
                      updateStatus(currentSelected.finding_id, "remediated");
                      setSelected(null);
                    }}
                    data-action="remediated"
                    className="h-9 px-3 rounded bg-[#11845b] text-white text-xs font-medium hover:bg-[#159a6b] dark:bg-[#0e6b4a] dark:hover:bg-[#0d8055]"
                    type="button"
                    aria-label="Mark finding as remediated"
                  >
                    Mark Remediated
                  </button>
                </div>
                <button
                  onClick={() => setSelected(null)}
                  className="h-9 px-4 rounded bg-[#17211c] text-white text-sm font-medium hover:bg-[#25322b] dark:bg-[#2a3a32] dark:hover:bg-[#3a4a42]"
                  type="button"
                  aria-label="Close blueprint"
                >
                  Close Blueprint
                </button>
              </div>
            </div>
          </div>
        </FocusTrap>
      )}
    </div>
  );
}
