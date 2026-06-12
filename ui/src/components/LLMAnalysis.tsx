import { useState, useEffect, useCallback, Fragment } from "react";
import { Brain, AlertCircle, CheckCircle, ChevronDown, ChevronUp, RefreshCw } from "lucide-react";
import { formatDate } from "./FindingsGrid";

interface LLMStatus {
  capability_mode: string;
  enabled: boolean;
  suggest_remediation: boolean;
  model_analysis: string;
  model_remediation: string;
  base_url_configured: boolean;
  api_key_configured: boolean;
}

interface LLMAnalysisJob {
  job_id: string;
  finding_id: string;
  job_type: string;
  status: string;
  error?: string;
  created_by: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
}

interface LLMVerdict {
  verdict_id: string;
  job_id: string;
  finding_id: string;
  verdict: string;
  adjusted_severity?: number;
  confidence: number;
  reasoning: string;
  evidence_citations: string[];
  abstention_reason?: string;
  model: string;
  prompt_version: string;
  created_at: string;
}

interface JobWithVerdict {
  job: LLMAnalysisJob;
  verdict?: LLMVerdict;
}

interface SubmitResult {
  job_id: string;
  status: string;
  verdict?: LLMVerdict;
  message?: string;
  error?: string;
}

function authHeaders(extra: Record<string, string> = {}): Record<string, string> {
  const token = localStorage.getItem("janus_token");
  const headers: Record<string, string> = { ...extra };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

function CapabilityModeBadge({ mode }: { mode: string }) {
  const map: Record<string, { label: string; cls: string }> = {
    disabled: {
      label: "Disabled",
      cls: "bg-[#edf1ea] text-[#4d594f] dark:bg-[#22302a] dark:text-[#6b7e6f]",
    },
    analysis_only: {
      label: "Analysis Only",
      cls: "bg-[#edf7ef] text-[#3a7d44] dark:bg-[#16281e] dark:text-[#4ade80]",
    },
    suggest_remediation: {
      label: "Suggest Remediation",
      cls: "bg-[#edf7ef] text-[#3a7d44] dark:bg-[#16281e] dark:text-[#4ade80]",
    },
  };
  const style = map[mode] ?? map["disabled"];
  return (
    <span className={`rounded px-2 py-1 text-xs font-medium ${style.cls}`}>
      {style.label}
    </span>
  );
}

function JobStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    queued:    "bg-[#edf1ea] text-[#4d594f] dark:bg-[#22302a] dark:text-[#6b7e6f]",
    running:   "bg-[#fefce8] text-[#713f12] dark:bg-[#2d2010] dark:text-[#fbbf24]",
    completed: "bg-[#edf7ef] text-[#3a7d44] dark:bg-[#0f2a1a] dark:text-[#4ade80]",
    failed:    "bg-[#fff4ee] text-[#8b2d16] dark:bg-[#2d1518] dark:text-[#f87171]",
    cancelled: "bg-[#edf1ea] text-[#4d594f] dark:bg-[#22302a] dark:text-[#6b7e6f]",
  };
  const cls = map[status] ?? "bg-[#edf1ea] text-[#4d594f] dark:bg-[#22302a] dark:text-[#6b7e6f]";
  const label = status.charAt(0).toUpperCase() + status.slice(1);
  return <span className={`rounded px-2 py-1 text-xs font-medium ${cls}`}>{label}</span>;
}

function VerdictBadge({ verdict }: { verdict: string }) {
  const map: Record<string, { label: string; cls: string }> = {
    false_positive:    { label: "False Positive",    cls: "bg-sky-100 text-sky-800 dark:bg-[#152238] dark:text-[#60a5fa]" },
    confirmed:         { label: "Confirmed",         cls: "bg-[#fff4ee] text-[#8b2d16] dark:bg-[#2d1518] dark:text-[#f87171]" },
    severity_adjusted: { label: "Severity Adjusted", cls: "bg-[#fefce8] text-[#713f12] dark:bg-[#2d2010] dark:text-[#fbbf24]" },
    needs_review:      { label: "Needs Review",      cls: "bg-violet-100 text-violet-800 dark:bg-[#1e1338] dark:text-[#a78bfa]" },
    abstain:           { label: "Abstain",           cls: "bg-amber-100 text-amber-800 dark:bg-[#2d2010] dark:text-[#fbbf24]" },
  };
  const style = map[verdict] ?? { label: verdict, cls: "bg-[#edf1ea] text-[#4d594f]" };
  return <span className={`rounded px-2 py-1 text-xs font-semibold ${style.cls}`}>{style.label}</span>;
}

function SkeletonRow() {
  return (
    <tr className="border-b border-[#edf1ea] dark:border-[#2a3a30]">
      {[1, 2, 3, 4, 5].map((i) => (
        <td key={i} className="py-2.5 pr-3">
          <div className="h-3 rounded bg-[#edf1ea] animate-pulse dark:bg-[#22302a]" style={{ width: i === 1 ? "60%" : i === 3 ? "80%" : "50%" }} />
        </td>
      ))}
    </tr>
  );
}

function StatusCard({ status, loading }: { status: LLMStatus | null; loading: boolean }) {
  if (loading) {
    return (
      <div className="rounded-md border border-[#dfe5dc] bg-white p-4 dark:border-[#2a3a30] dark:bg-[#1a2620]">
        <div className="h-4 w-40 rounded bg-[#edf1ea] animate-pulse dark:bg-[#22302a] mb-3" />
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
          {[1, 2, 3, 4, 5].map((i) => (
            <div key={i} className="h-3 rounded bg-[#edf1ea] animate-pulse dark:bg-[#22302a]" />
          ))}
        </div>
      </div>
    );
  }

  if (!status) return null;

  return (
    <div className="rounded-md border border-[#dfe5dc] bg-white p-4 dark:border-[#2a3a30] dark:bg-[#1a2620]">
      <div className="flex flex-wrap items-center gap-3 mb-3">
        <div className="rounded bg-[#eef2ec] p-2 text-[#3a7d44] dark:bg-[#22302a] dark:text-[#4ade80]" aria-hidden="true">
          <Brain size={20} />
        </div>
        <div>
          <h2 className="text-sm font-semibold text-[#17211c] dark:text-[#e8ede9]">LLM Analysis Service</h2>
          <p className="text-xs text-[#697469] dark:text-[#8fa991]">
            {status.enabled ? "Operational" : "Service disabled — configure JANUS_LLM_BASE_URL to enable"}
          </p>
        </div>
        <div className="ml-auto">
          <CapabilityModeBadge mode={status.capability_mode} />
        </div>
      </div>
      <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-xs sm:grid-cols-3">
        <div>
          <dt className="text-[#697469] dark:text-[#8fa991]">Base URL</dt>
          <dd className="font-medium text-[#17211c] dark:text-[#e8ede9]">
            {status.base_url_configured ? (
              <span className="text-[#3a7d44] dark:text-[#4ade80]">Configured</span>
            ) : (
              <span className="text-[#8b2d16] dark:text-[#f87171]">Not set</span>
            )}
          </dd>
        </div>
        <div>
          <dt className="text-[#697469] dark:text-[#8fa991]">API Key</dt>
          <dd className="font-medium text-[#17211c] dark:text-[#e8ede9]">
            {status.api_key_configured ? (
              <span className="text-[#3a7d44] dark:text-[#4ade80]">Configured</span>
            ) : (
              <span className="text-[#8b2d16] dark:text-[#f87171]">Not set</span>
            )}
          </dd>
        </div>
        <div>
          <dt className="text-[#697469] dark:text-[#8fa991]">Remediation</dt>
          <dd className="font-medium text-[#17211c] dark:text-[#e8ede9]">
            {status.suggest_remediation ? (
              <span className="text-[#3a7d44] dark:text-[#4ade80]">Available</span>
            ) : (
              <span className="text-[#697469] dark:text-[#8fa991]">Unavailable</span>
            )}
          </dd>
        </div>
        {status.model_analysis && (
          <div>
            <dt className="text-[#697469] dark:text-[#8fa991]">Analysis Model</dt>
            <dd className="font-mono font-medium text-[#17211c] dark:text-[#e8ede9]">{status.model_analysis}</dd>
          </div>
        )}
        {status.model_remediation && (
          <div>
            <dt className="text-[#697469] dark:text-[#8fa991]">Remediation Model</dt>
            <dd className="font-mono font-medium text-[#17211c] dark:text-[#e8ede9]">{status.model_remediation}</dd>
          </div>
        )}
      </dl>
    </div>
  );
}

function VerdictPanel({ verdict }: { verdict: LLMVerdict }) {
  return (
    <div className="mt-2 rounded border border-[#dfe5dc] bg-[#f7f8f5] p-3 text-xs space-y-2 dark:border-[#2a3a30] dark:bg-[#0d1210]">
      <div className="flex flex-wrap items-center gap-2">
        <VerdictBadge verdict={verdict.verdict} />
        <span className="text-[#697469] dark:text-[#8fa991]">
          Confidence: <span className="font-semibold text-[#17211c] dark:text-[#e8ede9]">{(verdict.confidence * 100).toFixed(0)}%</span>
        </span>
        {verdict.adjusted_severity != null && (
          <span className="text-[#697469] dark:text-[#8fa991]">
            Adjusted Severity: <span className="font-semibold text-[#17211c] dark:text-[#e8ede9]">{verdict.adjusted_severity}</span>
          </span>
        )}
        <span className="ml-auto font-mono text-[10px] text-[#697469] dark:text-[#8fa991]">{verdict.model}</span>
      </div>
      {verdict.abstention_reason && (
        <div>
          <span className="block font-semibold uppercase tracking-wider text-[#697469] mb-1 dark:text-[#8fa991]">Abstention Reason</span>
          <p className="text-[#4d594f] dark:text-[#6b7e6f]">{verdict.abstention_reason}</p>
        </div>
      )}
      {verdict.reasoning && (
        <div>
          <span className="block font-semibold uppercase tracking-wider text-[#697469] mb-1 dark:text-[#8fa991]">Reasoning</span>
          <p className="text-[#4d594f] leading-relaxed dark:text-[#6b7e6f]">{verdict.reasoning}</p>
        </div>
      )}
      {verdict.evidence_citations.length > 0 && (
        <div>
          <span className="block font-semibold uppercase tracking-wider text-[#697469] mb-1 dark:text-[#8fa991]">Evidence Citations</span>
          <ul className="list-disc pl-4 space-y-0.5">
            {verdict.evidence_citations.map((cite, idx) => (
              <li key={idx} className="text-[#4d594f] dark:text-[#6b7e6f]">{cite}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export function LLMAnalysis() {
  const [status, setStatus] = useState<LLMStatus | null>(null);
  const [statusLoading, setStatusLoading] = useState(true);
  const [statusError, setStatusError] = useState<string | null>(null);

  const [jobs, setJobs] = useState<LLMAnalysisJob[]>([]);
  const [jobsLoading, setJobsLoading] = useState(true);
  const [jobsError, setJobsError] = useState<string | null>(null);
  const [jobsTotal, setJobsTotal] = useState(0);
  const [jobsOffset, setJobsOffset] = useState(0);
  const jobsLimit = 20;

  const [expandedJobId, setExpandedJobId] = useState<string | null>(null);
  const [expandedData, setExpandedData] = useState<Record<string, JobWithVerdict>>({});
  const [expandLoading, setExpandLoading] = useState<string | null>(null);

  const [submitFindingId, setSubmitFindingId] = useState("");
  const [submitJobType, setSubmitJobType] = useState("false_positive_triage");
  const [submitLoading, setSubmitLoading] = useState(false);
  const [submitResult, setSubmitResult] = useState<SubmitResult | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);

  useEffect(() => {
    setStatusLoading(true);
    setStatusError(null);
    fetch("/api/llm/status", { headers: authHeaders() })
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json() as Promise<LLMStatus>;
      })
      .then((data) => setStatus(data))
      .catch((err: unknown) => setStatusError(err instanceof Error ? err.message : "Failed to load LLM status"))
      .finally(() => setStatusLoading(false));
  }, []);

  const loadJobs = useCallback((offset: number) => {
    setJobsLoading(true);
    setJobsError(null);
    fetch(`/api/llm/jobs?limit=${jobsLimit}&offset=${offset}`, { headers: authHeaders() })
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const total = res.headers.get("X-Total-Count");
        if (total) setJobsTotal(parseInt(total, 10));
        return res.json() as Promise<LLMAnalysisJob[]>;
      })
      .then((data) => setJobs(Array.isArray(data) ? data : []))
      .catch((err: unknown) => setJobsError(err instanceof Error ? err.message : "Failed to load analysis jobs"))
      .finally(() => setJobsLoading(false));
  }, []);

  useEffect(() => {
    loadJobs(jobsOffset);
  }, [loadJobs, jobsOffset]);

  const handleRowClick = async (job: LLMAnalysisJob) => {
    if (expandedJobId === job.job_id) {
      setExpandedJobId(null);
      return;
    }
    setExpandedJobId(job.job_id);

    if (expandedData[job.job_id]) return;

    setExpandLoading(job.job_id);
    try {
      const res = await fetch(`/api/llm/jobs/${job.job_id}`, { headers: authHeaders() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = (await res.json()) as JobWithVerdict;
      setExpandedData((prev) => ({ ...prev, [job.job_id]: data }));
    } catch {
      // Row stays expanded showing the data we already have; no verdict on fetch error
      setExpandedData((prev) => ({ ...prev, [job.job_id]: { job } }));
    } finally {
      setExpandLoading(null);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitError(null);
    setSubmitResult(null);
    if (!submitFindingId.trim()) {
      setSubmitError("finding_id is required");
      return;
    }
    setSubmitLoading(true);
    try {
      const res = await fetch("/api/llm/analyze", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ finding_id: submitFindingId.trim(), job_type: submitJobType }),
      });
      const data = (await res.json()) as SubmitResult;
      if (!res.ok) {
        setSubmitError(data.error ?? `HTTP ${res.status}`);
        return;
      }
      setSubmitResult(data);
      setSubmitFindingId("");
      loadJobs(jobsOffset);
    } catch (err: unknown) {
      setSubmitError(err instanceof Error ? err.message : "Submission failed");
    } finally {
      setSubmitLoading(false);
    }
  };

  const totalPages = Math.max(1, Math.ceil(jobsTotal / jobsLimit));
  const currentPage = Math.floor(jobsOffset / jobsLimit) + 1;

  return (
    <div className="space-y-6">
      <StatusCard status={status} loading={statusLoading} />

      {statusError && (
        <div className="flex items-center gap-2 rounded-md border border-[#efb7a5] bg-[#fff4ee] px-3 py-2 text-sm text-[#8b2d16] dark:border-[#f87171] dark:bg-[#2d1518] dark:text-[#f87171]" role="alert">
          <AlertCircle size={16} aria-hidden="true" />
          <span>LLM status: {statusError}</span>
        </div>
      )}

      <div className="rounded-md border border-[#dfe5dc] bg-white dark:border-[#2a3a30] dark:bg-[#1a2620]">
        <div className="flex items-center justify-between border-b border-[#dfe5dc] px-4 py-3 dark:border-[#2a3a30]">
          <h2 className="text-sm font-semibold text-[#17211c] dark:text-[#e8ede9]">Analysis Jobs</h2>
          <button
            type="button"
            onClick={() => loadJobs(jobsOffset)}
            disabled={jobsLoading}
            className="flex items-center gap-1.5 rounded border border-[#dfe5dc] bg-[#f7f8f5] px-2.5 py-1.5 text-xs font-medium text-[#4d594f] hover:bg-[#edf1ea] disabled:opacity-50 dark:border-[#2a3a30] dark:bg-[#0d1210] dark:text-[#6b7e6f] dark:hover:bg-[#22302a]"
            aria-label="Refresh jobs list"
          >
            <RefreshCw size={13} className={jobsLoading ? "animate-spin" : ""} aria-hidden="true" />
            Refresh
          </button>
        </div>

        {jobsError && (
          <div className="flex items-center gap-2 m-4 rounded-md border border-[#efb7a5] bg-[#fff4ee] px-3 py-2 text-sm text-[#8b2d16] dark:border-[#f87171] dark:bg-[#2d1518] dark:text-[#f87171]" role="alert">
            <AlertCircle size={16} aria-hidden="true" />
            <span>{jobsError}</span>
          </div>
        )}

        <div className="overflow-x-auto">
          <table className="w-full min-w-[640px] text-left text-sm" role="table">
            <thead className="border-b border-[#dfe5dc] text-xs uppercase text-[#697469] dark:border-[#2a3a30] dark:text-[#8fa991]">
              <tr>
                <th className="px-4 py-2" scope="col">Job ID</th>
                <th className="py-2 pr-3" scope="col">Finding ID</th>
                <th className="py-2 pr-3" scope="col">Type</th>
                <th className="py-2 pr-3" scope="col">Status</th>
                <th className="py-2 pr-3" scope="col">Created</th>
                <th className="py-2 pr-3 w-6" scope="col" aria-label="Expand" />
              </tr>
            </thead>
            <tbody>
              {jobsLoading && !jobs.length
                ? Array.from({ length: 5 }).map((_, i) => <SkeletonRow key={i} />)
                : jobs.map((job) => {
                    const isExpanded = expandedJobId === job.job_id;
                    const detail = expandedData[job.job_id];
                    const isExpandLoading = expandLoading === job.job_id;
                    return (
                      <Fragment key={job.job_id}>
                        <tr
                          className="border-b border-[#edf1ea] hover:bg-[#edf1ea]/40 cursor-pointer transition-colors dark:border-[#2a3a30] dark:hover:bg-[#22302a]/40"
                          onClick={() => void handleRowClick(job)}
                          tabIndex={0}
                          onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") void handleRowClick(job); }}
                          role="button"
                          aria-expanded={isExpanded}
                          aria-label={`Job ${job.job_id.slice(0, 8)}, status ${job.status}`}
                        >
                          <td className="px-4 py-2 font-mono text-xs text-[#697469] dark:text-[#8fa991]">{job.job_id.slice(0, 12)}&hellip;</td>
                          <td className="py-2 pr-3 font-mono text-xs text-[#697469] dark:text-[#8fa991]">{job.finding_id.slice(0, 12)}&hellip;</td>
                          <td className="py-2 pr-3 text-xs text-[#4d594f] dark:text-[#6b7e6f]">{job.job_type.replace(/_/g, " ")}</td>
                          <td className="py-2 pr-3">
                            <JobStatusBadge status={job.status} />
                          </td>
                          <td className="py-2 pr-3 text-xs text-[#697469] dark:text-[#8fa991]">{formatDate(job.created_at)}</td>
                          <td className="py-2 pr-3 text-[#697469] dark:text-[#8fa991]">
                            {isExpanded ? <ChevronUp size={14} aria-hidden="true" /> : <ChevronDown size={14} aria-hidden="true" />}
                          </td>
                        </tr>
                        {isExpanded && (
                          <tr className="dark:border-[#2a3a30]">
                            <td colSpan={6} className="px-4 pb-3">
                              {isExpandLoading ? (
                                <div className="mt-2 h-3 w-48 rounded bg-[#edf1ea] animate-pulse dark:bg-[#22302a]" />
                              ) : detail?.verdict ? (
                                <VerdictPanel verdict={detail.verdict} />
                              ) : job.status === "completed" ? (
                                <p className="mt-2 text-xs text-[#697469] dark:text-[#8fa991]">Verdict not available.</p>
                              ) : job.status === "failed" ? (
                                <p className="mt-2 text-xs text-[#8b2d16] dark:text-[#f87171]">{job.error || "Job failed without details."}</p>
                              ) : (
                                <p className="mt-2 text-xs text-[#697469] dark:text-[#8fa991]">No verdict yet — job is {job.status}.</p>
                              )}
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    );
                  })}
            </tbody>
          </table>
        </div>

        {!jobsLoading && !jobsError && jobs.length === 0 && (
          <div className="py-8 text-center text-sm text-[#697469] dark:text-[#8fa991]">No analysis jobs found</div>
        )}

        {jobsTotal > jobsLimit && (
          <div className="flex items-center justify-between border-t border-[#dfe5dc] px-4 py-3 dark:border-[#2a3a30]">
            <span className="text-xs text-[#697469] dark:text-[#8fa991]">
              Page {currentPage} of {totalPages} ({jobsTotal} total)
            </span>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setJobsOffset(Math.max(0, jobsOffset - jobsLimit))}
                disabled={jobsOffset === 0}
                className="h-8 px-3 rounded border border-[#dfe5dc] bg-white text-xs font-medium text-[#4d594f] hover:bg-[#edf1ea] disabled:opacity-50 disabled:cursor-not-allowed dark:border-[#2a3a30] dark:bg-[#1a2620] dark:text-[#6b7e6f] dark:hover:bg-[#22302a]"
                aria-label="Previous page"
              >
                Previous
              </button>
              <button
                type="button"
                onClick={() => setJobsOffset(jobsOffset + jobsLimit)}
                disabled={jobsOffset + jobsLimit >= jobsTotal}
                className="h-8 px-3 rounded border border-[#dfe5dc] bg-white text-xs font-medium text-[#4d594f] hover:bg-[#edf1ea] disabled:opacity-50 disabled:cursor-not-allowed dark:border-[#2a3a30] dark:bg-[#1a2620] dark:text-[#6b7e6f] dark:hover:bg-[#22302a]"
                aria-label="Next page"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      <div className="rounded-md border border-[#dfe5dc] bg-white p-5 dark:border-[#2a3a30] dark:bg-[#1a2620]">
        <h2 className="text-sm font-semibold text-[#17211c] mb-4 dark:text-[#e8ede9]">Submit Analysis Job</h2>
        <form onSubmit={(e) => void handleSubmit(e)} className="space-y-4">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label htmlFor="llm-finding-id" className="block text-xs font-semibold text-[#697469] mb-1 dark:text-[#8fa991]">
                Finding ID
              </label>
              <input
                id="llm-finding-id"
                type="text"
                value={submitFindingId}
                onChange={(e) => setSubmitFindingId(e.target.value)}
                placeholder="e.g. 3fa85f64-5717-4562-b3fc-2c963f66afa6"
                className="w-full rounded border border-[#dfe5dc] px-3 py-2 text-xs font-mono placeholder-[#697469] focus:outline-none focus:ring-1 focus:ring-[#3a7d44] dark:border-[#2a3a30] dark:bg-[#0d1210] dark:text-[#e8ede9] dark:placeholder-[#6b7e6f]"
                required
              />
            </div>
            <div>
              <label htmlFor="llm-job-type" className="block text-xs font-semibold text-[#697469] mb-1 dark:text-[#8fa991]">
                Job Type
              </label>
              <select
                id="llm-job-type"
                value={submitJobType}
                onChange={(e) => setSubmitJobType(e.target.value)}
                className="w-full h-9 rounded border border-[#dfe5dc] bg-white px-3 text-xs focus:outline-none focus:ring-1 focus:ring-[#3a7d44] dark:border-[#2a3a30] dark:bg-[#0d1210] dark:text-[#e8ede9]"
              >
                <option value="false_positive_triage">False Positive Triage</option>
                <option value="intent_classification">Intent Classification</option>
                <option value="remediation_suggestion">Remediation Suggestion</option>
              </select>
            </div>
          </div>

          {submitError && (
            <div className="flex items-center gap-2 rounded-md border border-[#efb7a5] bg-[#fff4ee] px-3 py-2 text-sm text-[#8b2d16] dark:border-[#f87171] dark:bg-[#2d1518] dark:text-[#f87171]" role="alert">
              <AlertCircle size={15} aria-hidden="true" />
              <span>{submitError}</span>
            </div>
          )}

          {submitResult && (
            <div className="rounded-md border border-[#b7efd4] bg-[#eefaf4] px-3 py-2 dark:border-[#3da06a] dark:bg-[#16281e]">
              <div className="flex items-center gap-2 text-sm text-[#0e6b4a] dark:text-[#4ade80]">
                <CheckCircle size={15} aria-hidden="true" />
                <span className="font-medium">
                  Job queued
                </span>
                <span className="font-mono text-xs">{submitResult.job_id}</span>
              </div>
              {submitResult.verdict && (
                <div className="mt-2">
                  <VerdictPanel verdict={submitResult.verdict} />
                </div>
              )}
              {submitResult.message && !submitResult.verdict && (
                <p className="mt-1 text-xs text-[#4d594f] dark:text-[#6b7e6f]">{submitResult.message}</p>
              )}
            </div>
          )}

          <button
            type="submit"
            disabled={submitLoading || !submitFindingId.trim()}
            className="rounded bg-[#3a7d44] px-4 py-2 text-xs font-bold text-white hover:bg-[#2f6638] disabled:opacity-50 disabled:cursor-not-allowed transition-colors dark:bg-[#2f6638] dark:hover:bg-[#3a7d44]"
          >
            {submitLoading ? "Submitting…" : "Submit Analysis Job"}
          </button>
        </form>
      </div>
    </div>
  );
}
