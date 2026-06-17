import { useState, useEffect } from "react";
import { X, Clock, RefreshCw, ArrowRight, RotateCcw, CheckCircle2, XCircle, AlertCircle } from "lucide-react";
import { formatDate, Empty } from "./FindingsGrid";
import { errorMessage } from "../apiError";
import { FocusTrap } from "../a11y/FocusTrap";

interface FindingLifecycleEvent {
  event_id: string;
  finding_id: string;
  host_uuid: string;
  event_type: string;
  from_status: string;
  to_status: string;
  actor: string;
  reason: string;
  occurred_at: string;
}

function getAuthHeaders(): Record<string, string> {
  const token = localStorage.getItem("janus_token");
  const headers: Record<string, string> = {};
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

function StatusBadge({ status }: { status: string }) {
  if (!status) return null;
  const map: Record<string, string> = {
    open: "bg-[#fef3c7] text-[#78350f] dark:bg-[#2d2010] dark:text-[#fbbf24]",
    remediated: "bg-[#d4ebd0] text-[#0e6b4a] dark:bg-[#0f2a1a] dark:text-[#4ade80]",
    accepted: "bg-[#e0e7ff] text-[#3730a3] dark:bg-[#1e1a3a] dark:text-[#a78bfa]",
    "false-positive": "bg-[#f1f5f9] text-[#475569] dark:bg-[#1e293b] dark:text-[#94a3b8]",
    reopened: "bg-[#fee2e2] text-[#991b1b] dark:bg-[#2a1010] dark:text-[#f87171]",
  };
  const cls = map[status] ?? "bg-[#edf1ea] text-[#4d594f] dark:bg-[#22302a] dark:text-[#6b7e6f]";
  return (
    <span className={`rounded px-1.5 py-0.5 text-[10px] font-semibold ${cls}`}>
      {status}
    </span>
  );
}

function EventIcon({ eventType }: { eventType: string }) {
  const base = "flex h-7 w-7 items-center justify-center rounded-full shrink-0";
  switch (eventType) {
    case "status_change":
      return (
        <span className={`${base} bg-[#e0e7ff] text-[#3730a3] dark:bg-[#1e1a3a] dark:text-[#a78bfa]`} aria-hidden="true">
          <RefreshCw size={13} />
        </span>
      );
    case "reopened":
      return (
        <span className={`${base} bg-[#fee2e2] text-[#991b1b] dark:bg-[#2a1010] dark:text-[#f87171]`} aria-hidden="true">
          <RotateCcw size={13} />
        </span>
      );
    case "resolved":
      return (
        <span className={`${base} bg-[#d4ebd0] text-[#0e6b4a] dark:bg-[#0f2a1a] dark:text-[#4ade80]`} aria-hidden="true">
          <CheckCircle2 size={13} />
        </span>
      );
    case "dismissed":
      return (
        <span className={`${base} bg-[#f1f5f9] text-[#475569] dark:bg-[#1e293b] dark:text-[#94a3b8]`} aria-hidden="true">
          <XCircle size={13} />
        </span>
      );
    default:
      return (
        <span className={`${base} bg-[#edf1ea] text-[#697469] dark:bg-[#22302a] dark:text-[#8fa991]`} aria-hidden="true">
          <AlertCircle size={13} />
        </span>
      );
  }
}

interface FindingTimelineProps {
  findingId: string;
  onClose: () => void;
}

interface FindingComment {
  comment_id: string;
  finding_id: string;
  actor: string;
  body: string;
  created_at: string;
}

export function FindingTimeline({ findingId, onClose }: FindingTimelineProps) {
  const [events, setEvents] = useState<FindingLifecycleEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // UX-003: comments + assignment.
  const role = (typeof localStorage !== "undefined" && localStorage.getItem("janus_role")) || "";
  const canManage = role === "admin" || role === "operator";
  const [comments, setComments] = useState<FindingComment[]>([]);
  const [newComment, setNewComment] = useState("");
  const [assignee, setAssignee] = useState("");
  const [dueDate, setDueDate] = useState("");
  const [metaMsg, setMetaMsg] = useState("");

  const loadComments = () => {
    fetch(`/api/findings/${findingId}/comments`, { headers: getAuthHeaders() })
      .then((res) => (res.ok ? res.json() : []))
      .then((d: FindingComment[]) => setComments(Array.isArray(d) ? d : []))
      .catch(() => { /* non-fatal */ });
  };
  useEffect(loadComments, [findingId]);

  // Load the current assignment so the form shows the existing owner/due (UX-003).
  useEffect(() => {
    fetch(`/api/findings/${findingId}/assign`, { headers: getAuthHeaders() })
      .then((res) => (res.ok ? res.json() : null))
      .then((a: { assigned_to?: string; due_date?: string } | null) => {
        if (a) {
          setAssignee(a.assigned_to || "");
          setDueDate(a.due_date ? a.due_date.slice(0, 10) : "");
        }
      })
      .catch(() => { /* non-fatal */ });
  }, [findingId]);

  const addComment = async () => {
    if (!newComment.trim()) return;
    try {
      const res = await fetch(`/api/findings/${findingId}/comments`, {
        method: "POST",
        headers: { ...getAuthHeaders(), "content-type": "application/json" },
        body: JSON.stringify({ body: newComment.trim() }),
      });
      if (!res.ok) throw new Error(await errorMessage(res));
      setNewComment("");
      loadComments();
    } catch (e) {
      setMetaMsg(e instanceof Error ? e.message : "Failed to add comment");
    }
  };

  const saveAssignment = async () => {
    try {
      const res = await fetch(`/api/findings/${findingId}/assign`, {
        method: "POST",
        headers: { ...getAuthHeaders(), "content-type": "application/json" },
        body: JSON.stringify({ assigned_to: assignee.trim(), due_date: dueDate }),
      });
      if (!res.ok) throw new Error(await errorMessage(res));
      setMetaMsg(`Assigned${assignee ? ` to ${assignee}` : ""}${dueDate ? `, due ${dueDate}` : ""}.`);
    } catch (e) {
      setMetaMsg(e instanceof Error ? e.message : "Failed to save assignment");
    }
  };

  useEffect(() => {
    setLoading(true);
    setError(null);
    fetch(`/api/findings/${findingId}/timeline`, {
      headers: getAuthHeaders(),
    })
      .then((res) => {
        if (!res.ok) throw new Error(`Request failed: ${res.status}`);
        return res.json();
      })
      .then((data: FindingLifecycleEvent[]) => {
        setEvents(Array.isArray(data) ? data : []);
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : "Failed to load timeline");
      })
      .finally(() => setLoading(false));
  }, [findingId]);

  return (
    <FocusTrap active onEscape={onClose}>
      <div
        className="fixed inset-0 z-50 flex justify-end bg-black/40 backdrop-blur-sm dark:bg-black/55"
        onClick={onClose}
        role="dialog"
        aria-modal="true"
        aria-label="Finding lifecycle history"
      >
        <div
          className="h-full w-full max-w-md bg-white shadow-2xl overflow-y-auto animate-slide-in flex flex-col text-[#17211c] dark:bg-[#1a2620] dark:text-[#e8ede9]"
          onClick={(e) => e.stopPropagation()}
        >
          {/* Header */}
          <div className="flex items-center justify-between border-b border-[#dfe5dc] px-5 py-4 dark:border-[#2a3a30]">
            <div className="flex items-center gap-2">
              <Clock size={17} className="text-[#697469] dark:text-[#8fa991]" aria-hidden="true" />
              <h3 className="text-sm font-bold tracking-tight">Finding History</h3>
            </div>
            <button
              onClick={onClose}
              type="button"
              className="rounded-md p-1 text-[#4d594f] hover:bg-[#edf1ea] dark:text-[#6b7e6f] dark:hover:bg-[#22302a]"
              aria-label="Close timeline"
            >
              <X size={18} aria-hidden="true" />
            </button>
          </div>

          {/* Body */}
          <div className="flex-1 px-5 py-4">
            <p className="mb-4 font-mono text-[10px] text-[#697469] dark:text-[#8fa991] break-all">
              {findingId}
            </p>

            {loading && (
              <div className="py-8 text-center text-sm text-[#697469] dark:text-[#8fa991]">
                Loading history...
              </div>
            )}

            {error && !loading && (
              <div className="flex items-center gap-2 rounded-md border border-[#efb7a5] bg-[#fff4ee] px-3 py-2 text-sm text-[#8b2d16] dark:border-[#f87171] dark:bg-[#2d1518] dark:text-[#f87171]">
                <AlertCircle size={15} aria-hidden="true" />
                <span>{error}</span>
              </div>
            )}

            {!loading && !error && events.length === 0 && (
              <Empty label="No history yet" />
            )}

            {!loading && !error && events.length > 0 && (
              <ol className="relative border-l border-[#dfe5dc] dark:border-[#2a3a30] space-y-5 pl-5">
                {events.map((evt) => (
                  <li key={evt.event_id} className="relative">
                    {/* connector dot */}
                    <span className="absolute -left-[26px] top-0 flex h-7 w-7 items-center justify-center">
                      <EventIcon eventType={evt.event_type} />
                    </span>

                    <div className="rounded-md border border-[#edf1ea] bg-[#f7f8f5] p-3 dark:border-[#2a3a30] dark:bg-[#0d1210]">
                      <div className="flex items-center justify-between gap-2 mb-1.5">
                        <span className="text-xs font-semibold capitalize text-[#17211c] dark:text-[#e8ede9]">
                          {evt.event_type.replace(/_/g, " ")}
                        </span>
                        <span className="text-[10px] text-[#697469] dark:text-[#8fa991] whitespace-nowrap">
                          {formatDate(evt.occurred_at)}
                        </span>
                      </div>

                      {(evt.from_status || evt.to_status) && (
                        <div className="flex items-center gap-1.5 mb-1.5">
                          {evt.from_status && <StatusBadge status={evt.from_status} />}
                          {evt.from_status && evt.to_status && (
                            <ArrowRight size={11} className="text-[#697469] dark:text-[#8fa991]" aria-hidden="true" />
                          )}
                          {evt.to_status && <StatusBadge status={evt.to_status} />}
                        </div>
                      )}

                      <div className="text-[11px] text-[#697469] dark:text-[#8fa991]">
                        {evt.actor && (
                          <span>
                            <span className="font-semibold text-[#4d594f] dark:text-[#6b7e6f]">by </span>
                            {evt.actor}
                          </span>
                        )}
                        {evt.reason && (
                          <p className="mt-1 italic">{evt.reason}</p>
                        )}
                      </div>
                    </div>
                  </li>
                ))}
              </ol>
            )}

            {/* Assignment + comments (UX-003) */}
            <div className="mt-6 space-y-4 border-t border-[#dfe5dc] pt-4 dark:border-[#2a3a30]">
              {canManage && (
                <div>
                  <h4 className="mb-2 text-xs font-bold uppercase tracking-wider text-[#697469] dark:text-[#8fa991]">Assignment</h4>
                  <div className="flex flex-wrap items-center gap-2">
                    <input
                      type="text"
                      value={assignee}
                      onChange={(e) => setAssignee(e.target.value)}
                      placeholder="Assign to (username)"
                      aria-label="Assign finding to"
                      className="flex-1 min-w-[8rem] rounded border border-[#dfe5dc] px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-[#3a7d44] dark:border-[#2a3a30] dark:bg-[#0d1210] dark:text-[#e8ede9]"
                    />
                    <input
                      type="date"
                      value={dueDate}
                      onChange={(e) => setDueDate(e.target.value)}
                      aria-label="Due date"
                      className="rounded border border-[#dfe5dc] px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-[#3a7d44] dark:border-[#2a3a30] dark:bg-[#0d1210] dark:text-[#e8ede9]"
                    />
                    <button
                      type="button"
                      onClick={() => void saveAssignment()}
                      className="rounded bg-[#17211c] px-3 py-1 text-xs font-semibold text-white hover:bg-[#25322b] dark:bg-[#2a3a32] dark:hover:bg-[#3a4a42]"
                    >
                      Save
                    </button>
                  </div>
                </div>
              )}

              <div>
                <h4 className="mb-2 text-xs font-bold uppercase tracking-wider text-[#697469] dark:text-[#8fa991]">
                  Comments {comments.length > 0 && `(${comments.length})`}
                </h4>
                {comments.length === 0 ? (
                  <p className="text-xs text-[#697469] dark:text-[#8fa991]">No comments yet.</p>
                ) : (
                  <ul className="space-y-2">
                    {comments.map((c) => (
                      <li key={c.comment_id} className="rounded-md border border-[#edf1ea] bg-[#f7f8f5] p-2.5 dark:border-[#2a3a30] dark:bg-[#0d1210]">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-[11px] font-semibold text-[#4d594f] dark:text-[#6b7e6f]">{c.actor || "—"}</span>
                          <span className="text-[10px] text-[#697469] dark:text-[#8fa991]">{formatDate(c.created_at)}</span>
                        </div>
                        <p className="mt-1 whitespace-pre-wrap text-xs text-[#17211c] dark:text-[#e8ede9]">{c.body}</p>
                      </li>
                    ))}
                  </ul>
                )}
                {canManage && (
                  <div className="mt-2 flex flex-col gap-2">
                    <textarea
                      value={newComment}
                      onChange={(e) => setNewComment(e.target.value)}
                      placeholder="Add an investigation note…"
                      aria-label="Add a comment"
                      rows={2}
                      className="w-full rounded border border-[#dfe5dc] px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-[#3a7d44] dark:border-[#2a3a30] dark:bg-[#0d1210] dark:text-[#e8ede9]"
                    />
                    <button
                      type="button"
                      onClick={() => void addComment()}
                      disabled={!newComment.trim()}
                      className="self-end rounded bg-[#3a7d44] px-3 py-1 text-xs font-bold text-white hover:bg-[#2f6638] disabled:opacity-50 dark:bg-[#2f6638] dark:hover:bg-[#3a7d44]"
                    >
                      Comment
                    </button>
                  </div>
                )}
                {metaMsg && <p className="mt-1 text-[11px] text-[#697469] dark:text-[#8fa991]" role="status">{metaMsg}</p>}
              </div>
            </div>
          </div>
        </div>
      </div>
    </FocusTrap>
  );
}
