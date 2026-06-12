import React, { useEffect, useState, useCallback } from "react";
import { Waves, Plus, Trash2, CheckSquare, Square, ChevronRight, X, AlertCircle, Loader2 } from "lucide-react";
import { FocusTrap } from "../a11y/FocusTrap";

interface WavePlan {
  plan_id: string;
  name: string;
  description?: string;
  wave_number: number;
  asset_ids: string[];
  algorithm_targets: string[];
  start_date?: string;
  target_date?: string;
  status: "planned" | "active" | "completed" | "cancelled";
  created_by: string;
  created_at: string;
  updated_at: string;
}

interface WavesResponse {
  plans: WavePlan[];
  checklist: string[];
}

interface CreateFormState {
  name: string;
  description: string;
  wave_number: string;
  asset_ids: string;
  algorithm_targets: string;
  start_date: string;
  target_date: string;
}

const EMPTY_FORM: CreateFormState = {
  name: "",
  description: "",
  wave_number: "1",
  asset_ids: "",
  algorithm_targets: "",
  start_date: "",
  target_date: "",
};

function getAuthHeaders(extra: Record<string, string> = {}): Record<string, string> {
  const token = localStorage.getItem("janus_token");
  const headers: Record<string, string> = { ...extra };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

function formatDate(iso?: string): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
  } catch {
    return iso;
  }
}

function StatusBadge({ status }: { status: WavePlan["status"] }) {
  const styles: Record<WavePlan["status"], string> = {
    planned:
      "bg-[#edf1ea] text-[#4d594f] dark:bg-[#22302a] dark:text-[#8fa991]",
    active:
      "bg-[#dbeafe] text-[#1e40af] dark:bg-[#152238] dark:text-[#60a5fa]",
    completed:
      "bg-[#dff3e9] text-[#0f6847] dark:bg-[#0f2a1a] dark:text-[#4ade80]",
    cancelled:
      "bg-[#ffe3dc] text-[#8b2d16] dark:bg-[#2d1518] dark:text-[#f87171]",
  };
  const labels: Record<WavePlan["status"], string> = {
    planned: "Planned",
    active: "Active",
    completed: "Completed",
    cancelled: "Cancelled",
  };
  return (
    <span className={`rounded px-2 py-0.5 text-xs font-semibold ${styles[status]}`}>
      {labels[status]}
    </span>
  );
}

function WaveNumberBadge({ n }: { n: number }) {
  return (
    <span className="inline-flex h-7 w-7 items-center justify-center rounded-full bg-[#edf7ef] text-xs font-bold text-[#3a7d44] dark:bg-[#16281e] dark:text-[#4ade80]">
      {n}
    </span>
  );
}

function AlgoChip({ label }: { label: string }) {
  return (
    <span className="rounded border border-[#dfe5dc] bg-[#f7f8f5] px-2 py-0.5 font-mono text-[10px] text-[#4d594f] dark:border-[#2a3a30] dark:bg-[#0d1210] dark:text-[#8fa991]">
      {label}
    </span>
  );
}

function InlineError({ message }: { message: string }) {
  return (
    <div
      role="alert"
      className="flex items-center gap-2 rounded border border-[#f3c3b3] bg-[#fff4ee] px-3 py-2 text-sm text-[#8b2d16] dark:border-[#f87171] dark:bg-[#2d1518] dark:text-[#f87171]"
    >
      <AlertCircle size={15} aria-hidden="true" />
      {message}
    </div>
  );
}

interface ConfirmDialogProps {
  title: string;
  message: string;
  confirmLabel: string;
  confirmClass: string;
  onConfirm: () => void;
  onCancel: () => void;
}

function ConfirmDialog({ title, message, confirmLabel, confirmClass, onConfirm, onCancel }: ConfirmDialogProps) {
  return (
    <FocusTrap active onEscape={onCancel}>
      <div
        className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm dark:bg-black/55"
        role="dialog"
        aria-modal="true"
        aria-labelledby="confirm-dialog-title"
      >
        <div className="w-full max-w-sm rounded-lg border border-[#dfe5dc] bg-white p-5 shadow-2xl dark:border-[#2a3a30] dark:bg-[#111e17]">
          <h3 id="confirm-dialog-title" className="mb-2 text-base font-semibold text-[#17211c] dark:text-[#e8ede9]">
            {title}
          </h3>
          <p className="mb-5 text-sm text-[#697469] dark:text-[#8fa991]">{message}</p>
          <div className="flex justify-end gap-3">
            <button
              type="button"
              onClick={onCancel}
              className="rounded border border-[#dfe5dc] px-4 py-2 text-sm text-[#4d594f] hover:bg-[#f7f8f5] transition dark:border-[#2a3a30] dark:text-[#6b7e6f] dark:hover:bg-[#22302a]"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={onConfirm}
              className={`rounded px-4 py-2 text-sm font-semibold text-white transition ${confirmClass}`}
            >
              {confirmLabel}
            </button>
          </div>
        </div>
      </div>
    </FocusTrap>
  );
}

interface CreateModalProps {
  onClose: () => void;
  onCreated: (plan: WavePlan) => void;
}

function CreateModal({ onClose, onCreated }: CreateModalProps) {
  const [form, setForm] = useState<CreateFormState>(EMPTY_FORM);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleChange = (field: keyof CreateFormState) => (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>
  ) => {
    setForm((prev) => ({ ...prev, [field]: e.target.value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name.trim()) {
      setError("Name is required.");
      return;
    }
    const waveNum = parseInt(form.wave_number, 10);
    if (isNaN(waveNum) || waveNum < 1) {
      setError("Wave number must be a positive integer.");
      return;
    }

    const assetIds = form.asset_ids
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);

    const algorithmTargets = form.algorithm_targets
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);

    const body: Record<string, unknown> = {
      name: form.name.trim(),
      description: form.description.trim() || undefined,
      wave_number: waveNum,
      asset_ids: assetIds,
      algorithm_targets: algorithmTargets,
    };
    if (form.start_date) body.start_date = form.start_date;
    if (form.target_date) body.target_date = form.target_date;

    setError(null);
    setSubmitting(true);
    try {
      const res = await fetch("/api/waves", {
        method: "POST",
        headers: getAuthHeaders({ "content-type": "application/json" }),
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(text || `HTTP ${res.status}`);
      }
      const plan: WavePlan = await res.json();
      onCreated(plan);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create wave plan.");
    } finally {
      setSubmitting(false);
    }
  };

  const inputClass =
    "w-full rounded border border-[#dfe5dc] bg-white px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-[#3a7d44] dark:border-[#2a3a30] dark:bg-[#0d1210] dark:text-[#e8ede9] dark:placeholder-[#6b7e6f]";
  const labelClass = "mb-1 block text-xs font-semibold text-[#697469] dark:text-[#8fa991]";

  return (
    <FocusTrap active onEscape={onClose}>
      <div
        className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm dark:bg-black/55"
        role="dialog"
        aria-modal="true"
        aria-labelledby="create-wave-modal-title"
      >
        <div className="w-full max-w-lg rounded-lg border border-[#dfe5dc] bg-white shadow-2xl dark:border-[#2a3a30] dark:bg-[#111e17]">
          <header className="flex items-center justify-between border-b border-[#dfe5dc] bg-[#f7f8f5] px-5 py-4 dark:border-[#2a3a30] dark:bg-[#0d1210]">
            <h2 id="create-wave-modal-title" className="flex items-center gap-2 text-base font-semibold text-[#17211c] dark:text-[#e8ede9]">
              <Waves size={18} aria-hidden="true" />
              New Migration Wave Plan
            </h2>
            <button
              type="button"
              onClick={onClose}
              className="rounded-full p-1 text-[#4d594f] hover:bg-gray-200 transition dark:text-[#6b7e6f] dark:hover:bg-[#22302a]"
              aria-label="Close modal"
            >
              <X size={18} aria-hidden="true" />
            </button>
          </header>

          <form onSubmit={handleSubmit} className="max-h-[75vh] overflow-y-auto p-5 space-y-4">
            {error && <InlineError message={error} />}

            <div>
              <label htmlFor="wave-name" className={labelClass}>
                Name <span className="text-[#8b2d16]" aria-hidden="true">*</span>
              </label>
              <input
                id="wave-name"
                type="text"
                required
                value={form.name}
                onChange={handleChange("name")}
                placeholder="e.g. Core Services Wave 1"
                className={inputClass}
              />
            </div>

            <div>
              <label htmlFor="wave-description" className={labelClass}>
                Description
              </label>
              <input
                id="wave-description"
                type="text"
                value={form.description}
                onChange={handleChange("description")}
                placeholder="Optional summary of this wave"
                className={inputClass}
              />
            </div>

            <div>
              <label htmlFor="wave-number" className={labelClass}>
                Wave Number <span className="text-[#8b2d16]" aria-hidden="true">*</span>
              </label>
              <input
                id="wave-number"
                type="number"
                min={1}
                required
                value={form.wave_number}
                onChange={handleChange("wave_number")}
                className={inputClass}
              />
            </div>

            <div>
              <label htmlFor="wave-asset-ids" className={labelClass}>
                Asset IDs <span className="text-[#697469] font-normal">(one per line)</span>
              </label>
              <textarea
                id="wave-asset-ids"
                rows={4}
                value={form.asset_ids}
                onChange={handleChange("asset_ids")}
                placeholder={"asset-uuid-1\nasset-uuid-2"}
                className={`${inputClass} resize-y font-mono text-xs`}
              />
            </div>

            <div>
              <label htmlFor="wave-algorithm-targets" className={labelClass}>
                Algorithm Targets <span className="text-[#697469] font-normal">(one per line)</span>
              </label>
              <textarea
                id="wave-algorithm-targets"
                rows={3}
                value={form.algorithm_targets}
                onChange={handleChange("algorithm_targets")}
                placeholder={"ML-KEM-768\nML-DSA-65\nSLH-DSA-128s"}
                className={`${inputClass} resize-y font-mono text-xs`}
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label htmlFor="wave-start-date" className={labelClass}>
                  Start Date
                </label>
                <input
                  id="wave-start-date"
                  type="date"
                  value={form.start_date}
                  onChange={handleChange("start_date")}
                  className={inputClass}
                />
              </div>
              <div>
                <label htmlFor="wave-target-date" className={labelClass}>
                  Target Date
                </label>
                <input
                  id="wave-target-date"
                  type="date"
                  value={form.target_date}
                  onChange={handleChange("target_date")}
                  className={inputClass}
                />
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={onClose}
                className="rounded border border-[#dfe5dc] px-4 py-2 text-sm text-[#4d594f] hover:bg-[#f7f8f5] transition dark:border-[#2a3a30] dark:text-[#6b7e6f] dark:hover:bg-[#22302a]"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={submitting}
                className="flex items-center gap-2 rounded bg-[#3a7d44] px-5 py-2 text-sm font-semibold text-white hover:bg-[#2e6b38] transition disabled:opacity-50 dark:bg-[#2e6b38] dark:hover:bg-[#3a7d44]"
              >
                {submitting && <Loader2 size={14} className="animate-spin" aria-hidden="true" />}
                Create Wave
              </button>
            </div>
          </form>
        </div>
      </div>
    </FocusTrap>
  );
}

type PendingAction =
  | {
      type: "status";
      planId: string;
      newStatus: "active" | "completed" | "cancelled";
      label: string;
    }
  | {
      type: "delete";
      planId: string;
      planName: string;
    };

export function WavePlanning() {
  const [plans, setPlans] = useState<WavePlan[]>([]);
  const [checklist, setChecklist] = useState<string[]>([]);
  const [checkedItems, setCheckedItems] = useState<Set<number>>(new Set());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [pendingAction, setPendingAction] = useState<PendingAction | null>(null);
  const [actionInFlight, setActionInFlight] = useState<string | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);

  const hasPlannedWave = plans.some((p) => p.status === "planned");

  const loadWaves = useCallback(async () => {
    setError(null);
    try {
      const res = await fetch("/api/waves", {
        headers: getAuthHeaders(),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(text || `HTTP ${res.status}`);
      }
      const data: WavesResponse = await res.json();
      setPlans(data.plans ?? []);
      setChecklist(data.checklist ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load wave plans.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadWaves();
  }, [loadWaves]);

  const handleStatusTransition = async (planId: string, newStatus: "active" | "completed" | "cancelled") => {
    setActionError(null);
    setActionInFlight(planId);
    try {
      const res = await fetch(`/api/waves/${planId}`, {
        method: "PUT",
        headers: getAuthHeaders({ "content-type": "application/json" }),
        body: JSON.stringify({ status: newStatus }),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(text || `HTTP ${res.status}`);
      }
      setPlans((prev) =>
        prev.map((p) => (p.plan_id === planId ? { ...p, status: newStatus, updated_at: new Date().toISOString() } : p))
      );
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Status update failed.");
    } finally {
      setActionInFlight(null);
    }
  };

  const handleDelete = async (planId: string) => {
    setActionError(null);
    setActionInFlight(planId);
    try {
      const res = await fetch(`/api/waves/${planId}`, {
        method: "DELETE",
        headers: getAuthHeaders(),
      });
      if (!res.ok && res.status !== 204) {
        const text = await res.text();
        throw new Error(text || `HTTP ${res.status}`);
      }
      setPlans((prev) => prev.filter((p) => p.plan_id !== planId));
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Delete failed.");
    } finally {
      setActionInFlight(null);
    }
  };

  const toggleChecklist = (idx: number) => {
    setCheckedItems((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) {
        next.delete(idx);
      } else {
        next.add(idx);
      }
      return next;
    });
  };

  const handleConfirm = async () => {
    if (!pendingAction) return;
    const action = pendingAction;
    setPendingAction(null);
    if (action.type === "status") {
      await handleStatusTransition(action.planId, action.newStatus);
    } else {
      await handleDelete(action.planId);
    }
  };

  const confirmDialog = pendingAction
    ? pendingAction.type === "status"
      ? {
          title: `Confirm: ${pendingAction.label}`,
          message: `Are you sure you want to mark this wave as "${pendingAction.newStatus}"? This action cannot be undone.`,
          confirmLabel: pendingAction.label,
          confirmClass:
            pendingAction.newStatus === "cancelled"
              ? "bg-[#8b2d16] hover:bg-[#6b2010]"
              : pendingAction.newStatus === "active"
              ? "bg-[#1e40af] hover:bg-[#1a35a0]"
              : "bg-[#3a7d44] hover:bg-[#2e6b38]",
        }
      : {
          title: "Delete Wave Plan",
          message: `Delete "${pendingAction.planName}"? This action is permanent and cannot be undone.`,
          confirmLabel: "Delete",
          confirmClass: "bg-[#8b2d16] hover:bg-[#6b2010]",
        }
    : null;

  if (loading) {
    return (
      <div className="flex items-center justify-center py-16 text-[#697469] dark:text-[#8fa991]">
        <Loader2 size={22} className="animate-spin mr-2" aria-hidden="true" />
        <span>Loading wave plans…</span>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* Header row */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Waves size={22} className="text-[#3a7d44] dark:text-[#4ade80]" aria-hidden="true" />
          <h1 className="text-lg font-semibold text-[#17211c] dark:text-[#e8ede9]">
            Migration Wave Planning
          </h1>
          <span className="rounded bg-[#edf7ef] px-2 py-0.5 text-xs font-semibold text-[#3a7d44] dark:bg-[#16281e] dark:text-[#4ade80]">
            WAVE-01
          </span>
        </div>
        <button
          type="button"
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 rounded bg-[#3a7d44] px-4 py-2 text-sm font-semibold text-white hover:bg-[#2e6b38] transition dark:bg-[#2e6b38] dark:hover:bg-[#3a7d44]"
          aria-label="Create new wave plan"
        >
          <Plus size={15} aria-hidden="true" />
          New Wave Plan
        </button>
      </div>

      {/* Global load error */}
      {error && <InlineError message={error} />}

      {/* Action error (status/delete) */}
      {actionError && <InlineError message={actionError} />}

      {/* Readiness checklist — shown when any wave is in planned status */}
      {hasPlannedWave && checklist.length > 0 && (
        <section
          className="rounded-lg border border-[#dfe5dc] bg-white p-4 dark:border-[#2a3a30] dark:bg-[#111e17]"
          aria-label="Migration readiness checklist"
        >
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold text-[#17211c] dark:text-[#e8ede9]">
            <ChevronRight size={15} className="text-[#3a7d44] dark:text-[#4ade80]" aria-hidden="true" />
            Pre-Migration Readiness Checklist
          </h2>
          <ul className="space-y-2">
            {checklist.map((item, idx) => {
              const checked = checkedItems.has(idx);
              return (
                <li key={idx}>
                  <button
                    type="button"
                    onClick={() => toggleChecklist(idx)}
                    className="flex w-full items-start gap-2 rounded px-1 py-0.5 text-left text-sm transition hover:bg-[#f7f8f5] dark:hover:bg-[#0d1210]"
                    aria-pressed={checked}
                    aria-label={item}
                  >
                    {checked ? (
                      <CheckSquare
                        size={16}
                        className="mt-px shrink-0 text-[#3a7d44] dark:text-[#4ade80]"
                        aria-hidden="true"
                      />
                    ) : (
                      <Square
                        size={16}
                        className="mt-px shrink-0 text-[#a0afa3] dark:text-[#4d594f]"
                        aria-hidden="true"
                      />
                    )}
                    <span
                      className={`${
                        checked
                          ? "text-[#a0afa3] line-through dark:text-[#4d594f]"
                          : "text-[#17211c] dark:text-[#e8ede9]"
                      }`}
                    >
                      {item}
                    </span>
                  </button>
                </li>
              );
            })}
          </ul>
        </section>
      )}

      {/* Wave plan list */}
      {plans.length === 0 && !loading && (
        <div className="rounded-lg border border-[#dfe5dc] bg-white py-14 text-center dark:border-[#2a3a30] dark:bg-[#111e17]">
          <Waves size={36} className="mx-auto mb-3 text-[#c7d4c9] dark:text-[#2a3a30]" aria-hidden="true" />
          <p className="text-sm text-[#697469] dark:text-[#8fa991]">No migration wave plans yet.</p>
          <button
            type="button"
            onClick={() => setShowCreateModal(true)}
            className="mt-4 flex items-center gap-1.5 mx-auto rounded bg-[#3a7d44] px-4 py-2 text-sm font-semibold text-white hover:bg-[#2e6b38] transition dark:bg-[#2e6b38] dark:hover:bg-[#3a7d44]"
          >
            <Plus size={14} aria-hidden="true" />
            Create First Wave Plan
          </button>
        </div>
      )}

      <div className="space-y-3">
        {plans.map((plan) => {
          const inFlight = actionInFlight === plan.plan_id;
          const canDelete = plan.status === "planned" || plan.status === "cancelled";

          return (
            <article
              key={plan.plan_id}
              className="rounded-lg border border-[#dfe5dc] bg-white p-4 dark:border-[#2a3a30] dark:bg-[#111e17]"
              aria-label={`Wave plan: ${plan.name}`}
            >
              {/* Card header */}
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="flex items-center gap-3">
                  <WaveNumberBadge n={plan.wave_number} />
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-semibold text-[#17211c] dark:text-[#e8ede9]">
                        {plan.name}
                      </span>
                      <StatusBadge status={plan.status} />
                    </div>
                    {plan.description && (
                      <p className="mt-0.5 text-xs text-[#697469] dark:text-[#8fa991]">
                        {plan.description}
                      </p>
                    )}
                  </div>
                </div>

                {/* Action buttons */}
                <div className="flex items-center gap-2">
                  {inFlight && (
                    <Loader2 size={14} className="animate-spin text-[#697469] dark:text-[#8fa991]" aria-hidden="true" />
                  )}

                  {plan.status === "planned" && !inFlight && (
                    <>
                      <button
                        type="button"
                        onClick={() =>
                          setPendingAction({
                            type: "status",
                            planId: plan.plan_id,
                            newStatus: "active",
                            label: "Activate",
                          })
                        }
                        className="rounded border border-[#1e40af] bg-[#dbeafe] px-3 py-1 text-xs font-semibold text-[#1e40af] hover:bg-[#bfdbfe] transition dark:border-[#60a5fa] dark:bg-[#152238] dark:text-[#60a5fa] dark:hover:bg-[#1e3a5f]"
                      >
                        Activate
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          setPendingAction({
                            type: "status",
                            planId: plan.plan_id,
                            newStatus: "cancelled",
                            label: "Cancel Wave",
                          })
                        }
                        className="rounded border border-[#f3c3b3] bg-[#fff4ee] px-3 py-1 text-xs font-semibold text-[#8b2d16] hover:bg-[#ffe3dc] transition dark:border-[#f87171] dark:bg-[#2d1518] dark:text-[#f87171] dark:hover:bg-[#3d2020]"
                      >
                        Cancel
                      </button>
                    </>
                  )}

                  {plan.status === "active" && !inFlight && (
                    <>
                      <button
                        type="button"
                        onClick={() =>
                          setPendingAction({
                            type: "status",
                            planId: plan.plan_id,
                            newStatus: "completed",
                            label: "Complete",
                          })
                        }
                        className="rounded border border-[#11845b] bg-[#dff3e9] px-3 py-1 text-xs font-semibold text-[#0f6847] hover:bg-[#bbf0d6] transition dark:border-[#3da06a] dark:bg-[#0f2a1a] dark:text-[#4ade80] dark:hover:bg-[#153520]"
                      >
                        Complete
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          setPendingAction({
                            type: "status",
                            planId: plan.plan_id,
                            newStatus: "cancelled",
                            label: "Cancel Wave",
                          })
                        }
                        className="rounded border border-[#f3c3b3] bg-[#fff4ee] px-3 py-1 text-xs font-semibold text-[#8b2d16] hover:bg-[#ffe3dc] transition dark:border-[#f87171] dark:bg-[#2d1518] dark:text-[#f87171] dark:hover:bg-[#3d2020]"
                      >
                        Cancel
                      </button>
                    </>
                  )}

                  {canDelete && !inFlight && (
                    <button
                      type="button"
                      onClick={() =>
                        setPendingAction({
                          type: "delete",
                          planId: plan.plan_id,
                          planName: plan.name,
                        })
                      }
                      className="rounded border border-[#dfe5dc] p-1.5 text-[#a0afa3] hover:border-[#f3c3b3] hover:bg-[#fff4ee] hover:text-[#8b2d16] transition dark:border-[#2a3a30] dark:text-[#4d594f] dark:hover:border-[#f87171] dark:hover:bg-[#2d1518] dark:hover:text-[#f87171]"
                      aria-label={`Delete wave plan ${plan.name}`}
                    >
                      <Trash2 size={14} aria-hidden="true" />
                    </button>
                  )}
                </div>
              </div>

              {/* Card meta */}
              <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-[#dfe5dc] pt-3 dark:border-[#2a3a30]">
                <span className="text-xs text-[#697469] dark:text-[#8fa991]">
                  <span className="font-medium text-[#4d594f] dark:text-[#8fa991]">Assets:</span>{" "}
                  {plan.asset_ids.length}
                </span>

                {(plan.start_date || plan.target_date) && (
                  <span className="text-xs text-[#697469] dark:text-[#8fa991]">
                    <span className="font-medium text-[#4d594f] dark:text-[#8fa991]">Timeline:</span>{" "}
                    {formatDate(plan.start_date)}
                    {plan.target_date && ` → ${formatDate(plan.target_date)}`}
                  </span>
                )}

                <span className="text-xs text-[#697469] dark:text-[#8fa991]">
                  <span className="font-medium text-[#4d594f] dark:text-[#8fa991]">Created by:</span>{" "}
                  {plan.created_by}
                </span>

                <span className="text-xs text-[#697469] dark:text-[#8fa991]">
                  <span className="font-medium text-[#4d594f] dark:text-[#8fa991]">Updated:</span>{" "}
                  {formatDate(plan.updated_at)}
                </span>
              </div>

              {plan.algorithm_targets.length > 0 && (
                <div className="mt-2 flex flex-wrap items-center gap-1.5">
                  <span className="text-xs font-medium text-[#697469] dark:text-[#8fa991]">Targets:</span>
                  {plan.algorithm_targets.map((algo) => (
                    <AlgoChip key={algo} label={algo} />
                  ))}
                </div>
              )}
            </article>
          );
        })}
      </div>

      {/* Confirmation dialog */}
      {pendingAction && confirmDialog && (
        <ConfirmDialog
          title={confirmDialog.title}
          message={confirmDialog.message}
          confirmLabel={confirmDialog.confirmLabel}
          confirmClass={confirmDialog.confirmClass}
          onConfirm={handleConfirm}
          onCancel={() => setPendingAction(null)}
        />
      )}

      {/* Create modal */}
      {showCreateModal && (
        <CreateModal
          onClose={() => setShowCreateModal(false)}
          onCreated={(plan) => {
            setPlans((prev) => [plan, ...prev]);
            setShowCreateModal(false);
          }}
        />
      )}
    </div>
  );
}
