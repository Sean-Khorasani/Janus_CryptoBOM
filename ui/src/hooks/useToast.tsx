import React, { createContext, useCallback, useContext, useRef, useState } from "react";

export type ToastKind = "success" | "error" | "info";
export interface Toast {
  id: number;
  kind: ToastKind;
  message: string;
}

interface ToastContextValue {
  notify: (message: string, kind?: ToastKind) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

/**
 * Lightweight toast surface (UX-008): transient, auto-dismissing, dismissible
 * confirmations for actions like finding-status changes, policy switches, and
 * agent commands — instead of inline strings that are easy to miss. Each toast
 * is mirrored into an aria-live region for screen-reader users.
 */
export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [live, setLive] = useState("");
  const nextId = useRef(1);

  const dismiss = useCallback((id: number) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  const notify = useCallback((message: string, kind: ToastKind = "info") => {
    const id = nextId.current++;
    setToasts(prev => [...prev, { id, kind, message }].slice(-4)); // keep at most 4
    setLive(message);
    window.setTimeout(() => dismiss(id), 5000);
  }, [dismiss]);

  return (
    <ToastContext.Provider value={{ notify }}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-80 max-w-[90vw] flex-col gap-2">
        {toasts.map(t => {
          const tone =
            t.kind === "success" ? "border-[#11845b] bg-[#ecfdf3] text-[#08734d] dark:bg-[#0f2419] dark:text-[#3da06a]"
            : t.kind === "error" ? "border-[#d33f49] bg-[#fff4ee] text-[#8b2d16] dark:bg-[#2d1518] dark:text-[#f0a08c]"
            : "border-[#dfe5dc] bg-white text-[#17211c] dark:border-[#2a3a30] dark:bg-[#1a2620] dark:text-[#e8ede9]";
          return (
            <div key={t.id} className={`pointer-events-auto flex items-start gap-2 rounded-md border px-3 py-2 text-xs shadow-md ${tone}`} role="status">
              <span className="flex-1">{t.message}</span>
              <button type="button" onClick={() => dismiss(t.id)} aria-label="Dismiss notification" className="font-bold opacity-60 hover:opacity-100">×</button>
            </div>
          );
        })}
      </div>
      <div className="sr-only" role="status" aria-live="polite">{live}</div>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  // A no-op fallback keeps components usable outside the provider (e.g. tests).
  return ctx ?? { notify: () => {} };
}
