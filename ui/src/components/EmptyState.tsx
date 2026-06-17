import type { ReactNode } from "react";

interface Props {
  icon?: ReactNode;
  title: string;
  message?: string;
  /** Optional call-to-action, e.g. a command hint or a button. */
  action?: ReactNode;
  /** Optional monospace hint rendered as a command, e.g. `janus-agent --once`. */
  command?: string;
}

/**
 * EmptyState renders a centered, illustrated placeholder for list/table views
 * that have no data yet, with a context-sensitive message and optional action
 * (UX-005). Use instead of an empty table body or a bare "no results" line.
 */
export function EmptyState({ icon, title, message, action, command }: Props) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-12 text-center">
      {icon && (
        <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-[#eef2ec] text-[#3a7d44] dark:bg-[#22302a] dark:text-[#4ade80]" aria-hidden="true">
          {icon}
        </div>
      )}
      <h3 className="text-sm font-semibold text-[#17211c] dark:text-[#e8ede9]">{title}</h3>
      {message && (
        <p className="mt-1 max-w-sm text-xs text-[#697469] dark:text-[#8fa991]">{message}</p>
      )}
      {command && (
        <code className="mt-3 rounded border border-[#dfe5dc] bg-[#f7f8f5] px-2.5 py-1 font-mono text-xs text-[#4d594f] dark:border-[#2a3a30] dark:bg-[#0d1210] dark:text-[#8fa991]">
          {command}
        </code>
      )}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
