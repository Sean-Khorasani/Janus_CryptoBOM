import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";

interface Props {
  children: ReactNode;
  /** Shown in the fallback heading, e.g. the tab name. */
  label?: string;
}

interface State {
  error: Error | null;
}

/**
 * ErrorBoundary catches render/runtime errors in its subtree and shows a
 * recovery panel instead of letting a single component exception white-screen
 * the whole dashboard (UX-005). Place one at the app root and one per tab panel
 * (keyed by tab) so an error in one tab is isolated and recoverable by switching
 * tabs or retrying.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Surface to the console for diagnostics; no telemetry sink wired yet.
    console.error("Janus UI error boundary caught:", error, info.componentStack);
  }

  private reset = () => this.setState({ error: null });

  render() {
    if (!this.state.error) return this.props.children;

    const { label } = this.props;
    return (
      <div
        role="alert"
        className="rounded-md border border-[#efb7a5] bg-[#fff4ee] p-6 text-center dark:border-[#f87171] dark:bg-[#2d1518]"
      >
        <div className="mx-auto mb-3 flex h-11 w-11 items-center justify-center rounded-full bg-[#ffe2d6] text-[#8b2d16] dark:bg-[#3a1d1d] dark:text-[#f87171]">
          <AlertTriangle size={22} aria-hidden="true" />
        </div>
        <h2 className="text-sm font-semibold text-[#8b2d16] dark:text-[#f87171]">
          Something went wrong{label ? ` in ${label}` : ""}
        </h2>
        <p className="mx-auto mt-1 max-w-md text-xs text-[#a14a30] dark:text-[#fca5a5]">
          This view hit an unexpected error. Your session and data are intact — retry,
          or switch to another tab and back.
        </p>
        <p className="mx-auto mt-2 max-w-md break-words font-mono text-[10px] text-[#a14a30]/80 dark:text-[#fca5a5]/80">
          {this.state.error.message}
        </p>
        <div className="mt-4 flex items-center justify-center gap-2">
          <button
            type="button"
            onClick={this.reset}
            className="flex items-center gap-1.5 rounded bg-[#8b2d16] px-3 py-1.5 text-xs font-bold text-white hover:bg-[#73250f] dark:bg-[#b3432a] dark:hover:bg-[#c4543b]"
          >
            <RefreshCw size={13} aria-hidden="true" /> Retry
          </button>
          <a
            href="https://github.com/janus-cbom/janus/issues/new"
            target="_blank"
            rel="noopener noreferrer"
            className="rounded border border-[#efb7a5] px-3 py-1.5 text-xs font-medium text-[#8b2d16] hover:bg-[#ffe9e0] dark:border-[#f87171] dark:text-[#f87171] dark:hover:bg-[#3a1d1d]"
          >
            Report issue
          </a>
        </div>
      </div>
    );
  }
}
