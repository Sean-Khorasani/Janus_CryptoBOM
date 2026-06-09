import { useEffect, useCallback } from "react";

/**
 * useKeyboardNav
 *
 * Provides keyboard navigation helpers for interactive elements:
 *  - Escape key to close modals/drawers/popovers
 *  - Arrow key navigation in tables/lists
 *
 * Usage:
 *   useKeyboardNav({
 *     onEscape: () => setSelected(null),
 *     arrowScope: "my-table",
 *     enabled: true,
 *   });
 */

interface UseKeyboardNavOptions {
  /** Called when Escape is pressed */
  onEscape?: () => void;
  /** An ID or CSS selector to scope arrow-key navigation within */
  arrowScope?: string;
  /** Whether the handler is active (default true) */
  enabled?: boolean;
}

export function useKeyboardNav({
  onEscape,
  arrowScope,
  enabled = true,
}: UseKeyboardNavOptions) {
  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (!enabled) return;

      // Escape key
      if (e.key === "Escape" && onEscape) {
        e.stopPropagation();
        onEscape();
        return;
      }

      // Arrow key navigation in tables
      if (
        arrowScope &&
        (e.key === "ArrowDown" || e.key === "ArrowUp")
      ) {
        const container = document.getElementById(arrowScope);
        if (!container) return;
        if (!container.contains(document.activeElement)) return;

        e.preventDefault();

        const focusables = Array.from(
          container.querySelectorAll<HTMLElement>(
            'button:not([disabled]), a[href], [tabindex]:not([tabindex="-1"]), input:not([disabled]), select:not([disabled]), textarea:not([disabled])'
          )
        );
        if (focusables.length === 0) return;

        const currentIndex = focusables.indexOf(document.activeElement as HTMLElement);
        let nextIndex: number;

        if (e.key === "ArrowDown") {
          nextIndex = currentIndex + 1;
          if (nextIndex >= focusables.length) nextIndex = focusables.length - 1;
        } else {
          nextIndex = currentIndex - 1;
          if (nextIndex < 0) nextIndex = 0;
        }

        if (nextIndex !== currentIndex && nextIndex >= 0 && nextIndex < focusables.length) {
          focusables[nextIndex].focus();
        }
      }
    },
    [onEscape, arrowScope, enabled]
  );

  useEffect(() => {
    if (!enabled) return;
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [handleKeyDown, enabled]);
}
