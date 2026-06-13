import React, { useRef, useEffect, useCallback } from "react";

/**
 * FocusTrap
 *
 * Traps keyboard focus within a container (modals, drawers, dialogs).
 * Automatically focuses the first focusable element on activation.
 * Restores focus to the previously focused element on deactivation.
 *
 * Usage:
 *   <FocusTrap active={isOpen}>
 *     <div role="dialog" aria-modal="true">
 *       ...
 *     </div>
 *   </FocusTrap>
 */

const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

interface FocusTrapProps {
  active: boolean;
  children: React.ReactNode;
  /** Ref of element to focus on activation (defaults to first focusable child) */
  initialFocusRef?: React.RefObject<HTMLElement | null>;
  /** Called when Escape is pressed inside the trap */
  onEscape?: () => void;
}

export function FocusTrap({ active, children, initialFocusRef, onEscape }: FocusTrapProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const previousActiveElement = useRef<HTMLElement | null>(null);

  const getFocusableElements = useCallback((): HTMLElement[] => {
    if (!containerRef.current) return [];
    return Array.from(
      containerRef.current.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)
    );
  }, []);

  // On activation, store previous focus and focus the first element
  useEffect(() => {
    if (!active) return;

    previousActiveElement.current = document.activeElement as HTMLElement;

    // Use microtask to ensure DOM is ready
    const raf = requestAnimationFrame(() => {
      if (initialFocusRef?.current) {
        initialFocusRef.current.focus();
      } else {
        const focusables = getFocusableElements();
        if (focusables.length > 0) {
          focusables[0].focus();
        }
      }
    });

    return () => {
      cancelAnimationFrame(raf);
      // Restore focus on deactivation
      previousActiveElement.current?.focus();
    };
  }, [active, initialFocusRef, getFocusableElements]);

  // Trap Tab and Shift+Tab within the container
  useEffect(() => {
    if (!active) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && onEscape) {
        onEscape();
        return;
      }

      if (e.key !== "Tab") return;

      const focusables = getFocusableElements();
      if (focusables.length === 0) {
        e.preventDefault();
        return;
      }

      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      const current = document.activeElement;

      if (e.shiftKey) {
        if (current === first) {
          e.preventDefault();
          last.focus();
        }
      } else {
        if (current === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };

    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [active, onEscape, getFocusableElements]);

  return (
    <div ref={containerRef} data-focus-trap="">
      {children}
    </div>
  );
}
