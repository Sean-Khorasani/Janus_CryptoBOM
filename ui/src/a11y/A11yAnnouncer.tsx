import React from "react";

/**
 * A11yAnnouncer
 *
 * A live region that pushes screen-reader-accessible announcements
 * without affecting visual layout. Multiple priority levels allow
 * assertive (immediate) and polite (queue) announcements.
 *
 * Usage:
 *   <A11yAnnouncer message="Finding updated to Accepted" priority="polite" />
 */
interface A11yAnnouncerProps {
  message: string;
  priority?: "polite" | "assertive";
}

export function A11yAnnouncer({ message, priority = "polite" }: A11yAnnouncerProps) {
  if (!message) return null;

  return (
    <div
      role="status"
      aria-live={priority}
      aria-atomic="true"
      className="sr-only"
      data-testid="a11y-announcer"
    >
      {message}
    </div>
  );
}

/**
 * ScreenReaderOnly
 *
 * Visually hidden element that is still accessible to screen readers.
 */
export function ScreenReaderOnly({ children }: { children: React.ReactNode }) {
  return (
    <span className="sr-only" aria-hidden="false">
      {children}
    </span>
  );
}
