import React from "react";

/**
 * SkipLink
 *
 * A "Skip to main content" link that becomes visible on keyboard focus.
 * Must be the first focusable element in the DOM.
 *
 * Usage:
 *   <SkipLink targetId="main-content" />
 *   ...
 *   <main id="main-content">...</main>
 */
interface SkipLinkProps {
  targetId?: string;
  label?: string;
}

export function SkipLink({
  targetId = "main-content",
  label = "Skip to main content",
}: SkipLinkProps) {
  const handleClick = (e: React.MouseEvent<HTMLAnchorElement>) => {
    e.preventDefault();
    const target = document.getElementById(targetId);
    if (target) {
      target.setAttribute("tabindex", "-1");
      target.focus();
      // Remove the temporary tabindex after focus so it doesn't persist
      setTimeout(() => target.removeAttribute("tabindex"), 100);
    }
  };

  return (
    <a
      href={`#${targetId}`}
      onClick={handleClick}
      className="skip-link sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[9999] focus:block focus:rounded focus:bg-white focus:px-4 focus:py-2 focus:text-sm focus:font-semibold focus:text-[#17211c] focus:shadow-lg focus:outline-none focus:ring-2 focus:ring-[#2f6fed] dark:focus:bg-[#1a2620] dark:focus:text-[#e8ede9]"
      data-testid="skip-link"
    >
      {label}
    </a>
  );
}
