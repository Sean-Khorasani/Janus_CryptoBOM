#!/usr/bin/env python3
"""Documentation-claim linter (WP-025).

Ties product/marketing claims to the capability-maturity framework so the
documentation cannot describe Janus as more mature than it is. Two checks:

  1. Over-claim scan: flags unsupportable superlatives ("production-ready",
     "military-grade", "unhackable", "FIPS certified", ...) anywhere in the
     README and docs. These assert a maturity or certification the project has
     not earned (see docs/CAPABILITY_MATURITY.md and docs/SUPPORT.md).

  2. Maturity-declaration completeness: docs/CAPABILITY_MATURITY.md must declare
     a "Current Janus status ... Level N" line for every maturity dimension, so
     each capability has an explicit, dated self-assessment.

Exit code 0 = clean, 1 = violations found. Wired into `make verify-claims`.

The tier-defining documents (CAPABILITY_MATURITY.md, SUPPORT.md) are exempt from
the over-claim scan because they legitimately define the vocabulary
("certified", "supported", ...).
"""

import os
import re
import sys

# Phrases that assert a maturity, certification, or guarantee Janus has not
# earned. Matched case-insensitively as whole phrases.
BANNED = [
    r"production[\s-]?ready",
    r"enterprise[\s-]?grade",
    r"military[\s-]?grade",
    r"bank[\s-]?grade",
    r"unhackable",
    r"100%\s+secure",
    r"fully\s+secure",
    r"guaranteed\s+secure",
    r"unbreakable",
    r"fully\s+autonomous",
    r"FIPS[\s-]?(140[\s-]?\d?\s+)?(certified|validated)",
    r"certified\s+post[\s-]?quantum",
    r"NIST[\s-]?certified",
    r"zero[\s-]?(false[\s-]?positives?|defects?)",
]

# The over-claim scan targets the PRODUCT-CLAIM surface — the documents that
# describe what Janus itself is/does to a prospective operator. Landscape and
# research docs (RESEARCH.md, competitive-analysis.md, the migration report)
# legitimately discuss external standards, FIPS validation of third-party HSMs,
# and "production-ready" NIST algorithms, so they are not part of this scan.
CLAIM_SURFACE = [
    "README.md",
    "docs/deployment.md",
    "docs/design.md",
    "docs/case_studies.md",
]

# A banned phrase is ignored when negated or marked not-applicable on the same
# line (e.g. "not production-ready", "❌ N/A (software platform)").
NEGATORS = re.compile(r"\b(not|never|isn'?t|aren'?t|without)\b|\bn/a\b|❌|⚠", re.IGNORECASE)

# The five maturity dimensions that must each carry a current-status declaration.
REQUIRED_DIMENSIONS = [
    "Discovery Coverage",
    "Assessment Accuracy",
    "Agility Metrics",
    "Migration Safety",
    "LLM Trustworthiness",
]


def project_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def check_overclaims(root):
    print("--- Check 1: over-claim scan (product-claim surface) ---")
    patterns = [(p, re.compile(p, re.IGNORECASE)) for p in BANNED]
    violations = []
    for rel in CLAIM_SURFACE:
        full = os.path.join(root, rel)
        if not os.path.exists(full):
            continue
        with open(full, encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                # Skip negated / not-applicable mentions — those are honest.
                if NEGATORS.search(line):
                    continue
                for raw, rx in patterns:
                    if rx.search(line):
                        violations.append((rel, lineno, raw, line.strip()))
    if not violations:
        print("  [PASS] no unsupportable claims found.")
        return True
    for rel, lineno, raw, text in violations:
        print(f"  [FAIL] {rel}:{lineno} matches /{raw}/: {text[:100]}")
    return False


def check_maturity_declarations(root):
    print("--- Check 2: maturity-declaration completeness ---")
    path = os.path.join(root, "docs", "CAPABILITY_MATURITY.md")
    if not os.path.exists(path):
        print("  [FAIL] docs/CAPABILITY_MATURITY.md is missing.")
        return False
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()

    # Every dimension heading must exist and the doc must carry a dated
    # "Current Janus status ... Level N" declaration for each.
    status_lines = re.findall(r"Current Janus status.*?Level\s*[0-9]", text)
    ok = True
    for dim in REQUIRED_DIMENSIONS:
        if dim not in text:
            print(f"  [FAIL] dimension '{dim}' not documented.")
            ok = False
    if len(status_lines) < len(REQUIRED_DIMENSIONS):
        print(
            f"  [FAIL] found {len(status_lines)} 'Current Janus status … Level N' "
            f"declarations; expected at least {len(REQUIRED_DIMENSIONS)} (one per dimension)."
        )
        ok = False
    if ok:
        print(
            f"  [PASS] all {len(REQUIRED_DIMENSIONS)} dimensions carry a current-status declaration."
        )
    return ok


def main():
    root = project_root()
    print("Janus documentation-claim linter (WP-025)\n")
    results = [check_overclaims(root), check_maturity_declarations(root)]
    print()
    if all(results):
        print("PASS: documentation claims are consistent with the maturity framework.")
        return 0
    print("FAIL: documentation claims need correction (see above).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
