#!/usr/bin/env python3
"""
Validation script for four recent fixes applied to the Phase 2 LaTeX report.

Checks:
  A) Abstract keywords line exists in main.tex after abstract body.
  B) Reference (bibitem) order matches first-citation order across chapters.
  C) Section 2.4 title contains a \\ break in Chapter2.tex.
  D) Chapter5.tex does NOT contain "This thesis" and DOES contain "This work".
"""

import re
import sys
from pathlib import Path

BASE = Path("/Users/aditya/Documents/Github/capstone-claude-code-version/Report/Phase_2")

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"

all_passed = True

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def result(label: str, ok: bool, detail: str = "") -> None:
    global all_passed
    status = PASS if ok else FAIL
    print(f"  [{status}] {label}")
    if detail:
        for line in detail.strip().splitlines():
            print(f"         {line}")
    if not ok:
        all_passed = False


# ===========================================================================
# A) Abstract keywords
# ===========================================================================

print("\n" + "=" * 60)
print("A) Abstract keywords check — main.tex")
print("=" * 60)

main_text = (BASE / "main.tex").read_text()

# Find the abstract block
abstract_match = re.search(
    r"\\chapter\*\{.*?ABSTRACT.*?\}(.*?)\\pagenumbering",
    main_text,
    re.DOTALL | re.IGNORECASE,
)

if not abstract_match:
    result("Abstract block found", False, "Could not locate abstract block in main.tex")
else:
    abstract_body = abstract_match.group(1)

    # Check for Keywords line
    kw_match = re.search(
        r"\\noindent\\textbf\{Keywords[:\}].*",
        abstract_body,
    )
    if kw_match:
        result("Keywords line present after abstract body", True, kw_match.group(0)[:120])
    else:
        result("Keywords line present after abstract body", False,
               "No \\noindent\\textbf{Keywords:} line found inside abstract block.")


# ===========================================================================
# B) Reference order check
# ===========================================================================

print("\n" + "=" * 60)
print("B) Reference order check — citation vs bibitem order")
print("=" * 60)

CHAPTER_FILES = [
    "Chapter1.tex",
    "Chapter2.tex",
    "Chapter3.tex",
    "Chapter4.tex",
    "Chapter5.tex",
    "appendix.tex",
]

# Extract citations in order of first appearance across all chapters
cite_pattern = re.compile(r"\\cite\{([^}]+)\}")
seen: dict[str, tuple[str, int]] = {}  # key → (file, approx_position)
citation_order: list[str] = []

for fname in CHAPTER_FILES:
    fpath = BASE / fname
    if not fpath.exists():
        print(f"  WARNING: {fname} not found, skipping.")
        continue
    text = fpath.read_text()
    for m in cite_pattern.finditer(text):
        # A \cite{} may contain multiple comma-separated keys
        keys = [k.strip() for k in m.group(1).split(",")]
        for key in keys:
            if key not in seen:
                seen[key] = (fname, m.start())
                citation_order.append(key)

# Extract bibitem order from main.tex
bibitem_pattern = re.compile(r"\\bibitem\{([^}]+)\}")
bibitem_order = [m.group(1) for m in bibitem_pattern.finditer(main_text)]

# Only compare keys that appear in BOTH lists (ignore stray bibitems)
# Build index maps
bib_index = {key: i for i, key in enumerate(bibitem_order)}
cite_index = {key: i for i, key in enumerate(citation_order)}

# Keys cited in chapters
cited_keys_in_bib = [k for k in citation_order if k in bib_index]
# Keys in bib that are cited
bib_keys_cited = [k for k in bibitem_order if k in cite_index]

mismatches = []
prev_bib_pos = -1
for rank, key in enumerate(cited_keys_in_bib):
    bib_pos = bib_index[key]
    if bib_pos < prev_bib_pos:
        mismatches.append(
            f"  Citation #{rank+1}: '{key}' (first cited in {seen[key][0]}) "
            f"→ bibitem position {bib_pos+1} (earlier than previous bibitem position {prev_bib_pos+1})"
        )
    prev_bib_pos = bib_pos

# Check for cited keys missing from bibliography
missing_from_bib = [k for k in citation_order if k not in bib_index]
# Check for bibitems never cited
uncited_bibitems = [k for k in bibitem_order if k not in cite_index]

ok_order = len(mismatches) == 0
result(
    f"Bibitem order matches first-citation order ({len(cited_keys_in_bib)} common keys checked)",
    ok_order,
    "\n".join(mismatches) if mismatches else "",
)

if missing_from_bib:
    result(
        f"All cited keys present in bibliography",
        False,
        "Missing from \\bibitem: " + ", ".join(missing_from_bib),
    )
else:
    result("All cited keys present in bibliography", True)

if uncited_bibitems:
    # This is informational — not a hard failure
    print(f"  [INFO] Bibitem entries never cited in chapters ({len(uncited_bibitems)}): "
          + ", ".join(uncited_bibitems))

# Print the matched ordering for visibility
print("\n  Citation order (first appearance) vs bibitem position:")
print(f"  {'#':<4} {'Key':<30} {'First seen in':<16} {'Cite#':<7} {'Bib#':<6}")
print("  " + "-" * 67)
for rank, key in enumerate(cited_keys_in_bib):
    bib_pos = bib_index[key]
    fname_short = seen[key][0]
    marker = "  <-- OUT OF ORDER" if any(key in m for m in mismatches) else ""
    print(f"  {rank+1:<4} {key:<30} {fname_short:<16} {rank+1:<7} {bib_pos+1:<6}{marker}")


# ===========================================================================
# C) Section 2.4 title — \\ break
# ===========================================================================

print("\n" + "=" * 60)
print("C) Section 2.4 title backslash-break check — Chapter2.tex")
print("=" * 60)

ch2_text = (BASE / "Chapter2.tex").read_text()

# Look for the Hybrid section title with \\
hybrid_match = re.search(
    r"\\section\{[^}]*Hybrid[^}]*\\\\[^}]*\}",
    ch2_text,
)

if hybrid_match:
    result(r"Section 2.4 title contains \\ break", True, hybrid_match.group(0))
else:
    # Try without the break to give a useful error
    plain_match = re.search(r"\\section\{[^}]*[Hh]ybrid[^}]*\}", ch2_text)
    if plain_match:
        result(
            r"Section 2.4 title contains \\ break",
            False,
            f"Found section but WITHOUT \\\\ break: {plain_match.group(0)}",
        )
    else:
        result(r"Section 2.4 title contains \\ break", False,
               "No Hybrid section found in Chapter2.tex at all.")


# ===========================================================================
# D) "This thesis" → "This work" in Chapter5.tex
# ===========================================================================

print("\n" + "=" * 60)
print('D) "This thesis" → "This work" fix — Chapter5.tex')
print("=" * 60)

ch5_text = (BASE / "Chapter5.tex").read_text()

has_this_thesis = bool(re.search(r"\bThis thesis\b", ch5_text))
has_this_work = bool(re.search(r"\bThis work\b", ch5_text))

result(
    '"This thesis" is absent from Chapter5.tex',
    not has_this_thesis,
    ('STILL FOUND "This thesis" in Chapter5.tex' if has_this_thesis else ""),
)
result(
    '"This work" is present in Chapter5.tex',
    has_this_work,
    ('"This work" NOT found — fix may not have been applied.' if not has_this_work else ""),
)

if has_this_work:
    # Show context
    for m in re.finditer(r".{0,60}This work.{0,60}", ch5_text):
        print(f"  Context: ...{m.group(0).strip()}...")


# ===========================================================================
# Summary
# ===========================================================================

print("\n" + "=" * 60)
if all_passed:
    print(f"  OVERALL: {PASS} — All checks passed.")
else:
    print(f"  OVERALL: {FAIL} — One or more checks failed (see above).")
print("=" * 60 + "\n")

sys.exit(0 if all_passed else 1)
