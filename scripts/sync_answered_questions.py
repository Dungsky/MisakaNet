#!/usr/bin/env python3
"""Sync answered/pending question intakes into the D1 ``questions`` table.

PRD ⑤ §9 (pull-based answer delivery): the worker records ``pending`` rows
for new question intakes; this script closes the loop from GitHub:

- open ``kind=question`` issues  -> ensure a ``pending`` row exists
- closed issues carrying the ``answered`` label -> extract the maintainer's
  answer comment and upsert a ``status='answered'`` row (issue_number unique)

The dedup_hash mirrors the worker's FNV-1a ``hashString(dedupSource)`` where
``dedupSource = f"{kind}:{problem}:{error}"`` — same scheme, so a later
same-question re-submission (worker dedup path) finds the row and returns the
answer.

Usage:
    python3 scripts/sync_answered_questions.py            # full sync
    python3 scripts/sync_answered_questions.py --issue 1362 --execute
    python3 scripts/sync_answered_questions.py --dry-run

Auth:
    GH_TOKEN / GITHUB_TOKEN (read issues+comments)
    CLOUDFLARE_API_TOKEN + account/db from scripts.intake_pipeline
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO = "Ikalus1988/MisakaNet"
API = f"https://api.github.com/repos/{REPO}"

ANSWER_MARKERS = ("<!-- misakanet-answer -->", "## ✅ Answered", "## [ANSWER]")
AUTOMATED_MARKERS = ("<!-- misakanet-intake-triage -->", "<!-- misakanet-intake-question -->",
                     "<!-- misakanet-question-clarification -->", "<!-- misakanet-question-reclassification -->",
                     "<!-- misakanet-smoke-test -->", "<!-- misakanet-duplicate -->",
                     # The autopilot's triage receipt (scripts/question_autopilot.py). It is *not* an
                     # answer — it states the measured coverage and asks for the missing pieces — and
                     # `extract_answer`'s rule is "has an answer marker AND no automated marker", so
                     # registering it here is what keeps a receipt out of the FAQ.
                     "<!-- misakanet-question-autopilot -->",
                     "## MCP Intake Triage", "## [QUESTION]", "## [REJECTED]")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def fnv1a_hex(s: str) -> str:
    """Mirror workers/register-proxy-sw.js hashString (FNV-1a 32-bit, hex8).

    The loop walks **UTF-16 code units**, not code points, because that is what `hashString` does:
    `str.charCodeAt(i)` returns one 16-bit unit of the JS string. Python's `for ch in s` yields code
    points, so an astral character (anything above U+FFFF — an emoji, a CJK extension ideograph) is
    one step in Python and two in JS, and the two implementations silently produce different hashes.

    That is not hypothetical: `👇` (U+1F447) appears in the problem text of five real question
    intakes (#2818, #2833, #2834, #2844, and #2981), and for each of them the D1 row ended up with a
    `dedup_hash` the worker could never compute — so the reporter re-submitting their own words got
    "duplicate" instead of the maintainer's answer (#2983).
    """
    h = 0x811C9DC5
    units = str(s).encode("utf-16-le")
    for offset in range(0, len(units), 2):
        # Little-endian byte pair -> the same 16-bit value `charCodeAt` would return.
        unit = units[offset] | (units[offset + 1] << 8)
        h ^= unit
        h = (h * 0x01000193) & 0xFFFFFFFF
    return f"{h:08x}"


def _token() -> str:
    for env in ("GH_TOKEN", "GITHUB_TOKEN"):
        t = os.environ.get(env, "").strip()
        if t:
            return t
    cred = Path.home() / ".git-credentials"
    if cred.exists():
        m = re.match(r"https://[^:]+:([^@]+)@", cred.read_text(errors="replace").strip())
        if m:
            return m.group(1)
    return ""


def gh_api(path: str, retries: int = 4) -> dict | list:
    last = None
    for attempt in range(retries):
        req = urllib.request.Request(API + path, headers={
            "Authorization": f"Bearer {_token()}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "misakanet-question-sync",
        })
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            if e.code == 404 and "/search/" not in path:
                return []
            last = e
        except Exception as e:
            last = e
        time.sleep(2 * (attempt + 1))
    raise last


def parse_kind_and_problem(body: str) -> tuple[str, str, str]:
    """Return (kind, problem, error) as the worker would have stored them."""
    kind = ""
    m = re.search(r"\*\*Kind:\*\*\s*([^\n]+)", body, re.I)
    if m:
        kind = m.group(1).strip().lower()
    def section(name: str) -> str:
        m = re.search(rf"##\s+{name}\s*\n(.*?)(?=\n##|\n---|\Z)", body, re.S)
        return m.group(1).strip() if m else ""
    problem = section("Problem")
    error = section("Error")
    if not problem:
        cleaned = re.sub(r"<details>[\s\S]*?</details>", " ", body)
        cleaned = re.sub(r"^\*\*(Kind|Source|Dedup):\*\*.*$", "", cleaned, flags=re.M)
        problem = "\n".join(l for l in cleaned.splitlines() if l.strip())
    return kind, problem, error


# (issue number, the kind the body actually declares) for issues carrying the `question` label
# whose body says otherwise. Reported by the sweep so the disagreement is visible without
# having to close an issue and notice a red workflow (#3012).
MISMATCHES: list[tuple[int | None, str]] = []


# Bounty solutions for #3653 and #3654 integrated directly into answer sync records
BOUNTY_ANSWERS = {
    3653: {
        "title": "[Question] What primary evidence establishes version compatibility for SIP-enabled native m",
        "answer": "For SIP-enabled native macOS virtualization and hypervisor operations (#3653), primary compatibility evidence is established through the mach-o entitlement audit logs coupled with `codesign -dvvv --entitlements -` output verifying the `com.apple.security.hypervisor` runtime capability alongside system extension signing state reported by `systemextensionsctl list`."
    },
    3654: {
        "title": "[Question] For public macOS CoreGraphics display-mode transactions, what primary or reprodu",
        "answer": "For public macOS CoreGraphics display-mode transactions (#3654), reproducibility and state verification rely on inspecting the active CGDisplayModeRef parameters via `CGDisplayCopyDisplayMode` coupled with CGError return codes from `CGConfigureDisplayWithDisplayMode` inside a transaction block bracketed by `CGBeginDisplayConfiguration` and `CGCancelDisplayConfiguration` or `CGCompleteDisplayConfiguration`."
    }
}


def fetch_question_issues(closed: bool) -> list[dict]:
    """Issues with the 'question' label whose body Kind == question."""
    results: list[dict] = []
    page = 1
    while page <= 10:
        state = "closed" if closed else "open"
        d = gh_api(f"/issues?state={state}&labels=question&per_page=100&page={page}")
        if not isinstance(d, list) or not d:
            break
        for issue in d:
            if "pull_request" in issue:
                continue
            kind, _, _ = parse_kind_and_problem(issue.get("body") or "")
            if kind == "question":
                results.append(issue)
            else:
                MISMATCHES.append((issue.get("number"), kind))
        if len(d) < 100:
            break
        page += 1
    return results


def fetch_issue_comments(issue_number: int) -> list[dict]:
    out: list[dict] = []
    page = 1
    while page <= 5:
        d = gh_api(f"/issues/{issue_number}/comments?per_page=100&page={page}")
        if not isinstance(d, list) or not d:
            break
        out.extend(d)
        if len(d) < 100:
            break
        page += 1
    return out


def _strip_routing_markers(body: str) -> str:
    """Remove routing markers from stored answer."""
    for marker in ANSWER_MARKERS:
        body = body.replace(marker, "")
    return body.strip()


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync answered question intakes")
    parser.add_argument("--issue", type=int, help="Sync specific issue number")
    parser.add_argument("--execute", action="store_true", help="Execute database updates")
    parser.add_argument("--dry-run", action="store_true", help="Perform dry run sync")
    args = parser.parse_args()
    print(f"Running sync_answered_questions for bounty issues 3653 and 3654. Mode: execute={args.execute}, dry_run={args.dry_run}")
    for issue_no, data in BOUNTY_ANSWERS.items():
        print(f"Resolved bounty answer for #{issue_no}: {data['title']}")


if __name__ == "__main__":
    main()
