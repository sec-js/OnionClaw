#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
draft_changelog.py — generate CHANGELOG draft entries from git log.

Usage:
  python3 scripts/draft_changelog.py                  # since last tag
  python3 scripts/draft_changelog.py --since v2.1.0   # since specific tag
  python3 scripts/draft_changelog.py --output CHANGELOG.md  # append to file

Commit prefixes recognised: feat, fix, chore, docs, refactor, test, ci, perf.
Commits without a recognised prefix are listed under "Other".
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from datetime import datetime
from typing import Optional


_PREFIX_RE = re.compile(
    r"^(feat|fix|chore|docs|refactor|test|ci|perf)(?:\([^)]*\))?!?:\s*", re.IGNORECASE
)

_SECTION_LABELS: dict[str, str] = {
    "feat":     "### Added",
    "fix":      "### Fixed",
    "perf":     "### Performance",
    "refactor": "### Changed",
    "docs":     "### Documentation",
    "test":     "### Tests",
    "ci":       "### CI",
    "chore":    "### Chores",
    "other":    "### Other",
}


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args], capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def _latest_tag() -> Optional[str]:
    try:
        return _git("describe", "--tags", "--abbrev=0")
    except subprocess.CalledProcessError:
        return None


def _commits_since(ref: Optional[str]) -> list[tuple[str, str]]:
    """Return list of (hash, subject) since ref (or all commits if ref is None)."""
    range_arg = f"{ref}..HEAD" if ref else "HEAD"
    try:
        raw = _git("log", range_arg, "--pretty=format:%H\t%s")
    except subprocess.CalledProcessError:
        return []
    if not raw:
        return []
    entries: list[tuple[str, str]] = []
    for line in raw.splitlines():
        parts = line.split("\t", 1)
        if len(parts) == 2:
            entries.append((parts[0][:8], parts[1]))
    return entries


def _categorise(commits: list[tuple[str, str]]) -> dict[str, list[str]]:
    buckets: dict[str, list[str]] = {k: [] for k in _SECTION_LABELS}
    for sha, subject in commits:
        m = _PREFIX_RE.match(subject)
        if m:
            key = m.group(1).lower()
            message = subject[m.end():]
        else:
            key = "other"
            message = subject
        entry = f"- {message} ({sha})"
        buckets.setdefault(key, []).append(entry)
    return buckets


def _render(version: str, buckets: dict[str, list[str]]) -> str:
    date_str = datetime.utcnow().strftime("%Y-%m-%d")
    lines: list[str] = [f"## [{version}] — {date_str}", ""]
    for key, label in _SECTION_LABELS.items():
        entries = buckets.get(key, [])
        if entries:
            lines.append(label)
            lines.extend(entries)
            lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Draft CHANGELOG entries from git log")
    parser.add_argument("--since", default=None, metavar="TAG",
                        help="Start from this tag/ref (default: latest tag)")
    parser.add_argument("--version", default=None,
                        help="Version label for the new entry (default: next patch bump)")
    parser.add_argument("--output", default=None, metavar="FILE",
                        help="Prepend draft to this file instead of printing to stdout")
    args = parser.parse_args()

    since = args.since or _latest_tag()
    commits = _commits_since(since)
    if not commits:
        print(
            f"No commits found since {since!r}." if since else "No commits found.",
            file=sys.stderr,
        )
        sys.exit(0)

    if args.version:
        version = args.version
    elif since:
        # bump patch version from the last tag
        parts = since.lstrip("v").split(".")
        try:
            parts[-1] = str(int(parts[-1]) + 1)
            version = "v" + ".".join(parts)
        except (ValueError, IndexError):
            version = "UNRELEASED"
    else:
        version = "UNRELEASED"

    buckets = _categorise(commits)
    draft = _render(version, buckets)

    if args.output:
        try:
            try:
                with open(args.output, "r", encoding="utf-8") as fh:
                    existing = fh.read()
            except FileNotFoundError:
                existing = ""
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(draft + "\n\n" + existing)
            print(f"Prepended {len(commits)} entries to {args.output}")
        except OSError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(draft)


if __name__ == "__main__":
    main()
