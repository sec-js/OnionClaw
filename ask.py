#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
OnionClaw — ask.py
Analyse dark web content with an LLM and get a structured OSINT report.

Usage:
  python3 ask.py --query "QUERY" --mode MODE --content "RAW TEXT"
  python3 ask.py --query "QUERY" --mode MODE --file /path/to/content.txt
  echo "content" | python3 ask.py --query "QUERY" --mode MODE

Modes: threat_intel (default), ransomware, personal_identity, corporate
"""
import os
import sys

from _bootstrap import (
    SKILL_DIR,
    import_sicry,
    sanitise_llm_content,
    setup_logging,
    validate_env,
)

sicry = import_sicry()

import argparse

MODES = ["threat_intel", "ransomware", "personal_identity", "corporate"]

parser = argparse.ArgumentParser(description="OSINT analysis of dark web content")
parser.add_argument("--version", action="version",
                    version=f"OnionClaw ask {getattr(sicry, '__version__', '?')}")
parser.add_argument("--query",   default="", help="Investigation query / topic")
parser.add_argument("--mode",    default="threat_intel", choices=MODES,
                    help="Analysis mode (default: threat_intel)")
parser.add_argument("--content", default=None, help="Content to analyse (inline string)")
parser.add_argument("--file",    default=None, help="File containing content to analyse")
parser.add_argument("--custom",  default="", help="Custom instructions appended to the mode prompt")
parser.add_argument("--no-sanitise", action="store_true",
                    help="Skip prompt-injection sanitisation of input content")
parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
parser.add_argument("--debug",   action="store_true", help="Enable debug logging")
args = parser.parse_args()

log = setup_logging(verbose=args.verbose, debug=args.debug)

for warning in validate_env():
    print(f"WARN: {warning}", file=sys.stderr)

# ── Load content ──────────────────────────────────────────────────
if args.file:
    try:
        with open(args.file, "r", errors="replace") as f:
            content = f.read()
        print(f"Content: loaded from {args.file} ({len(content)} chars)")
    except OSError as e:
        print(f"ERROR: cannot read file: {e}")
        sys.exit(1)
elif args.content:
    content = args.content
    print(f"Content: {len(content)} chars (inline)")
elif not sys.stdin.isatty():
    content = sys.stdin.read()
    print(f"Content: {len(content)} chars (stdin)")
else:
    print("ERROR: provide content via --content, --file, or stdin")
    parser.print_help()
    sys.exit(1)

if not content.strip():
    print("ERROR: content is empty")
    sys.exit(1)

# Sanitise scraped content to mitigate prompt injection from dark web data
max_chars = int(os.environ.get("SICRY_MAX_CHARS", "8000"))
if args.no_sanitise:
    log.debug("Prompt-injection sanitisation disabled via --no-sanitise")
    safe_content = content[:max_chars]
else:
    safe_content = sanitise_llm_content(content, max_chars=max_chars)
    if safe_content != content[:max_chars]:
        log.info("Content sanitised: potential prompt-injection patterns filtered")

print(f"Query  : {args.query or '(none)'}")
print(f"Mode   : {args.mode}")
if args.custom:
    print(f"Custom : {args.custom[:80]}")
print()
print("Analysing via LLM...")
print()

log.debug("Calling sicry.ask(mode=%r, query=%r)", args.mode, args.query)
report = sicry.ask(
    safe_content,
    query=args.query,
    mode=args.mode,
    custom_instructions=args.custom,
)

if report.startswith("[SICRY:"):
    print("✗ LLM error:", report)
    print()
    print("  Set LLM_PROVIDER and API key in", os.path.join(SKILL_DIR, ".env"))
    print("  Options: LLM_PROVIDER=openai|anthropic|gemini|ollama|llamacpp")
    sys.exit(1)

print(report)
