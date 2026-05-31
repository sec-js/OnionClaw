#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
OnionClaw — search.py
Search active dark web search engines simultaneously.

Usage:
  python3 search.py --query "TERM"
  python3 search.py --query "TERM" --max 30
  python3 search.py --query "TERM" --engines Ahmia Tor66 Ahmia-clearnet
  python3 search.py --query "TERM" --json          # machine-readable output only
"""
import json
import sys

from _bootstrap import import_sicry, setup_logging, validate_env, validate_query

sicry = import_sicry()

import argparse

parser = argparse.ArgumentParser(description="Search dark web engines via Tor")
parser.add_argument("--version", action="version",
                    version=f"OnionClaw search {getattr(sicry, '__version__', '?')}")
parser.add_argument("--query",   required=True, help="Search query (≤5 keywords works best)")
parser.add_argument("--max",     type=int, default=20, help="Max results (default 20)")
parser.add_argument("--engines", nargs="*", metavar="ENGINE",
                    help="Specific engines (default: all). E.g: Ahmia Tor66 Ahmia-clearnet")
parser.add_argument("--json",    action="store_true",
                    help="Output raw JSON only — no human-readable headers")
parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
parser.add_argument("--debug",   action="store_true", help="Enable debug logging")
args = parser.parse_args()

log = setup_logging(verbose=args.verbose, debug=args.debug)

for warning in validate_env():
    print(f"WARN: {warning}", file=sys.stderr)

query = validate_query(args.query)

# BUG-4: validate engine names before searching
if args.engines:
    known_names = {e["name"].lower() for e in getattr(sicry, "SEARCH_ENGINES", [])}
    bad   = [n for n in args.engines if n.lower() not in known_names] if known_names else []
    valid = [n for n in args.engines if n.lower() in known_names]     if known_names else args.engines
    if bad and not args.json:
        print(f"WARN: unknown engine name(s): {', '.join(bad)}", file=sys.stderr)
    if not valid:
        print(
            f"ERROR: none of the specified engines are known. "
            f"Known: {', '.join(e['name'] for e in getattr(sicry, 'SEARCH_ENGINES', []))}",
            file=sys.stderr,
        )
        sys.exit(1)
    engines_to_use = valid
else:
    engines_to_use = None

if not args.json:
    print(f'Searching dark web: "{query}"')
    if engines_to_use:
        print(f"Engines : {', '.join(engines_to_use)}")
    else:
        print("Engines : all")
    print()

# Verify Tor is reachable before attempting network calls
if not getattr(sicry, "_tor_port_open", lambda: True)():
    host = getattr(sicry, "TOR_SOCKS_HOST", "127.0.0.1")
    port = getattr(sicry, "TOR_SOCKS_PORT", 9050)
    print(f"✗ Tor SOCKS port {host}:{port} is not reachable.", file=sys.stderr)
    print("  Start Tor first:  apt install tor && systemctl start tor", file=sys.stderr)
    sys.exit(1)

log.debug("Calling sicry.search(query=%r, engines=%r, max_results=%d)", query, engines_to_use, args.max)
results = sicry.search(query, engines=engines_to_use, max_results=args.max)

if args.json:
    print(json.dumps(results, indent=2))
    sys.exit(0)

if not results:
    print("No results found.")
    print("Tip: run check_engines.py first to see which engines are alive.")
    sys.exit(0)

print(f"Found {len(results)} results:\n")
for i, r in enumerate(results, 1):
    print(f"  {i:>2}. [{r.get('engine', '?')}] {r.get('title', '(no title)')}")
    print(f"       {r.get('url', '')}")
