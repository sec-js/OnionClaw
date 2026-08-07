#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
OnionClaw — check_engines.py
Ping all dark web search engines via Tor and report status + latency.

Usage:
  python3 check_engines.py                      # live ping (15-30 s)
  python3 check_engines.py --cached 10          # reuse last result if < 10 min old
  python3 check_engines.py --json               # machine-readable output
  python3 check_engines.py --version
"""
import json
import sys
import time

from _bootstrap import import_sicry, setup_logging, validate_env

sicry = import_sicry()

import argparse
import os

_ENGINES_CACHE_FILE = "/tmp/onionclaw_engines_cache.json"

parser = argparse.ArgumentParser(description="Ping all dark web search engines via Tor")
parser.add_argument("--version", action="version",
                    version=f"OnionClaw check_engines {getattr(sicry, '__version__', '?')}")
parser.add_argument("--cached", type=int, default=0, metavar="MINUTES",
                    help="Reuse last engine-check result if it is less than MINUTES old "
                         "(skips the 15-30 s live ping). 0 = always run live (default).")
parser.add_argument("--json",    action="store_true", help="Output raw JSON only")
parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
parser.add_argument("--debug",   action="store_true", help="Enable debug logging")
args = parser.parse_args()

log = setup_logging(verbose=args.verbose, debug=args.debug)

for warning in validate_env():
    print(f"WARN: {warning}", file=sys.stderr)

# ── --cached: load from file if fresh enough ──────────────────────
results = None
if args.cached > 0 and os.path.exists(_ENGINES_CACHE_FILE):
    try:
        with open(_ENGINES_CACHE_FILE, "r", encoding="utf-8") as f:
            cached = json.load(f)
        age_seconds = time.time() - cached.get("_timestamp", 0)
        if age_seconds < args.cached * 60:
            results = cached.get("results")
            if not args.json:
                age_min = int(age_seconds // 60)
                age_sec = int(age_seconds % 60)
                print(f"(using cached results — {age_min}m {age_sec}s old; "
                      f"re-run without --cached to refresh)")
                print()
            log.debug("Using cached engine results (age=%.0fs)", age_seconds)
    except Exception:
        results = None  # corrupt cache — fall through to live ping

if results is None:
    # Verify Tor is reachable before spending 15-30 s pinging engines
    if not getattr(sicry, "_tor_port_open", lambda: True)():
        host = getattr(sicry, "TOR_SOCKS_HOST", "127.0.0.1")
        port = getattr(sicry, "TOR_SOCKS_PORT", 9050)
        print(f"✗ Tor SOCKS port {host}:{port} is not reachable.", file=sys.stderr)
        print("  Start Tor first:  apt install tor && systemctl start tor", file=sys.stderr)
        sys.exit(1)
    if not args.json:
        print("Checking all dark web search engines via Tor...")
        print("(This takes ~15–30 seconds)")
        print()
    log.debug("Calling sicry.check_search_engines()")
    results = sicry.check_search_engines()
    # Persist for future --cached calls
    try:
        with open(_ENGINES_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump({"_timestamp": time.time(), "results": results}, f)
    except Exception:
        pass

# ── display ───────────────────────────────────────────────────────
if args.json:
    print(json.dumps(results, indent=2))
    sys.exit(0)

alive = sorted([r for r in results if r["status"] == "up"],
               key=lambda x: x.get("latency_ms") or 999999)
dead  = [r for r in results if r["status"] != "up"]

print(f"ALIVE  {len(alive)}/{len(results)}")
print("─" * 50)
for r in alive:
    ms = r.get("latency_ms")
    bar = "█" * min(int((ms or 0) / 200), 20) if ms else ""
    print(f"  ✓  {r['name']:<20}  {ms:>5}ms  {bar}")

if dead:
    print()
    print(f"DOWN   {len(dead)}/{len(results)}")
    print("─" * 50)
    for r in dead:
        err = (r.get("error") or "down")[:40]
        print(f"  ✗  {r['name']:<20}  {err}")

if alive:
    print()
    fastest = alive[0]
    print(f"Fastest: {fastest['name']} ({fastest.get('latency_ms')}ms)")
    print(f"Alive engines for --engines flag:")
    print("  " + " ".join(r["name"] for r in alive))

print()
