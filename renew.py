#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
OnionClaw — renew.py
Rotate the Tor circuit and get a new exit node / identity.
"""
import json
import sys

from _bootstrap import import_sicry, setup_logging, validate_env

sicry = import_sicry()

import argparse

parser = argparse.ArgumentParser(
    description="OnionClaw — rotate Tor circuit and get a new exit identity")
parser.add_argument("--version", action="version",
                    version=f"OnionClaw renew {getattr(sicry, '__version__', '?')}")
parser.add_argument("--json",    action="store_true",
                    help="Print only the JSON result, no human-readable output")
parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
parser.add_argument("--debug",   action="store_true", help="Enable debug logging")
args = parser.parse_args()

log = setup_logging(verbose=args.verbose, debug=args.debug)

for warning in validate_env():
    print(f"WARN: {warning}", file=sys.stderr)

if not args.json:
    print("Rotating Tor circuit...")

log.debug("Calling sicry.renew_identity()")
result = sicry.renew_identity()

if args.json:
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["success"] else 1)

if result["success"]:
    print("✓ Identity renewed — new Tor circuit established")
    print("  The next request will use a different exit node.")
else:
    print(f"✗ Renew failed: {result['error']}")
    print()
    print("  Common causes:")
    print("  1. ControlPort 9051 not enabled in torrc")
    print("     → Add: ControlPort 9051  and  CookieAuthentication 1")
    print("  2. TOR_DATA_DIR not set in .env")
    print("     → Set TOR_DATA_DIR=/tmp/tor_data  (your Tor DataDirectory)")
    print("  3. TOR_CONTROL_PASSWORD wrong (if HashedControlPassword is set)")
    sys.exit(1)

print()
print(json.dumps(result, indent=2))
