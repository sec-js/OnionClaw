#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
OnionClaw — check_tor.py
Verify Tor is running and return the exit IP address.
"""
import json
import sys

from _bootstrap import import_sicry, setup_logging, validate_env

sicry = import_sicry()

import argparse

parser = argparse.ArgumentParser(
    description="OnionClaw — verify Tor is running and show exit IP")
parser.add_argument("--version", action="version",
                    version=f"OnionClaw check_tor {getattr(sicry, '__version__', '?')}")
parser.add_argument("--json", action="store_true",
                    help="Print only the JSON result, no human-readable output")
parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
parser.add_argument("--debug",   action="store_true", help="Enable debug logging")
args = parser.parse_args()

log = setup_logging(verbose=args.verbose, debug=args.debug)

for warning in validate_env():
    print(f"WARN: {warning}", file=sys.stderr)

log.debug("Calling sicry.check_tor()")
result = sicry.check_tor()

if args.json:
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["tor_active"] else 1)

if result["tor_active"]:
    print(f"✓ Tor active")
    print(f"  Exit IP  : {result['exit_ip']}")
else:
    print(f"✗ Tor NOT active")
    print(f"  Error    : {result['error']}")
    print()
    print("  Start Tor first:")
    print("    Linux : apt install tor && tor &")
    print("    macOS : brew install tor && tor &")
    sys.exit(1)

print()
print(json.dumps(result, indent=2))
