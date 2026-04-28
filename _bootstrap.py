#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
Shared bootstrap utilities for OnionClaw CLI scripts.

Import at the top of each script instead of repeating the env-load,
sicry-import, and validation boilerplate inline.
"""
from __future__ import annotations

import logging
import os
import re
import sys
from typing import Any
from urllib.parse import urlparse

# ── path & .env setup ────────────────────────────────────────────
SKILL_DIR: str = os.path.dirname(os.path.abspath(__file__))

if SKILL_DIR not in sys.path:
    sys.path.insert(0, SKILL_DIR)

_env_path = os.path.join(SKILL_DIR, ".env")
if os.path.exists(_env_path):
    try:
        from dotenv import load_dotenv  # type: ignore[import-untyped]
        load_dotenv(_env_path, override=False)
    except ImportError:
        pass


# ── logging ───────────────────────────────────────────────────────

def setup_logging(verbose: bool = False, debug: bool = False) -> logging.Logger:
    """Configure root logger and return the onionclaw logger."""
    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        level=level,
        stream=sys.stderr,
    )
    # basicConfig is a no-op if the root logger already has handlers; force level anyway
    logging.root.setLevel(level)
    return logging.getLogger("onionclaw")


# ── sicry import ──────────────────────────────────────────────────

def import_sicry() -> Any:
    """Import and return the sicry module, exiting with a clear error on failure."""
    try:
        import sicry  # type: ignore[import-untyped]
        return sicry
    except Exception as exc:
        msg = str(exc)
        if "sicry" in msg.lower() or "No module named 'sicry'" in msg:
            print(f"ERROR: sicry.py not found in {SKILL_DIR}", file=sys.stderr)
            print("       Make sure sicry.py is in the OnionClaw folder.", file=sys.stderr)
        else:
            print(f"ERROR: failed to import sicry: {exc}", file=sys.stderr)
            print(
                "       Run:  pip install requests[socks] beautifulsoup4 python-dotenv stem",
                file=sys.stderr,
            )
        sys.exit(1)


# ── URL validation ────────────────────────────────────────────────

_VALID_SCHEMES: frozenset[str] = frozenset({"http", "https"})
_MAX_URL_LEN: int = 2048


def validate_url(raw: str) -> str:
    """Normalise and validate a URL for Tor fetch. Returns the normalised URL."""
    if not raw or not raw.strip():
        print("ERROR: URL cannot be empty.", file=sys.stderr)
        sys.exit(1)

    url = raw.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    if len(url) > _MAX_URL_LEN:
        print(f"ERROR: URL exceeds {_MAX_URL_LEN} characters.", file=sys.stderr)
        sys.exit(1)

    try:
        parsed = urlparse(url)
    except ValueError as exc:
        print(f"ERROR: malformed URL: {exc}", file=sys.stderr)
        sys.exit(1)

    if parsed.scheme not in _VALID_SCHEMES:
        print(
            f"ERROR: URL scheme must be http or https, got {parsed.scheme!r}.",
            file=sys.stderr,
        )
        sys.exit(1)

    if not parsed.netloc:
        print("ERROR: URL has no host.", file=sys.stderr)
        sys.exit(1)

    if parsed.username or parsed.password:
        print("ERROR: URL must not contain credentials.", file=sys.stderr)
        sys.exit(1)

    return url


# ── query validation ──────────────────────────────────────────────

_MAX_QUERY_WORDS: int = 5
_MAX_QUERY_LEN: int = 200


def validate_query(query: str, *, warn_word_limit: bool = True) -> str:
    """Validate and normalise a search query. Returns stripped query."""
    q = query.strip()
    if not q:
        print("ERROR: --query cannot be empty.", file=sys.stderr)
        sys.exit(1)

    if len(q) > _MAX_QUERY_LEN:
        print(f"ERROR: query exceeds {_MAX_QUERY_LEN} characters.", file=sys.stderr)
        sys.exit(1)

    if warn_word_limit:
        word_count = len(q.split())
        if word_count > _MAX_QUERY_WORDS:
            print(
                f"WARN: query has {word_count} words; "
                f"≤{_MAX_QUERY_WORDS} keywords works best for dark web engines.",
                file=sys.stderr,
            )

    return q


# ── .env validation ───────────────────────────────────────────────

_VALID_LLM_PROVIDERS: frozenset[str] = frozenset(
    {"openai", "anthropic", "gemini", "ollama", "llamacpp"}
)


def validate_env() -> list[str]:
    """Check .env values at startup and return a list of warning strings."""
    warnings: list[str] = []

    for var, default in (("TOR_SOCKS_PORT", "9050"), ("TOR_CONTROL_PORT", "9051")):
        raw = os.environ.get(var, default)
        try:
            val = int(raw)
            if not (1 <= val <= 65535):
                warnings.append(f"{var}={val} is outside valid port range 1–65535")
        except ValueError:
            warnings.append(f"{var}={raw!r} is not a valid integer")

    raw_timeout = os.environ.get("TOR_TIMEOUT", "45")
    try:
        timeout = int(raw_timeout)
        if timeout < 5:
            warnings.append(f"TOR_TIMEOUT={timeout} is very low; minimum recommended is 10")
    except ValueError:
        warnings.append(f"TOR_TIMEOUT={raw_timeout!r} is not a valid integer")

    provider = os.environ.get("LLM_PROVIDER", "")
    if provider and provider not in _VALID_LLM_PROVIDERS:
        warnings.append(
            f"LLM_PROVIDER={provider!r} is unrecognised; "
            f"valid: {', '.join(sorted(_VALID_LLM_PROVIDERS))}"
        )

    if provider == "openai":
        key = os.environ.get("OPENAI_API_KEY", "")
        if not key or key == "sk-...":
            warnings.append("LLM_PROVIDER=openai but OPENAI_API_KEY is not set")
    elif provider == "anthropic":
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not key or key == "sk-ant-...":
            warnings.append("LLM_PROVIDER=anthropic but ANTHROPIC_API_KEY is not set")
    elif provider == "gemini":
        key = os.environ.get("GEMINI_API_KEY", "")
        if not key or key == "AIza...":
            warnings.append("LLM_PROVIDER=gemini but GEMINI_API_KEY is not set")

    return warnings


# ── LLM prompt injection mitigation ──────────────────────────────

# Patterns that commonly appear in prompt injection attempts embedded in
# scraped content. We replace them with a literal marker so the LLM treats
# them as data rather than instructions.
_INJECTION_RE = re.compile(
    r"(?i)"
    r"(ignore\s+(all\s+)?(previous|prior|above)\s+instructions?"
    r"|you\s+are\s+now\s+"
    r"|disregard\s+(all\s+)?instructions?"
    r"|new\s+system\s+prompt"
    r"|<\s*/?(?:system|user|assistant)\s*>"
    r")"
)

# Role-separator patterns used by many LLM chat templates
_ROLE_COLON_RE = re.compile(
    r"(?m)^(system|user|assistant)\s*:",
    re.IGNORECASE,
)


def sanitise_llm_content(text: str, max_chars: int = 8000) -> str:
    """
    Lightly sanitise scraped dark-web text before injecting into an LLM prompt.

    Neutralises the most common prompt-injection patterns and role-separator
    markers, then truncates to max_chars.  This is defence-in-depth, not a
    guarantee — the LLM system prompt should still instruct the model to treat
    the content block as untrusted third-party data.
    """
    cleaned = _INJECTION_RE.sub("[FILTERED]", text)
    # Insert zero-width space after the colon so the role marker is no longer
    # a valid chat-template separator but is still readable in the report.
    cleaned = _ROLE_COLON_RE.sub(lambda m: m.group(0).replace(":", "​:"), cleaned)
    return cleaned[:max_chars]
