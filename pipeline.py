#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
OnionClaw — pipeline.py v2.0.0
Full OSINT pipeline: refine → check engines → search → filter → scrape → ask.
Includes: SQLite resume checkpoints, confidence scores, STIX/CSV/JSON/MD output,
          watch/alert mode, no-LLM mode via analyze_nollm(), mode routing.

Usage:
  python3 pipeline.py --query "INVESTIGATION TOPIC"
  python3 pipeline.py --query "QUERY" --mode ransomware --format stix --out bundle.json
  python3 pipeline.py --query "QUERY" --mode corporate --max 50 --scrape 12
  python3 pipeline.py --query "QUERY" --no-llm --confidence
  python3 pipeline.py --query "QUERY" --watch --interval 4
  python3 pipeline.py --watch-check
  python3 pipeline.py --query "QUERY" --resume <job_id>
  python3 pipeline.py --interactive
"""
from __future__ import annotations

import argparse
import json
import logging as _logging
import os
import sys
import time as _time
import uuid
from typing import Any

from _bootstrap import (
    SKILL_DIR as _skill_dir,
    import_sicry,
    sanitise_llm_content,
    setup_logging,
    validate_env,
    validate_query,
)

sicry = import_sicry()

MODES: list[str] = ["threat_intel", "ransomware", "personal_identity", "corporate"]
TOTAL: int = 7

_log = _logging.getLogger("onionclaw")


# ── Checkpoint / display helpers ──────────────────────────────────


def _step_header(n: int, total: int, label: str) -> None:
    print(f"\n[{n}/{total}] {label}")
    print("─" * 55)


def _save_checkpoint(step: str, data: Any, checkpoint: dict, job_id: str) -> None:
    try:
        from sicry import _db  # type: ignore[attr-defined]
        checkpoint.setdefault("steps", {})[step] = True
        checkpoint.setdefault("data", {})[step] = data
        _db().cache_set(f"pipeline_checkpoint:{job_id}", "pipeline", checkpoint)
    except Exception:
        pass


def _ckpt_get(step: str, checkpoint: dict) -> Any:
    return checkpoint.get("data", {}).get(step)


# ── Pipeline step functions ───────────────────────────────────────


def run_step1_verify_tor(sicry_mod: Any) -> dict[str, Any]:
    """Step 1: Verify Tor is active. Returns status dict; exits on failure."""
    status: dict[str, Any] = sicry_mod.check_tor()
    if not status["tor_active"]:
        print(f"✗ Tor is not active: {status['error']}")
        print("  Start Tor first:  apt install tor && tor &")
        sys.exit(1)
    print(f"✓ Tor active | exit IP: {status['exit_ip']}")
    pool_sz: int = getattr(sicry_mod, "TOR_POOL_SIZE", 0)
    if pool_sz > 0:
        pool_base: int = getattr(sicry_mod, "TOR_POOL_BASE_PORT", 9060)
        print(
            f"  TorPool: {pool_sz} circuits active "
            f"(SICRY_POOL_SIZE={pool_sz}, socks ports {pool_base}–{pool_base + pool_sz - 1})"
        )
    return status


def run_step2_check_engines(
    sicry_mod: Any, args: argparse.Namespace
) -> list[str]:
    """Step 2: Health-check engines or validate user-supplied --engines list."""
    live_names: list[str] = args.engines or []
    if not live_names:
        _step_header(2, TOTAL, "Check which search engines are alive")
        engine_status: list[dict[str, Any]] = sicry_mod.check_search_engines()
        alive = sorted(
            [e for e in engine_status if e["status"] == "up"],
            key=lambda x: x.get("latency_ms") or 999999,
        )
        dead = [e for e in engine_status if e["status"] != "up"]
        live_names = [e["name"] for e in alive]
        total_engines = len(engine_status)
        print(f"✓ {len(alive)}/{total_engines} engines alive  |  {len(dead)} down")
        if alive:
            rel = alive[0].get("reliability")
            rel_str = f"  reliability={rel:.0%}" if rel is not None else ""
            print(f"  Fastest: {alive[0]['name']} ({alive[0].get('latency_ms')}ms){rel_str}")
        if not alive:
            print("✗ No engines alive — check your Tor connection")
            sys.exit(1)
        if args.mode in MODES:
            mc: dict[str, Any] = sicry_mod.mode_config(args.mode)
            mode_engines: list[str] = mc.get("engines") or []
            if mode_engines:
                filtered = [n for n in live_names if n in mode_engines]
                if filtered:
                    print(
                        f"  Mode '{args.mode}' filter: using {len(filtered)} of {len(live_names)} engines"
                    )
                    live_names = filtered
                else:
                    print(f"  Mode '{args.mode}': no preferred engines alive — using all")
    else:
        known: set[str] = {e["name"].lower() for e in getattr(sicry_mod, "SEARCH_ENGINES", [])}
        bad = [n for n in live_names if n.lower() not in known] if known else []
        if bad:
            print(f"WARN: unknown engine(s): {', '.join(bad)} — will be ignored by search()")
        if args.mode and args.mode != "threat_intel":
            mc = sicry_mod.mode_config(args.mode)
            mode_engines = mc.get("engines") or []
            if mode_engines:
                print(
                    f"  NOTE: --engines overrides mode '{args.mode}' routing "
                    f"(mode default: {', '.join(mode_engines)})"
                )
        _step_header(2, TOTAL, f"Using specified engines: {', '.join(live_names)}")
    return live_names


def run_step3_refine_query(
    sicry_mod: Any,
    args: argparse.Namespace,
    checkpoint: dict,
    job_id: str,
) -> str:
    """Step 3: Optionally refine query via LLM. Returns refined query string."""
    raw_query: str = args.query
    if not _ckpt_get("__meta__", checkpoint):
        _save_checkpoint(
            "__meta__", {"query": raw_query, "mode": args.mode}, checkpoint, job_id
        )
        refined: str = raw_query
        print(f"\n[skip 3/{TOTAL}] Query refinement skipped (--no-llm)")
        print(f"    Query: {refined}")
    else:
        cached_refined: str = _ckpt_get("refine", checkpoint)
        if cached_refined:
            refined = cached_refined
            print(f"\n[3/{TOTAL}] Query refinement (from checkpoint)")
            print(f"    Query: {refined}")
        else:
            _step_header(3, TOTAL, "Refine query")
            refined = sicry_mod.refine_query(raw_query)
            if refined != raw_query:
                print(f"  Original : {raw_query}")
                print(f"  Refined  : {refined}")
            else:
                print(f"  Query    : {refined}  (no LLM key — using as-is)")
            _save_checkpoint("refine", refined, checkpoint, job_id)
    return refined


def run_step4_search(
    sicry_mod: Any,
    args: argparse.Namespace,
    live_names: list[str],
    refined: str,
    checkpoint: dict,
    job_id: str,
) -> list[dict[str, Any]]:
    """Step 4: Search engines. Returns raw_results list."""
    _step_header(4, TOTAL, f'Search {len(live_names)} engines for: "{refined}"')
    mc_s4: dict[str, Any] = sicry_mod.mode_config(args.mode)
    s4_seeds: list[str] = mc_s4.get("extra_seeds") or []
    if s4_seeds:
        seed_preview = ", ".join(s4_seeds[:3])
        seed_more = f" … +{len(s4_seeds) - 3} more" if len(s4_seeds) > 3 else ""
        print(f"  + {len(s4_seeds)} mode seed onion(s): {seed_preview}{seed_more}")
    cached: list[dict[str, Any]] = _ckpt_get("search", checkpoint)
    if cached:
        raw_results: list[dict[str, Any]] = cached
        print(f"  (from checkpoint: {len(raw_results)} results)")
    else:
        raw_results = sicry_mod.search(
            refined,
            engines=live_names,
            max_results=args.max,
            mode=args.mode,
            _use_cache=not args.no_cache,
        )
        _save_checkpoint("search", raw_results, checkpoint, job_id)
    print(f"✓ {len(raw_results)} raw results (deduplicated)")
    if not raw_results:
        print("No results found. Try a broader query or different engines.")
        sys.exit(0)
    for r in raw_results[:5]:
        conf_str = (
            f"  [conf={r.get('confidence', 0):.2f}]"
            if args.confidence and "confidence" in r
            else ""
        )
        print(f"  [{r.get('engine', '?')}]{conf_str} {r.get('title', '?')[:65]}")
    if len(raw_results) > 5:
        print(f"  ... and {len(raw_results) - 5} more")
    return raw_results


def run_step5_filter(
    sicry_mod: Any,
    args: argparse.Namespace,
    raw_results: list[dict[str, Any]],
    refined: str,
    checkpoint: dict,
    job_id: str,
    no_llm: bool = False,
) -> list[dict[str, Any]]:
    """Step 5: Filter/rank results. Returns best list."""
    if no_llm:
        best: list[dict[str, Any]] = sicry_mod.score_results(refined, raw_results)[:20]
        print(f"\n[5/{TOTAL}] Ranked top {len(best)} results by BM25 confidence (--no-llm)")
        if args.confidence and best:
            for i, r in enumerate(best[:10], 1):
                print(
                    f"  {i:>3}. [conf={r.get('confidence', 0):.4f}] "
                    f"[{r.get('engine', '?')}] {r.get('title', '?')[:55]}"
                )
    else:
        cached_best: list[dict[str, Any]] = _ckpt_get("filter", checkpoint)
        if cached_best:
            best = cached_best
            print(f"\n[5/{TOTAL}] Result filtering (from checkpoint: {len(best)} results)")
        else:
            _step_header(5, TOTAL, "Filter to most relevant results")
            best = sicry_mod.filter_results(refined, raw_results)
            print(f"✓ {len(best)} most relevant results selected")
            if len(best) == len(raw_results[:20]):
                print("  (no LLM key — using top 20 by position)")
            _save_checkpoint("filter", best, checkpoint, job_id)
    return best


def run_step6_scrape(
    sicry_mod: Any,
    args: argparse.Namespace,
    best: list[dict[str, Any]],
    refined: str,
    checkpoint: dict,
    job_id: str,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Step 6: Batch-scrape pages. Returns (best, pages); best may be re-scored."""
    scrape_count: int = min(args.scrape, len(best))
    _step_header(6, TOTAL, f"Batch-scrape top {scrape_count} pages concurrently")
    cached_pages: dict[str, str] = _ckpt_get("scrape", checkpoint)
    if cached_pages:
        pages: dict[str, str] = cached_pages
        print(f"  (from checkpoint: {len(pages)} pages)")
    else:
        pages = sicry_mod.scrape_all(best[:scrape_count], max_workers=5)
        _save_checkpoint("scrape", pages, checkpoint, job_id)
    print(f"✓ {len(pages)}/{scrape_count} pages scraped successfully")
    if len(pages) < scrape_count:
        print(
            f"  {scrape_count - len(pages)} pages were unreachable "
            f"(hidden services can be offline)"
        )
    total_chars: int = sum(len(v) for v in pages.values())
    print(f"  Total content: {total_chars:,} chars")
    # BUG-3: re-score best using scraped page content for richer BM25 weighting
    if best and pages:
        best = sicry_mod.score_results(refined, best, texts=pages)
        scraped_urls: set[str] = set(pages.keys())
        for br in best:
            if br.get("url") not in scraped_urls:
                br.setdefault("_no_content", True)
    if not pages:
        if scrape_count > 0:
            print("No pages could be scraped — all hidden services unreachable.")
            sys.exit(0)
        else:
            # [BUG-NEW v2.1.13] --scrape 0: warn and continue so output file is written
            print(
                "WARN: --scrape 0: no pages scraped — "
                "output file will contain search results only.",
                file=sys.stderr,
            )
    return best, pages


def run_step7_analyze(
    sicry_mod: Any,
    args: argparse.Namespace,
    pages: dict[str, str],
    best: list[dict[str, Any]],
    refined: str,
    checkpoint: dict,
    job_id: str,
    no_llm: bool = False,
) -> tuple[str, str]:
    """Step 7: LLM/no-LLM analysis. Returns (report, header_label)."""
    combined: str = "\n\n".join(
        f"[SOURCE: {url}]\n{text}" for url, text in pages.items()
    )
    max_chars: int = int(os.environ.get("SICRY_MAX_CHARS", "8000"))
    combined_safe: str = sanitise_llm_content(
        combined, max_chars=max_chars * max(1, len(pages))
    )
    if combined_safe != combined:
        _log.info("Pipeline content sanitised before LLM submission")
    report: str
    header_label: str
    if no_llm:
        _step_header(7, TOTAL, "No-LLM entity/keyword extraction (analyze_nollm)")
        report = sicry_mod.analyze_nollm(combined_safe, query=refined)
        header_label = "ANALYSIS REPORT (no-LLM)"
    else:
        cached_report: str = _ckpt_get("ask", checkpoint)
        if cached_report:
            report = cached_report
            print(f"\n[7/{TOTAL}] LLM analysis (from checkpoint)")
            header_label = "INVESTIGATION REPORT"
        else:
            _step_header(7, TOTAL, f"OSINT analysis — mode: {args.mode}")
            report = sicry_mod.ask(
                combined_safe,
                query=refined,
                mode=args.mode,
                custom_instructions=args.custom,
            )
            _save_checkpoint("ask", report, checkpoint, job_id)
            header_label = "INVESTIGATION REPORT"
    return report, header_label


def _write_output(
    sicry_mod: Any,
    args: argparse.Namespace,
    best: list[dict[str, Any]],
    pages: dict[str, str],
    report: str,
    refined: str,
    raw_query: str,
    job_id: str,
    no_llm: bool = False,
) -> None:
    """Write the pipeline output to --out or --output-dir if set."""
    if not (args.out or args.output_dir):
        return
    fmt: str = args.format
    try:
        out_path: str
        if args.output_dir:
            os.makedirs(args.output_dir, exist_ok=True)
            ext_map = {"json": "json", "csv": "csv", "stix": "json", "misp": "json", "md": "md"}
            out_path = os.path.join(
                args.output_dir, f"{job_id}.{ext_map.get(fmt, 'txt')}"
            )
        else:
            out_path = args.out
        out_payload: str
        if fmt == "json":
            out_payload = json.dumps(
                {
                    "query": args.query,
                    "refined_query": None if no_llm else refined,
                    "mode": args.mode,
                    "results": best,
                    "report": report,
                    "job_id": job_id,
                },
                indent=2,
            )
        elif fmt == "csv":
            out_payload = sicry_mod.to_csv(best)
        elif fmt == "stix":
            out_payload = json.dumps(
                sicry_mod.to_stix(best, query=refined, report_text=report), indent=2
            )
        elif fmt == "misp":
            out_payload = json.dumps(
                sicry_mod.to_misp(
                    best,
                    query=refined,
                    report_text=report,
                    threat_level=args.misp_threat_level,
                    distribution=args.misp_distribution,
                ),
                indent=2,
            )
        else:  # md (default)
            import datetime

            combined_text: str = "\n\n".join(pages.values()) if pages else ""
            kw_list: list[str] = sicry_mod.extract_keywords(combined_text, top_n=15)
            keywords: str = ", ".join(kw_list)
            out_payload = (
                f"# OnionClaw OSINT Report\n\n"
                f"**Query:** {args.query}  \n"
                + (
                    f"**Refined:** {refined}  \n"
                    if not no_llm and refined != raw_query
                    else ""
                )
                + f"**Mode:** {args.mode}  \n"
                f"**Date:** {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}  \n"
                f"**Job ID:** {job_id}  \n\n"
                f"---\n\n"
                f"{report}\n\n"
                f"---\n\n"
                f"## Top Keywords\n\n{keywords}\n\n"
                f"## Sources ({len(best)} results)\n\n"
                + "\n".join(
                    f"- [{r.get('title', '(no title)')[:80]}]({r['url']})"
                    + (f" — conf={r.get('confidence', 0):.2f}" if args.confidence else "")
                    for r in best
                )
            )
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(out_payload)
        print(f"\nReport saved to: {out_path}  (format: {fmt})")
    except Exception as we:
        print(f"\nERROR: could not write output file: {we}", file=sys.stderr)
        sys.exit(1)


# ── Main entry point ──────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="pipeline",
        description="OnionClaw full dark web OSINT pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 pipeline.py --query "ransomware data leak" --mode ransomware
  python3 pipeline.py --query "QUERY" --no-llm --confidence
  python3 pipeline.py --query "QUERY" --format stix --out bundle.json
  python3 pipeline.py --query "QUERY" --watch --interval 6
  python3 pipeline.py --watch-check
  python3 pipeline.py --query "QUERY" --resume abc123
  python3 pipeline.py --interactive
  python3 pipeline.py --query "QUERY" --format misp --out event.json --misp-threat-level 1
  python3 pipeline.py --watch-list
  python3 pipeline.py --modes
  python3 pipeline.py --engine-stats

TorPool (multi-circuit Tor):
  Set SICRY_POOL_SIZE=N in .env to use N isolated Tor circuits (see .env.example).
  pipeline.py prints pool status at step 1 when SICRY_POOL_SIZE > 0.
    """,
    )
    parser.add_argument(
        "--version", action="version",
        version=f"OnionClaw pipeline {getattr(sicry, '__version__', '?')}"
    )
    parser.add_argument(
        "--query", default=None,
        help="Investigation topic (required unless --watch-check or --interactive)"
    )
    parser.add_argument(
        "--mode", default="threat_intel", choices=MODES,
        help="Analysis mode — routes to optimal engines (default: threat_intel)"
    )
    parser.add_argument("--max", type=int, default=30, help="Max raw search results (default 30)")
    parser.add_argument("--scrape", type=int, default=8, help="Pages to batch-scrape (default 8)")
    parser.add_argument(
        "--custom", default="", help="Custom LLM instructions appended to mode prompt"
    )
    parser.add_argument("--out", default=None, help="Write final report to this file")
    parser.add_argument("--engines", nargs="*", metavar="ENGINE",
                        help="Limit search to specific engines")
    parser.add_argument(
        "--no-llm", action="store_true",
        help="Skip LLM steps — use analyze_nollm() for structured entity/keyword extraction"
    )
    parser.add_argument(
        "--confidence", action="store_true",
        help="Show BM25 confidence scores next to each search result"
    )
    parser.add_argument(
        "--format", choices=["md", "json", "csv", "stix", "misp"], default="md",
        help="Output format for --out (default: md)"
    )
    parser.add_argument(
        "--clear-cache", action="store_true",
        help="Clear all cached fetch results before running"
    )
    parser.add_argument(
        "--check-update", action="store_true",
        help="Check GitHub for the latest OnionClaw release and exit"
    )
    parser.add_argument(
        "--watch", action="store_true",
        help="Register this query as a watch/alert job and exit"
    )
    parser.add_argument(
        "--interval", type=float, default=6.0,
        help="Watch re-check interval in hours (default: 6, requires --watch)"
    )
    parser.add_argument("--watch-check", action="store_true",
                        help="Run all due watch jobs now and exit")
    parser.add_argument("--watch-list", action="store_true",
                        help="List all active watch jobs and exit")
    parser.add_argument("--watch-disable", default=None, metavar="JOB_ID",
                        help="Disable a watch job by ID and exit")
    parser.add_argument(
        "--resume", default=None, metavar="JOB_ID",
        help="Resume a previous pipeline run from its SQLite checkpoint"
    )
    parser.add_argument(
        "--interactive", action="store_true",
        help="Interactive drill-down mode — ask follow-up questions after the report"
    )
    parser.add_argument("--no-cache", action="store_true",
                        help="Skip search cache, force live queries")
    parser.add_argument("--modes", action="store_true",
                        help="List all modes and their engine routing, then exit")
    parser.add_argument("--engine-stats", action="store_true",
                        help="Print per-engine reliability / latency table and exit")
    parser.add_argument(
        "--watch-daemon", action="store_true",
        help="Run watch daemon as a foreground loop (Ctrl+C to stop)"
    )
    parser.add_argument(
        "--daemon-poll", type=int, default=None, metavar="SECONDS",
        help="Daemon poll interval in seconds (default: 360). Overrides --interval for daemon tick rate."
    )
    parser.add_argument(
        "--misp-threat-level", type=int, default=2, choices=[1, 2, 3, 4],
        help="MISP threat level (1=High 2=Medium 3=Low 4=Undefined; default 2)"
    )
    parser.add_argument(
        "--misp-distribution", type=int, default=0, choices=[0, 1, 2, 3, 4, 5],
        help="MISP distribution setting (0=Organisation only … 5=All; default 0)"
    )
    parser.add_argument(
        "--output-dir", default=None, metavar="DIR",
        help="Write output to DIR/<job_id>.<ext> instead of --out (batch-friendly)"
    )
    parser.add_argument("--watch-clear-all", action="store_true",
                        help="Disable ALL active watch jobs at once and exit")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Check Tor + engines then print execution plan without searching or scraping"
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    setup_logging(verbose=args.verbose, debug=args.debug)

    for env_warn in validate_env():
        print(f"WARN: {env_warn}", file=sys.stderr)

    # ── BUG-4: warn if --interval used without --watch ────────────
    if args.interval != 6.0 and not args.watch and not args.watch_check:
        print("WARN: --interval only takes effect with --watch. Ignoring.", file=sys.stderr)

    # ── Validate --out path early (before any network calls) ──────
    if args.out:
        out_parent: str = os.path.dirname(os.path.abspath(args.out)) or "."
        if not os.path.isdir(out_parent):
            print(f"ERROR: --out directory does not exist: {out_parent}", file=sys.stderr)
            sys.exit(1)
        if not os.access(out_parent, os.W_OK):
            print(f"ERROR: --out directory is not writable: {out_parent}", file=sys.stderr)
            sys.exit(1)

    # ── pre-run actions ───────────────────────────────────────────
    if args.clear_cache:
        n: int = sicry.clear_cache()
        print(f"[cache] Cleared {n} cached result(s).")

    if args.check_update:
        u: dict[str, Any] = sicry.check_update()
        if u["error"] and not u["latest"]:
            print(f"Update check failed: {u['error']}")
        elif u["up_to_date"]:
            print(f"OnionClaw {u['current']} is up-to-date.")
        else:
            print(f"Update available: v{u['current']} → v{u['latest']}")
            if u["url"]:
                print(f"  Release notes : {u['url']}")
            print(f"  Upgrade       : git -C {_skill_dir} pull")
            print(f"                  python3 {os.path.join(_skill_dir, 'sync_sicry.py')}")
        try:
            import urllib.request
            sicry_api = "https://api.github.com/repos/JacobJandon/Sicry/tags?per_page=1"
            with urllib.request.urlopen(sicry_api, timeout=4) as sr:
                stags = json.loads(sr.read())
            if stags:
                def _sver(v: str) -> tuple:
                    try:
                        return tuple(int(x) for x in v.lstrip("v").split("."))
                    except Exception:
                        return (0,)
                latest_sicry = max(stags, key=lambda t: _sver(t["name"]))["name"].lstrip("v")
                bundled = getattr(sicry, "__version__", "0.0.0")
                if _sver(bundled) < _sver(latest_sicry):
                    print(
                        f"NOTICE: bundled sicry.py (v{bundled}) is behind upstream "
                        f"SICRY™ (v{latest_sicry})."
                    )
                    print(f"        Run: python3 {os.path.join(_skill_dir, 'sync_sicry.py')}")
        except Exception:
            pass
        sys.exit(0)

    # ── standalone: watch-check ───────────────────────────────────
    if args.watch_check:
        print("[watch-check] Running all due watch jobs…")
        alerts: list[dict[str, Any]] = sicry.watch_check()
        n_saved: int = 0
        if not alerts:
            print("  No due jobs.")
            if args.output_dir:
                print("  --output-dir: no files written (no due jobs).")
        else:
            import json as _json
            for a in alerts:
                new_flag: str = "[NEW]" if a.get("new") else "[unchanged]"
                last_run = a.get("last_run")
                last_str: str = (
                    _time.strftime("%Y-%m-%d %H:%M", _time.localtime(last_run))
                    if last_run
                    else "never"
                )
                interval_h = a.get("interval_hours", 6)
                if last_run:
                    next_ts = last_run + interval_h * 3600
                    next_str: str = _time.strftime(
                        "%Y-%m-%d %H:%M", _time.localtime(next_ts)
                    )
                else:
                    next_str = "overdue"
                print(
                    f"  {new_flag} [{a['job_id']}] {a.get('result_count', 0)} results  "
                    f"last={last_str}  next={next_str}"
                )
                print(f"       query: {a.get('query')!r}")
                if a.get("new") and a.get("results"):
                    for tr in a["results"][:5]:
                        conf = tr.get("confidence")
                        tc: str = f"[conf={conf:.2f}] " if conf is not None else ""
                        print(f"         {tc}{tr.get('title', '(no title)')[:70]}")
                        print(f"           {tr.get('url', '')}")
                if args.output_dir:
                    try:
                        os.makedirs(args.output_dir, exist_ok=True)
                        wout: str = os.path.join(args.output_dir, f"{a['job_id']}.json")
                        with open(wout, "w") as wf:
                            _json.dump(
                                {
                                    "job_id": a["job_id"],
                                    "query": a.get("query", ""),
                                    "new": a.get("new", False),
                                    "result_count": a.get("result_count", 0),
                                    "mode": a.get("mode", "threat_intel"),
                                    "last_run": last_str,
                                    "last_run_ts": last_run,
                                    "next_run": next_str,
                                    "results": a.get("results") or [],
                                },
                                wf,
                                indent=2,
                            )
                        print(f"       saved → {wout}")
                        n_saved += 1
                    except Exception as wce:
                        print(f"\nERROR: could not write output file: {wce}", file=sys.stderr)
                        sys.exit(1)
            if args.output_dir:
                print(f"  Saved {n_saved} file(s) to {args.output_dir!r}")
        due_ids: set[str] = {a["job_id"] for a in alerts}
        waiting = [j for j in sicry.watch_list() if j["id"] not in due_ids]
        if waiting:
            print()
            print(f"Waiting jobs ({len(waiting)}) — not yet due:")
            for wj in waiting:
                wlast = wj.get("last_run")
                wint = wj.get("interval_hours", 6)
                wlast_str: str = (
                    _time.strftime("%Y-%m-%d %H:%M", _time.localtime(wlast))
                    if wlast
                    else "never"
                )
                if wlast:
                    wnext_str: str = _time.strftime(
                        "%Y-%m-%d %H:%M", _time.localtime(wlast + wint * 3600)
                    )
                else:
                    wnext_str = "overdue (never run)"
                print(
                    f"  [waiting] [{wj['id']}] [{wj['mode']}] every {wint}h  "
                    f"last={wlast_str}  next={wnext_str}"
                )
                print(f"       query: {wj['query']!r}")
        sys.exit(0)

    # ── standalone: watch-list ────────────────────────────────────
    if args.watch_list:
        jobs: list[dict[str, Any]] = sicry.watch_list()
        if not jobs:
            print("No active watch jobs.")
        else:
            print(f"Active watch jobs ({len(jobs)}):")
            for j in jobs:
                last = j.get("last_run")
                last_str = (
                    _time.strftime("%Y-%m-%d %H:%M", _time.localtime(last)) if last else "never"
                )
                print(
                    f"  {j['id']}  [{j['mode']}]  every {j['interval_hours']}h  "
                    f"last={last_str}  query={j['query']!r}"
                )
        sys.exit(0)

    # ── standalone: watch-disable ─────────────────────────────────
    if args.watch_disable:
        existing_ids: list[str] = [j["id"] for j in sicry.watch_list()]
        if args.watch_disable not in existing_ids:
            print(
                f"ERROR: no watch job with ID {args.watch_disable!r} "
                f"— run --watch-list to see active jobs.",
                file=sys.stderr,
            )
            sys.exit(1)
        sicry.watch_disable(args.watch_disable)
        print(f"Disabled watch job: {args.watch_disable}")
        sys.exit(0)

    # ── standalone: --modes ───────────────────────────────────────
    if args.modes:
        print("Available modes  (--mode <name>):")
        print()
        for m in MODES:
            mc: dict[str, Any] = sicry.mode_config(m)
            engs: list[str] = mc.get("engines") or ["(all alive engines)"]
            extra: int = len(mc.get("extra_seeds") or [])
            print(f"  {m:<22}  engines : {', '.join(engs)}")
            print(
                f"  {'':22}  max_results={mc.get('max_results', 30)}  "
                f"scrape={mc.get('scrape', 8)}"
                + (f"  +{extra} seed onion(s)" if extra else "")
            )
            print()
        sys.exit(0)

    # ── standalone: --engine-stats ────────────────────────────────
    if args.engine_stats:
        scores: dict[str, Any] = sicry.engine_reliability_scores()
        hist: dict[str, Any] = {e: sicry.engine_health_history(e, n=1) for e in scores}
        if not scores:
            print(
                "No engine history yet — run without --engine-stats first to trigger health checks."
            )
        else:
            print(f"  {'Engine':<24} {'Reliability':>12}  {'Last Latency':>14}  Last Seen")
            print("  " + "─" * 62)
            for eng, rel in sorted(
                scores.items(), key=lambda x: (x[1] is None, -(x[1] or 0))
            ):
                last = (hist.get(eng) or [{}])[0]
                lat: str = f"{last.get('latency_ms')}ms" if last.get("latency_ms") else "—"
                ts = last.get("ts")
                ts_s: str = (
                    _time.strftime("%Y-%m-%d %H:%M", _time.localtime(ts)) if ts else "—"
                )
                rel_str: str = f"{rel:.0%}" if rel is not None else "(no data)"
                print(f"  {eng:<24} {rel_str:>11}  {lat:>14}  {ts_s}")
        sys.exit(0)

    # ── standalone: interactive mode (no --query required) ────────
    if args.interactive and not args.query:
        print("OnionClaw Interactive Mode  (type 'exit' to quit, 'help' for commands)")
        print("=" * 65)
        session_history: list[str] = []
        last_results: list[dict] = []
        repl_format: str = "text"
        while True:
            try:
                q: str = input("\nQuery > ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nGoodbye.")
                break
            if q.lower() in ("exit", "quit", "q"):
                print("Goodbye.")
                break
            if not q:
                continue
            if q.lower() in ("help", "?"):
                print("  Commands:")
                print("    <query text>      Search the dark web")
                print("    <number>          Fetch page N from the last result set")
                print("    history           Show previous queries this session")
                print("    set format <fmt>  Set output format: text (default), json, stix, misp, csv")
                print(f"    Current format:   {repl_format}")
                print("    exit / quit       Exit the REPL")
                print("    help / ?          Show this help")
                continue
            if q.lower() == "history":
                if not session_history:
                    print("  No queries yet.")
                else:
                    for i, hq in enumerate(session_history, 1):
                        print(f"  {i}. {hq}")
                continue
            if q.lower().startswith("set format "):
                repl_format = q.split()[-1].lower()
                valid_fmts = ("text", "json", "stix", "misp", "csv")
                if repl_format not in valid_fmts:
                    print(f"  Unknown format {repl_format!r}. Options: {', '.join(valid_fmts)}")
                    repl_format = "text"
                else:
                    print(f"  Output format set to: {repl_format}")
                continue
            if q.isdigit():
                idx: int = int(q) - 1
                if last_results and 0 <= idx < len(last_results):
                    page: dict[str, Any] = sicry.fetch(last_results[idx]["url"])
                    if page["error"]:
                        print(f"  Error: {page['error']}")
                    else:
                        print(f"\n  === {page['title']} ===")
                        if repl_format == "json":
                            import json as _rj
                            print(
                                _rj.dumps(
                                    {
                                        "url": last_results[idx]["url"],
                                        "title": page["title"],
                                        "text": page["text"][:4000],
                                    },
                                    indent=2,
                                )
                            )
                        elif repl_format in ("stix", "misp"):
                            rfmt_result = [
                                {
                                    "url": last_results[idx]["url"],
                                    "title": page.get("title", ""),
                                    "confidence": last_results[idx].get("confidence", 0.5),
                                    "engine": last_results[idx].get("engine", "fetch"),
                                }
                            ]
                            if repl_format == "stix":
                                import json as _rj
                                print(
                                    _rj.dumps(sicry.to_stix(rfmt_result, query=q), indent=2)[:3000]
                                )
                            else:
                                import json as _rj
                                print(
                                    _rj.dumps(sicry.to_misp(rfmt_result, query=q), indent=2)[:3000]
                                )
                        else:
                            print(page["text"][:4000])
                        if page.get("text") and repl_format == "text":
                            import re as _re
                            pt: str = page["text"]
                            emails: list[str] = list(
                                set(
                                    _re.findall(
                                        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", pt
                                    )
                                )
                            )
                            onions: list[str] = list(
                                set(
                                    _re.findall(
                                        r"https?://[a-z2-7]{16,56}\.onion(?:/[^\s\"'<>]*)?", pt
                                    )
                                )
                            )
                            btc: list[str] = list(
                                set(
                                    _re.findall(
                                        r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b", pt
                                    )
                                )
                            )
                            has_pgp: bool = bool(_re.search(r"BEGIN PGP|END PGP", pt))
                            if any([emails, onions, btc, has_pgp]):
                                print("\n  ── Extracted Entities ──")
                                if emails:
                                    print(f"  Emails     : {', '.join(emails[:5])}")
                                if onions:
                                    print(f"  Onion links: {', '.join(onions[:5])}")
                                if btc:
                                    print(f"  BTC addrs  : {', '.join(btc[:3])}")
                                if has_pgp:
                                    print("  PGP key    : detected")
                            ents: str = sicry.analyze_nollm(
                                page["text"][:2000],
                                query=last_results[idx].get("query", ""),
                            )
                            if ents:
                                print("\n  --- Entities / Keywords ---")
                                print(ents[:1200])
                else:
                    print(f"  No result #{int(q)} — run a query first.")
                continue
            session_history.append(q)
            last_results = sicry.search(
                q, max_results=20, mode=args.mode, _use_cache=not args.no_cache
            )
            if not last_results:
                print("  No results.")
                continue
            for i, r in enumerate(last_results, 1):
                iconf = r.get("confidence")
                conf_str: str = f" [{iconf:.2f}]" if iconf is not None else ""
                print(f"  {i:>3}.{conf_str} [{r['engine']}] {r.get('title', '')[:60]}")
                print(f"       {r['url']}")
            print("\n  Type a number to fetch a page, a new query to search, or 'help'.")
        sys.exit(0)

    # ── standalone: --watch-clear-all ─────────────────────────────
    if args.watch_clear_all:
        n_cleared: int = sicry.watch_clear_all()
        print(f"Cleared {n_cleared} active watch job(s).")
        if n_cleared == 0:
            print("  (no active watch jobs found — run --watch-list to check)")
        sys.exit(0)

    # ── BUG-1: initialise checkpoint + job_id ─────────────────────
    checkpoint: dict = {}
    job_id: str = args.resume or str(uuid.uuid4())[:8]

    # ── standalone: --watch-daemon ────────────────────────────────
    if args.watch_daemon:
        import signal

        poll_s: int = (
            args.daemon_poll
            if args.daemon_poll and args.daemon_poll > 0
            else max(int(args.interval * 60), 60)
        )
        print(
            f"[watch-daemon] Starting foreground daemon. Poll every {poll_s}s. Ctrl+C to stop."
        )

        def _daemon_sig(s: int, f: Any) -> None:
            print("\n[watch-daemon] Stopped.")
            sys.exit(0)

        signal.signal(signal.SIGINT, _daemon_sig)
        while True:
            da: list[dict] = sicry.watch_check()
            if da:
                for a in da:
                    print(
                        f"  [ALERT] [{a['job_id']}] {a.get('result_count', 0)} results  "
                        f"query={a.get('query')!r}"
                    )
            else:
                nxt: str = _time.strftime(
                    "%H:%M:%S", _time.localtime(_time.time() + poll_s)
                )
                print(
                    f"  [{_time.strftime('%H:%M:%S')}] No due jobs. Next check at {nxt}."
                )
            _time.sleep(poll_s)

    if args.resume:
        try:
            from sicry import _db  # type: ignore[attr-defined]
            checkpoint = (
                _db().cache_get(
                    f"pipeline_checkpoint:{args.resume}", "pipeline", ttl=86400 * 90
                )
                or {}
            )
            if checkpoint:
                if not args.query:
                    args.query = (
                        (checkpoint.get("data") or {}).get("__meta__", {}).get("query")
                    )
                print(f"[resume] Loaded checkpoint for job {args.resume!r}")
                print(
                    f"         Steps already completed: "
                    f"{list(checkpoint.get('steps', {}).keys())}"
                )
                if args.query:
                    print(f"         Query: {args.query!r}")
            else:
                if not args.query:
                    print(
                        f"ERROR: No checkpoint found for job {args.resume!r}.",
                        file=sys.stderr,
                    )
                    print(
                        "       Either provide --query to start fresh, or check the job ID.",
                        file=sys.stderr,
                    )
                    sys.exit(1)
                print(f"[resume] No checkpoint found for {args.resume!r} — starting fresh")
        except Exception as re_err:
            print(
                f"[resume] Warning: could not load checkpoint — {re_err}", file=sys.stderr
            )

    # ── UX-2: clean error for empty --query ───────────────────────
    if args.query is not None:
        args.query = validate_query(args.query)

    if not args.query:
        parser.error("--query is required")

    # ── standalone: register watch job ───────────────────────────
    if args.watch:
        job_id = sicry.watch_add(
            args.query, mode=args.mode, interval_hours=args.interval
        )
        print(f"Watch job registered: {job_id}")
        print(f"  Query   : {args.query!r}")
        print(f"  Mode    : {args.mode}")
        print(f"  Interval: every {args.interval}h")
        print("  Run 'python3 pipeline.py --watch-check' to check due jobs.")
        sys.exit(0)

    # ── passive update notice ─────────────────────────────────────
    try:
        u = sicry.check_update()
        if not u["up_to_date"] and not u["error"]:
            print(
                f"\n⚡ OnionClaw update available: "
                f"v{u['current']} → v{u['latest']}  "
                f"| run with --check-update for details\n"
            )
    except Exception:
        pass

    no_llm: bool = args.no_llm

    # ── Steps 1–2: connectivity + engines ─────────────────────────
    _step_header(1, TOTAL, "Verify Tor connectivity")
    run_step1_verify_tor(sicry)

    live_names: list[str] = run_step2_check_engines(sicry, args)

    # ── --dry-run: print plan and exit ────────────────────────────
    if args.dry_run:
        print()
        print("=" * 55)
        print("DRY-RUN — execution plan (no searches or scrapes)")
        print("=" * 55)
        print(f"  Query     : {args.query!r}")
        print(f"  Mode      : {args.mode}")
        print(f"  Engines   : {', '.join(live_names)}")
        print(f"  Max results: {args.max}")
        print(f"  Scrape    : {args.scrape} pages")
        print(f"  No-LLM    : {args.no_llm}")
        print(f"  Format    : {args.format}")
        if args.out:
            print(f"  Output    : {args.out}")
        if args.output_dir:
            print(f"  Output dir: {args.output_dir}")
        print()
        print("Steps that would run:")
        print(
            "  [3] Refine query via LLM"
            + (" — SKIPPED (--no-llm)" if args.no_llm else "")
        )
        print(f"  [4] Search {len(live_names)} engine(s)")
        print(
            "  [5] Filter/rank results"
            + (" via BM25 (--no-llm)" if args.no_llm else " via LLM")
        )
        print(
            f"  [6] Scrape top {args.scrape} pages"
            + (" — SKIPPED (--scrape 0)" if args.scrape == 0 else "")
        )
        print(
            "  [7] Analyse via "
            + (
                "no-LLM entity extraction"
                if args.no_llm
                else f"LLM ({args.mode} mode)"
            )
        )
        print()
        print("[dry-run] No network calls made beyond Tor + engine health checks.")
        sys.exit(0)

    # ── Steps 3–7 ─────────────────────────────────────────────────
    raw_query: str = args.query
    refined: str = run_step3_refine_query(sicry, args, checkpoint, job_id)
    raw_results: list[dict[str, Any]] = run_step4_search(
        sicry, args, live_names, refined, checkpoint, job_id
    )
    best: list[dict[str, Any]] = run_step5_filter(
        sicry, args, raw_results, refined, checkpoint, job_id, no_llm=no_llm
    )
    best, pages = run_step6_scrape(sicry, args, best, refined, checkpoint, job_id)
    report: str
    header_label: str
    report, header_label = run_step7_analyze(
        sicry, args, pages, best, refined, checkpoint, job_id, no_llm=no_llm
    )

    print()
    if not no_llm and report.startswith("[SICRY:"):
        print("✗ LLM error:", report)
        print()
        print("  Set LLM_PROVIDER and API key in", os.path.join(_skill_dir, ".env"))
        print(
            "  Tip: re-run with --no-llm for structured entity extraction without an API key."
        )
        print()
        print("  Scraped URLs:")
        for url in pages:
            print(f"    {url}")
        sys.exit(1)

    print("=" * 55)
    print(header_label)
    print("=" * 55)
    print(report)

    _write_output(
        sicry, args, best, pages, report, refined, raw_query, job_id, no_llm=no_llm
    )

    # ── Interactive follow-up drill-down ──────────────────────────
    if args.interactive:
        print("\n[interactive] Ask follow-up questions about the report above.")
        print("  Type 'help' for commands, 'exit' to quit.\n")
        ifollup_history: list[str] = []
        while True:
            try:
                q = input("Follow-up > ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nGoodbye.")
                break
            if q.lower() in ("exit", "quit", "q", ""):
                break
            if q.lower() in ("help", "?"):
                print("  Commands:")
                print("    <question text>   Search for follow-up results")
                print("    fetch N           Fetch result N from the original search")
                print("    history           Show follow-up queries this session")
                print("    exit / quit       Exit")
                continue
            if q.lower() == "history":
                if not ifollup_history:
                    print("  No follow-up queries yet.")
                else:
                    for i, hq in enumerate(ifollup_history, 1):
                        print(f"  {i}. {hq}")
                continue
            if q.lower().startswith("fetch "):
                parts = q.split()
                if len(parts) > 1 and parts[1].isdigit():
                    fetch_idx: int = int(parts[1]) - 1
                    if 0 <= fetch_idx < len(best):
                        fetched: dict[str, Any] = sicry.fetch(best[fetch_idx]["url"])
                        if fetched["error"]:
                            print(f"Error: {fetched['error']}")
                        else:
                            print(f"\n=== {fetched['title']} ===")
                            print(fetched["text"][:4000])
                continue
            ifollup_history.append(q)
            follow_results: list[dict[str, Any]] = sicry.search(
                q, max_results=10, mode=args.mode
            )
            for i, r in enumerate(follow_results[:8], 1):
                conf_str = (
                    f"  [conf={r.get('confidence', 0):.2f}]" if args.confidence else ""
                )
                print(f"  {i:>3}.{conf_str} [{r['engine']}] {r.get('title', '')[:65]}")
                print(f"       {r['url']}")


if __name__ == "__main__":
    main()
