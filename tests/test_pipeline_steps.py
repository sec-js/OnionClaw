"""
Integration tests for pipeline.py step functions using the mock_sicry fixture.

No Tor, no network, no real sicry required.
The mock_sicry fixture (from conftest.py) injects a fake sicry module so
pipeline.py can be imported and its step functions called directly.
"""

from __future__ import annotations

import argparse
import sys

import pytest

# Ensure a clean pipeline import each test (so mock_sicry is active at import time)
@pytest.fixture(autouse=True)
def _fresh_pipeline_import():
    sys.modules.pop("pipeline", None)
    yield
    sys.modules.pop("pipeline", None)


def _args(**kwargs) -> argparse.Namespace:
    """Build a minimal argparse.Namespace for pipeline step tests."""
    defaults = {
        "mode": "threat_intel",
        "max": 30,
        "scrape": 8,
        "confidence": False,
        "no_cache": False,
        "custom": "",
        "format": "md",
        "out": None,
        "output_dir": None,
        "engines": None,
        "no_llm": False,
        "misp_threat_level": 2,
        "misp_distribution": 0,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


# ── Step 1: verify Tor ────────────────────────────────────────────


class TestStep1VerifyTor:
    def test_tor_active_returns_status(self, mock_sicry):
        from pipeline import run_step1_verify_tor

        result = run_step1_verify_tor(mock_sicry)
        assert result["tor_active"] is True
        mock_sicry.check_tor.assert_called_once()

    def test_tor_inactive_exits(self, mock_sicry):
        from pipeline import run_step1_verify_tor

        mock_sicry.check_tor.return_value = {
            "tor_active": False,
            "exit_ip": None,
            "error": "Tor not running",
        }
        with pytest.raises(SystemExit):
            run_step1_verify_tor(mock_sicry)

    def test_tor_exit_ip_printed(self, mock_sicry, capsys):
        from pipeline import run_step1_verify_tor

        run_step1_verify_tor(mock_sicry)
        out = capsys.readouterr().out
        assert "1.2.3.4" in out


# ── Step 2: check engines ─────────────────────────────────────────


class TestStep2CheckEngines:
    def test_health_check_returns_alive(self, mock_sicry):
        from pipeline import run_step2_check_engines

        live = run_step2_check_engines(mock_sicry, _args())
        # At least one alive engine must be returned after any mode-based filtering
        assert len(live) >= 1
        # "Excavator" is status "down" in mock_sicry fixture — never in alive list
        assert "Excavator" not in live

    def test_user_engines_skips_health_check(self, mock_sicry):
        from pipeline import run_step2_check_engines

        live = run_step2_check_engines(mock_sicry, _args(engines=["Ahmia"]))
        assert live == ["Ahmia"]
        mock_sicry.check_search_engines.assert_not_called()

    def test_no_alive_engines_exits(self, mock_sicry):
        from pipeline import run_step2_check_engines

        mock_sicry.check_search_engines.return_value = [
            {"name": "Ahmia", "status": "down", "error": "timeout"},
        ]
        with pytest.raises(SystemExit):
            run_step2_check_engines(mock_sicry, _args())


# ── Step 3: refine query ──────────────────────────────────────────


class TestStep3RefineQuery:
    def test_fresh_run_skips_llm(self, mock_sicry):
        from pipeline import run_step3_refine_query

        args = _args()
        args.query = "ransomware leak"
        refined = run_step3_refine_query(mock_sicry, args, {}, "job1")
        assert refined == "ransomware leak"
        mock_sicry.refine_query.assert_not_called()

    def test_resume_with_cached_refinement(self, mock_sicry):
        from pipeline import run_step3_refine_query

        args = _args()
        args.query = "original query"
        checkpoint = {"data": {"__meta__": {"query": "original query"}, "refine": "refined query"}}
        refined = run_step3_refine_query(mock_sicry, args, checkpoint, "job1")
        assert refined == "refined query"
        mock_sicry.refine_query.assert_not_called()

    def test_resume_without_cached_refinement_calls_llm(self, mock_sicry):
        from pipeline import run_step3_refine_query

        mock_sicry.refine_query.side_effect = lambda q: q + " refined"
        args = _args()
        args.query = "hospital breach"
        checkpoint = {"data": {"__meta__": {"query": "hospital breach"}}}
        refined = run_step3_refine_query(mock_sicry, args, checkpoint, "job1")
        assert refined == "hospital breach refined"
        mock_sicry.refine_query.assert_called_once()


# ── Step 4: search ────────────────────────────────────────────────


class TestStep4Search:
    def test_returns_results(self, mock_sicry):
        from pipeline import run_step4_search

        raw = run_step4_search(
            mock_sicry, _args(), ["Ahmia", "Tor66"], "ransomware", {}, "job1"
        )
        assert len(raw) >= 1
        mock_sicry.search.assert_called_once()

    def test_uses_checkpoint_cache(self, mock_sicry):
        from pipeline import run_step4_search

        cached = [{"url": "http://cached.onion", "title": "cached", "engine": "Ahmia"}]
        checkpoint = {"data": {"search": cached}}
        raw = run_step4_search(
            mock_sicry, _args(), ["Ahmia"], "ransomware", checkpoint, "job1"
        )
        assert raw == cached
        mock_sicry.search.assert_not_called()

    def test_no_results_exits(self, mock_sicry):
        from pipeline import run_step4_search

        mock_sicry.search.return_value = []
        with pytest.raises(SystemExit):
            run_step4_search(mock_sicry, _args(), ["Ahmia"], "ransomware", {}, "job1")


# ── Step 5: filter ────────────────────────────────────────────────


class TestStep5Filter:
    def test_no_llm_calls_score_results(self, mock_sicry):
        from pipeline import run_step5_filter

        raw = [{"url": "http://x.onion", "title": "test", "engine": "Ahmia"}]
        mock_sicry.score_results.return_value = raw
        best = run_step5_filter(
            mock_sicry, _args(), raw, "query", {}, "job1", no_llm=True
        )
        mock_sicry.score_results.assert_called_once()
        assert best == raw

    def test_with_llm_calls_filter_results(self, mock_sicry):
        from pipeline import run_step5_filter

        raw = [{"url": "http://x.onion", "title": "test", "engine": "Ahmia"}]
        best = run_step5_filter(
            mock_sicry, _args(), raw, "query", {}, "job1", no_llm=False
        )
        mock_sicry.filter_results.assert_called_once()
        assert best is not None

    def test_checkpoint_skips_filter(self, mock_sicry):
        from pipeline import run_step5_filter

        cached = [{"url": "http://cached.onion"}]
        checkpoint = {"data": {"filter": cached}}
        best = run_step5_filter(
            mock_sicry, _args(), [], "query", checkpoint, "job1", no_llm=False
        )
        assert best == cached
        mock_sicry.filter_results.assert_not_called()


# ── Step 6: scrape ────────────────────────────────────────────────


class TestStep6Scrape:
    def test_returns_pages(self, mock_sicry):
        from pipeline import run_step6_scrape

        best = [
            {"url": "http://x.onion", "title": "X"},
            {"url": "http://y.onion", "title": "Y"},
        ]
        mock_sicry.scrape_all.return_value = {
            "http://x.onion": "content x",
            "http://y.onion": "content y",
        }
        best_out, pages = run_step6_scrape(
            mock_sicry, _args(scrape=2), best, "query", {}, "job1"
        )
        assert "http://x.onion" in pages
        mock_sicry.scrape_all.assert_called_once()

    def test_scrape_zero_warns_continues(self, mock_sicry, capsys):
        from pipeline import run_step6_scrape

        best = [{"url": "http://x.onion", "title": "X"}]
        mock_sicry.scrape_all.return_value = {}
        best_out, pages = run_step6_scrape(
            mock_sicry, _args(scrape=0), best, "query", {}, "job1"
        )
        assert pages == {}
        err = capsys.readouterr().err
        assert "scrape 0" in err.lower() or "--scrape 0" in err


# ── Step 7: analyze ───────────────────────────────────────────────


class TestStep7Analyze:
    def test_no_llm_uses_analyze_nollm(self, mock_sicry):
        from pipeline import run_step7_analyze

        pages = {"http://x.onion": "dark web content here"}
        best = [{"url": "http://x.onion", "title": "T"}]
        report, label = run_step7_analyze(
            mock_sicry, _args(), pages, best, "ransomware", {}, "job1", no_llm=True
        )
        mock_sicry.analyze_nollm.assert_called_once()
        assert label == "ANALYSIS REPORT (no-LLM)"

    def test_with_llm_calls_ask(self, mock_sicry):
        from pipeline import run_step7_analyze

        pages = {"http://x.onion": "content"}
        best = [{"url": "http://x.onion", "title": "T"}]
        report, label = run_step7_analyze(
            mock_sicry, _args(), pages, best, "ransomware", {}, "job1", no_llm=False
        )
        mock_sicry.ask.assert_called_once()
        assert label == "INVESTIGATION REPORT"
        assert report == mock_sicry.ask.return_value

    def test_checkpoint_skips_ask(self, mock_sicry):
        from pipeline import run_step7_analyze

        pages = {"http://x.onion": "content"}
        best = [{"url": "http://x.onion", "title": "T"}]
        checkpoint = {"data": {"ask": "## Cached Report\n\nFrom checkpoint."}}
        report, label = run_step7_analyze(
            mock_sicry, _args(), pages, best, "ransomware", checkpoint, "job1",
            no_llm=False,
        )
        mock_sicry.ask.assert_not_called()
        assert report == "## Cached Report\n\nFrom checkpoint."
