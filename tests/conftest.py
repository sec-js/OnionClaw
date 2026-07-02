"""
Shared pytest fixtures for OnionClaw tests.

All network / Tor / LLM interactions are mocked so no live Tor is required.
"""

from __future__ import annotations

import os
import sys
from types import ModuleType
from unittest.mock import MagicMock

import pytest

# Ensure the repo root is on sys.path so _bootstrap and scripts are importable
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


@pytest.fixture()
def mock_sicry(monkeypatch) -> ModuleType:
    """Return a lightweight mock of the sicry module injected into sys.modules."""
    mod = ModuleType("sicry")
    mod.__version__ = "9.9.9-test"  # type: ignore[attr-defined]

    mod.SEARCH_ENGINES = [  # type: ignore[attr-defined]
        {"name": "Ahmia"},
        {"name": "Tor66"},
        {"name": "Excavator"},
    ]

    mod.check_tor = MagicMock(
        return_value={"tor_active": True, "exit_ip": "1.2.3.4", "error": None}
    )  # type: ignore[attr-defined]
    mod.renew_identity = MagicMock(return_value={"success": True, "error": None})  # type: ignore[attr-defined]
    mod.check_search_engines = MagicMock(
        return_value=[  # type: ignore[attr-defined]
            {"name": "Ahmia", "status": "up", "latency_ms": 800},
            {"name": "Tor66", "status": "up", "latency_ms": 1200},
            {"name": "Excavator", "status": "down", "error": "timeout"},
        ]
    )
    mod.search = MagicMock(
        return_value=[  # type: ignore[attr-defined]
            {
                "engine": "Ahmia",
                "title": "Result 1",
                "url": "http://example.onion/1",
                "confidence": 0.85,
            },
            {
                "engine": "Tor66",
                "title": "Result 2",
                "url": "http://example.onion/2",
                "confidence": 0.70,
            },
        ]
    )
    mod.fetch = MagicMock(
        return_value={  # type: ignore[attr-defined]
            "status": 200,
            "title": "Test Page",
            "text": "Hello dark web",
            "links": [],
            "error": None,
            "truncated": False,
        }
    )
    mod.ask = MagicMock(return_value="## Threat Intelligence Report\n\nFindings: none.")  # type: ignore[attr-defined]
    mod.clear_cache = MagicMock(return_value=0)  # type: ignore[attr-defined]
    mod.refine_query = MagicMock(side_effect=lambda q: q)  # type: ignore[attr-defined]
    mod.filter_results = MagicMock(side_effect=lambda q, r: r[:20])  # type: ignore[attr-defined]
    mod.score_results = MagicMock(side_effect=lambda q, r, **kw: r)  # type: ignore[attr-defined]
    mod.scrape_all = MagicMock(return_value={})  # type: ignore[attr-defined]
    mod.analyze_nollm = MagicMock(return_value="Keywords: test")  # type: ignore[attr-defined]
    mod.check_update = MagicMock(
        return_value={
            "up_to_date": True,
            "current": "9.9.9",
            "latest": "9.9.9",
            "url": None,
            "error": None,
        }
    )  # type: ignore[attr-defined]
    mod.watch_list = MagicMock(return_value=[])  # type: ignore[attr-defined]
    mod.watch_add = MagicMock(return_value="abc12345")  # type: ignore[attr-defined]
    mod.watch_check = MagicMock(return_value=[])  # type: ignore[attr-defined]
    mod.watch_disable = MagicMock()  # type: ignore[attr-defined]
    mod.watch_clear_all = MagicMock(return_value=0)  # type: ignore[attr-defined]
    mod.mode_config = MagicMock(
        return_value={"engines": ["Ahmia"], "max_results": 30, "scrape": 8, "extra_seeds": []}
    )  # type: ignore[attr-defined]
    mod.engine_reliability_scores = MagicMock(return_value={})  # type: ignore[attr-defined]
    mod.engine_health_history = MagicMock(return_value=[])  # type: ignore[attr-defined]
    mod.to_csv = MagicMock(return_value="url,title\n")  # type: ignore[attr-defined]
    mod.to_stix = MagicMock(return_value={"type": "bundle", "objects": []})  # type: ignore[attr-defined]
    mod.to_misp = MagicMock(return_value={"Event": {}})  # type: ignore[attr-defined]
    mod.extract_keywords = MagicMock(return_value=["keyword1", "keyword2"])  # type: ignore[attr-defined]
    mod._tor_port_open = MagicMock(return_value=True)  # type: ignore[attr-defined]
    mod.TOR_SOCKS_HOST = "127.0.0.1"  # type: ignore[attr-defined]
    mod.TOR_SOCKS_PORT = 9050  # type: ignore[attr-defined]
    mod.TOR_POOL_SIZE = 0  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "sicry", mod)
    return mod
