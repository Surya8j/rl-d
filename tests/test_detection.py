"""Unit tests for rl-d's pure detection helpers. Run: python3 -m pytest -q"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ratelimit_detect import (  # noqa: E402
    detect_waf, extract_rate_limit_headers, body_deviates, linreg_slope,
    normalise_url, to_int, Config,
)


def test_detect_cloudflare():
    assert detect_waf("<title>Just a moment...</title>") == (True, "Cloudflare")
    assert detect_waf("please complete the Turnstile") == (True, "Cloudflare")


def test_detect_generic_waf():
    assert detect_waf("Access Denied") == (True, "Generic WAF")
    assert detect_waf("Please verify you are human") == (True, "Generic WAF")


def test_detect_waf_clean():
    assert detect_waf('{"ok": true}') == (False, "")
    assert detect_waf("") == (False, "")


def test_extract_rate_limit_headers():
    h = {"X-RateLimit-Remaining": "0", "Retry-After": "60", "Content-Type": "json"}
    out = extract_rate_limit_headers(h)
    assert "X-RateLimit-Remaining" in out
    assert "Retry-After" in out
    assert "Content-Type" not in out


def test_body_deviates():
    assert body_deviates(2000, 1000) is True      # +100%
    assert body_deviates(1100, 1000) is False     # +10%
    assert body_deviates(500, None) is False      # no baseline
    assert body_deviates(600, 0) is True          # baseline empty, now large


def test_linreg_slope():
    assert linreg_slope([1, 2, 3], [2, 4, 6]) == 2.0        # perfect line
    assert linreg_slope([1, 2, 3], [5, 5, 5]) == 0.0        # flat
    assert linreg_slope([1], [1]) == 0.0                    # degenerate


def test_normalise_url_adds_scheme():
    assert normalise_url("example.com").startswith("https://")
    assert normalise_url("http://example.com") == "http://example.com"


def test_to_int():
    assert to_int("15", 10) == 15
    assert to_int("nope", 10) == 10
    assert to_int("", 10) == 10


def test_config_build_headers():
    cfg = Config(url="https://x", target_type="api",
                 custom_headers={"Authorization": "Bearer t"}, cookies="a=b")
    h = cfg.build_headers()
    assert h["Authorization"] == "Bearer t"
    assert h["Cookie"] == "a=b"
    assert "Accept" in h
