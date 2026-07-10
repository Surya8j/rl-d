"""Unit tests for rl-d's pure detection helpers. Run: python3 -m pytest -q"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ratelimit_detect import (  # noqa: E402
    detect_waf, detect_waf_headers, extract_rate_limit_headers, body_deviates, linreg_slope,
    normalise_url, to_int, to_float, Config, parse_retry_after,
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


def test_detect_waf_headers_block_signals():
    assert detect_waf_headers({"cf-mitigated": "challenge"}) == (True, "Cloudflare")
    assert detect_waf_headers({"X-Sucuri-Block": "1"}) == (True, "Sucuri")
    assert detect_waf_headers({"Server": "AkamaiGHost"}) == (True, "Akamai")
    assert detect_waf_headers({"X-Denied-Reason": "bot"}) == (True, "Generic WAF")


def test_detect_waf_headers_ignores_generic_cdn_presence():
    # A bare CDN-presence header (not a block/challenge signal) must NOT trigger —
    # otherwise every normal page load through that CDN would false-positive.
    assert detect_waf_headers({"cf-ray": "abcd1234-DFW"}) == (False, "")
    assert detect_waf_headers({"Server": "cloudflare"}) == (False, "")
    assert detect_waf_headers({}) == (False, "")


def test_extract_rate_limit_headers():
    h = {"X-RateLimit-Remaining": "0", "Retry-After": "60", "Content-Type": "json"}
    out = extract_rate_limit_headers(h)
    assert "X-RateLimit-Remaining" in out
    assert "Retry-After" in out
    assert "Content-Type" not in out


def test_body_deviates():
    assert body_deviates(2000, 1000, 0) is True      # +100%, no stdev -> flat % rule
    assert body_deviates(1100, 1000, 0) is False     # +10%, no stdev -> flat % rule
    assert body_deviates(500, None) is False         # no baseline
    assert body_deviates(600, 0, 0) is True          # baseline empty, now large
    assert body_deviates(1300, 1000, 50) is True     # 6 stdev above mean -> deviates
    assert body_deviates(1140, 1000, 50) is False    # under k*stdev -> within noise


def test_body_deviates_noisy_page():
    # a page that legitimately swings body size >50% between clean 200s
    # (ads/CSRF/timestamps) should NOT be flagged once stdev captures that noise
    assert body_deviates(1600, 1000, 250) is False   # 2.4 stdev, under k=3
    assert body_deviates(2600, 1000, 250) is True     # 6.4 stdev, beyond k=3


def test_parse_retry_after_seconds():
    assert parse_retry_after({"Retry-After": "30"}) == 30.0
    assert parse_retry_after({"retry-after": "5"}) == 5.0
    assert parse_retry_after({}) is None
    assert parse_retry_after({"Content-Type": "json"}) is None


def test_parse_retry_after_http_date():
    from datetime import datetime, timedelta, timezone
    future = datetime.now(timezone.utc) + timedelta(seconds=60)
    http_date = future.strftime("%a, %d %b %Y %H:%M:%S GMT")
    seconds = parse_retry_after({"Retry-After": http_date})
    assert seconds is not None
    assert 50 <= seconds <= 65


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


def test_to_float():
    assert to_float("15.5", None) == 15.5
    assert to_float("nope", None) is None
    assert to_float("", 30.0) == 30.0


def test_config_build_headers():
    cfg = Config(url="https://x", target_type="api",
                 custom_headers={"Authorization": "Bearer t"}, cookies="a=b")
    h = cfg.build_headers()
    assert h["Authorization"] == "Bearer t"
    assert h["Cookie"] == "a=b"
    assert "Accept" in h


def test_config_max_duration_defaults_to_none():
    cfg = Config(url="https://x")
    assert cfg.max_duration is None
    cfg2 = Config(url="https://x", max_duration=120.0)
    assert cfg2.max_duration == 120.0


def test_parse_args_max_duration():
    from ratelimit_detect import parse_args
    args = parse_args(["-u", "https://x", "--max-duration", "90"])
    assert args.max_duration == 90.0
    args_default = parse_args(["-u", "https://x"])
    assert args_default.max_duration is None
