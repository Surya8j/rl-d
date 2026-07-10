#!/usr/bin/env python3
"""
rl-d — Rate Limit Detector

An async CLI to detect AND measure rate limiting, WAF challenges, and silent
blocks on web applications you are authorised to test.

Cross-platform (macOS / Linux), no sudo required.

Quick start:
    python3 ratelimit_detect.py                      # interactive wizard
    python3 ratelimit_detect.py -u https://api.x/v1  # flags, sequential scan
    python3 ratelimit_detect.py -u https://api.x/v1 --concurrency 20
    python3 ratelimit_detect.py -u https://api.x/v1 --discover --json out.json

Dependencies:
    pip install curl_cffi
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from urllib.parse import urlparse

# ─── Dependency check ────────────────────────────────────────────────────────
try:
    from curl_cffi.requests import AsyncSession
except ImportError:
    sys.stderr.write(
        "\n  ✖  Missing dependency: curl_cffi\n"
        "     Install it with:  pip install curl_cffi\n\n"
    )
    sys.exit(1)


# ─── Constants ───────────────────────────────────────────────────────────────
DEFAULT_MAX_REQUESTS = 300
# 429 is a high-confidence rate-limit signal. 503 is often a genuine outage, so
# it only counts as a limit once it recurs (see AMBIGUOUS_503_CORROBORATION).
TRUE_RATE_LIMIT_STATUS_CODES = {429}
AMBIGUOUS_STATUS_CODES = {503}
AMBIGUOUS_503_CORROBORATION = 2  # consecutive/total 503s required before treating as a limit
RATE_LIMIT_STATUS_CODES = TRUE_RATE_LIMIT_STATUS_CODES | AMBIGUOUS_STATUS_CODES
BLOCK_STATUS_CODES = {401, 403, 406, 418, 444}
BROWSER_IMPERSONATIONS = ["chrome124", "chrome120", "safari17_0"]

# Baseline is now a distribution (mean + stdev) over the first N clean 200s,
# not a single sample — a single page load can be an outlier (ads, CSRF
# tokens, timestamps) and previously tripped the deviation check on its own.
BASELINE_SAMPLE_SIZE = 5
BASELINE_STDEV_K = 3.0
BASELINE_NOISY_RELATIVE_STDEV = 0.3

CLOUDFLARE_SIGNATURES = [
    "managed challenge", "cf-chl-bypass", "challenge-platform", "just a moment",
    "checking your browser", "cf-browser-verification", "attention required",
    "ray id", "_cf_chl_opt", "turnstile",
]

WAF_SIGNATURES = [
    "access denied", "request blocked", "web application firewall",
    "security check", "bot detection", "are you a robot", "captcha",
    "recaptcha", "hcaptcha", "please verify", "request rejected",
    "incident id", "reference #",  # Akamai / Imperva style
]
# NOTE (maintenance): body-text signatures above are brittle — vendors change
# challenge-page copy without notice. Review both lists periodically. Header
# signatures below are deliberately narrow: only headers/values that indicate a
# mitigation action was actually TAKEN, not "this site merely sits behind vendor
# X" (e.g. a bare cf-ray/x-iinfo header rides along on every request through that
# CDN, challenged or not, and would false-positive on every normal page load).
WAF_HEADER_SIGNATURES = (
    ("cf-mitigated", "Cloudflare"),
    ("x-sucuri-block", "Sucuri"),
    ("x-denied-reason", "Generic WAF"),
    ("x-waf-block-reason", "Generic WAF"),
    ("x-blocked-reason", "Generic WAF"),
)
WAF_SERVER_HEADER_SIGNATURES = (
    ("akamaighost", "Akamai"),  # Akamai's generic error/block page server string
)

# Item 6: the tool measures exactly one (source IP + supplied credentials + this
# route) tuple. Real limits are often keyed on a different dimension (API key,
# user, endpoint group) — surfaced verbatim so a report doesn't over-generalise.
MEASUREMENT_SCOPE = (
    "measured for a single (source IP + supplied credentials/headers + this route) "
    "tuple only — the underlying limit may be keyed on a different dimension "
    "(API key, authenticated user, endpoint group, etc.); this tool does not "
    "attempt to infer the keying dimension"
)

# Item 10: distinct exit codes per signal type so CI can branch on what was found
# instead of collapsing every finding into a single exit(1).
EXIT_CODE_BY_SIGNAL = {
    None: 0,
    "rate_limit": 1,
    "rate_limit_ambiguous": 1,
    "rate_limit_header": 1,
    "throttling_trend": 1,
    "connection_drop": 1,
    "block_status_shift": 2,
    "waf_challenge": 3,
    "silent_block": 4,
    "ip_reputation": 5,
    "unreachable": 6,
}

DELAY_MODES = {"burst": 0.0, "steady": 0.2, "slow": 0.5}

WEBPAGE_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Cache-Control": "max-age=0",
}

API_HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
}


# ─── Colors ──────────────────────────────────────────────────────────────────
class C:
    BOLD = "\033[1m"; DIM = "\033[2m"; RED = "\033[91m"; GREEN = "\033[92m"
    YELLOW = "\033[93m"; BLUE = "\033[94m"; CYAN = "\033[96m"; MAGENTA = "\033[95m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls):
        for name in ("BOLD", "DIM", "RED", "GREEN", "YELLOW", "BLUE", "CYAN", "MAGENTA", "RESET"):
            setattr(cls, name, "")


def eprint(*args, **kwargs):
    """Print to stderr so stdout can stay clean for --json piping."""
    print(*args, file=sys.stderr, **kwargs)


# ─── Result model ──────────────────────────────────────────────────────────
@dataclass
class RequestResult:
    request_num: int
    status: int = 0
    response_time: float = 0.0
    body_size: int = 0
    error: str | None = None
    rate_limit_headers: dict = field(default_factory=dict)
    waf_detected: bool = False
    waf_type: str = ""
    body_size_shifted: bool = False
    sent_at: float = 0.0  # monotonic timestamp when the request was launched


# ─── Detection helpers (pure functions, easy to unit test) ───────────────────
def detect_waf(body: str) -> tuple[bool, str]:
    body_lower = body.lower() if body else ""
    for sig in CLOUDFLARE_SIGNATURES:
        if sig in body_lower:
            return True, "Cloudflare"
    for sig in WAF_SIGNATURES:
        if sig in body_lower:
            return True, "Generic WAF"
    return False, ""


def detect_waf_headers(resp_headers: dict) -> tuple[bool, str]:
    """Header-based WAF/CDN mitigation signal, higher-precision than body text —
    works even when the block page has no visible copy (empty body, JSON 403, etc).
    """
    headers_lower = {k.lower(): v for k, v in (resp_headers or {}).items()}
    for key, vendor in WAF_HEADER_SIGNATURES:
        if key in headers_lower:
            return True, vendor
    server = headers_lower.get("server", "").lower()
    for needle, vendor in WAF_SERVER_HEADER_SIGNATURES:
        if needle in server:
            return True, vendor
    return False, ""


def extract_rate_limit_headers(resp_headers: dict) -> dict:
    keys = ("ratelimit", "rate-limit", "x-ratelimit", "retry-after",
            "x-retry-after", "x-rate-limit")
    return {k: v for k, v in resp_headers.items()
            if any(needle in k.lower() for needle in keys)}


def body_deviates(current: int, baseline_mean: float | None, baseline_stdev: float = 0.0,
                   k: float = BASELINE_STDEV_K) -> bool:
    """Flag a body-size shift against a baseline DISTRIBUTION, not a single sample.

    Pages with CSRF tokens, timestamps, ads, or personalization legitimately vary
    body size >50% between clean 200s. Using mean +/- k*stdev instead of a flat
    percentage against one sample avoids false-positiving on that noise.
    """
    if baseline_mean is None:
        return False
    if baseline_stdev > 0:
        return abs(current - baseline_mean) > k * baseline_stdev
    if baseline_mean == 0:
        return current > 500
    return abs(current - baseline_mean) / max(baseline_mean, 1) > 0.5


def parse_retry_after(headers: dict) -> float | None:
    """Parse a Retry-After value (delta-seconds or HTTP-date) from response headers."""
    value = None
    for k, v in (headers or {}).items():
        if k.lower() == "retry-after":
            value = v
            break
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        pass
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = (dt - datetime.now(timezone.utc)).total_seconds()
        return max(delta, 0.0)
    except (TypeError, ValueError, IndexError):
        return None


def linreg_slope(xs: list[float], ys: list[float]) -> float:
    """Ordinary-least-squares slope; used for throttling trend."""
    n = len(xs)
    if n < 2:
        return 0.0
    mx = sum(xs) / n
    my = sum(ys) / n
    denom = sum((x - mx) ** 2 for x in xs)
    if denom == 0:
        return 0.0
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / denom


# ─── Config ─────────────────────────────────────────────────────────────────
@dataclass
class Config:
    url: str
    target_type: str = "webpage"
    method: str = "GET"
    custom_headers: dict = field(default_factory=dict)
    cookies: str = ""
    data: str | None = None
    delay_mode: str = "burst"
    delay_seconds: float = 0.0
    timeout: int = 10
    max_requests: int = DEFAULT_MAX_REQUESTS
    concurrency: int = 1
    proxy: str | None = None
    mode: str = "scan"          # scan | discover
    window: float = 60.0        # discover: window length in seconds
    verify: bool = True
    max_duration: float | None = None  # hard wall-clock cap for the whole run (self-protection)

    def build_headers(self) -> dict:
        headers = dict(WEBPAGE_HEADERS if self.target_type == "webpage" else API_HEADERS)
        headers.update(self.custom_headers)
        if self.cookies:
            headers["Cookie"] = self.cookies
        return headers


# ─── Detector ────────────────────────────────────────────────────────────────
class RateLimitDetector:
    def __init__(self, config: Config, quiet: bool = False):
        self.config = config
        self.quiet = quiet
        self.results: list[RequestResult] = []
        self.baseline_body_sizes: list[int] = []
        self.baseline_time_samples: list[float] = []
        self.baseline_body_mean: float | None = None
        self.baseline_body_stdev: float = 0.0
        self.baseline_time_mean: float | None = None
        self.baseline_time_stdev: float = 0.0
        self.baseline_noisy = False
        self.baseline_status: int | None = None
        self.ambiguous_503_count = 0
        self.retry_after_seconds: float | None = None
        self.backends_seen: set[str] = set()
        self.rate_limit_detected = False
        self.detection_reason = ""
        self.detection_request_num = 0
        self.signal_type: str | None = None
        self.stopped_early: str | None = None
        self.run_start: float = 0.0
        self.waf_challenge_detected = False
        self.waf_type = ""
        self.ip_reputation_issue = False
        self.rate_limit_headers_found: dict = {}
        self.status_code_counts: dict = {}
        self.connection_errors = 0
        self.timeout_errors = 0
        self.body_size_shifts = 0
        self.ever_connected = False
        self.target_unreachable = False
        self.threshold_estimate: int | None = None
        self.started_at = ""

    # ── networking ──
    async def send_request(self, session: AsyncSession, req_num: int) -> RequestResult:
        result = RequestResult(request_num=req_num)
        start = time.monotonic()
        result.sent_at = start
        try:
            kwargs = dict(
                headers=self.config.build_headers(),
                timeout=self.config.timeout,
                allow_redirects=True,
            )
            if self.config.data is not None and self.config.method in ("POST", "PUT", "PATCH"):
                kwargs["data"] = self.config.data
            resp = await session.request(self.config.method, self.config.url, **kwargs)
            elapsed = time.monotonic() - start

            body = resp.text or ""
            resp_headers = dict(resp.headers) if resp.headers else {}
            result.status = resp.status_code
            result.response_time = elapsed
            result.body_size = len(body.encode("utf-8", errors="replace"))
            self.ever_connected = True
            self.status_code_counts[resp.status_code] = self.status_code_counts.get(resp.status_code, 0) + 1

            rl_headers = extract_rate_limit_headers(resp_headers)
            if rl_headers:
                result.rate_limit_headers = rl_headers
                self.rate_limit_headers_found.update(rl_headers)

            result.waf_detected, result.waf_type = detect_waf(body)
            if not result.waf_detected:
                result.waf_detected, result.waf_type = detect_waf_headers(resp_headers)
            for key in ("server", "x-served-by", "x-backend", "x-upstream", "via"):
                val = resp_headers.get(key, "")
                if val:
                    self.backends_seen.add(f"{key}: {val}")

            if resp.status_code == 200 and len(self.baseline_body_sizes) < BASELINE_SAMPLE_SIZE:
                if self.baseline_status is None:
                    self.baseline_status = resp.status_code
                self.baseline_body_sizes.append(result.body_size)
                self.baseline_time_samples.append(elapsed)
                if len(self.baseline_body_sizes) >= 2:
                    self.baseline_body_mean = statistics.mean(self.baseline_body_sizes)
                    self.baseline_body_stdev = statistics.stdev(self.baseline_body_sizes)
                    self.baseline_time_mean = statistics.mean(self.baseline_time_samples)
                    self.baseline_time_stdev = statistics.stdev(self.baseline_time_samples)
                else:
                    self.baseline_body_mean = float(result.body_size)
                    self.baseline_time_mean = elapsed
                if (len(self.baseline_body_sizes) == BASELINE_SAMPLE_SIZE
                        and self.baseline_body_mean):
                    rel_stdev = self.baseline_body_stdev / self.baseline_body_mean
                    self.baseline_noisy = rel_stdev > BASELINE_NOISY_RELATIVE_STDEV

            # Only judge shifts once the baseline distribution is fully sampled —
            # comparing against a still-growing baseline would be comparing noise to noise.
            if len(self.baseline_body_sizes) >= BASELINE_SAMPLE_SIZE:
                result.body_size_shifted = body_deviates(
                    result.body_size, self.baseline_body_mean, self.baseline_body_stdev)
                if result.body_size_shifted:
                    self.body_size_shifts += 1

            if result.status in TRUE_RATE_LIMIT_STATUS_CODES or result.status in AMBIGUOUS_STATUS_CODES:
                retry_after = parse_retry_after(resp_headers)
                if retry_after is not None:
                    self.retry_after_seconds = retry_after

        except Exception as e:  # noqa: BLE001 - report any transport failure
            result.response_time = time.monotonic() - start
            result.error = str(e)
            if "timeout" in result.error.lower() or "timed out" in result.error.lower():
                self.timeout_errors += 1
            else:
                self.connection_errors += 1
        return result

    # ── progress line ──
    def _progress(self, r: RequestResult, warning: str = ""):
        if self.quiet:
            return
        s = r.status
        if s == 200:
            sc = f"{C.GREEN}{s}{C.RESET}"
        elif s in RATE_LIMIT_STATUS_CODES or s in BLOCK_STATUS_CODES:
            sc = f"{C.RED}{s}{C.RESET}"
        elif s == 0:
            sc = f"{C.RED}ERR{C.RESET}"
        else:
            sc = f"{C.YELLOW}{s}{C.RESET}"
        if r.response_time > 5.0:
            rt = f"{C.RED}{r.response_time:.2f}s{C.RESET}"
        elif r.response_time > 2.0:
            rt = f"{C.YELLOW}{r.response_time:.2f}s{C.RESET}"
        else:
            rt = f"{C.DIM}{r.response_time:.2f}s{C.RESET}"
        line = f"  {C.DIM}#{r.request_num:>4}{C.RESET}  status={sc}  time={rt}  size={r.body_size:>7}B"
        if warning:
            line += f"  {C.YELLOW}⚠ {warning}{C.RESET}"
        eprint(line)

    # ── per-result evaluation (order-tolerant) ──
    def _evaluate(self, r: RequestResult) -> tuple[bool, str, str | None]:
        n = r.request_num
        if n <= 3 and (r.status in BLOCK_STATUS_CODES or r.waf_detected):
            self.ip_reputation_issue = True
            self._progress(r, "early block/challenge — possible IP reputation issue")
            if n == 3:
                return (True, "IP reputation / pre-existing block detected (blocked on first requests)",
                        "ip_reputation")
            return False, "", None

        if r.status in TRUE_RATE_LIMIT_STATUS_CODES:
            self._progress(r, "RATE LIMIT STATUS CODE")
            return (True, self._with_retry_after(f"HTTP {r.status} returned at request #{n}"),
                    "rate_limit")

        if r.status in AMBIGUOUS_STATUS_CODES:
            self.ambiguous_503_count += 1
            if self.ambiguous_503_count < AMBIGUOUS_503_CORROBORATION:
                # 503 is often a genuine outage rather than a limit — don't assert a
                # rate-limit verdict off a single occurrence.
                self._progress(r, "503 service unavailable (possible limit or outage)")
                return False, "", None
            self._progress(r, "repeated 503 — possible limit (not a confirmed 429)")
            return (True, self._with_retry_after(
                f"HTTP 503 returned {self.ambiguous_503_count}x (latest at request #{n}) "
                f"— service unavailable / possible rate limit, not a confirmed 429"),
                "rate_limit_ambiguous")

        if r.status in BLOCK_STATUS_CODES and n > 3 and self.baseline_status and self.baseline_status != r.status:
            self._progress(r, "status code shifted to block")
            return (True, f"Status shifted from {self.baseline_status} to {r.status} at request #{n}",
                    "block_status_shift")

        if r.waf_detected and n > 3 and not self.waf_challenge_detected:
            self.waf_challenge_detected = True
            self.waf_type = r.waf_type
            self._progress(r, f"{r.waf_type} challenge detected")
            return True, f"{r.waf_type} challenge/captcha triggered at request #{n}", "waf_challenge"

        if r.body_size_shifted and n > 5 and self.body_size_shifts >= 3:
            # Item 9: a body-size shift alone can be dynamic content (ads, timestamps,
            # personalization) even beyond the baseline stdev threshold on a long run.
            # Require a second, independent signal — a status-code shift or a latency
            # shift beyond the baseline stdev — before asserting a silent block.
            status_corroborates = self.baseline_status is not None and r.status != self.baseline_status
            latency_corroborates = self._latency_deviates(r.response_time)
            if status_corroborates or latency_corroborates:
                corroboration = "status" if status_corroborates else "latency"
                self._progress(r, f"response body changed significantly ({corroboration}-corroborated)")
                return (True, (f"Response body size shifted significantly at request #{n}, "
                               f"corroborated by a {corroboration} shift (possible silent block)"),
                        "silent_block")
            self._progress(r, "body size shifted (uncorroborated — possibly dynamic content)")
            return False, "", None

        if r.error:
            self._progress(r, f"connection error: {r.error[:50]}")
            if not self.ever_connected and self.connection_errors >= 3:
                self.target_unreachable = True
                return (True, "Target appears unreachable (no successful connection). Check URL, network, or firewall.",
                        "unreachable")
            if self.ever_connected and self.connection_errors + self.timeout_errors >= 5 and n > 5:
                return (True, (f"Connection drops after successful requests "
                              f"({self.connection_errors} errors, {self.timeout_errors} timeouts) "
                              f"by request #{n} — likely rate limiting"),
                        "connection_drop")
            return False, "", None

        if r.rate_limit_headers:
            for k, v in r.rate_limit_headers.items():
                if "remaining" in k.lower():
                    try:
                        if int(v) <= 0:
                            self._progress(r, "rate limit remaining = 0")
                            return (True, f"Rate limit header shows 0 remaining at request #{n}",
                                    "rate_limit_header")
                    except (ValueError, TypeError):
                        pass

        warning = "body size shifted" if r.body_size_shifted else ""
        self._progress(r, warning)
        return False, "", None

    def _mark_detected(self, reason: str, req_num: int, signal_type: str | None = None):
        self.rate_limit_detected = True
        self.detection_reason = reason
        self.detection_request_num = req_num
        self.signal_type = signal_type

    def _with_retry_after(self, reason: str) -> str:
        if self.retry_after_seconds is not None and "Retry-After" not in reason:
            return f"{reason} (server requested Retry-After: {self.retry_after_seconds:.0f}s)"
        return reason

    def _threshold_confidence(self) -> str | None:
        if self.threshold_estimate is None:
            return None
        if len(self.backends_seen) > 1:
            return "low — distributed backends detected, single-source-IP allowance may not generalise"
        if self.baseline_noisy:
            return "medium — noisy baseline (high response variance)"
        return "high"

    def _latency_deviates(self, response_time: float) -> bool:
        if self.baseline_time_mean is None:
            return False
        if self.baseline_time_stdev > 0:
            return abs(response_time - self.baseline_time_mean) > BASELINE_STDEV_K * self.baseline_time_stdev
        return response_time > self.baseline_time_mean * 2

    def _corroborating_signal_count(self) -> int:
        """How many independent signals agree a limit/block exists, not just the
        one that happened to trip first."""
        signals = 0
        if any(rr.status in TRUE_RATE_LIMIT_STATUS_CODES for rr in self.results):
            signals += 1
        if self.ambiguous_503_count >= AMBIGUOUS_503_CORROBORATION:
            signals += 1
        if self.waf_challenge_detected:
            signals += 1
        if self.ip_reputation_issue:
            signals += 1
        if self.body_size_shifts >= 3:
            signals += 1
        if any("remaining" in k.lower() for k in self.rate_limit_headers_found):
            signals += 1
        return signals

    def _detection_confidence(self) -> str | None:
        """Item 7: overall confidence in the verdict — factors in baseline noise,
        sample count, corroborating signal count, and backend count."""
        if not self.rate_limit_detected and not self.target_unreachable:
            return None
        if self.target_unreachable:
            return "low — target never confirmed reachable, can't rule out a network/firewall issue"
        score = 0
        score += 1 if len(self.results) >= 10 else 0
        score += 1 if not self.baseline_noisy else 0
        score += 1 if len(self.backends_seen) <= 1 else 0
        score += 1 if self._corroborating_signal_count() >= 2 else 0
        if score >= 3:
            return "high"
        if score >= 2:
            return "medium"
        return "low"

    def _duration_cap_exceeded(self) -> bool:
        if self.config.max_duration is None:
            return False
        return (time.monotonic() - self.run_start) >= self.config.max_duration

    def _stop_for_duration_cap(self):
        # Item 11: an aggressive/long scan can leave the tester's own source IP
        # blocked for follow-up manual testing. Stop cleanly at the operator's
        # requested wall-clock cap rather than running to max_requests regardless.
        self.stopped_early = (
            f"max-duration cap ({self.config.max_duration:.0f}s) reached — stopping to avoid "
            f"over-scanning the target and risking this source IP getting blocked for "
            f"follow-up manual testing"
        )
        if not self.quiet:
            eprint(f"  {C.YELLOW}⚠ {self.stopped_early}{C.RESET}")

    # ── throttling trend via regression slope, normalised against the baseline ──
    def _throttling_trend(self) -> tuple[bool, str]:
        pts = [(r.request_num, r.response_time) for r in self.results if r.error is None]
        if len(pts) < 20:
            return False, ""
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        slope = linreg_slope(xs, ys)
        early = statistics.mean(ys[:10])
        late = statistics.mean(ys[-10:])

        # Express slope/deviation relative to the measured baseline instead of
        # absolute seconds — a sub-100ms API throttling 50ms -> 200ms never clears
        # a fixed "1.5s" floor, while a slow-but-steady origin trips it at idle.
        baseline_mean = self.baseline_time_mean if self.baseline_time_mean else early
        baseline_stdev = self.baseline_time_stdev if self.baseline_time_mean else 0.0
        if baseline_mean <= 0:
            return False, ""

        relative_slope = slope / baseline_mean  # fraction of baseline mean, per request
        if baseline_stdev > 0:
            late_deviation = (late - baseline_mean) / baseline_stdev  # z-score
            deviation_desc = f"{late_deviation:.1f}σ above baseline"
        else:
            late_deviation = (late - baseline_mean) / baseline_mean
            deviation_desc = f"{late_deviation*100:.0f}% above baseline"

        if relative_slope > 0.03 and late_deviation > 3:
            return True, (
                f"Response time trending up: {early:.3f}s → {late:.3f}s "
                f"(baseline {baseline_mean:.3f}s, slope {relative_slope*100:.1f}%/req, "
                f"{deviation_desc}) — possible progressive throttling"
            )
        return False, ""

    # ── SCAN strategy: sequential or concurrent waves ──
    async def run_scan(self, session: AsyncSession):
        cfg = self.config
        counter = 0
        stop = False

        async def one(req_num: int):
            r = await self.send_request(session, req_num)
            return r

        if cfg.concurrency <= 1:
            # sequential — order-precise, best for gradual throttling
            for req_num in range(1, cfg.max_requests + 1):
                r = await one(req_num)
                self.results.append(r)
                detected, reason, signal_type = self._evaluate(r)
                if detected:
                    self._mark_detected(reason, req_num, signal_type)
                    return
                if req_num % 50 == 0:
                    t, why = self._throttling_trend()
                    if t:
                        self._mark_detected(why, req_num, "throttling_trend")
                        return
                if self._duration_cap_exceeded():
                    self._stop_for_duration_cap()
                    return
                if cfg.delay_seconds > 0:
                    await asyncio.sleep(cfg.delay_seconds)
        else:
            # concurrent waves — best for hard limits and realistic bursts
            while counter < cfg.max_requests and not stop:
                wave = min(cfg.concurrency, cfg.max_requests - counter)
                nums = list(range(counter + 1, counter + wave + 1))
                counter += wave
                batch = await asyncio.gather(*(one(n) for n in nums))
                batch.sort(key=lambda r: r.request_num)
                for r in batch:
                    self.results.append(r)
                    detected, reason, signal_type = self._evaluate(r)
                    if detected and not self.rate_limit_detected:
                        self._mark_detected(reason, r.request_num, signal_type)
                        stop = True
                if stop:
                    return
                t, why = self._throttling_trend()
                if t:
                    self._mark_detected(why, counter, "throttling_trend")
                    return
                if self._duration_cap_exceeded():
                    self._stop_for_duration_cap()
                    return
                if cfg.delay_seconds > 0:
                    await asyncio.sleep(cfg.delay_seconds)

        if not self.rate_limit_detected:
            t, why = self._throttling_trend()
            if t:
                self._mark_detected(why, len(self.results), "throttling_trend")

    # ── DISCOVER strategy: measure the actual allowance per window ──
    async def run_discover(self, session: AsyncSession):
        """Send a steady stream and record how many requests succeed before the
        first limit signal within the window. Reports an allowance estimate."""
        cfg = self.config
        if not self.quiet:
            eprint(f"  {C.DIM}discover mode: measuring allowance over a "
                   f"{cfg.window:.0f}s window (max {cfg.max_requests} requests){C.RESET}")
        window_start = time.monotonic()
        ok_before_limit = 0
        limited_at: int | None = None

        for req_num in range(1, cfg.max_requests + 1):
            r = await self.send_request(session, req_num)
            self.results.append(r)
            detected, reason, signal_type = self._evaluate(r)

            is_limit_signal = (
                r.status in TRUE_RATE_LIMIT_STATUS_CODES
                or (r.status in AMBIGUOUS_STATUS_CODES
                    and self.ambiguous_503_count >= AMBIGUOUS_503_CORROBORATION)
                or (r.status in BLOCK_STATUS_CODES and req_num > 3)
                or (r.waf_detected and req_num > 3)
            )
            if is_limit_signal and limited_at is None:
                limited_at = req_num
                if signal_type is None:
                    # is_limit_signal's own criteria can fire even when _evaluate's
                    # narrower branch didn't (e.g. a block status that never "shifted"
                    # because it was already present from request #1) — derive a
                    # reasonable signal_type from the response itself in that case.
                    if r.status in TRUE_RATE_LIMIT_STATUS_CODES:
                        signal_type = "rate_limit"
                    elif r.status in AMBIGUOUS_STATUS_CODES:
                        signal_type = "rate_limit_ambiguous"
                    elif r.status in BLOCK_STATUS_CODES:
                        signal_type = "block_status_shift"
                    elif r.waf_detected:
                        signal_type = "waf_challenge"
                self._mark_detected(
                    self._with_retry_after(reason or f"first limit signal at request #{req_num}"),
                    req_num,
                    signal_type,
                )
                self.threshold_estimate = ok_before_limit
                # Never keep hammering after a limit signal: report what we measured
                # and stop cleanly rather than sleeping-and-retrying against a target
                # that may already be tracking us as abusive.
                break
            if r.error is None and 200 <= r.status < 400:
                ok_before_limit += 1

            elapsed = time.monotonic() - window_start
            if elapsed >= cfg.window:
                break
            if self._duration_cap_exceeded():
                self._stop_for_duration_cap()
                break
            if cfg.delay_seconds > 0:
                await asyncio.sleep(cfg.delay_seconds)

        elapsed = time.monotonic() - window_start
        if limited_at is None:
            if not self.quiet:
                eprint(f"  {C.GREEN}No limit hit{C.RESET} — {ok_before_limit} requests "
                       f"succeeded in {elapsed:.1f}s with no throttling.")

    async def run(self):
        cfg = self.config
        self.run_start = time.monotonic()
        self.started_at = datetime.now(timezone.utc).isoformat()
        if not self.quiet:
            eprint(f"  {C.BOLD}Target:{C.RESET}      {cfg.url}")
            eprint(f"  {C.BOLD}Type:{C.RESET}        {cfg.target_type}   "
                   f"{C.BOLD}Method:{C.RESET} {cfg.method}")
            eprint(f"  {C.BOLD}Mode:{C.RESET}        {cfg.mode}   "
                   f"{C.BOLD}Concurrency:{C.RESET} {cfg.concurrency}   "
                   f"{C.BOLD}Delay:{C.RESET} {cfg.delay_mode} ({cfg.delay_seconds}s)")
            if cfg.proxy:
                eprint(f"  {C.BOLD}Proxy:{C.RESET}       {cfg.proxy}")
            eprint(f"  {C.BOLD}Max:{C.RESET}         {cfg.max_requests} requests"
                   + (f"   {C.BOLD}Max duration:{C.RESET} {cfg.max_duration:.0f}s" if cfg.max_duration else ""))
            eprint(f"\n{'─' * 64}")
            eprint(f"  {C.DIM}{'#':>5}  {'status':>8}  {'time':>10}  {'size':>10}  notes{C.RESET}")
            eprint(f"{'─' * 64}")

        impersonation = BROWSER_IMPERSONATIONS[0]
        session_kwargs = dict(impersonate=impersonation)
        if cfg.proxy:
            session_kwargs["proxies"] = {"http": cfg.proxy, "https": cfg.proxy}
        if not cfg.verify:
            session_kwargs["verify"] = False

        async with AsyncSession(**session_kwargs) as session:
            if cfg.mode == "discover":
                await self.run_discover(session)
            else:
                await self.run_scan(session)

    # ── reporting ──
    def report_dict(self) -> dict:
        times = [r.response_time for r in self.results if r.error is None]
        stats = {}
        if times:
            stats = {
                "count": len(times),
                "avg": round(statistics.mean(times), 4),
                "min": round(min(times), 4),
                "max": round(max(times), 4),
                "stdev": round(statistics.stdev(times), 4) if len(times) > 1 else 0.0,
            }
        return {
            "tool": "rl-d",
            "version": VERSION,
            "started_at": self.started_at,
            "target": self.config.url,
            "target_type": self.config.target_type,
            "method": self.config.method,
            "mode": self.config.mode,
            "concurrency": self.config.concurrency,
            "requests_sent": len(self.results),
            "rate_limit_detected": self.rate_limit_detected,
            "detection_reason": self.detection_reason or None,
            "detection_request_num": self.detection_request_num or None,
            "signal_type": self.signal_type,
            "detection_confidence": self._detection_confidence(),
            "measurement_scope": MEASUREMENT_SCOPE,
            "stopped_early": self.stopped_early,
            "threshold_estimate": self.threshold_estimate,
            "threshold_confidence": self._threshold_confidence(),
            "retry_after_seconds": self.retry_after_seconds,
            "waf_challenge_detected": self.waf_challenge_detected,
            "waf_type": self.waf_type or None,
            "ip_reputation_issue": self.ip_reputation_issue,
            "target_unreachable": self.target_unreachable,
            "rate_limit_headers": self.rate_limit_headers_found,
            "status_code_counts": self.status_code_counts,
            "backends_seen": sorted(self.backends_seen),
            "connection_errors": self.connection_errors,
            "timeout_errors": self.timeout_errors,
            "response_time": stats,
            "baseline": {
                "sample_count": len(self.baseline_body_sizes),
                "body_mean": round(self.baseline_body_mean, 1) if self.baseline_body_mean is not None else None,
                "body_stdev": round(self.baseline_body_stdev, 1),
                "time_mean": round(self.baseline_time_mean, 4) if self.baseline_time_mean is not None else None,
                "time_stdev": round(self.baseline_time_stdev, 4),
                "noisy": self.baseline_noisy,
            },
        }

    def print_report(self):
        if self.quiet:
            return
        eprint(f"\n{'═' * 64}")
        eprint(f"  {C.BOLD}{C.CYAN}DETECTION REPORT{C.RESET}")
        eprint(f"{'═' * 64}\n")

        if self.target_unreachable:
            eprint(f"  {C.BOLD}Rate Limit:{C.RESET}   {C.YELLOW}INCONCLUSIVE{C.RESET}  "
                   f"(target unreachable — not a rate limit)")
        elif self.rate_limit_detected:
            eprint(f"  {C.BOLD}Rate Limit:{C.RESET}   {C.RED}YES{C.RESET}  "
                   f"@ request #{self.detection_request_num}")
            eprint(f"  {C.BOLD}Signal type:{C.RESET}  {self.signal_type}")
            eprint(f"  {C.BOLD}Reason:{C.RESET}       {self.detection_reason}")
            eprint(f"  {C.BOLD}Confidence:{C.RESET}   {self._detection_confidence()}")
            if self.threshold_estimate is not None:
                eprint(f"  {C.BOLD}Allowance:{C.RESET}    ~{C.MAGENTA}{self.threshold_estimate}{C.RESET} "
                       f"successful requests before the first limit signal "
                       f"(window {self.config.window:.0f}s)  "
                       f"{C.DIM}confidence: {self._threshold_confidence()}{C.RESET}")
        else:
            eprint(f"  {C.BOLD}Rate Limit:{C.RESET}   {C.GREEN}NO{C.RESET}  "
                   f"({len(self.results)} requests sent, no limit within cap)")

        eprint(f"  {C.DIM}Scope: {MEASUREMENT_SCOPE}{C.RESET}")

        if self.retry_after_seconds is not None:
            eprint(f"  {C.BOLD}Retry-After:{C.RESET}  {C.YELLOW}{self.retry_after_seconds:.0f}s{C.RESET} "
                   f"advertised by target — scan stopped rather than waiting/retrying")

        if self.baseline_noisy:
            eprint(f"  {C.YELLOW}⚠ Baseline is noisy (high response variance) — "
                   f"body/latency shift detections have lower confidence.{C.RESET}")

        if self.stopped_early:
            eprint(f"  {C.YELLOW}⚠ Stopped early: {self.stopped_early}{C.RESET}")

        times = [r.response_time for r in self.results if r.error is None]
        if times:
            eprint(f"\n  {C.BOLD}Response Time:{C.RESET}")
            if len(times) >= 5:
                eprint(f"    baseline(5): {statistics.mean(times[:5]):.3f}s")
            eprint(f"    avg {statistics.mean(times):.3f}s   min {min(times):.3f}s   max {max(times):.3f}s"
                   + (f"   stdev {statistics.stdev(times):.3f}s" if len(times) > 1 else ""))

        if self.status_code_counts:
            eprint(f"\n  {C.BOLD}Status Codes:{C.RESET}")
            for code, count in sorted(self.status_code_counts.items()):
                bar = "█" * min(count, 40)
                color = C.GREEN if code == 200 else C.RED if code in (429, 403, 503) else C.YELLOW
                eprint(f"    {color}{code}{C.RESET}: {count:>4}  {C.DIM}{bar}{C.RESET}")

        if self.rate_limit_headers_found:
            eprint(f"\n  {C.BOLD}Rate Limit Headers:{C.RESET}")
            for k, v in self.rate_limit_headers_found.items():
                eprint(f"    {C.MAGENTA}{k}{C.RESET}: {v}")

        eprint(f"\n  {C.BOLD}WAF/Challenge:{C.RESET}  "
               + (f"{C.RED}YES ({self.waf_type}){C.RESET}" if self.waf_challenge_detected else f"{C.GREEN}NO{C.RESET}"))
        eprint(f"  {C.BOLD}IP Reputation:{C.RESET}  "
               + (f"{C.RED}YES{C.RESET}" if self.ip_reputation_issue else f"{C.GREEN}NO{C.RESET}"))

        if len(self.backends_seen) > 1:
            eprint(f"\n  {C.YELLOW}⚠ Multiple backends ({len(self.backends_seen)}) — "
                   f"limit counts may be distributed (false-negative risk){C.RESET}")
            for b in sorted(self.backends_seen):
                eprint(f"    {C.DIM}{b}{C.RESET}")

        if self.connection_errors or self.timeout_errors:
            eprint(f"\n  {C.BOLD}Errors:{C.RESET}  "
                   f"connection={self.connection_errors}  timeouts={self.timeout_errors}")
        eprint(f"\n{'═' * 64}\n")


VERSION = "2.0.0"

BANNER = r"""
  ██████╗     ██╗                   ██████╗
  ██╔══██╗    ██║                   ██╔══██╗
  ██████╔╝    ██║         █████╗    ██║  ██║
  ██╔══██╗    ██║         ╚════╝    ██║  ██║
  ██║  ██║    ███████╗              ██████╔╝
  ╚═╝  ╚═╝    ╚══════╝              ╚═════╝
"""


def print_banner():
    """Amber startup banner (stderr). Callers decide when to suppress it."""
    eprint(f"{C.BOLD}{C.YELLOW}{BANNER.strip(chr(10))}{C.RESET}")
    eprint(f"  {C.CYAN}rate-limit · WAF · silent-block detector{C.RESET}"
           f"  {C.DIM}·  v{VERSION}{C.RESET}")
    eprint(f"  {C.DIM}authorised testing only · github.com/Surya8j/rl-d{C.RESET}\n")


# ─── Interactive wizard (fallback when no -u given) ──────────────────────────
def prompt_input(question: str, default: str = "", required: bool = False) -> str:
    suffix = f" [default: {default}]" if default else (" [Enter to skip]" if not required else "")
    while True:
        answer = input(f"\n  {C.CYAN}?{C.RESET} {question}{C.DIM}{suffix}{C.RESET}: ").strip()
        if answer:
            return answer
        if default:
            return default
        if required:
            eprint(f"  {C.RED}✖{C.RESET} This field is required.")
        else:
            return ""


def gather_inputs_interactive() -> Config:
    eprint(f"  {C.BOLD}Interactive setup{C.RESET} {C.DIM}— press Enter to accept defaults{C.RESET}")
    eprint(f"{C.DIM}{'─' * 60}{C.RESET}")

    url = normalise_url(prompt_input("Target URL", required=True))
    target_type = prompt_input("Target type? (api / webpage)", default="webpage").lower()
    if target_type not in ("api", "webpage"):
        target_type = "webpage"
    method = prompt_input("HTTP method? (GET / POST / HEAD)", default="GET").upper()
    if method not in ("GET", "POST", "HEAD", "PUT", "PATCH"):
        method = "GET"

    headers = {}
    headers_raw = prompt_input("Custom headers? (Key: Value, comma-separated)")
    if headers_raw:
        for part in headers_raw.split(","):
            if ":" in part:
                k, v = part.split(":", 1)
                headers[k.strip()] = v.strip()

    cookies = prompt_input("Cookie string?")
    delay = prompt_input("Delay mode? (burst / steady / slow)", default="burst").lower()
    if delay not in DELAY_MODES:
        delay = "burst"
    conc = to_int(prompt_input("Concurrency (parallel requests)?", default="1"), 1)
    mode = prompt_input("Mode? (scan / discover)", default="scan").lower()
    if mode not in ("scan", "discover"):
        mode = "scan"
    timeout = to_int(prompt_input("Request timeout (seconds)?", default="10"), 10)
    max_duration_raw = prompt_input("Max duration cap in seconds? (blank = no cap, "
                                     "protects your own IP on long scans)")
    max_duration = to_float(max_duration_raw, None)

    eprint(f"\n{C.GREEN}✔{C.RESET} Configuration complete. Starting...\n")
    return Config(
        url=url, target_type=target_type, method=method, custom_headers=headers,
        cookies=cookies, delay_mode=delay, delay_seconds=DELAY_MODES[delay],
        timeout=timeout, concurrency=max(1, conc), mode=mode,
        max_duration=max_duration,
    )


# ─── helpers ──
def normalise_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    if not urlparse(url).netloc:
        eprint(f"  {C.RED}✖{C.RESET} Invalid URL: {url}")
        sys.exit(2)
    return url


def to_int(s: str, default: int) -> int:
    try:
        return int(s)
    except (ValueError, TypeError):
        return default


def to_float(s: str, default: float | None) -> float | None:
    try:
        return float(s)
    except (ValueError, TypeError):
        return default


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="rl-d",
        description="Detect and measure rate limiting, WAF challenges, and silent "
                    "blocks on web apps you are authorised to test.",
        epilog="Run with no --url to launch the interactive wizard.",
    )
    p.add_argument("-u", "--url", help="target URL")
    p.add_argument("-t", "--type", dest="target_type", choices=["api", "webpage"],
                   default="webpage", help="target type (default: webpage)")
    p.add_argument("-X", "--method", default="GET",
                   choices=["GET", "POST", "HEAD", "PUT", "PATCH"], help="HTTP method")
    p.add_argument("-H", "--header", action="append", default=[], metavar="K:V",
                   help="custom header (repeatable)")
    p.add_argument("-b", "--cookie", default="", help="cookie string")
    p.add_argument("-d", "--data", default=None, help="request body for POST/PUT/PATCH")
    p.add_argument("-c", "--concurrency", type=int, default=1,
                   help="parallel requests per wave (default: 1 = sequential)")
    p.add_argument("-n", "--max-requests", type=int, default=DEFAULT_MAX_REQUESTS,
                   help=f"max requests (default: {DEFAULT_MAX_REQUESTS})")
    p.add_argument("--delay", choices=list(DELAY_MODES), default="burst",
                   help="delay between requests/waves (default: burst)")
    p.add_argument("--timeout", type=int, default=10, help="per-request timeout (s)")
    p.add_argument("--discover", action="store_true",
                   help="measure the allowance (requests before first limit) instead of just detecting it")
    p.add_argument("--window", type=float, default=60.0,
                   help="discover mode: measurement window in seconds (default: 60)")
    p.add_argument("--max-duration", type=float, default=None, metavar="SECONDS",
                   help="hard wall-clock cap for the whole run — stop cleanly instead of "
                        "risking your own source IP getting blocked on a long/aggressive scan")
    p.add_argument("--proxy", default=None,
                   help="route through an upstream proxy, e.g. http://127.0.0.1:8080 (Burp)")
    p.add_argument("--insecure", action="store_true", help="skip TLS certificate verification")
    p.add_argument("--json", dest="json_out", default=None, metavar="PATH",
                   help="write full report as JSON ('-' for stdout)")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress live output (use with --json)")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    p.add_argument("--no-banner", action="store_true", help="suppress the startup banner")
    p.add_argument("-y", "--yes", action="store_true",
                   help="skip the authorisation confirmation prompt (for scripting)")
    p.add_argument("-V", "--version", action="version", version=f"rl-d {VERSION}")
    return p.parse_args(argv)


def config_from_args(a: argparse.Namespace) -> Config:
    headers = {}
    for h in a.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    return Config(
        url=normalise_url(a.url),
        target_type=a.target_type,
        method=a.method,
        custom_headers=headers,
        cookies=a.cookie,
        data=a.data,
        delay_mode=a.delay,
        delay_seconds=DELAY_MODES[a.delay],
        timeout=a.timeout,
        max_requests=a.max_requests,
        concurrency=max(1, a.concurrency),
        proxy=a.proxy,
        mode="discover" if a.discover else "scan",
        window=a.window,
        verify=not a.insecure,
        max_duration=a.max_duration,
    )


def confirm_authorisation(url: str, assume_yes: bool):
    """Rate-limit probing generates real traffic against the target. Confirm the
    operator is authorised to test it before sending anything."""
    if assume_yes:
        return
    if not sys.stdin.isatty():
        return
    host = urlparse(url).netloc
    eprint(f"\n  {C.YELLOW}This will send live requests to {C.BOLD}{host}{C.RESET}{C.YELLOW}.{C.RESET}")
    eprint(f"  {C.YELLOW}Only test systems you own or are explicitly authorised to assess.{C.RESET}")
    try:
        answer = input(f"  {C.CYAN}?{C.RESET} Proceed? (y/N): ").strip().lower()
    except EOFError:
        answer = ""
    if answer not in ("y", "yes"):
        eprint(f"  {C.DIM}Aborted.{C.RESET}")
        sys.exit(0)


def main(argv: list[str] | None = None):
    argv = sys.argv[1:] if argv is None else argv
    args = parse_args(argv)
    if args.no_color or not sys.stderr.isatty():
        C.disable()

    if not args.quiet and not args.no_banner and sys.stderr.isatty():
        print_banner()

    try:
        if args.url:
            config = config_from_args(args)
        else:
            config = gather_inputs_interactive()

        confirm_authorisation(config.url, args.yes)

        detector = RateLimitDetector(config, quiet=args.quiet)
        asyncio.run(detector.run())
        detector.print_report()

        if args.json_out:
            payload = json.dumps(detector.report_dict(), indent=2)
            if args.json_out == "-":
                print(payload)
            else:
                with open(args.json_out, "w") as f:
                    f.write(payload)
                eprint(f"  {C.GREEN}✔{C.RESET} Report written to {args.json_out}")

        # Item 10: distinct exit codes per signal type so CI can branch on what was
        # found (rate limit vs WAF vs silent block vs unreachable) instead of every
        # finding collapsing into a single exit(1).
        exit_code = EXIT_CODE_BY_SIGNAL.get(detector.signal_type,
                                             1 if detector.rate_limit_detected else 0)
        sys.exit(exit_code)

    except KeyboardInterrupt:
        eprint(f"\n\n  {C.YELLOW}⚠ Interrupted by user.{C.RESET}\n")
        sys.exit(130)


if __name__ == "__main__":
    main()
