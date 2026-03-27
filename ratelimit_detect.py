#!/usr/bin/env python3
"""
Rate Limit Detector — CLI tool to detect rate limiting on web applications.
Cross-platform: macOS and Linux. No sudo required.

Usage:
    python3 ratelimit_detect.py

Dependencies:
    pip install curl_cffi
"""

import asyncio
import sys
import time
import statistics
import json
import re
from urllib.parse import urlparse

# ─── Dependency check ────────────────────────────────────────────────────────
try:
    from curl_cffi.requests import AsyncSession
except ImportError:
    print("\n  ✖  Missing dependency: curl_cffi")
    print("     Install it with:  pip install curl_cffi\n")
    sys.exit(1)


# ─── Constants ───────────────────────────────────────────────────────────────
MAX_REQUESTS = 300
RATE_LIMIT_STATUS_CODES = {429, 503}
BLOCK_STATUS_CODES = {403, 406, 418}
BROWSER_IMPERSONATIONS = ["chrome120", "chrome119", "safari17_0"]

CLOUDFLARE_SIGNATURES = [
    "managed challenge",
    "cf-chl-bypass",
    "challenge-platform",
    "just a moment",
    "checking your browser",
    "cf-browser-verification",
    "attention required",
    "ray id",
    "_cf_chl_opt",
    "turnstile",
]

WAF_SIGNATURES = [
    "access denied",
    "request blocked",
    "web application firewall",
    "security check",
    "bot detection",
    "are you a robot",
    "captcha",
    "recaptcha",
    "hcaptcha",
    "please verify",
]

DELAY_MODES = {
    "burst": 0.0,
    "steady": 0.2,
    "slow": 0.5,
}

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


# ─── Colors (ANSI, works on macOS + Linux terminals) ────────────────────────
class C:
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    RESET = "\033[0m"


# ─── Interactive prompts ─────────────────────────────────────────────────────
def prompt_input(question: str, default: str = "", required: bool = False) -> str:
    """Ask a single question, return answer or default."""
    suffix = f" [default: {default}]" if default else ""
    if not required:
        suffix += " [press Enter to skip]" if not default else ""

    while True:
        answer = input(f"\n  {C.CYAN}?{C.RESET} {question}{C.DIM}{suffix}{C.RESET}: ").strip()
        if answer:
            return answer
        if default:
            return default
        if required:
            print(f"  {C.RED}✖{C.RESET} This field is required.")
        else:
            return ""


def gather_inputs() -> dict:
    """Walk through interactive prompts one at a time."""
    print(f"\n{C.BOLD}{'─' * 60}{C.RESET}")
    print(f"  {C.BOLD}{C.CYAN}Rate Limit Detector{C.RESET} — Interactive Setup")
    print(f"{C.BOLD}{'─' * 60}{C.RESET}")

    config = {}

    # 1. URL
    url = prompt_input("Enter target URL", required=True)
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    if not parsed.netloc:
        print(f"  {C.RED}✖{C.RESET} Invalid URL.")
        sys.exit(1)
    config["url"] = url

    # 2. Target type
    target_type = prompt_input("Target type? (api / webpage)", default="webpage").lower()
    if target_type not in ("api", "webpage"):
        target_type = "webpage"
    config["target_type"] = target_type

    # 3. HTTP method
    method = prompt_input("HTTP method? (GET / POST / HEAD)", default="GET").upper()
    if method not in ("GET", "POST", "HEAD"):
        method = "GET"
    config["method"] = method

    # 4. Custom headers
    headers_raw = prompt_input("Custom headers? (e.g. Authorization: Bearer xxx)")
    config["custom_headers"] = {}
    if headers_raw:
        for part in headers_raw.split(","):
            if ":" in part:
                k, v = part.split(":", 1)
                config["custom_headers"][k.strip()] = v.strip()

    # 5. Cookies
    cookies = prompt_input("Cookie string?")
    config["cookies"] = cookies

    # 6. Delay mode
    delay = prompt_input("Request delay mode? (burst / steady / slow)", default="burst").lower()
    if delay not in DELAY_MODES:
        delay = "burst"
    config["delay_mode"] = delay
    config["delay_seconds"] = DELAY_MODES[delay]

    # 7. Timeout
    timeout_str = prompt_input("Request timeout in seconds?", default="10")
    try:
        config["timeout"] = int(timeout_str)
    except ValueError:
        config["timeout"] = 10

    print(f"\n{C.BOLD}{'─' * 60}{C.RESET}")
    print(f"  {C.GREEN}✔{C.RESET} Configuration complete. Starting detection...\n")

    return config


# ─── Detection logic ─────────────────────────────────────────────────────────
class RateLimitDetector:
    def __init__(self, config: dict):
        self.config = config
        self.results = []
        self.baseline_body_size = None
        self.baseline_status = None
        self.backends_seen = set()
        self.rate_limit_detected = False
        self.detection_reason = ""
        self.detection_request_num = 0
        self.waf_challenge_detected = False
        self.waf_type = ""
        self.ip_reputation_issue = False
        self.rate_limit_headers_found = {}
        self.status_code_counts = {}
        self.connection_errors = 0
        self.timeout_errors = 0
        self.body_size_shifts = 0
        self.ever_connected = False  # True once we get at least one HTTP response
        self.target_unreachable = False

    def _build_headers(self) -> dict:
        """Build request headers based on target type."""
        if self.config["target_type"] == "webpage":
            headers = dict(WEBPAGE_HEADERS)
        else:
            headers = dict(API_HEADERS)

        headers.update(self.config.get("custom_headers", {}))

        if self.config.get("cookies"):
            headers["Cookie"] = self.config["cookies"]

        return headers

    def _check_rate_limit_headers(self, resp_headers: dict) -> dict:
        """Extract rate limit related headers."""
        rl_headers = {}
        for key, value in resp_headers.items():
            key_lower = key.lower()
            if any(
                k in key_lower
                for k in [
                    "ratelimit",
                    "rate-limit",
                    "x-ratelimit",
                    "retry-after",
                    "x-retry-after",
                    "x-rate-limit",
                ]
            ):
                rl_headers[key] = value
        return rl_headers

    def _check_waf_challenge(self, body: str) -> tuple[bool, str]:
        """Check if response body contains WAF/challenge content."""
        body_lower = body.lower() if body else ""

        for sig in CLOUDFLARE_SIGNATURES:
            if sig in body_lower:
                return True, "Cloudflare"

        for sig in WAF_SIGNATURES:
            if sig in body_lower:
                return True, "Generic WAF"

        return False, ""

    def _check_backend(self, resp_headers: dict):
        """Track backend server identifiers."""
        for key in ["server", "x-served-by", "x-backend", "x-upstream", "via"]:
            val = resp_headers.get(key, "")
            if val:
                self.backends_seen.add(f"{key}: {val}")

    def _check_body_size_deviation(self, current_size: int, request_num: int) -> bool:
        """Detect significant body size changes from baseline."""
        if self.baseline_body_size is None:
            return False
        if self.baseline_body_size == 0:
            return current_size > 500

        deviation = abs(current_size - self.baseline_body_size) / max(self.baseline_body_size, 1)
        return deviation > 0.5  # more than 50% change

    def _print_progress(self, req_num: int, status: int, resp_time: float, body_size: int, warning: str = ""):
        """Print live progress line."""
        # Color status code
        if status == 200:
            sc = f"{C.GREEN}{status}{C.RESET}"
        elif status in RATE_LIMIT_STATUS_CODES:
            sc = f"{C.RED}{status}{C.RESET}"
        elif status in BLOCK_STATUS_CODES:
            sc = f"{C.RED}{status}{C.RESET}"
        elif status == 0:
            sc = f"{C.RED}ERR{C.RESET}"
        else:
            sc = f"{C.YELLOW}{status}{C.RESET}"

        # Color response time
        if resp_time > 5.0:
            rt = f"{C.RED}{resp_time:.2f}s{C.RESET}"
        elif resp_time > 2.0:
            rt = f"{C.YELLOW}{resp_time:.2f}s{C.RESET}"
        else:
            rt = f"{C.DIM}{resp_time:.2f}s{C.RESET}"

        line = f"  {C.DIM}#{req_num:>3}{C.RESET}  status={sc}  time={rt}  size={body_size:>7}B"
        if warning:
            line += f"  {C.YELLOW}⚠ {warning}{C.RESET}"
        print(line)

    async def send_request(self, session: AsyncSession, req_num: int) -> dict:
        """Send a single request and collect metrics."""
        headers = self._build_headers()
        result = {
            "request_num": req_num,
            "status": 0,
            "response_time": 0.0,
            "body_size": 0,
            "error": None,
            "rate_limit_headers": {},
            "waf_detected": False,
            "waf_type": "",
            "body_size_shifted": False,
        }

        start = time.monotonic()
        try:
            resp = await session.request(
                self.config["method"],
                self.config["url"],
                headers=headers,
                timeout=self.config["timeout"],
                allow_redirects=True,
            )
            elapsed = time.monotonic() - start

            body = resp.text or ""
            resp_headers = dict(resp.headers) if resp.headers else {}

            result["status"] = resp.status_code
            result["response_time"] = elapsed
            result["body_size"] = len(body.encode("utf-8", errors="replace"))

            # We got an HTTP response — target is reachable
            self.ever_connected = True

            # Track status codes
            self.status_code_counts[resp.status_code] = self.status_code_counts.get(resp.status_code, 0) + 1

            # Check rate limit headers
            rl_headers = self._check_rate_limit_headers(resp_headers)
            if rl_headers:
                result["rate_limit_headers"] = rl_headers
                self.rate_limit_headers_found.update(rl_headers)

            # Check WAF / challenge
            is_waf, waf_type = self._check_waf_challenge(body)
            result["waf_detected"] = is_waf
            result["waf_type"] = waf_type

            # Track backends
            self._check_backend(resp_headers)

            # Establish baseline from first successful response
            if req_num <= 3 and resp.status_code == 200:
                if self.baseline_body_size is None:
                    self.baseline_body_size = result["body_size"]
                    self.baseline_status = resp.status_code

            # Check body size deviation
            if self.baseline_body_size is not None:
                shifted = self._check_body_size_deviation(result["body_size"], req_num)
                result["body_size_shifted"] = shifted
                if shifted:
                    self.body_size_shifts += 1

        except Exception as e:
            elapsed = time.monotonic() - start
            result["response_time"] = elapsed
            result["error"] = str(e)
            error_str = str(e).lower()
            if "timeout" in error_str or "timed out" in error_str:
                self.timeout_errors += 1
            else:
                self.connection_errors += 1

        return result

    def _evaluate_result(self, result: dict, req_num: int) -> tuple[bool, str]:
        """Evaluate a single result for rate limiting signals. Returns (detected, reason)."""
        warning = ""

        # 1. IP reputation check on first 3 requests
        if req_num <= 3:
            if result["status"] in BLOCK_STATUS_CODES or result["waf_detected"]:
                self.ip_reputation_issue = True
                warning = "early block/challenge — possible IP reputation issue"
                self._print_progress(req_num, result["status"], result["response_time"], result["body_size"], warning)
                if req_num == 3 and self.ip_reputation_issue:
                    return True, "IP reputation / pre-existing block detected (blocked on first requests)"
                return False, ""

        # 2. Hard rate limit status codes
        if result["status"] in RATE_LIMIT_STATUS_CODES:
            warning = "RATE LIMIT STATUS CODE"
            self._print_progress(req_num, result["status"], result["response_time"], result["body_size"], warning)
            return True, f"HTTP {result['status']} returned at request #{req_num}"

        # 3. Block status codes (after baseline established)
        if result["status"] in BLOCK_STATUS_CODES and req_num > 3:
            if self.baseline_status and self.baseline_status != result["status"]:
                warning = "status code shifted to block"
                self._print_progress(req_num, result["status"], result["response_time"], result["body_size"], warning)
                return True, f"Status shifted from {self.baseline_status} to {result['status']} at request #{req_num}"

        # 4. WAF challenge appeared mid-session
        if result["waf_detected"] and req_num > 3:
            if not self.waf_challenge_detected:
                self.waf_challenge_detected = True
                self.waf_type = result["waf_type"]
                warning = f"{result['waf_type']} challenge detected"
                self._print_progress(req_num, result["status"], result["response_time"], result["body_size"], warning)
                return True, f"{result['waf_type']} challenge/captcha triggered at request #{req_num}"

        # 5. Body size deviation (silent block)
        if result["body_size_shifted"] and req_num > 5:
            if self.body_size_shifts >= 3:
                warning = "response body changed significantly"
                self._print_progress(req_num, result["status"], result["response_time"], result["body_size"], warning)
                return True, f"Response body size shifted significantly at request #{req_num} (possible silent block)"

        # 6. Connection errors / timeouts spike
        if result["error"]:
            warning = f"connection error: {result['error'][:50]}"
            self._print_progress(req_num, 0, result["response_time"], 0, warning)

            # If we NEVER got a successful response, this is likely unreachable, not rate limiting
            if not self.ever_connected and self.connection_errors >= 3:
                self.target_unreachable = True
                return True, "Target appears unreachable (no successful connection established). Check URL, network, or firewall."

            # If we DID connect before but now getting errors, likely rate-limit triggered connection drops
            if self.ever_connected and self.connection_errors + self.timeout_errors >= 5 and req_num > 5:
                return True, f"Connection drops after successful requests ({self.connection_errors} errors, {self.timeout_errors} timeouts) by request #{req_num} — likely rate limiting"
            return False, ""

        # 7. Rate limit headers showing exhaustion
        if result["rate_limit_headers"]:
            remaining = None
            for k, v in result["rate_limit_headers"].items():
                if "remaining" in k.lower():
                    try:
                        remaining = int(v)
                    except (ValueError, TypeError):
                        pass
            if remaining is not None and remaining <= 0:
                warning = "rate limit remaining = 0"
                self._print_progress(req_num, result["status"], result["response_time"], result["body_size"], warning)
                return True, f"Rate limit header shows 0 remaining at request #{req_num}"

        # Print normal progress
        if result["body_size_shifted"]:
            warning = "body size shifted"
        elif len(self.backends_seen) > 1 and req_num == 10:
            warning = f"multiple backends detected ({len(self.backends_seen)})"
        self._print_progress(req_num, result["status"], result["response_time"], result["body_size"], warning)

        return False, ""

    def _check_response_time_trend(self) -> tuple[bool, str]:
        """Check for gradual throttling via response time analysis."""
        times = [r["response_time"] for r in self.results if r["error"] is None]
        if len(times) < 20:
            return False, ""

        early = times[:10]
        late = times[-10:]
        early_avg = statistics.mean(early)
        late_avg = statistics.mean(late)

        if early_avg > 0 and late_avg > early_avg * 3 and late_avg > 2.0:
            return True, f"Response time degradation detected: early avg {early_avg:.2f}s → late avg {late_avg:.2f}s (possible throttling)"

        return False, ""

    async def run(self):
        """Main detection loop."""
        print(f"  {C.BOLD}Target:{C.RESET}  {self.config['url']}")
        print(f"  {C.BOLD}Type:{C.RESET}    {self.config['target_type']}")
        print(f"  {C.BOLD}Method:{C.RESET}  {self.config['method']}")
        print(f"  {C.BOLD}Delay:{C.RESET}   {self.config['delay_mode']} ({self.config['delay_seconds']}s)")
        print(f"  {C.BOLD}Max:{C.RESET}     {MAX_REQUESTS} requests")
        print(f"\n{'─' * 60}")
        print(f"  {C.DIM}{'#':>4}  {'status':>8}  {'time':>10}  {'size':>10}  {'notes'}{C.RESET}")
        print(f"{'─' * 60}")

        impersonation = BROWSER_IMPERSONATIONS[0] if self.config["target_type"] == "webpage" else BROWSER_IMPERSONATIONS[0]

        async with AsyncSession(impersonate=impersonation) as session:
            for req_num in range(1, MAX_REQUESTS + 1):
                result = await self.send_request(session, req_num)
                self.results.append(result)

                detected, reason = self._evaluate_result(result, req_num)
                if detected:
                    self.rate_limit_detected = True
                    self.detection_reason = reason
                    self.detection_request_num = req_num
                    break

                # Check response time trend periodically
                if req_num % 50 == 0 and req_num >= 50:
                    time_detected, time_reason = self._check_response_time_trend()
                    if time_detected:
                        self.rate_limit_detected = True
                        self.detection_reason = time_reason
                        self.detection_request_num = req_num
                        break

                # Delay between requests
                if self.config["delay_seconds"] > 0:
                    await asyncio.sleep(self.config["delay_seconds"])

        # Final response time check if we hit max
        if not self.rate_limit_detected:
            time_detected, time_reason = self._check_response_time_trend()
            if time_detected:
                self.rate_limit_detected = True
                self.detection_reason = time_reason
                self.detection_request_num = len(self.results)

        self._print_report()

    def _print_report(self):
        """Print final summary report."""
        print(f"\n{'═' * 60}")
        print(f"  {C.BOLD}{C.CYAN}DETECTION REPORT{C.RESET}")
        print(f"{'═' * 60}\n")

        # Rate limit result
        if self.target_unreachable:
            print(f"  {C.BOLD}Rate Limit Detected:{C.RESET}  {C.YELLOW}INCONCLUSIVE{C.RESET}")
            print(f"  {C.BOLD}Reason:{C.RESET}               {C.YELLOW}Target unreachable — could not establish connection{C.RESET}")
            print(f"  {C.DIM}  Check the URL, your network, DNS, or firewall settings.{C.RESET}")
            print(f"  {C.DIM}  This is NOT a rate limit — the target was never reachable.{C.RESET}")
        elif self.rate_limit_detected:
            print(f"  {C.BOLD}Rate Limit Detected:{C.RESET}  {C.RED}YES{C.RESET}")
            print(f"  {C.BOLD}Triggered At:{C.RESET}         Request #{self.detection_request_num}")
            print(f"  {C.BOLD}Reason:{C.RESET}               {self.detection_reason}")
        else:
            print(f"  {C.BOLD}Rate Limit Detected:{C.RESET}  {C.GREEN}NO{C.RESET}")
            print(f"  {C.BOLD}Requests Sent:{C.RESET}        {len(self.results)}")
            print(f"  {C.DIM}  (No rate limiting detected within {MAX_REQUESTS} requests){C.RESET}")

        # Response time stats
        times = [r["response_time"] for r in self.results if r["error"] is None]
        if times:
            print(f"\n  {C.BOLD}Response Time:{C.RESET}")
            print(f"    Baseline (first 5):  {statistics.mean(times[:5]):.3f}s" if len(times) >= 5 else "")
            print(f"    Average:             {statistics.mean(times):.3f}s")
            print(f"    Min:                 {min(times):.3f}s")
            print(f"    Max:                 {max(times):.3f}s")
            if len(times) > 1:
                print(f"    Std Dev:             {statistics.stdev(times):.3f}s")

        # Status codes
        if self.status_code_counts:
            print(f"\n  {C.BOLD}Status Codes:{C.RESET}")
            for code, count in sorted(self.status_code_counts.items()):
                bar = "█" * min(count, 40)
                color = C.GREEN if code == 200 else C.RED if code in (429, 403, 503) else C.YELLOW
                print(f"    {color}{code}{C.RESET}: {count:>4}  {C.DIM}{bar}{C.RESET}")

        # Rate limit headers
        if self.rate_limit_headers_found:
            print(f"\n  {C.BOLD}Rate Limit Headers Found:{C.RESET}")
            for k, v in self.rate_limit_headers_found.items():
                print(f"    {C.MAGENTA}{k}{C.RESET}: {v}")

        # WAF / challenge
        print(f"\n  {C.BOLD}WAF/Challenge Detected:{C.RESET}  ", end="")
        if self.waf_challenge_detected:
            print(f"{C.RED}YES ({self.waf_type}){C.RESET}")
        else:
            print(f"{C.GREEN}NO{C.RESET}")

        # IP reputation
        print(f"  {C.BOLD}IP Reputation Issue:{C.RESET}    ", end="")
        if self.ip_reputation_issue:
            print(f"{C.RED}YES (early block/challenge on initial requests){C.RESET}")
        else:
            print(f"{C.GREEN}NO{C.RESET}")

        # Backend diversity
        if self.backends_seen:
            print(f"\n  {C.BOLD}Backend Servers ({len(self.backends_seen)}):{C.RESET}")
            for b in self.backends_seen:
                print(f"    {C.DIM}{b}{C.RESET}")
            if len(self.backends_seen) > 1:
                print(f"    {C.YELLOW}⚠ Multiple backends detected — rate limit counts may be")
                print(f"      distributed across servers (false negative risk){C.RESET}")

        # Errors
        if self.connection_errors or self.timeout_errors:
            print(f"\n  {C.BOLD}Errors:{C.RESET}")
            if self.connection_errors:
                print(f"    Connection errors:  {self.connection_errors}")
            if self.timeout_errors:
                print(f"    Timeouts:           {self.timeout_errors}")

        print(f"\n{'═' * 60}\n")


# ─── Main ────────────────────────────────────────────────────────────────────
def main():
    try:
        config = gather_inputs()
        detector = RateLimitDetector(config)
        asyncio.run(detector.run())
    except KeyboardInterrupt:
        print(f"\n\n  {C.YELLOW}⚠ Interrupted by user.{C.RESET}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
