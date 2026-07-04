# rl-d — Rate Limit Detector

An async Python CLI to **detect and measure** rate limiting, WAF challenges, and
silent blocks on web applications you are authorised to test.

> ⚠️ **Authorised testing only.** rl-d sends live traffic to its target. Only run
> it against systems you own or have explicit written permission to assess.

## What it does

- Detects hard rate limits (HTTP 429 / 503) and block responses (401/403/406/418/444)
- Detects Cloudflare and generic WAF challenges (Akamai/Imperva-style signatures)
- Detects **silent blocks** via response-body size deviation from a baseline
- Detects **progressive throttling** via response-time regression (least-squares slope)
- Detects IP-reputation issues (blocks/challenges on the first few requests)
- **Measures the allowance** — `--discover` reports how many requests succeed before the first limit
- Parses `X-RateLimit-*` / `Retry-After` headers
- Flags multiple backends (distributed-limit false-negative risk)
- Browser impersonation via `curl_cffi` (Chrome / Safari TLS + JA3 fingerprints)

## Install

```bash
pip install -r requirements.txt        # just curl_cffi
# or install as a command:
pip install .                          # exposes the `rl-d` command
```

## Usage

```bash
# Interactive wizard (no flags):
python3 ratelimit_detect.py

# Sequential scan:
python3 ratelimit_detect.py -u https://api.example.com/v1/search -t api

# Concurrent scan — 20 parallel requests per wave (surfaces hard limits fast):
python3 ratelimit_detect.py -u https://api.example.com/v1 -c 20 -n 500

# Measure the actual allowance over a 60s window:
python3 ratelimit_detect.py -u https://api.example.com/v1 --discover --window 60

# Authenticated POST, custom headers, JSON report for your findings:
python3 ratelimit_detect.py -u https://api.example.com/login -X POST \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '{"user":"x"}' --json login.report.json

# Route through Burp for capture/replay:
python3 ratelimit_detect.py -u https://api.example.com -c 10 --proxy http://127.0.0.1:8080 --insecure
```

Non-interactive runs need `-y/--yes` to skip the authorisation prompt (or pipe input).
The process **exit code is `1` when a limit/block is found, `0` when clean** — handy in CI.

## Key options

| Flag | Purpose |
|------|---------|
| `-u, --url` | Target URL (omit for interactive wizard) |
| `-c, --concurrency N` | Parallel requests per wave (`1` = sequential) |
| `-n, --max-requests N` | Request cap (default 300) |
| `--discover` | Measure the allowance instead of only detecting |
| `--window S` | Discover-mode measurement window (seconds) |
| `-X, -H, -b, -d` | Method, header (repeatable), cookie, body |
| `--delay` | `burst` / `steady` / `slow` pacing |
| `--proxy` | Upstream proxy (e.g. Burp) |
| `--json PATH` | Write full machine-readable report (`-` for stdout) |
| `-q, --quiet` | Suppress live output (pair with `--json`) |

## Detection signals

| Signal | How detected |
|--------|-------------|
| Hard rate limit | HTTP 429 / 503 |
| Block / shift | 401/403/406/418/444 after a 200 baseline |
| WAF / Cloudflare | Body signature match |
| Silent block | >50% body-size deviation, sustained |
| Throttling | Positive response-time regression slope + magnitude |
| IP reputation | Block/challenge within first 3 requests |
| Exhaustion | `X-RateLimit-Remaining: 0` / `Retry-After` |

## Development

```bash
pip install -e ".[dev]"
python3 -m pytest -q
```

## Scope

rl-d is an **assessment** tool: it measures a target's protections. It deliberately
does **not** include evasion features (IP rotation, distributed sourcing, or
limit-bypass) — the goal is to characterise rate limiting for a report, not to
circumvent it.

## License

MIT — see [LICENSE](LICENSE).
