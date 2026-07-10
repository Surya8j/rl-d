# rl-d — Rate Limit Detector

```text
██████╗     ██╗                   ██████╗
██╔══██╗    ██║                   ██╔══██╗
██████╔╝    ██║         █████╗    ██║  ██║
██╔══██╗    ██║         ╚════╝    ██║  ██║
██║  ██║    ███████╗              ██████╔╝
╚═╝  ╚═╝    ╚══════╝              ╚═════╝
  rate-limit · WAF · silent-block detector
```

**rl-d** is an async Python CLI that finds out how a web target defends itself.
Point it at an endpoint and it fires a controlled stream of requests to surface
hard rate limits, WAF/Cloudflare challenges, silent blocks, and progressive
throttling — then, in `--discover` mode, measures the actual allowance (how many
requests get through before the limit trips). Built for authorised assessments:
it characterises protections for a report, it does not try to evade them.

> ⚠️ **Authorised testing only.** rl-d sends live traffic to its target. Only run
> it against systems you own or have explicit written permission to assess.

## What it does

- Detects hard rate limits (HTTP 429); HTTP 503 is treated as ambiguous (outage-or-limit) until it recurs
- Detects Cloudflare and generic WAF challenges via **both** body signatures and header signatures (`cf-mitigated`, `x-sucuri-block`, `AkamaiGHost`, etc.)
- Detects **silent blocks** via response-body size deviation from a baseline distribution (mean ± stdev, not a flat %), corroborated by a status or latency shift before flagging
- Detects **progressive throttling** via response-time regression normalised against the baseline (z-score), not a fixed absolute-seconds floor
- Detects IP-reputation issues (blocks/challenges on the first few requests)
- **Measures the allowance** — `--discover` reports how many requests succeed before the first limit, with a confidence rating
- Parses `X-RateLimit-*` / `Retry-After` headers and honours the advertised backoff by stopping cleanly, never auto-retrying
- Flags multiple backends (distributed-limit false-negative risk); every finding carries a `signal_type` and `detection_confidence`
- Optional `--max-duration` wall-clock cap so a long/aggressive scan doesn't get your own source IP blocked
- Browser impersonation via `curl_cffi` (Chrome / Safari TLS + JA3 fingerprints)

## Install

**One command** (installs the `rl-d` command via pipx, with a venv fallback):

```bash
git clone https://github.com/Surya8j/rl-d.git
cd rl-d
./install.sh
```

Open a new terminal afterwards if `rl-d` isn't found immediately — the installer
adds `~/.local/bin` to your PATH.

**Alternatives:**

```bash
pipx install git+https://github.com/Surya8j/rl-d.git   # isolated, no clone needed
pip install .                                          # into the current environment
```

Prefer not to install? Run it directly (after `pip install -r requirements.txt`):

```bash
python3 ratelimit_detect.py …
```

Run `rl-d` for the interactive wizard, or `rl-d --help` for the full flag
reference. (From a bare clone without installing: `python3 ratelimit_detect.py`.)

## Key options

| Flag | Purpose |
|------|---------|
| `-u, --url` | Target URL (omit for interactive wizard) |
| `-c, --concurrency N` | Parallel requests per wave (`1` = sequential) |
| `-n, --max-requests N` | Request cap (default 300) |
| `--discover` | Measure the allowance instead of only detecting |
| `--window S` | Discover-mode measurement window (seconds) |
| `--max-duration S` | Hard wall-clock cap for the whole run (self-protection) |
| `-X, -H, -b, -d` | Method, header (repeatable), cookie, body |
| `--delay` | `burst` / `steady` / `slow` pacing |
| `--proxy` | Upstream proxy (e.g. Burp) |
| `--json PATH` | Write full machine-readable report (`-` for stdout) |
| `-q, --quiet` | Suppress live output (pair with `--json`) |

Non-interactive runs need `-y/--yes` to skip the authorisation prompt.

## Exit codes

Distinct per `signal_type` so CI can branch on what was found, instead of every
finding collapsing into a single `exit(1)`:

| Code | Meaning |
|------|---------|
| `0` | Clean — no limit/block found |
| `1` | Rate limit (429, confirmed 503, header exhaustion, throttling trend, or connection drops) |
| `2` | Block status shifted mid-run |
| `3` | WAF/challenge triggered |
| `4` | Silent block (corroborated body-size shift) |
| `5` | IP-reputation issue (blocked from the first few requests) |
| `6` | Target unreachable |

## Detection signals

| Signal | How detected |
|--------|-------------|
| Hard rate limit | HTTP 429 (503 requires 2+ occurrences — see below) |
| Ambiguous 503 | HTTP 503 alone is reported but not asserted as a limit until it recurs |
| Block / shift | 401/403/406/418/444 after a 200 baseline |
| WAF / Cloudflare | Body signature match, or header signature (`cf-mitigated`, `x-sucuri-block`, `AkamaiGHost`, etc.) |
| Silent block | Body-size shift beyond baseline mean ± 3·stdev, corroborated by a status or latency shift |
| Throttling | Response-time regression slope + z-score deviation, relative to the measured baseline |
| IP reputation | Block/challenge within first 3 requests |
| Exhaustion | `X-RateLimit-Remaining: 0` / `Retry-After` |

Every report also carries a `detection_confidence` (`high`/`medium`/`low`, from
baseline noise + sample count + corroborating-signal count + backend count) and a
`measurement_scope` caveat: the allowance/verdict is measured for one
(source IP + supplied credentials + this route) tuple — the underlying limit may
be keyed on a different dimension.

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
