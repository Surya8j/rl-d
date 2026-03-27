# rl-d — Rate Limit Detector

An async Python CLI tool to detect rate limiting, WAF challenges, and silent blocks on web applications.

## Features

- Detects HTTP 429/503 hard rate limits
- Detects silent blocks via response body size deviation
- Detects Cloudflare and generic WAF challenges
- Detects gradual throttling via response time analysis
- Detects IP reputation issues (early blocks on first requests)
- Browser impersonation via `curl_cffi` (Chrome/Safari)
- Supports burst, steady, and slow delay modes
- Cross-platform: macOS and Linux, no sudo required

## Install

```bash
pip install curl_cffi
```

## Usage

```bash
python3 ratelimit_detect.py
```

The tool will interactively prompt for:
- Target URL
- Target type (api / webpage)
- HTTP method (GET / POST / HEAD)
- Custom headers (optional)
- Cookies (optional)
- Delay mode (burst / steady / slow)
- Request timeout

## Detection Methods

| Signal | How Detected |
|--------|-------------|
| Hard rate limit | HTTP 429 / 503 status code |
| WAF / Cloudflare | Body signature matching |
| Silent block | >50% body size deviation from baseline |
| Throttling | Response time degradation over time |
| IP reputation | Block/challenge on first 3 requests |
| Rate limit headers | `X-RateLimit-Remaining: 0` etc. |

## License

MIT
