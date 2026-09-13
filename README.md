# HawkProbe

HawkProbe is a fast, lightweight web exposure and configuration scanner written in Go.

It is designed around a small concurrent scanning engine, built-in rule profiles, custom JSON rules, clean terminal output, and easy automation.

- Repository: https://github.com/d00m5dae/HawkProbe
- Releases: https://github.com/d00m5dae/HawkProbe/releases
- Issues: https://github.com/d00m5dae/HawkProbe/issues

## Install

### Prebuilt release

Linux/macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/d00m5dae/HawkProbe/main/install-release.sh | sh
```

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/d00m5dae/HawkProbe/main/install.ps1 | iex
```

### From source

Requires Go 1.20 or newer.

```bash
git clone https://github.com/d00m5dae/HawkProbe.git
cd HawkProbe
sh install.sh
```

You can also use Go directly:

```bash
go install github.com/d00m5dae/HawkProbe@latest
```

## Usage

```text
hawkprobe [options] <url>
hawkprobe -list targets.txt [options]
hawkprobe rules
hawkprobe version
```

Basic scan:

```bash
hawkprobe https://example.com
```

Quick scan:

```bash
hawkprobe -profile quick https://example.com
```

Full scan:

```bash
hawkprobe -profile full -c 64 https://example.com
```

Multiple authorized targets:

```bash
hawkprobe -list targets.txt
```

JSON Lines for automation:

```bash
hawkprobe -list targets.txt -jsonl -o results.jsonl
```

Custom headers:

```bash
hawkprobe -H "X-Test: 1" -H "Accept-Language: en-US" https://example.com
```

Basic authentication:

```bash
hawkprobe -user username -pass password https://example.com
```

Bearer authentication:

```bash
hawkprobe -token TOKEN https://example.com
```

Proxy:

```bash
hawkprobe -proxy http://127.0.0.1:8080 https://example.com
```

## Profiles

HawkProbe v1.1 ships with 74 built-in rules.

| Profile | Built-in rules | Use |
| --- | ---: | --- |
| `quick` | 12 | Fast common exposure checks |
| `default` | 34 | Normal scans |
| `full` | 74 | Complete built-in rule set |

The scanner also performs checks that are not part of the path rule count, including security headers, cookie flags, TLS certificate health, directory listing detection, CORS configuration, and basic technology fingerprinting.

## Built-in checks

HawkProbe can identify or check for:

- Exposed Git, SVN, Mercurial, and Bazaar metadata
- `.env` and environment configuration files
- Backup archives and database dumps
- Common application and framework configuration files
- Exposed private keys and cloud/Kubernetes credential files
- `phpinfo`, Apache status/info, pprof, Spring Boot actuator, metrics, and trace endpoints
- Admin, login, WordPress, phpMyAdmin, Grafana, and Jenkins endpoints
- Swagger/OpenAPI and GraphQL endpoints
- Exposed logs and build/dependency files
- HSTS, CSP, frame protection, Referrer-Policy, Permissions-Policy, and X-Content-Type-Options
- Cookie `Secure`, `HttpOnly`, and `SameSite` flags
- Directory listing
- TLS certificate validity, hostname matching, expiry, and legacy TLS negotiation
- Server and `X-Powered-By` disclosure
- Basic technology fingerprinting for nginx, Apache, IIS, Cloudflare, PHP, ASP.NET, WordPress, Grafana, and Jenkins
- Random missing-path baseline filtering to reduce false positives

## Custom rules

Add your own rules without rebuilding HawkProbe:

```bash
hawkprobe -rules custom-rules.json https://example.com
```

Example:

```json
[
  {
    "id": "internal-health",
    "path": "/internal/health",
    "name": "internal health endpoint exposed",
    "severity": "low",
    "statuses": [200],
    "contains": ["healthy", "ok"]
  }
]
```

Rule fields:

- `id`: stable rule identifier
- `path`: path to request
- `name`: finding text
- `severity`: `info`, `low`, `medium`, or `high`
- `statuses`: accepted HTTP status codes
- `contains`: at least one string must appear in the response body
- `not_contains`: none of these strings may appear
- `headers`: required response headers; values are optional substring matches

Run this to dump every built-in rule as JSON:

```bash
hawkprobe rules
```

## Options

```text
-profile string       quick, default, or full
-c int                concurrent requests per target
-timeout duration     request timeout
-rules file.json      add custom rules
-list targets.txt     scan targets from a file
-H "Name: value"      custom request header; repeatable
-user string          basic auth username
-pass string          basic auth password
-token string         bearer token
-proxy URL            HTTP proxy
-ua string            custom User-Agent
-no-redirect          do not follow redirects
-max-redirects int    maximum redirects
-k                    allow invalid TLS certificates
-json                 JSON output
-jsonl                JSON Lines output
-o file               write output to a file
```

## Development

```bash
make test
make build
```

HawkProbe targets Go 1.20 and newer. CI tests multiple Go versions.

## Release

Push a version tag:

```bash
git tag v1.1.0
git push origin v1.1.0
```

GitHub Actions builds Linux amd64/arm64, macOS amd64/arm64, Windows amd64, and SHA-256 checksums.

## Scope

HawkProbe is an exposure and configuration scanner. Its default rules use non-destructive HTTP GET requests and do not attempt exploitation.

Only scan systems you own or have permission to test.

## License

MIT
