# HawkProbe

HawkProbe is a fast web exposure and misconfiguration scanner written in Go.

It is built for authorized pentesting, HTB/CTF labs, homelabs, and defensive web auditing. The scanner combines a concurrent path engine with HTTP/TLS checks, technology fingerprinting, soft-404 filtering, optional content discovery, and structured output.

## Highlights

- 159 built-in path rules organized by purpose instead of one giant flat list
- Concurrent requests per target and concurrent multi-target scanning
- Scan modes for quick checks, broad scans, HTB/CTF work, APIs, admin surfaces, debug endpoints, exposure checks, headers, TLS, and fingerprinting
- Two-sample soft-404 baseline detection to reduce wildcard/custom-404 false positives
- Active but non-destructive CORS and HTTP method checks
- `robots.txt` and `sitemap.xml` discovery
- Optional wordlist discovery with extension expansion
- Response checks for exposed secrets, private keys, stack traces, source-map references, and interesting HTML comments
- Technology fingerprinting for common web servers, frameworks, CDNs, and applications
- TLS certificate, expiry, hostname, and negotiated-version reporting
- Detailed finding metadata: category, confidence, evidence, and remediation
- JSON and JSONL output for automation
- Custom JSON rules with regex, headers, methods, status codes, content-type matching, and exclusions
- Go 1.20+ with no runtime dependency beyond the compiled binary

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

```bash
git clone https://github.com/d00m5dae/HawkProbe.git
cd HawkProbe
sh install.sh
```

Or:

```bash
go install github.com/d00m5dae/HawkProbe@latest
```

## Basic usage

```bash
hawkprobe https://example.com
```

Flags can go before or after the target:

```bash
hawkprobe -mode full -c 64 https://example.com
hawkprobe https://example.com -mode full -c 64
```

HTB/CTF-oriented scan:

```bash
hawkprobe http://box.htb -mode htb -v
```

Show evidence and remediation:

```bash
hawkprobe https://example.com -mode exposure -evidence
```

Virtual host against an IP:

```bash
hawkprobe http://10.10.10.10 -host internal.htb -mode htb
```

Multiple targets:

```bash
hawkprobe -list targets.txt -target-c 8
```

## Scan modes

| Mode | Purpose |
| --- | --- |
| `quick` | Small set of high-value checks |
| `default` | Balanced everyday scan |
| `full` / `deep` | Broad path coverage plus discovery |
| `htb` | HTB/CTF-oriented discovery, exposures, admin, API, and debug checks |
| `exposure` | Secrets, backups, VCS metadata, configs, logs |
| `admin` | Admin, login, and management surfaces |
| `api` | Swagger/OpenAPI, GraphQL, and API docs |
| `debug` | pprof, Actuator, traces, metrics, diagnostic pages |
| `headers` | Headers, cookies, CORS, and HTTP methods |
| `tls` | TLS/certificate checks only |
| `tech` | Technology fingerprinting only |

The old `-profile` flag remains available as an alias for `-mode`.

## HTB content discovery

HawkProbe can use a path wordlist while keeping the same soft-404 filtering used by built-in rules:

```bash
hawkprobe http://box.htb -mode htb -wordlist paths.txt
```

Add extensions:

```bash
hawkprobe http://box.htb -mode htb -wordlist paths.txt -ext php,txt,bak
```

For example, a word `admin` generates checks for:

```text
/admin
/admin.php
/admin.txt
/admin.bak
```

The generated discovery set is capped to avoid accidentally creating an unbounded scan.

## Discovery

Enable dynamic discovery explicitly:

```bash
hawkprobe https://example.com -discover
```

`full`, `deep`, and `htb` enable it automatically. HawkProbe parses same-host paths from `robots.txt` and `sitemap.xml`, probes a bounded number of them, and filters likely custom-404 responses.

## Built-in coverage

HawkProbe includes checks for categories such as:

- Git, SVN, Mercurial, and Bazaar metadata
- `.env` files and application configuration
- AWS, Docker, Kubernetes, Terraform, and key material
- ZIP/TAR backups, source archives, SQL dumps, editor backups
- Apache status/info, PHP info, Go pprof, Spring Boot Actuator, ELMAH, metrics
- Admin/login panels, Tomcat manager, WordPress, phpMyAdmin, Grafana, Jenkins, Kibana
- Swagger/OpenAPI, GraphQL, GraphiQL, ReDoc, API roots
- Logs, package manifests, build files, CI configs, source maps
- Security headers, cookie flags, CORS, HTTP methods
- TLS certificate validity, expiry, hostname, and negotiated protocol
- Technology markers for nginx, Apache, IIS, Caddy, Cloudflare, PHP, ASP.NET, Express, WordPress, Next.js, Laravel, Django, Grafana, Jenkins, and Spring Boot
- Response-body indicators for private keys, access keys, generic secrets, stack traces, debug errors, source maps, and useful HTML comments

## Verbose mode

```bash
hawkprobe http://box.htb -mode htb -v
```

Example:

```text
[check] /.git/HEAD                              404 no-match
[check] /.env                                   200 FOUND
[check] /admin                                  302 FOUND
```

The summary includes rules checked, total requests, findings, no-match checks, skipped checks, and elapsed time.

## Custom rules

Example:

```json
[
  {
    "id": "internal-health",
    "path": "/internal/health",
    "name": "internal health endpoint exposed",
    "severity": "low",
    "category": "debug",
    "confidence": "high",
    "method": "GET",
    "statuses": [200],
    "contains": ["healthy"],
    "regex": "(?i)status\\s*[:=]\\s*ok",
    "content_type": "json",
    "remediation": "Restrict the health endpoint to trusted networks."
  }
]
```

Useful fields include:

- `id`, `path`, `name`
- `severity`: `info`, `low`, `medium`, `high`, `critical`
- `category`, `confidence`
- `method`: `GET`, `HEAD`, or `OPTIONS`
- `statuses`, `exclude_statuses`
- `contains`, `not_contains`, `regex`
- `headers`, `content_type`
- `evidence`, `remediation`

Validate a rule file before scanning:

```bash
hawkprobe rules validate custom-rules.json
```

List built-in rules:

```bash
hawkprobe rules list
```

Dump built-in rules as JSON:

```bash
hawkprobe rules
```

## Authentication and proxying

Custom header:

```bash
hawkprobe -H "X-Test: 1" https://example.com
```

Basic auth:

```bash
hawkprobe -user username -pass password https://example.com
```

Bearer token:

```bash
hawkprobe -token TOKEN https://example.com
```

HTTP proxy:

```bash
hawkprobe -proxy http://127.0.0.1:8080 https://example.com
```

Secrets supplied through auth flags are not added to normal findings or verbose output.

## Output

JSON:

```bash
hawkprobe https://example.com -json
```

JSON Lines across multiple targets:

```bash
hawkprobe -list targets.txt -jsonl -o results.jsonl
```

Human-readable evidence:

```bash
hawkprobe https://example.com -evidence
```

## Main options

```text
-mode string          scan mode
-c int                concurrent requests per target
-target-c int         targets scanned concurrently
-timeout duration     request timeout
-discover             parse robots/sitemap and probe discovered paths
-wordlist file        optional content-discovery wordlist
-ext php,txt,bak      extensions added to wordlist entries
-v                    verbose per-check output
-evidence             show evidence and remediation
-rules file.json      add custom rules
-list targets.txt     scan multiple targets
-H "Name: value"      repeatable request header
-host string          override Host header
-user / -pass         Basic auth
-token string         Bearer auth
-proxy URL            HTTP proxy
-ua string            custom User-Agent
-no-redirect          do not follow redirects
-max-redirects int    redirect limit
-k                    allow invalid TLS certificates
-json / -jsonl        structured output
-o file               output file
```

## Development

```bash
gofmt -w *.go
go test ./...
go vet ./...
go test -race ./...
```

HawkProbe targets Go 1.20 and newer.

## Scope

HawkProbe is intended for systems you own or are authorized to test. Normal checks are non-destructive HTTP/TLS probes. It does not deploy payloads, modify remote systems, or attempt persistence.

## License

MIT
