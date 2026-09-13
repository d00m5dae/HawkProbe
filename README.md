# HawkProbe

[![CI](https://github.com/d00m5dae/HawkProbe/actions/workflows/test.yml/badge.svg)](https://github.com/d00m5dae/HawkProbe/actions/workflows/test.yml)
![Go](https://img.shields.io/badge/Go-1.20%2B-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/github/license/d00m5dae/HawkProbe)

**Fast web exposure scanning without the setup tax.**

HawkProbe is a single-binary web scanner written in Go for finding exposed files, weak configuration, forgotten admin/debug surfaces, API documentation, leaked project metadata, and common web-server mistakes.

It is built for the part of a pentest where you already have HTTP services and want useful answers quickly. HawkProbe can consume output from tools such as Nmap and httpx, use an installed SecLists tree without making you type giant paths, and export clean URLs for the next tool in your pipeline.

> Use HawkProbe only on systems you own or are authorized to test. Default checks are designed to be non-destructive.

## Why HawkProbe

- **450+ built-in checks** across exposure, backup, cloud, DevOps, admin, API, debug, CMS/framework, source/build, and metadata classes.
- **Fast by default** — concurrent Go HTTP engine, connection reuse, HTTP/2, multi-target workers, and optional request pacing.
- **Useful on HTB/CTFs** — `htb` mode, Host-header overrides, exposed-file checks, framework/debug discovery, and optional SecLists enumeration.
- **Pipeline friendly** — plain files, stdin, Nmap XML, Nmap grepable output, and httpx JSONL can all become scan targets.
- **No runtime stack** — one Go binary; no Python, Perl, Node, Docker, or template engine required.
- **Low-noise design** — randomized missing-path baselines help reject wildcard routes and soft 404s.
- **Readable findings** — severity, category, confidence, evidence, remediation, URL, and structured JSON/JSONL/CSV/SARIF output.
- **CI friendly** — fail builds on a configurable severity threshold with `-fail-on`.
- **Extensible** — custom JSON rules, category/tag filtering, and a built-in rule database organized around real exposure classes.

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

Or:

```bash
go install github.com/d00m5dae/HawkProbe@latest
```

## Quick start

Balanced scan:

```bash
hawkprobe https://example.com
```

HTB-style scan:

```bash
hawkprobe http://box.htb -mode htb -evidence
```

Broad scan with a faster request pool:

```bash
hawkprobe https://example.com -mode full -c 64
```

A live terminal gets an adaptive progress bar automatically. Progress disables itself for structured output, quiet mode, verbose mode, or redirected stderr.

## Scan modes

| Mode | Purpose |
| --- | --- |
| `quick` | Small high-value pass |
| `default` | Balanced everyday scan |
| `full` / `deep` | Broad built-in catalog |
| `htb` | CTF/HTB-oriented discovery and exposure checks |
| `exposure` | VCS, secrets, configs, backups, logs, cloud/devops artifacts |
| `admin` | Login, administration, management surfaces |
| `api` | OpenAPI, Swagger, GraphQL, API metadata |
| `debug` | Diagnostics, Actuator, pprof, metrics, monitoring |
| `headers` | Security headers, cookies, CORS, HTTP methods |
| `tls` | Certificate/TLS checks |
| `tech` | Technology fingerprinting |

You can narrow a broad mode without inventing another profile:

```bash
hawkprobe https://example.com -mode full -category cloud,devops
hawkprobe https://example.com -mode full -tag exposure
hawkprobe https://example.com -mode full -severity medium
```

See the live catalog breakdown:

```bash
hawkprobe rules stats
```

## Nmap compatibility

HawkProbe auto-detects Nmap XML and grepable output passed with `-list`.

```bash
nmap -sV -p- -oX scan.xml 10.10.10.10
hawkprobe -list scan.xml -mode htb
```

Or pipe grepable output directly:

```bash
nmap -sV -p80,443,8000,8080,8443 -oG - 10.10.10.10 \
  | hawkprobe -list - -mode htb
```

Only open services that look like HTTP/HTTPS are converted into targets. Common alternate web ports are recognized even when Nmap does not return a useful service name.

## httpx compatibility

httpx JSONL can be fed directly to HawkProbe:

```bash
httpx -l hosts.txt -json | hawkprobe -list - -mode exposure
```

Plain URLs/hosts on stdin work too:

```bash
cat targets.txt | hawkprobe -list - -mode default
```

## SecLists without the giant path

If SecLists is installed in a common location, HawkProbe can find it automatically.

```bash
hawkprobe wordlists
```

Then use presets:

```bash
hawkprobe http://box.htb -mode htb -wordlist @common
hawkprobe http://box.htb -wordlist @dirs-small
hawkprobe http://box.htb -wordlist @dirs-medium -c 80
hawkprobe http://box.htb -wordlist @graphql
```

Useful aliases include:

```text
@common
@combined
@dirs-small
@dirs-medium
@dirs-large
@words-small
@words-medium
@words-large
@files-small
@files-medium
@files-large
@graphql
@mcp
```

If your SecLists checkout lives somewhere unusual:

```bash
export SECLISTS_PATH="$HOME/tools/SecLists"
```

Extensions can be generated for extensionless words:

```bash
hawkprobe http://box.htb -wordlist @common -ext php,txt,bak
```

HawkProbe supports large lists, but remember that extensions can multiply the request count substantially.

## Chain it into other tools

Export every unique target/finding URL:

```bash
hawkprobe https://app.example -mode full -urls-out discovered.txt
```

Then use the file anywhere that accepts URLs:

```bash
nuclei -l discovered.txt
httpx -l discovered.txt
ffuf -w params.txt -u 'https://app.example/FUZZ'
```

HawkProbe does not require these tools and does not shell out to them. The integration is intentionally file/stdin based so pipelines stay predictable.

Check what is installed locally:

```bash
hawkprobe doctor
```

## Control speed

Concurrency controls how many requests can be in flight:

```bash
hawkprobe https://example.com -mode full -c 96
```

Rate limiting is useful when a lab, WAF, proxy, or small service does not like bursts:

```bash
hawkprobe https://example.com -mode full -c 64 -rate 100
```

`-rate` is per target. `0` means unlimited.

For lists of targets:

```bash
hawkprobe -list targets.txt -target-c 8 -c 48
```

## HTB / virtual hosts

Override the HTTP Host header without changing the connection address:

```bash
hawkprobe http://10.10.10.10 -host internal.htb -mode htb
```

If you already added the host to `/etc/hosts`, just scan it normally:

```bash
hawkprobe http://internal.htb -mode htb -wordlist @common
```

## Authentication and proxies

Basic auth:

```bash
hawkprobe https://lab.example -user admin -pass password
```

Bearer token:

```bash
hawkprobe https://api.example -token "$TOKEN" -mode api
```

Custom headers:

```bash
hawkprobe https://app.example \
  -H 'Cookie: session=...' \
  -H 'X-Forwarded-For: 127.0.0.1'
```

Proxy through Burp or another HTTP proxy:

```bash
hawkprobe https://app.example -proxy http://127.0.0.1:8080 -k
```

Secrets supplied through auth flags are not intentionally printed in findings.

## Output and automation

Human-readable terminal output is the default.

```bash
hawkprobe https://example.com -evidence
```

Only findings/errors:

```bash
hawkprobe https://example.com -q
```

Disable color/progress explicitly:

```bash
hawkprobe https://example.com -no-color -no-progress
```

HawkProbe also honors the `NO_COLOR` environment variable.

JSON:

```bash
hawkprobe https://example.com -json
```

JSON Lines across many targets:

```bash
hawkprobe -list targets.txt -jsonl -o results.jsonl
```

CSV for spreadsheets/reporting:

```bash
hawkprobe -list targets.txt -csv -o findings.csv
```

SARIF for security/CI tooling:

```bash
hawkprobe -list targets.txt -sarif -o hawkprobe.sarif
```

Make a CI job fail with exit code `3` when a high-or-critical finding appears:

```bash
hawkprobe https://staging.example -mode exposure -fail-on high
```

`-fail-on` does not change what HawkProbe scans or prints. It only controls the final process exit code.

Structured findings include fields such as rule ID, category, severity, confidence, URL, evidence, and remediation when available.

## Shell completion

HawkProbe can generate completion scripts without installing an extra package:

```bash
hawkprobe completion bash
hawkprobe completion zsh
hawkprobe completion fish
```

You can redirect the output into the completion directory used by your shell or source it from your shell configuration.

## Built-in coverage

The catalog includes 450+ checks across areas such as:

- Git, SVN, Mercurial, Bazaar, CVS, and other repository metadata
- environment/configuration files
- backup archives, database dumps, editor/temp files
- AWS, Azure, GCP, Kubernetes, Vault, Terraform, Pulumi, and other cloud/devops metadata
- CI/CD files and deployment manifests
- WordPress, Drupal, Joomla, Laravel, Symfony, Django, Rails, Node/frontend build metadata
- admin/login/database-management surfaces
- Swagger/OpenAPI/GraphQL and machine-readable API metadata
- Spring Actuator, Go pprof, framework debuggers, diagnostics, health and metrics endpoints
- server/security headers, cookies, CORS, allowed methods, directory listing
- TLS certificate health and legacy negotiation
- response-body indicators for secrets, stack traces, source maps, and interesting comments
- robots.txt and sitemap-driven discovery

The built-in database is original HawkProbe data. HawkProbe can *use* an installed SecLists wordlist but does not vendor/copy the SecLists database into this repository.

## Custom rules

Create a JSON array:

```json
[
  {
    "id": "internal-health",
    "path": "/internal/health",
    "name": "internal health endpoint exposed",
    "severity": "low",
    "category": "debug",
    "confidence": "high",
    "statuses": [200],
    "contains": ["healthy", "ok"],
    "remediation": "Restrict the endpoint to trusted networks."
  }
]
```

Validate it before scanning:

```bash
hawkprobe rules validate custom-rules.json
```

Run it:

```bash
hawkprobe https://example.com -rules custom-rules.json
```

Supported rule capabilities include status matching/exclusion, GET/HEAD/OPTIONS, body contains/not-contains, regex, response headers, content type, category, confidence, tags, evidence, and remediation.

## Development

```bash
gofmt -w *.go
go test ./...
go vet ./...
go test -race ./...
```

The project intentionally targets Go 1.20+ and keeps dependencies minimal.

See [CONTRIBUTING.md](CONTRIBUTING.md) before submitting larger changes.

## Scope

HawkProbe is an exposure, discovery, and configuration scanner. It is not intended to deploy payloads, modify targets, maintain persistence, or perform destructive exploitation.

A positive result means **look closer**. Fingerprinting and exposure detection are evidence for a tester, not proof that an application is exploitable.

## License

MIT
