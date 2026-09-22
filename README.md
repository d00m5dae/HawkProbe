# HawkProbe

[![CI](https://github.com/d00m5dae/HawkProbe/actions/workflows/test.yml/badge.svg)](https://github.com/d00m5dae/HawkProbe/actions/workflows/test.yml)
![Go](https://img.shields.io/badge/Go-1.20%2B-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/github/license/d00m5dae/HawkProbe)

**Fast web exposure scanning without the setup tax.**

HawkProbe is a single-binary web scanner written in Go for finding exposed files, weak configuration, forgotten admin/debug surfaces, API documentation, leaked project metadata, and common web-server mistakes.

It is built for the part of a pentest where you already have HTTP services and want useful answers quickly. HawkProbe can consume output from tools such as Nmap and httpx, use an installed SecLists tree without making you type giant paths, and export clean URLs for the next tool in your pipeline.

> Use HawkProbe only on systems you own or are authorized to test. Default checks are designed to be non-destructive.

## Why HawkProbe

- **899 built-in checks** across exposure, backup, cloud, DevOps, admin, API, debug, CMS/framework, source/build, and metadata classes.
- **Fast by default** — concurrent Go HTTP engine, connection reuse, HTTP/2, multi-target workers, and optional request pacing.
- **Useful on HTB/CTFs** — `htb` mode, Host-header overrides, exposed-file checks, framework/debug discovery, and optional SecLists enumeration.
- **Pipeline friendly** — plain files, stdin, Nmap XML, Nmap grepable/normal output, and httpx JSONL can all become scan targets.
- **No runtime stack** — one Go binary; no Python, Perl, Node, Docker, or template engine required.
- **Low-noise design** — randomized missing-path baselines help reject wildcard routes and soft 404s.
- **Readable findings** — severity, category, confidence, evidence, remediation, URL, and structured JSON/JSONL/CSV/SARIF/HTML/Markdown output.
- **CI friendly** — fail builds on a configurable severity threshold with `-fail-on`; retry transient errors with `-retries` and cap work with `-max-requests`.
- **Trackable over time** — workspaces record scans, `resume` finishes interrupted runs, and `diff` shows what changed between scans.
- **Extensible** — a custom rule DSL for project-specific checks, reusable named profiles, finding suppressions for known issues, and an optional local Ollama AI summary per target.

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

## Profiles

Repeated flag combinations can be saved as named profiles in the local config file (`~/.config/hawkprobe/config.json`):

```bash
hawkprobe config set staging '{"mode":"exposure","rate":50,"severity":"medium","fail-on":"high"}'
hawkprobe config set htb-box '{"mode":"htb","wordlist":"@common","rate":200}'

hawkprobe https://staging.example -profile staging
hawkprobe http://box.htb -profile htb-box
```

Explicit CLI flags always win over profile values. Inspect or remove profiles with:

```bash
hawkprobe config show
hawkprobe config rm staging
hawkprobe config path
```

Profiles can pin mode, category, tag, severity, fail-on, concurrency, rate, retries, max-requests, timeout, wordlist, extensions, discover, insecure, suppressions, custom rules, and AI settings.

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

HawkProbe understands Nmap XML, grepable (`-oG`), and normal saved text output.

```bash
nmap -sV -p- -oX scan.xml 10.10.10.10
hawkprobe -nmap scan.xml -mode htb
```

`-nmap` is just a friendly alias over the same auto-detect input pipeline, so this works too:

```bash
hawkprobe -list scan.xml -mode htb
```

Pipe grepable output directly:

```bash
nmap -sV -p80,443,8000,8080,8443 -oG - 10.10.10.10 \
  | hawkprobe -stdin -mode htb
```

A normal text report can also be reused:

```bash
nmap -sV -p- -oN scan.txt 10.10.10.10
hawkprobe -nmap scan.txt -mode htb
```

Only open services that look like HTTP/HTTPS are converted into targets. Common alternate web ports are recognized even when Nmap does not return a useful service name.

## httpx compatibility

httpx JSONL can be fed directly to HawkProbe:

```bash
httpx -l hosts.txt -json | hawkprobe -stdin -mode exposure
```

Plain URLs/hosts on stdin work too:

```bash
cat targets.txt | hawkprobe -stdin -mode default
```

`-stdin` is equivalent to `-list -`.

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

Or use the friendlier alias:

```bash
hawkprobe http://box.htb -mode htb -seclists common
hawkprobe http://box.htb -seclists dirs-medium -ext php,bak,txt
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

## Retries and request budgets

Flaky lab gear, rate-limited WAFs, or overloaded services can drop individual requests. Retry transient failures (502/503/504, connection resets, timeouts) with a short backoff:

```bash
hawkprobe https://example.com -retries 2
```

Cap the total number of requests per target when the surface is large or the service is fragile:

```bash
hawkprobe https://example.com -mode full -max-requests 2000
```

Both options compose with `-rate` and apply per target.

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

## Reports

Share results as a self-contained HTML page or a Markdown document:

```bash
hawkprobe https://example.com -mode full -html -o report.html
hawkprobe -list targets.txt -md -o report.md
```

Or write every format at once:

```bash
hawkprobe https://example.com -bundle ./report-bundle
```

`-bundle` produces `report.html`, `report.md`, `findings.csv`, `hawkprobe.sarif`, `results.json`, and `results.jsonl` in the given directory.

## Workspaces, diff, and resume

Record scans into a workspace directory to build a local history you can query later:

```bash
hawkprobe -list targets.txt -workspace ./hawk-work
```

Every run stores its options, per-target results, and a summary in the workspace. Inspect recorded scans and compare any two of them:

```bash
hawkprobe workspace list
hawkprobe diff <scan-id-a> <scan-id-b>
```

`diff` reports new findings, resolved findings, and severity regressions by rule — useful to show what a patch actually changed.

If a scan was interrupted (Ctrl-C, timeout, lost connectivity), pick it up where it stopped:

```bash
hawkprobe workspace list        # find the incomplete scan id
hawkprobe resume <scan-id>
```

Resume reuses the recorded options and only scans the targets that were not completed.

## Suppressions

Known-and-accepted findings can be suppressed so they stop cluttering reports and CI without re-editing your rule set:

```bash
hawkprobe suppress add --rule env --reason "staging exposure, accepted" --expires 30d
hawkprobe suppress add --rule csp-missing --target https://old.example --expires 12h
hawkprobe suppress list
hawkprobe suppress remove 0
```

Suppressions are scoped by rule, target, and/or URL path, and expire automatically. They are read from `-suppressions file.json` (or the default config location), apply before output and fail-on evaluation, and show up as a per-target suppressed count.

## AI summaries (Ollama)

With a local [Ollama](https://ollama.com) instance, add a short report-style summary for every target:

```bash
hawkprobe https://example.com -mode full -ai
hawkprobe https://example.com -ai -ai-model qwen2.5:7b
```

The host defaults to `http://127.0.0.1:11434` (override with `OLLAMA_HOST` or the `ai` block in the config file); the model defaults to `llama3.2`. Summaries appear in terminal, JSON, HTML, and Markdown output. If Ollama is unreachable, HawkProbe prints a note and completes the scan normally.

## Shell completion

HawkProbe can generate completion scripts without installing an extra package:

```bash
hawkprobe completion bash
hawkprobe completion zsh
hawkprobe completion fish
```

You can redirect the output into the completion directory used by your shell or source it from your shell configuration.

## Built-in coverage

The catalog includes 899 built-in checks across areas such as:

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

### Rule DSL with expect blocks

For project-specific checks, the DSL format pairs a path with an `expect` block — all conditions must match for the rule to fire:

```json
{
  "rules": [
    {
      "name": "admin-panel",
      "path": "/admin*",
      "severity": "medium",
      "message": "Admin panel exposed",
      "expect": { "status": 200, "contains": "login" }
    },
    {
      "name": "internal-health",
      "path": "/internal/health",
      "severity": "low",
      "category": "debug",
      "expect": {
        "status_any": [200, 204],
        "contains_any": ["healthy", "ok"],
        "not_contains": ["not found"],
        "header": { "Content-Type": "json" }
      }
    }
  ]
}
```

See [custom-rules.dsl.example.json](custom-rules.dsl.example.json) for a complete sample. Expect fields: `status` (exact code), `status_any` (any of), `contains` (all must appear), `contains_any` (at least one), `not_contains` (none may appear), and `header` (header value must contain the string). `contains`-family fields accept a single string or an array. `path` may be a relative path, an absolute URL, or a trailing glob — `/admin*` fetches both `/admin` and `/admin/`. Optional fields: `method`, `category`, `message`, `remediation`.

Validate and run:

```bash
hawkprobe rules check custom-rules.dsl.json
hawkprobe https://example.com -custom-rules custom-rules.dsl.json
```

The file also comes from the `HAWKPROBE_CUSTOM_RULES` environment variable or a `custom-rules` key in a profile. Findings from DSL rules are reported under the `custom` category with rule id `custom:<name>`.

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
