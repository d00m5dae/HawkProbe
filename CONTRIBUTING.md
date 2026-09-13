# Contributing to HawkProbe

HawkProbe is intentionally kept small, fast, and readable. Contributions are welcome when they improve coverage, correctness, usability, or performance without turning the scanner into a pile of one-off hacks.

## Before opening a PR

Run:

```bash
gofmt -w *.go
go test ./...
go vet ./...
go test -race ./...
```

Keep default checks non-destructive. HawkProbe is for authorized testing and defensive auditing; normal checks should not alter remote state.

## Adding a built-in check

Prefer a data rule when a check can be expressed as a request plus response matching. Use code only when the behavior genuinely needs logic such as TLS inspection, soft-404 detection, CORS probing, discovery parsing, or fingerprinting.

Useful rule fields include:

- `id`
- `path`
- `name`
- `severity`
- `category`
- `confidence`
- `method`
- `statuses`
- `exclude_statuses`
- `contains` / `not_contains`
- `regex`
- `headers`
- `content_type`
- `tags`
- `evidence`
- `remediation`

Avoid rules that report every HTTP 200 as a vulnerability. Give HawkProbe enough matching context to reduce false positives.

## Rule categories

Use an existing category when possible:

- `vcs`
- `secrets`
- `config`
- `backup`
- `exposure`
- `logs`
- `admin`
- `api`
- `debug`
- `monitoring`
- `discovery`
- `build`
- `headers`
- `tls`
- `tech`
- `cloud`

## Tags

Tags are used to build focused scans. Common tags include:

- `htb`
- `exposure`
- `admin`
- `api`
- `debug`
- `cloud`

## Code style

- Prefer the Go standard library unless a dependency clearly earns its cost.
- Keep functions focused.
- Avoid unnecessary abstractions.
- Avoid comments that only restate obvious code.
- Reuse the scanner's request, baseline, and matching helpers instead of creating alternate HTTP stacks.
- Keep output stable when possible so scripts do not break.

## Tests

New parsers, matchers, flags, and non-trivial checks should have tests. Prefer `httptest` for scanner behavior rather than relying on public websites.

## Good pull requests

A strong PR explains:

1. what problem it solves,
2. why the implementation belongs in HawkProbe,
3. how it was tested,
4. whether CLI or structured output changes,
5. whether the change affects scan volume or false-positive risk.
