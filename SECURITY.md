# Security policy

## Reporting a vulnerability

If you find a vulnerability in HawkProbe itself, please avoid publishing working exploitation details before the issue can be reviewed.

For ordinary bugs, open a GitHub issue. For a security-sensitive report, use GitHub's private vulnerability reporting feature if it is available for this repository.

Useful reports include:

- affected HawkProbe version or commit
- operating system and Go version
- the smallest reproduction you can provide
- expected and actual behavior
- whether the issue affects scanner output, credential handling, proxying, TLS validation, or local file access

## Scanner scope

HawkProbe is built for authorized testing. Default checks should remain non-destructive and should not modify the target. Contributions that add intrusive behavior need a strong reason, explicit opt-in, documentation, and tests.

## Secrets

Do not include real API keys, passwords, session cookies, authorization headers, private keys, or other live credentials in issues, pull requests, test fixtures, or screenshots.
