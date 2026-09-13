# Security Policy

## Reporting a vulnerability in HawkProbe

Please do not publish a working exploit for a HawkProbe vulnerability before maintainers have had a reasonable chance to review it.

For issues that could expose user credentials, execute unintended code, corrupt output, bypass target scoping, or otherwise create a meaningful security risk, open a GitHub Security Advisory for this repository when available.

For ordinary bugs, false positives, compatibility problems, or feature requests, use a normal GitHub issue.

Include enough information to reproduce the problem:

- HawkProbe version or commit
- operating system and architecture
- command used, with secrets redacted
- expected behavior
- actual behavior
- minimal reproduction when possible

Never include real passwords, API tokens, session cookies, private keys, or other credentials in an issue.

## Scanner scope

HawkProbe is intended for systems you own or are authorized to test. Default functionality is designed around non-destructive HTTP/TLS inspection and discovery.
