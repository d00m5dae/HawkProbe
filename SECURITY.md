# Security Policy

## Reporting a vulnerability in HawkProbe

If you find a security issue in HawkProbe itself, please avoid publishing sensitive exploit details in a normal issue before a fix is available.

Use GitHub's private vulnerability reporting for this repository when available. If private reporting is not available, open a minimal issue stating that you have a security report and avoid including secrets, tokens, private targets, or weaponized proof-of-concept details in the public thread.

Useful information includes:

- affected HawkProbe version/commit
- operating system and Go version
- the vulnerable behavior
- minimal reproduction steps
- expected behavior
- whether the issue can expose local credentials, files, or scan-target secrets

## Supported versions

Security fixes are applied to the current development line and latest release. Older releases may be asked to upgrade rather than receive a backport.

## Scanner findings are not project vulnerabilities

If HawkProbe reports a weakness in a website you are authorized to test, that is a finding about the target—not a vulnerability in HawkProbe. Report it through the target owner's authorized disclosure process.

Do not post credentials, private keys, session cookies, private HTB/VPN material, or other sensitive target data in HawkProbe issues.
