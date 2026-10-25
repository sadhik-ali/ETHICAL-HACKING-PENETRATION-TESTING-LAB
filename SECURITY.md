# Security Policy

## Intended use

This lab is for **authorized security testing and education only**:

- Systems you own.
- Systems with explicit written permission to test.
- Intentionally vulnerable targets running in local, isolated environments.

## Out of scope

- Testing any system without written authorization.
- Using techniques from this lab against real-world applications, APIs, or infrastructure.

## Scope enforced by the tool

`secscan` and `labserver` implement the rules above rather than only describing them:

- Loopback targets (`localhost`, `127.0.0.1`, `::1`) may be scanned without further confirmation, since they cannot leave your machine.
- Any other host is refused until the operator passes `-authorized`, which is an explicit assertion of written permission; the flag is recorded in the JSON report.
- The scanner is passive: one `GET` plus one TLS handshake per target. It does not fuzz, exploit, brute-force, or enumerate ports.
- `labserver` refuses to bind outside loopback unless `-allow-non-loopback` is passed.

## Reporting a vulnerability in this project

If you find a security issue in this repository's code or documentation, open a private security advisory on GitHub or contact the maintainer directly. Please do not file a public issue with exploit details.

## Legal note

Unauthorized access to computer systems violates laws such as the Computer Fraud and Abuse Act (US) and the IT Act (India). The maintainer assumes no liability for misuse of this material.
