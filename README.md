# Ethical Hacking & Penetration Testing Lab

A beginner-friendly, dependency-free **Go** lab for learning authorized web-application
security assessment. It ships two binaries:

- **`secscan`** - a passive checker for HTTP security headers, HTTPS certificates and cookie flags that writes evidence-grade JSON reports.
- **`labserver`** - an intentionally vulnerable localhost target to practise against.

> **Status: v0.1.0 - core checks implemented.** OWASP Top 10 workflows, SQLi/XSS detection and
> authentication testing are still roadmap items (see [Roadmap](#roadmap)).

[Scope and authorisation](#scope-and-authorisation) ·
[Quick start](#quick-start) ·
[What secscan checks](#what-secscan-checks) ·
[The lab target](#the-lab-target) ·
[JSON report format](#json-report-format) ·
[Project layout](#project-layout) ·
[Design notes](#design-notes) ·
[Testing](#testing) ·
[Roadmap](#roadmap)

---

## Scope and authorisation

**Only test systems you own or have explicit written permission to assess.** Unauthorized access
to computer systems is illegal in most jurisdictions. The authors are not responsible for misuse.

This tool is deliberately limited to that boundary:

| Guardrail | Behaviour |
| --- | --- |
| Loopback always allowed | `localhost`, `127.0.0.1`, `::1` can be scanned without extra flags - they can only reach your own machine. |
| Everything else needs consent | Any non-loopback host is **refused** unless you pass `-authorized`, which asserts written permission. |
| Passive by design | One `GET` per URL plus a TLS handshake. No payloads, no fuzzing, no parameter tampering, no authentication attempts, no port scanning, no denial-of-service behaviour. |
| Evidence stays with you | Reports record the operator note and target list, so an exported scan carries its own scope statement. |
| Vulnerable target is fenced in | `labserver` refuses to bind outside loopback unless you pass `-allow-non-loopback`. |

`SECURITY.md` restates these rules; `CONTRIBUTING.md` requires every new check to keep them.

## Quick start

Requires **Go 1.24 or newer** and nothing else - the standard library is the only dependency.

```bash
git clone https://github.com/sadhik-ali/Ethical-Hacking-Penetration-Testing-Lab.git
cd Ethical-Hacking-Penetration-Testing-Lab

# 1. start the intentionally vulnerable lab target (terminal A)
go run ./cmd/labserver                 # http://127.0.0.1:8080
go run ./cmd/labserver -https          # https://127.0.0.1:8080 with an ephemeral self-signed cert

# 2. scan it (terminal B)
go run ./cmd/secscan http://127.0.0.1:8080/insecure
go run ./cmd/secscan -out report.json http://127.0.0.1:8080/bad-csp https://127.0.0.1:8080/login
go run ./cmd/secscan -format json http://127.0.0.1:8080/            # machine-readable stdout
go run ./cmd/secscan -h                                             # all flags
```

Build named binaries instead:

```bash
go build -o build/secscan.exe   ./cmd/secscan
go build -o build/labserver.exe ./cmd/labserver
```

### Sample session

```
$ secscan http://127.0.0.1:8080/insecure
secscan v0.1.0 - passive web security check
generated: 2026-10-25T06:16:31Z
authorization: targets=http://127.0.0.1:8080/insecure, loopback-only=true, written-permission=false
scope: Passive, non-intrusive inspection of HTTP response headers, cookies and TLS certificates. ...

=== http://127.0.0.1:8080/insecure
    final url:    http://127.0.0.1:8080/insecure (HTTP 200, 2 ms)
    findings:     8
      [HIGH  ] Content-Security-Policy header missing
                 check: content-security-policy | Without CSP the browser has no policy restricting script sources...
                 evidence: header absent
                 fix: Send a CSP that whitelists script sources, for example: default-src 'self'; ...
      [HIGH  ] Target served over unencrypted HTTP
                 check: plain-http | Content fetched from http://127.0.0.1:8080/insecure travels in plaintext...
      [MEDIUM] Clickjacking protection missing (X-Frame-Options or CSP frame-ancestors)
      [MEDIUM] X-Content-Type-Options: nosniff missing
      [LOW   ] Referrer-Policy header missing
      [LOW   ] X-Powered-By exposes the technology stack
                 evidence: X-Powered-By: PHP/7.4.3
      [INFO  ] Permissions-Policy header missing
      [INFO  ] Server header discloses a software version
                 evidence: Server: Apache/2.4.41 (Ubuntu)

--- summary: 1 target(s), 8 finding(s), highest severity: high
    high   2
    medium 2
    low    2
    info   2
```

## What secscan checks

Every rule produces a finding with a severity, evidence string, remediation and reference, so the
output is usable as report material without rewriting it.

### HTTP security headers

| Check id | Severity when triggered |
| --- | --- |
| `content-security-policy` | high - header absent, or contains `'unsafe-inline'` / `'unsafe-eval'`, or constrains no script source |
| `strict-transport-security` | high - absent over HTTPS; medium - `max-age` below ~6 months or unparseable |
| `clickjacking-protection` | medium - no `X-Frame-Options` and no CSP `frame-ancestors`; medium - `ALLOWALL` |
| `x-content-type-options` | medium - missing; low - present but not exactly `nosniff` |
| `referrer-policy` | low - missing; low - value `unsafe-url` |
| `permissions-policy` | info - missing |
| `cache-control-on-sensitive-response` | low - `/login`, `/token`, `/session`, `/admin` paths served without `no-store` |
| `server-version-disclosure` | info - `Server` banner carries a version |
| `x-powered-by-disclosure` | low - `X-Powered-By` present |
| `deprecated-x-xss-protection` | info - legacy header present |

### HTTPS certificate and TLS

| Check id | Severity |
| --- | --- |
| `tls-chain-untrusted` | high (medium when self-signed) - chain does not verify against system roots |
| `tls-hostname-mismatch` | high - leaf does not cover the requested hostname/IP |
| `tls-expired` / `tls-not-yet-valid` | high |
| `tls-expiring-soon` | medium - expires within 30 days |
| `tls-weak-signature` | high - MD5 or SHA-1 certificate signature |
| `tls-weak-key` | high/medium - RSA below 2048 bits, or ECDSA below 224 bits |
| `tls-no-identity` | medium - no DNS SAN and no Common Name |
| `tls-old-protocol` | high/medium - TLS 1.0 or 1.1 negotiated |
| `tls-intermediates` | low - leaf served without its intermediate |
| `tls-handshake` | medium - host refused or failed the TLS handshake |

The report also records protocol version, subject, issuer, serial, validity window, days
remaining and SAN entries for each HTTPS target.

### Cookie security

| Check id | Severity |
| --- | --- |
| `cookie-httponly` | high for session-like names (`session`, `sid`, `JSESSIONID`, `csrf`, `token`, ...), medium otherwise |
| `cookie-secure` | high for session-like names, medium otherwise |
| `cookie-samesite` | medium - attribute absent |
| `cookie-samesite-none-without-secure` | high - browsers reject the combination |
| `cookie-domain-scope` | low - `Domain` is a parent of the scanned host, or a single label |
| `cookie-carries-jwt` | info - token-looking value; evidence never echoes the value |

Cookies set on **any** redirect hop are inspected, not just the final response.

Out of scope on purpose: certificate revocation (OCSP/CRL), cipher-suite enumeration,
mixed-content analysis, and any active vulnerability testing.

## The lab target

`go run ./cmd/labserver` serves five deliberately different routes so you can compare a clean
baseline with each class of mistake:

| Route | Lesson |
| --- | --- |
| `/` | hardened reference: full header set, version-free `Server` banner - expect one finding (`plain-http`) unless `-https` is used |
| `/insecure` | every security header absent plus `Server`/`X-Powered-By` banners |
| `/login` | three cookies: no `HttpOnly`, no `Secure`, one `SameSite=None`, one JWT-shaped value, broad `Domain` |
| `/redirect` | `302` that sets a cookie on the first hop - shows why every hop must be parsed |
| `/bad-csp` | headers that exist but are wrong: `'unsafe-inline'`, `X-Frame-Options: ALLOWALL`, malformed `nosniff` |

Add `-https` to any route and the same scan also reports certificate findings: an untrusted
self-signed chain and an expiry only 72 hours out.

`-addr` defaults to `127.0.0.1:8080`; `-https` mints an ephemeral self-signed certificate for
`localhost`/`127.0.0.1` valid for 72 hours so the expiry and trust checks have something to say.

## JSON report format

`-out <file>` (or `-format json` to stdout) emits:

```json
{
  "tool": "secscan",
  "version": "0.1.0",
  "generated_at": "2026-10-25T06:16:31Z",
  "scope_note": "Passive, non-intrusive inspection ... written permission to test.",
  "authorization": {
    "loopback_only": true,
    "written_permission_confirmed": false,
    "operator_note": "engagement 2026-10",
    "targets": ["https://127.0.0.1:8443/login"]
  },
  "summary": {
    "targets": 1,
    "findings": 22,
    "by_severity": { "high": 9, "medium": 6, "low": 4, "info": 3 },
    "by_check": { "cookie-httponly": 3, "tls-expiring-soon": 1 },
    "highest_severity": "high",
    "errors": 0
  },
  "targets": [
    {
      "url": "https://127.0.0.1:8443/login",
      "final_url": "https://127.0.0.1:8443/login",
      "method": "GET",
      "status_code": 200,
      "accessed_at": "2026-10-25T06:16:31Z",
      "elapsed_ms": 21,
      "tls": {
        "protocol": "TLS 1.3",
        "subject": "CN=secscan-lab,O=Ethical Hacking Lab",
        "issuer": "CN=secscan-lab,O=Ethical Hacking Lab",
        "not_after": "2026-10-28T06:16:04Z",
        "days_remaining": 2,
        "hostname_valid": true,
        "chain_verified": false,
        "handshake_verification_skipped": true,
        "verify_error": "x509: certificate signed by unknown authority"
      },
      "set_cookie_headers": ["session_id=...; Path=/; Domain=localhost"],
      "findings": [
        {
          "check": "cookie-httponly",
          "severity": "high",
          "title": "Cookie \"session_id\" is readable from JavaScript (no HttpOnly)",
          "detail": "Without HttpOnly any cross-site scripting bug can exfiltrate or replace this cookie...",
          "evidence": "session_id=abc123def456; Path=/; Domain=localhost",
          "remediation": "Add the HttpOnly attribute to the cookie.",
          "reference": "https://owasp.org/www-community/controls/SecureCookieAttribute"
        }
      ],
      "errors": []
    }
  ]
}
```

Two example reports are committed under [`reports/`](reports) so the schema is visible without
running anything. **Never commit real scan output**: `evidence/`, `reports/raw/` and `*.log` are
git-ignored for exactly that reason.

## Project layout

```
.
├── cmd/
│   ├── secscan/main.go      # CLI: flags, authorization gate, output selection
│   └── labserver/main.go    # vulnerable localhost target + loopback bind guard
├── internal/
│   └── scanner/
│       ├── scan.go          # request walk, redirect hops, orchestration
│       ├── headers.go       # 10 header rules
│       ├── cookies.go       # Set-Cookie parser and 6 cookie rules
│       ├── tls.go           # certificate validation, protocol and key strength
│       ├── report.go        # report types, summary, JSON writer, text renderer
│       ├── scope.go         # loopback / -authorized authorization gate
│       └── *_test.go        # unit + httptest end-to-end coverage
├── reports/                 # example JSON output
├── go.mod                   # module definition, no third-party requires
├── CONTRIBUTING.md  LICENSE  SECURITY.md
└── .github/workflows/ci.yml # fmt + vet + test on every push
```

## Design notes

- **Standard library only.** `net/http`, `crypto/tls`, `crypto/x509`, `encoding/json`, `flag`. No
  supply-chain weight, and the code is readable top to bottom for a learner.
- **One request per target.** The scanner reads response headers, so it never buffers or stores
  page content - there is no body to leak into a report.
- **Verification is explicit, not delegated.** The TLS probe deliberately accepts the handshake and
  then verifies hostname, chain, validity window and key strength itself. That is why an invalid
  certificate still produces headers *and* a full certificate finding instead of a connection error;
  the trade-off is recorded in the report as `handshake_verification_skipped: true`.
- **Checks are data, not control flow.** Each header rule is a `headerRule` with one `evaluate`
  func returning `*Finding` - add a rule by appending to `headerRules` in `headers.go`.
- **Severity is contextual.** A missing `Secure` flag on `session_id` is high; on `theme` it is
  medium. HSTS is only reported over TLS, because browsers ignore it otherwise.
- **The authorization statement travels with the evidence.** `authorization` in every report means a
  JSON file cannot be forwarded without showing whether scope was confirmed.

## Testing

```bash
go test ./...          # unit tests plus httptest end-to-end scans (loopback only)
go test -race ./...    # concurrency-safe check
go vet ./...           # static analysis
gofmt -l .             # formatting must be clean
```

Tests use Go's `httptest` servers, which bind `127.0.0.1`, so the suite never touches a routable
address. Table-driven cases cover each header rule, each cookie rule, certificate validity and
strength paths, redirect-hop cookie collection, unreachable targets, the loopback/`-authorized` gate
and JSON round-tripping.

## Roadmap

- [x] Local lab target (Go, no Docker required)
- [x] Security header, cookie and certificate checks
- [x] JSON + text evidence reports
- [x] Authorization gate for non-loopback scope
- [ ] Subdomain/asset inventory within an authorized scope file
- [ ] OWASP Top 10 checklist and test cases
- [ ] SQLi and XSS detection workflows (isolated targets only)
- [ ] Authentication, session management and access-control (IDOR) modules
- [ ] Baseline/diff mode to compare scans over time
- [ ] SARIF or CSV export for CI and ticketing

## License

Released under the [BSD 3-Clause "New" or "Revised" License](LICENSE) (`BSD-3-Clause`).

The license text is the verbatim SPDX template, which is what lets GitHub detect it and show
**BSD-3-Clause license** in the repository sidebar. If the sidebar ever disagrees, compare the file
against [choosealicense.com's BSD-3-Clause text](https://choosealicense.com/licenses/bsd-3-clause/);
any edit to the wording - even a single line - breaks detection.
