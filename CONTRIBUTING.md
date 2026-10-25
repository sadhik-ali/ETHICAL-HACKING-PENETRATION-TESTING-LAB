# Contributing

Thanks for your interest in contributing to the Ethical Hacking & Penetration Testing Lab.

## Rules

1. **Authorized testing only.** All contributions must assume written permission from the system owner.
2. **Local lab targets only.** Vulnerable examples must run in isolated, local environments (the bundled `cmd/labserver` target, or Docker) and never point at real-world systems. Tests must use Go's `httptest` loopback servers.
3. **No weaponization.** Do not submit exploits targeting production services, real-world vendors, or live infrastructure.
4. **Non-loopback scope requires an assertion.** Any new CLI path that could reach a routable host must go through `scanner.Authorize`, so `-authorized` remains mandatory.

## Getting started

```bash
go run ./cmd/labserver          # intentionally vulnerable target on http://127.0.0.1:8080
go run ./cmd/secscan http://127.0.0.1:8080/insecure
go test ./...                   # unit + end-to-end checks, loopback only
gofmt -l .                      # must print nothing
go vet ./...
```

## Adding a check

Header rules are data: append a `headerRule` to `headerRules` in `internal/scanner/headers.go` and
return a `*Finding` with `Check`, `Severity`, `Title`, `Detail`, `Evidence`, `Remediation` and a
`Reference`. Cookie rules live in `cookies.go`, TLS rules in `tls.go`. Add a table-driven test next
to the rule and, if the case is teachable, a route in `cmd/labserver` that triggers it.

## How to contribute

- Open an issue first to describe what you want to add or fix.
- Keep changes focused: one vulnerability check, report template, or doc page per pull request.
- Documentation-only changes (README, guides, report templates) are welcome at any time.

## Code of conduct

Be professional. Findings and discussions here are for defensive security education and authorized assessments only.
