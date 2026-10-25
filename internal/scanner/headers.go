package scanner

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

const (
	refMDNHeaders = "https://developer.mozilla.org/docs/Web/HTTP/Headers"
	refOWASPHead  = "https://owasp.org/www-project-secure-headers/"
	refCSP        = "https://content-security-policy.com/"
	refDisclosure = "https://cwe.mitre.org/data/definitions/200.html"
)

// HeaderContext carries the small amount of extra state a header rule needs:
// the final response plus whether it was reached over TLS.
type HeaderContext struct {
	UsesTLS bool
}

type headerRule struct {
	check     string
	evaluate  func(*http.Response, HeaderContext) *Finding
	reference string
}

var headerRules = []headerRule{
	{
		check: "content-security-policy",
		evaluate: func(resp *http.Response, _ HeaderContext) *Finding {
			value := resp.Header.Get("Content-Security-Policy")
			if value == "" {
				return missing("content-security-policy", SeverityHigh,
					"Content-Security-Policy header missing",
					"Without CSP the browser has no policy restricting script sources, so any injected markup executes as the page origin.",
					"Send a CSP that whitelists script sources, for example: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'.",
					refCSP)
			}
			lowered := strings.ToLower(value)
			var weak []string
			for _, keyword := range []string{"'unsafe-inline'", "'unsafe-eval'", "'unsafe-allow-redirects'"} {
				if strings.Contains(lowered, keyword) {
					weak = append(weak, keyword)
				}
			}
			if len(weak) > 0 {
				return &Finding{
					Check:       "content-security-policy",
					Severity:    SeverityHigh,
					Title:       "Content-Security-Policy contains unsafe sources",
					Detail:      fmt.Sprintf("%s keep inline or eval'd script executable, which defeats the purpose of the policy.", strings.Join(weak, ", ")),
					Evidence:    "Content-Security-Policy: " + value,
					Remediation: "Remove the unsafe keywords; whitelist exact origins, or use nonces/hashes for the few inline scripts the app needs.",
					Reference:   refCSP,
				}
			}
			if !strings.Contains(lowered, "default-src") && !strings.Contains(lowered, "script-src") {
				return &Finding{
					Check:       "content-security-policy",
					Severity:    SeverityMedium,
					Title:       "Content-Security-Policy does not constrain script sources",
					Detail:      "A policy with neither default-src nor script-src still allows inline and third-party script to run.",
					Evidence:    "Content-Security-Policy: " + value,
					Remediation: "Add default-src 'self' (or an explicit script-src) to the policy.",
					Reference:   refCSP,
				}
			}
			return nil
		},
		reference: refCSP,
	},
	{
		check: "strict-transport-security",
		evaluate: func(resp *http.Response, ctx HeaderContext) *Finding {
			value := resp.Header.Get("Strict-Transport-Security")
			if !ctx.UsesTLS {
				// HSTS is ignored by browsers over plaintext, so only the absence of
				// HTTPS itself is reportable; transportFindings covers that.
				return nil
			}
			if value == "" {
				return missing("strict-transport-security", SeverityHigh,
					"Strict-Transport-Security header missing",
					"HSTS tells browsers to always use HTTPS, which blocks SSL-stripping and http-to-https downgrade attacks.",
					"Send: Strict-Transport-Security: max-age=31536000; includeSubDomains",
					refMDNHeaders)
			}
			maxAge, ok := maxAgeSeconds(value)
			if !ok {
				return &Finding{
					Check:       "strict-transport-security",
					Severity:    SeverityMedium,
					Title:       "Strict-Transport-Security header has no usable max-age",
					Detail:      "Browsers discard an HSTS policy without a numeric max-age directive.",
					Evidence:    "Strict-Transport-Security: " + value,
					Remediation: "Send: max-age=31536000; includeSubDomains",
					Reference:   refMDNHeaders,
				}
			}
			if maxAge >= 15768000 {
				return nil
			}
			return &Finding{
				Check:       "strict-transport-security",
				Severity:    SeverityMedium,
				Title:       "HSTS max-age is short-lived",
				Detail:      fmt.Sprintf("max-age=%d seconds is below the ~6 months (15768000 seconds) that browsers and the preload list treat as durable.", maxAge),
				Evidence:    "Strict-Transport-Security: " + value,
				Remediation: "Raise max-age to 31536000 (1 year) once HTTPS is guaranteed for the whole host.",
				Reference:   refMDNHeaders,
			}
		},
		reference: refMDNHeaders,
	},
	{
		check: "clickjacking-protection",
		evaluate: func(resp *http.Response, _ HeaderContext) *Finding {
			frame := resp.Header.Get("X-Frame-Options")
			csp := strings.ToLower(resp.Header.Get("Content-Security-Policy"))
			if strings.Contains(csp, "frame-ancestors") {
				return nil
			}
			if frame == "" {
				return missing("clickjacking-protection", SeverityMedium,
					"Clickjacking protection missing (X-Frame-Options or CSP frame-ancestors)",
					"The page can be embedded by another origin, which is the basis of clickjacking attacks.",
					"Send: X-Frame-Options: DENY (or SAMEORIGIN); prefer CSP frame-ancestors 'none'.",
					refOWASPHead)
			}
			if strings.Contains(strings.ToLower(frame), "allowall") {
				return &Finding{
					Check:       "clickjacking-protection",
					Severity:    SeverityMedium,
					Title:       "X-Frame-Options allows framing by any origin",
					Detail:      "ALLOWALL is a non-standard value that older browsers honour, leaving the page frameable.",
					Evidence:    "X-Frame-Options: " + frame,
					Remediation: "Use DENY or SAMEORIGIN.",
					Reference:   refMDNHeaders,
				}
			}
			return nil
		},
		reference: refOWASPHead,
	},
	{
		check: "x-content-type-options",
		evaluate: func(resp *http.Response, _ HeaderContext) *Finding {
			value := resp.Header.Get("X-Content-Type-Options")
			if value == "" {
				return missing("x-content-type-options", SeverityMedium,
					"X-Content-Type-Options: nosniff missing",
					"Browsers may MIME-sniff a response and execute it as a content type other than the one declared.",
					"Send: X-Content-Type-Options: nosniff on every response.",
					refMDNHeaders)
			}
			if strings.EqualFold(strings.TrimSpace(value), "nosniff") {
				return nil
			}
			return &Finding{
				Check:       "x-content-type-options",
				Severity:    SeverityLow,
				Title:       "X-Content-Type-Options has an unexpected value",
				Detail:      "Only the exact token nosniff disables browser MIME sniffing.",
				Evidence:    "X-Content-Type-Options: " + value,
				Remediation: "Set the header to exactly: nosniff",
				Reference:   refMDNHeaders,
			}
		},
		reference: refMDNHeaders,
	},
	{
		check: "referrer-policy",
		evaluate: func(resp *http.Response, _ HeaderContext) *Finding {
			value := resp.Header.Get("Referrer-Policy")
			if value == "" {
				return missing("referrer-policy", SeverityLow,
					"Referrer-Policy header missing",
					"Outbound requests can leak full URLs - which often carry tokens or identifiers - to third-party origins in the Referer header.",
					"Send: Referrer-Policy: strict-origin-when-cross-origin (or no-referrer for sensitive pages).",
					refMDNHeaders)
			}
			if strings.EqualFold(strings.TrimSpace(value), "unsafe-url") {
				return &Finding{
					Check:       "referrer-policy",
					Severity:    SeverityLow,
					Title:       "Referrer-Policy is unsafe-url",
					Detail:      "The full path and query string is sent to every cross-origin referer.",
					Evidence:    "Referrer-Policy: " + value,
					Remediation: "Use strict-origin-when-cross-origin or no-referrer.",
					Reference:   refMDNHeaders,
				}
			}
			return nil
		},
		reference: refMDNHeaders,
	},
	{
		check: "permissions-policy",
		evaluate: func(resp *http.Response, _ HeaderContext) *Finding {
			if resp.Header.Get("Permissions-Policy") != "" {
				return nil
			}
			return missing("permissions-policy", SeverityInfo,
				"Permissions-Policy header missing",
				"Browser features such as camera, microphone and geolocation stay available to the document and its embeds.",
				"Send: Permissions-Policy: camera=(), microphone=(), geolocation=() to disable features the app does not use.",
				refOWASPHead)
		},
		reference: refOWASPHead,
	},
	{
		check: "server-version-disclosure",
		evaluate: func(resp *http.Response, _ HeaderContext) *Finding {
			value := resp.Header.Get("Server")
			if value == "" || !strings.ContainsAny(value, "0123456789") {
				return nil
			}
			return &Finding{
				Check:       "server-version-disclosure",
				Severity:    SeverityInfo,
				Title:       "Server header discloses a software version",
				Detail:      "A versioned product banner can be matched directly against public vulnerability and exploit data.",
				Evidence:    "Server: " + value,
				Remediation: "Remove the version detail, leaving at most a generic product name. Nginx: server_tokens off; Apache: ServerTokens Prod.",
				Reference:   refDisclosure,
			}
		},
		reference: refDisclosure,
	},
	{
		check: "x-powered-by-disclosure",
		evaluate: func(resp *http.Response, _ HeaderContext) *Finding {
			value := resp.Header.Get("X-Powered-By")
			if value == "" {
				return nil
			}
			return &Finding{
				Check:       "x-powered-by-disclosure",
				Severity:    SeverityLow,
				Title:       "X-Powered-By exposes the technology stack",
				Detail:      "Framework and runtime versions advertised in headers narrow down which known issues apply to this host.",
				Evidence:    "X-Powered-By: " + value,
				Remediation: "Disable the banner: Express app.disable('x-powered-by'); PHP expose_php = Off.",
				Reference:   refDisclosure,
			}
		},
		reference: refDisclosure,
	},
	{
		check: "deprecated-x-xss-protection",
		evaluate: func(resp *http.Response, _ HeaderContext) *Finding {
			value := resp.Header.Get("X-XSS-Protection")
			if value == "" {
				return nil
			}
			return &Finding{
				Check:       "deprecated-x-xss-protection",
				Severity:    SeverityInfo,
				Title:       "Deprecated X-XSS-Protection header present",
				Detail:      "The reflective-XSS auditor has been removed from modern browsers; the header is inert at best and can disable built-in filtering where it still exists.",
				Evidence:    "X-XSS-Protection: " + value,
				Remediation: "Remove the header and rely on a Content-Security-Policy instead.",
				Reference:   refMDNHeaders,
			}
		},
		reference: refMDNHeaders,
	},
	{
		check: "cache-control-on-sensitive-response",
		evaluate: func(resp *http.Response, ctx HeaderContext) *Finding {
			if !ctx.UsesTLS {
				return nil
			}
			if !looksLikeAuthEndpoint(resp.Request.URL.Path) {
				return nil
			}
			if strings.Contains(strings.ToLower(resp.Header.Get("Cache-Control")), "no-store") {
				return nil
			}
			return &Finding{
				Check:       "cache-control-on-sensitive-response",
				Severity:    SeverityLow,
				Title:       fmt.Sprintf("Authentication-related path %s is served without Cache-Control: no-store", resp.Request.URL.Path),
				Detail:      "Shared caches and browser history may retain a response that carries credentials, tokens or personal data.",
				Evidence:    "Cache-Control: " + headerOrAbsent(resp, "Cache-Control"),
				Remediation: "Send: Cache-Control: no-store on login, token, session and account responses.",
				Reference:   "https://datatracker.ietf.org/doc/html/rfc9110#section.5.2.2",
			}
		},
		reference: "https://owasp.org/www-project-web-security-testing-guide/",
	},
}

// CheckHeaders runs every header rule against one response.
func CheckHeaders(resp *http.Response, ctx HeaderContext) []Finding {
	var findings []Finding
	for _, rule := range headerRules {
		if f := rule.evaluate(resp, ctx); f != nil {
			findings = append(findings, *f)
		}
	}
	sortFindings(findings)
	return findings
}

func missing(check, severity, title, detail, remediation, reference string) *Finding {
	return &Finding{
		Check:       check,
		Severity:    severity,
		Title:       title,
		Detail:      detail,
		Evidence:    "header absent",
		Remediation: remediation,
		Reference:   reference,
	}
}

func headerOrAbsent(resp *http.Response, header string) string {
	if got := resp.Header.Get(header); got != "" {
		return got
	}
	return "(absent)"
}

func looksLikeAuthEndpoint(path string) bool {
	lowered := strings.ToLower(path)
	for _, hint := range []string{"/login", "/signin", "/logout", "/oauth", "/token", "/session", "/account", "/password", "/admin"} {
		if strings.Contains(lowered, hint) {
			return true
		}
	}
	return false
}

func maxAgeSeconds(value string) (int, bool) {
	for _, part := range strings.Split(value, ";") {
		key, arg, found := strings.Cut(strings.TrimSpace(part), "=")
		if !found || !strings.EqualFold(strings.TrimSpace(key), "max-age") {
			continue
		}
		seconds, err := strconv.Atoi(strings.Trim(strings.TrimSpace(arg), `"`))
		if err != nil {
			return 0, false
		}
		return seconds, true
	}
	return 0, false
}
