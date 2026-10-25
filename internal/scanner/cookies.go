package scanner

import (
	"fmt"
	"strings"
)

const refCookies = "https://owasp.org/www-community/controls/SecureCookieAttribute"

// cookieAttribute is a parsed attribute of one Set-Cookie header.
type cookieAttribute struct {
	Name  string
	Value string
}

type parsedCookie struct {
	Name       string
	Value      string
	Attributes []cookieAttribute
	Raw        string
}

func (c parsedCookie) has(flag string) bool {
	for _, a := range c.Attributes {
		if a.Name == "" && strings.EqualFold(a.Value, flag) {
			return true
		}
	}
	return false
}

func (c parsedCookie) attr(name string) (string, bool) {
	for _, a := range c.Attributes {
		if strings.EqualFold(a.Name, name) {
			return a.Value, true
		}
	}
	return "", false
}

var sessionNameHints = []string{"session", "sess", "sid", "jsessionid", "phpsessid", "connect.sid", "auth", "token", "jwt", "csrf", "remember"}

// CheckCookies inspects every Set-Cookie header seen for a target.
func CheckCookies(headers []string, scheme string, host string) []Finding {
	var findings []Finding
	for _, raw := range headers {
		cookie := parseSetCookie(raw)
		if cookie.Name == "" {
			findings = append(findings, Finding{
				Check:       "cookie-unparsable",
				Severity:    SeverityInfo,
				Title:       "Set-Cookie header could not be parsed",
				Detail:      "The header is not in a recognised name=value;attribute form, so attribute checks were skipped.",
				Evidence:    raw,
				Remediation: "Emit cookies as name=value; Path=/; Secure; HttpOnly; SameSite=Lax",
				Reference:   refCookies,
			})
			continue
		}
		sessionish := looksLikeSessionCookie(cookie.Name)
		sameSite, hasSameSite := cookie.attr("SameSite")

		if !cookie.has("HttpOnly") {
			findings = append(findings, Finding{
				Check:       "cookie-httponly",
				Severity:    severityIf(sessionish, SeverityHigh, SeverityMedium),
				Title:       fmt.Sprintf("Cookie %q is readable from JavaScript (no HttpOnly)", cookie.Name),
				Detail:      "Without HttpOnly any cross-site scripting bug can exfiltrate or replace this cookie through document.cookie.",
				Evidence:    cookie.Raw,
				Remediation: "Add the HttpOnly attribute to the cookie.",
				Reference:   refCookies,
			})
		}

		if !cookie.has("Secure") {
			detail := "The cookie was set on an encrypted page but lacks Secure, so browsers will also send it over plaintext http://, where it can be captured."
			if strings.EqualFold(scheme, "http") {
				detail = "The page itself is served over plaintext http://, so this cookie crossed the network unencrypted and was readable by anyone on the path."
			}
			findings = append(findings, Finding{
				Check:       "cookie-secure",
				Severity:    severityIf(sessionish, SeverityHigh, SeverityMedium),
				Title:       fmt.Sprintf("Cookie %q is missing the Secure flag", cookie.Name),
				Detail:      detail,
				Evidence:    cookie.Raw,
				Remediation: "Add the Secure attribute and serve the application over HTTPS only.",
				Reference:   refCookies,
			})
		}

		if !hasSameSite {
			findings = append(findings, Finding{
				Check:       "cookie-samesite",
				Severity:    SeverityMedium,
				Title:       fmt.Sprintf("Cookie %q has no SameSite attribute", cookie.Name),
				Detail:      "Browsers then apply their own default, which historically meant the cookie rode along on cross-site requests, enabling CSRF.",
				Evidence:    cookie.Raw,
				Remediation: "Set SameSite=Lax for session cookies; use SameSite=None only when cross-site posting is genuinely required.",
				Reference:   refCookies,
			})
		} else if strings.EqualFold(sameSite, "None") && !cookie.has("Secure") {
			findings = append(findings, Finding{
				Check:       "cookie-samesite-none-without-secure",
				Severity:    SeverityHigh,
				Title:       fmt.Sprintf("Cookie %q uses SameSite=None without Secure", cookie.Name),
				Detail:      "SameSite=None requires Secure; browsers reject the combination, and until they do the cookie is sent cross-site over plaintext.",
				Evidence:    cookie.Raw,
				Remediation: "Add Secure, or switch to SameSite=Lax/Strict.",
				Reference:   refCookies,
			})
		}

		if domain, ok := cookie.attr("Domain"); ok && domainIsTooBroad(domain, host) {
			findings = append(findings, Finding{
				Check:       "cookie-domain-scope",
				Severity:    SeverityLow,
				Title:       fmt.Sprintf("Cookie %q is scoped to the whole domain %q", cookie.Name, domain),
				Detail:      "Every current and future subdomain receives this cookie, so a weak subdomain can read or set session material for the main application.",
				Evidence:    cookie.Raw,
				Remediation: "Omit Domain, or pin it to the exact host that needs the cookie.",
				Reference:   refCookies,
			})
		}

		if strings.HasPrefix(cookie.Value, "eyJ") {
			findings = append(findings, Finding{
				Check:       "cookie-carries-jwt",
				Severity:    SeverityInfo,
				Title:       fmt.Sprintf("Cookie %q appears to carry a JWT", cookie.Name),
				Detail:      "Tokens in cookies inherit every header risk above; also confirm the signature algorithm, expiry, and that refresh tokens are not stored client-side.",
				Evidence:    cookie.Name + "=<" + fmt.Sprint(len(cookie.Value)) + " byte token>",
				Remediation: "Keep HttpOnly+Secure+SameSite, use short access-token lifetimes, and store long-lived tokens server-side.",
				Reference:   "https://datatracker.ietf.org/doc/html/rfc7519",
			})
		}
	}
	sortFindings(findings)
	return findings
}

// parseSetCookie splits one Set-Cookie header into its name/value pair and
// attributes. Go's http package does not export a parser for this direction.
func parseSetCookie(raw string) parsedCookie {
	parts := strings.Split(raw, ";")
	if len(parts) == 0 {
		return parsedCookie{Raw: raw}
	}
	name, value, found := strings.Cut(strings.TrimSpace(parts[0]), "=")
	if !found || strings.TrimSpace(name) == "" {
		return parsedCookie{Raw: raw}
	}
	cookie := parsedCookie{
		Name:  strings.TrimSpace(name),
		Value: strings.Trim(strings.TrimSpace(value), `"`),
		Raw:   raw,
	}
	reserved := map[string]bool{"expires": true, "max-age": true, "domain": true, "path": true,
		"secure": true, "httponly": true, "samesite": true, "partitioned": true, "priority": true}
	for _, part := range parts[1:] {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		key, arg, hasArg := strings.Cut(trimmed, "=")
		key = strings.TrimSpace(key)
		if !reserved[strings.ToLower(key)] {
			// A stray token that is not a known attribute: treat it as part of the
			// cookie value rather than dropping it silently.
			cookie.Value += ";" + trimmed
			continue
		}
		if hasArg {
			cookie.Attributes = append(cookie.Attributes, cookieAttribute{Name: key, Value: strings.Trim(strings.TrimSpace(arg), `"`)})
			continue
		}
		cookie.Attributes = append(cookie.Attributes, cookieAttribute{Value: key})
	}
	return cookie
}

func looksLikeSessionCookie(name string) bool {
	lower := strings.ToLower(name)
	for _, hint := range sessionNameHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

func domainIsTooBroad(domain, host string) bool {
	domain = strings.TrimPrefix(strings.ToLower(domain), ".")
	host = strings.ToLower(host)
	if !strings.Contains(domain, ".") {
		return true
	}
	// The exact host is fine; any Domain that is a parent of the host widens the
	// cookie to every subdomain, present and future.
	return host != domain && strings.HasSuffix(host, "."+domain)
}

func severityIf(cond bool, high, other string) string {
	if cond {
		return high
	}
	return other
}
