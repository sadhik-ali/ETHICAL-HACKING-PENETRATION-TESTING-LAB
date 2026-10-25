package scanner

import (
	"strings"
	"testing"
)

func checksIn(findings []Finding) map[string]Finding {
	out := map[string]Finding{}
	for _, finding := range findings {
		out[finding.Check] = finding
	}
	return out
}

func TestCheckCookiesHardenedCookie(t *testing.T) {
	findings := CheckCookies(
		[]string{"session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"},
		"https", "app.example.com",
	)
	if len(findings) != 0 {
		t.Fatalf("expected no cookie findings, got %+v", findings)
	}
}

func TestCheckCookiesInsecureSessionCookie(t *testing.T) {
	findings := CheckCookies([]string{"session_id=abc123; Path=/"}, "http", "app.example.com")
	got := checksIn(findings)

	for check, wantSeverity := range map[string]string{
		"cookie-httponly": SeverityHigh,
		"cookie-secure":   SeverityHigh,
		"cookie-samesite": SeverityMedium,
	} {
		if got[check].Severity != wantSeverity {
			t.Errorf("%s severity = %q, want %q (all findings: %+v)", check, got[check].Severity, wantSeverity, findings)
		}
	}
}

func TestCheckCookiesNonSessionCookieIsLowerSeverity(t *testing.T) {
	got := checksIn(CheckCookies([]string{"theme=dark; Path=/"}, "https", "app.example.com"))
	if got["cookie-httponly"].Severity != SeverityMedium {
		t.Errorf("non-session cookie HttpOnly severity = %q, want %q", got["cookie-httponly"].Severity, SeverityMedium)
	}
	if got["cookie-secure"].Severity != SeverityMedium {
		t.Errorf("non-session cookie Secure severity = %q, want %q", got["cookie-secure"].Severity, SeverityMedium)
	}
}

func TestCheckCookiesSameSiteNoneWithoutSecure(t *testing.T) {
	got := checksIn(CheckCookies([]string{"prefs=a; Path=/; SameSite=None; HttpOnly"}, "https", "app.example.com"))
	if got["cookie-samesite-none-without-secure"].Severity != SeverityHigh {
		t.Fatalf("expected a high cookie-samesite-none-without-secure finding, got %+v", got)
	}
	if _, present := got["cookie-samesite"]; present {
		t.Errorf("SameSite was present, so the missing-SameSite check should not fire")
	}
}

func TestCheckCookiesSameSiteNoneWithSecureIsAccepted(t *testing.T) {
	got := checksIn(CheckCookies([]string{"sso=t; Path=/; Secure; HttpOnly; SameSite=None"}, "https", "app.example.com"))
	for _, check := range []string{"cookie-samesite", "cookie-samesite-none-without-secure", "cookie-secure", "cookie-httponly"} {
		if _, present := got[check]; present {
			t.Errorf("unexpected %s finding for a correctly flagged cross-site cookie", check)
		}
	}
}

func TestCheckCookiesDomainScope(t *testing.T) {
	broad := checksIn(CheckCookies([]string{"id=1; Domain=.example.com; Path=/; Secure; HttpOnly; SameSite=Lax"}, "https", "app.example.com"))
	if broad["cookie-domain-scope"].Severity != SeverityLow {
		t.Errorf("expected a low cookie-domain-scope finding for Domain=.example.com, got %+v", broad)
	}

	exact := checksIn(CheckCookies([]string{"id=1; Domain=app.example.com; Path=/; Secure; HttpOnly; SameSite=Lax"}, "https", "app.example.com"))
	if _, present := exact["cookie-domain-scope"]; present {
		t.Errorf("Domain matching the host should not be reported")
	}

	tldOnly := checksIn(CheckCookies([]string{"id=1; Domain=example; Path=/; Secure; HttpOnly; SameSite=Lax"}, "https", "example.com"))
	if _, present := tldOnly["cookie-domain-scope"]; !present {
		t.Errorf("a single-label Domain should be reported as too broad")
	}
}

func TestCheckCookiesDetectsJWT(t *testing.T) {
	got := checksIn(CheckCookies([]string{"access=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.sig; Path=/; Secure; HttpOnly; SameSite=Strict"}, "https", "app.example.com"))
	if got["cookie-carries-jwt"].Severity != SeverityInfo {
		t.Fatalf("expected an info cookie-carries-jwt finding, got %+v", got)
	}
	if strings.Contains(got["cookie-carries-jwt"].Evidence, "eyJ") {
		t.Errorf("report evidence must not echo the token itself: %q", got["cookie-carries-jwt"].Evidence)
	}
}

func TestCheckCookiesUnparsableHeader(t *testing.T) {
	got := checksIn(CheckCookies([]string{"this-is-not-a-cookie"}, "https", "app.example.com"))
	if got["cookie-unparsable"].Severity != SeverityInfo {
		t.Fatalf("expected an info cookie-unparsable finding, got %+v", got)
	}
}

func TestCheckCookiesAllRedirectHopsAreInspected(t *testing.T) {
	headers := []string{"early=1; Path=/", "session=2; Path=/; Secure"}
	got := checksIn(CheckCookies(headers, "https", "app.example.com"))
	if got["cookie-httponly"].Title == "" {
		t.Fatalf("expected a finding for the cookie from the first hop")
	}
	if !strings.Contains(got["cookie-httponly"].Evidence, "early=1") {
		t.Errorf("finding should reference the weakest cookie, got %q", got["cookie-httponly"].Evidence)
	}
	if len(got) < 3 {
		t.Errorf("expected findings for both cookies, got %+v", got)
	}
}

func TestParseSetCookie(t *testing.T) {
	cookie := parseSetCookie(`SID=abc; SECURE; HttpOnly; SameSite=None; DOMAIN=Example.COM; Path=/admin; Max-Age="60"; Expires=Wed, 21 Oct 2026 07:28:00 GMT`)

	if cookie.Name != "SID" || cookie.Value != "abc" {
		t.Fatalf("name/value = %q/%q, want SID/abc", cookie.Name, cookie.Value)
	}
	if !cookie.has("Secure") || !cookie.has("httponly") {
		t.Errorf("flag attributes should match case-insensitively: %+v", cookie.Attributes)
	}
	for name, want := range map[string]string{"SameSite": "None", "Domain": "Example.COM", "Path": "/admin", "Max-Age": "60"} {
		if got, ok := cookie.attr(name); !ok || got != want {
			t.Errorf("attr %s = %q (%t), want %q", name, got, ok, want)
		}
	}
	if _, ok := cookie.attr("Expires"); !ok {
		t.Errorf("Expires should be captured as an attribute")
	}
}

func TestParseSetCookieKeepsUnknownTokensInValue(t *testing.T) {
	cookie := parseSetCookie("prefs=dark; compact")
	if cookie.Name != "prefs" || cookie.Value != "dark;compact" {
		t.Fatalf("got %q/%q, want prefs/\"dark;compact\"", cookie.Name, cookie.Value)
	}
}

func TestLooksLikeSessionCookie(t *testing.T) {
	for _, name := range []string{"JSESSIONID", "connect.sid", "PHPSESSID", "auth_token", "rememberme", "_csrf"} {
		if !looksLikeSessionCookie(name) {
			t.Errorf("looksLikeSessionCookie(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"theme", "locale", "analytics"} {
		if looksLikeSessionCookie(name) {
			t.Errorf("looksLikeSessionCookie(%q) = true, want false", name)
		}
	}
}
