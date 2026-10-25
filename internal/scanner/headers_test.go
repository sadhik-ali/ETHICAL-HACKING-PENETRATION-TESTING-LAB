package scanner

import (
	"net/http"
	"testing"
)

func responseWith(t *testing.T, path string, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "https://target.example"+path, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Request:    req,
	}
	for name, value := range headers {
		resp.Header.Set(name, value)
	}
	return resp
}

func TestCheckHeadersHardenedResponse(t *testing.T) {
	resp := responseWith(t, "/app", map[string]string{
		"Content-Security-Policy":   "default-src 'self'; script-src 'self'; frame-ancestors 'none'",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Permissions-Policy":        "camera=(), microphone=()",
		"Cache-Control":             "no-store",
		"Server":                    "labserver",
	})

	findings := CheckHeaders(resp, HeaderContext{UsesTLS: true})
	if len(findings) != 0 {
		t.Fatalf("expected no header findings for a hardened response, got %d: %+v", len(findings), findings)
	}
}

func TestCheckHeadersMissingSet(t *testing.T) {
	resp := responseWith(t, "/", map[string]string{})
	findings := CheckHeaders(resp, HeaderContext{UsesTLS: true})

	got := map[string]string{}
	for _, finding := range findings {
		got[finding.Check] = finding.Severity
	}
	for _, want := range []struct {
		check    string
		severity string
	}{
		{"content-security-policy", SeverityHigh},
		{"strict-transport-security", SeverityHigh},
		{"clickjacking-protection", SeverityMedium},
		{"x-content-type-options", SeverityMedium},
		{"referrer-policy", SeverityLow},
		{"permissions-policy", SeverityInfo},
	} {
		if got[want.check] != want.severity {
			t.Errorf("check %q severity = %q, want %q", want.check, got[want.check], want.severity)
		}
	}
}

func TestCheckHeadersValueRules(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		headers  map[string]string
		ctx      HeaderContext
		wantChek string
		absent   bool
	}{
		{
			name:     "unsafe-inline csp is still a finding",
			path:     "/",
			headers:  map[string]string{"Content-Security-Policy": "script-src 'self' 'unsafe-inline'"},
			ctx:      HeaderContext{UsesTLS: true},
			wantChek: "content-security-policy",
		},
		{
			name:     "csp without script constraints",
			path:     "/",
			headers:  map[string]string{"Content-Security-Policy": "img-src *"},
			ctx:      HeaderContext{UsesTLS: true},
			wantChek: "content-security-policy",
		},
		{
			name:     "short hsts max-age",
			path:     "/",
			headers:  map[string]string{"Strict-Transport-Security": "max-age=60"},
			ctx:      HeaderContext{UsesTLS: true},
			wantChek: "strict-transport-security",
		},
		{
			name:     "hsts without max-age",
			path:     "/",
			headers:  map[string]string{"Strict-Transport-Security": "includeSubDomains"},
			ctx:      HeaderContext{UsesTLS: true},
			wantChek: "strict-transport-security",
		},
		{
			name:     "hsts not reported over plaintext",
			path:     "/",
			headers:  map[string]string{},
			ctx:      HeaderContext{UsesTLS: false},
			wantChek: "strict-transport-security",
			absent:   true,
		},
		{
			name:     "allowall framing",
			path:     "/",
			headers:  map[string]string{"X-Frame-Options": "ALLOWALL"},
			ctx:      HeaderContext{UsesTLS: true},
			wantChek: "clickjacking-protection",
		},
		{
			name:     "csp frame-ancestors satisfies clickjacking rule",
			path:     "/",
			headers:  map[string]string{"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"},
			ctx:      HeaderContext{UsesTLS: true},
			wantChek: "clickjacking-protection",
			absent:   true,
		},
		{
			name:     "nosniff with extra text",
			path:     "/",
			headers:  map[string]string{"X-Content-Type-Options": "nosniff; charset=utf-8"},
			ctx:      HeaderContext{UsesTLS: true},
			wantChek: "x-content-type-options",
		},
		{
			name:     "unsafe-url referrer policy",
			path:     "/",
			headers:  map[string]string{"Referrer-Policy": "unsafe-url"},
			ctx:      HeaderContext{UsesTLS: true},
			wantChek: "referrer-policy",
		},
		{
			name:     "versioned server banner",
			path:     "/",
			headers:  map[string]string{"Server": "Apache/2.4.41 (Ubuntu)"},
			ctx:      HeaderContext{UsesTLS: true},
			wantChek: "server-version-disclosure",
		},
		{
			name:     "generic server banner is accepted",
			path:     "/",
			headers:  map[string]string{"Server": "labserver"},
			ctx:      HeaderContext{UsesTLS: true},
			wantChek: "server-version-disclosure",
			absent:   true,
		},
		{
			name:     "x-powered-by disclosure",
			path:     "/",
			headers:  map[string]string{"X-Powered-By": "PHP/7.4.3"},
			ctx:      HeaderContext{UsesTLS: true},
			wantChek: "x-powered-by-disclosure",
		},
		{
			name:     "deprecated x-xss-protection",
			path:     "/",
			headers:  map[string]string{"X-XSS-Protection": "1; mode=block"},
			ctx:      HeaderContext{UsesTLS: true},
			wantChek: "deprecated-x-xss-protection",
		},
		{
			name:     "login page cached over tls",
			path:     "/login",
			headers:  map[string]string{"Cache-Control": "max-age=600"},
			ctx:      HeaderContext{UsesTLS: true},
			wantChek: "cache-control-on-sensitive-response",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := responseWith(t, tc.path, tc.headers)
			found := false
			for _, finding := range CheckHeaders(resp, tc.ctx) {
				if finding.Check == tc.wantChek {
					found = true
					if finding.Severity == "" || finding.Title == "" || finding.Remediation == "" {
						t.Errorf("finding %q must carry severity, title and remediation: %+v", finding.Check, finding)
					}
				}
			}
			if found == tc.absent {
				t.Errorf("check %q reported = %t, want %t", tc.wantChek, found, !tc.absent)
			}
		})
	}
}

func TestCheckHeadersFindingsAreSortedBySeverity(t *testing.T) {
	resp := responseWith(t, "/", map[string]string{})
	findings := CheckHeaders(resp, HeaderContext{UsesTLS: true})
	if len(findings) < 3 {
		t.Fatalf("expected several findings, got %d", len(findings))
	}
	ranks := map[string]int{SeverityHigh: 0, SeverityMedium: 1, SeverityLow: 2, SeverityInfo: 3}
	for i := 1; i < len(findings); i++ {
		if ranks[findings[i-1].Severity] > ranks[findings[i].Severity] {
			t.Fatalf("findings not ordered by descending severity at %d: %s then %s",
				i, findings[i-1].Severity, findings[i].Severity)
		}
	}
}

func TestMaxAgeSeconds(t *testing.T) {
	cases := map[string]struct {
		want  int
		found bool
	}{
		"max-age=31536000; includeSubDomains": {31536000, true},
		"MAX-AGE = 60":                        {60, true},
		`max-age="120"`:                       {120, true},
		"includeSubDomains":                   {0, false},
		"max-age":                             {0, false},
		"max-age=abc":                         {0, false},
	}
	for input, want := range cases {
		got, found := maxAgeSeconds(input)
		if got != want.want || found != want.found {
			t.Errorf("maxAgeSeconds(%q) = (%d, %t), want (%d, %t)", input, got, found, want.want, want.found)
		}
	}
}

func TestIsLoopback(t *testing.T) {
	cases := map[string]bool{
		"localhost":     true,
		"LOCALHOST":     true,
		"127.0.0.1":     true,
		"127.5.5.5":     true,
		"::1":           true,
		"10.0.0.5":      false,
		"192.168.1.10":  false,
		"example.com":   false,
		"sub.localhost": false,
	}
	for host, want := range cases {
		if got := IsLoopback(host); got != want {
			t.Errorf("IsLoopback(%q) = %t, want %t", host, got, want)
		}
	}
}
