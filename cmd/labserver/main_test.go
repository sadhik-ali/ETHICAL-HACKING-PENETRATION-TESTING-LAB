package main

import (
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGuardBindStaysOnLoopbackByDefault(t *testing.T) {
	cases := []struct {
		addr      string
		expose    bool
		wantError bool
	}{
		{"127.0.0.1:8080", false, false},
		{"localhost:8080", false, false},
		{"[::1]:8080", false, false},
		{"0.0.0.0:8080", false, true},
		{":8080", false, true},
		{"192.168.1.20:8080", false, true},
		{"0.0.0.0:8080", true, false},
		{"not-an-address", false, true},
	}
	for _, tc := range cases {
		err := guardBind(tc.addr, tc.expose)
		if tc.wantError && err == nil {
			t.Errorf("guardBind(%q, %t) = nil, want an error", tc.addr, tc.expose)
		}
		if !tc.wantError && err != nil {
			t.Errorf("guardBind(%q, %t) = %v, want nil", tc.addr, tc.expose, err)
		}
	}
}

func TestLabRoutes(t *testing.T) {
	server := httptest.NewServer(buildMux())
	defer server.Close()

	// Inspect each hop the way secscan does, without following redirects.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	cases := []struct {
		path         string
		wantStatus   int
		wantAbsent   []string
		wantPresent  []string
		wantCookies  int
		wantRedirect bool
	}{
		{
			path:       "/",
			wantStatus: http.StatusOK,
			wantPresent: []string{
				"Content-Security-Policy",
				"X-Content-Type-Options",
				"Referrer-Policy",
				"Permissions-Policy",
			},
			wantAbsent:  []string{"X-Powered-By"},
			wantCookies: 0,
		},
		{
			path:        "/insecure",
			wantStatus:  http.StatusOK,
			wantAbsent:  []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"},
			wantPresent: []string{"Server", "X-Powered-By"},
		},
		{
			path:        "/login",
			wantStatus:  http.StatusOK,
			wantAbsent:  []string{"Content-Security-Policy"},
			wantPresent: []string{"Server"},
			wantCookies: 3,
		},
		{
			path:         "/redirect",
			wantStatus:   http.StatusFound,
			wantCookies:  1,
			wantRedirect: true,
		},
		{
			path:        "/bad-csp",
			wantStatus:  http.StatusOK,
			wantPresent: []string{"Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options"},
		},
		{
			path:       "/health",
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			resp, err := client.Get(server.URL + tc.path)
			if err != nil {
				t.Fatalf("GET %s: %v", tc.path, err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)

			if resp.StatusCode != tc.wantStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			for _, header := range tc.wantPresent {
				if resp.Header.Get(header) == "" {
					t.Errorf("%s should set %s", tc.path, header)
				}
			}
			for _, header := range tc.wantAbsent {
				if resp.Header.Get(header) != "" {
					t.Errorf("%s must not set %s, got %q", tc.path, header, resp.Header.Get(header))
				}
			}
			if got := len(resp.Header["Set-Cookie"]); got != tc.wantCookies {
				t.Errorf("Set-Cookie count = %d, want %d (%v)", got, tc.wantCookies, resp.Header["Set-Cookie"])
			}
			if tc.wantRedirect && resp.Header.Get("Location") == "" {
				t.Errorf("%s should redirect somewhere", tc.path)
			}
			if len(body) == 0 {
				t.Errorf("%s returned an empty body", tc.path)
			}
		})
	}
}

func TestLabInsecureCookiesAreDeliberatelyWeak(t *testing.T) {
	server := httptest.NewServer(buildMux())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	defer resp.Body.Close()

	cookies := resp.Header["Set-Cookie"]
	joined := strings.Join(cookies, "\n")
	for _, want := range []string{"session_id", "remember_me", "csrf_token"} {
		if !strings.Contains(joined, want) {
			t.Errorf("/login should set %s, got %q", want, joined)
		}
	}
	// The lab only teaches anything if these flags really are missing.
	for _, header := range cookies {
		if strings.Contains(strings.ToLower(header), "httponly") {
			t.Errorf("lab cookie should omit HttpOnly, got %q", header)
		}
		if strings.Contains(strings.ToLower(header), "secure") {
			t.Errorf("lab cookie should omit Secure, got %q", header)
		}
	}
}

func TestLabHardenedHomeIsClean(t *testing.T) {
	server := httptest.NewServer(buildMux())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()

	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'self'") {
		t.Errorf("home CSP should restrict to self, got %q", resp.Header.Get("Content-Security-Policy"))
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Errorf("home X-Frame-Options = %q, want DENY", resp.Header.Get("X-Frame-Options"))
	}
	if resp.Header.Get("Server") != "labserver" {
		t.Errorf("home Server banner = %q, want the version-free labserver", resp.Header.Get("Server"))
	}
}

func TestSelfSignedCertCoversLocalhost(t *testing.T) {
	cert, err := selfSignedCert()
	if err != nil {
		t.Fatalf("selfSignedCert: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse generated certificate: %v", err)
	}
	if err := leaf.VerifyHostname("localhost"); err != nil {
		t.Errorf("certificate should cover localhost: %v", err)
	}
	if err := leaf.VerifyHostname("127.0.0.1"); err != nil {
		t.Errorf("certificate should cover 127.0.0.1: %v", err)
	}
	if time.Until(leaf.NotAfter) > 7*24*time.Hour {
		t.Errorf("lab certificate should be short-lived so the scanner reports expiry proximity, got %s", leaf.NotAfter)
	}
	if leaf.Issuer.String() != leaf.Subject.String() {
		t.Errorf("lab certificate is expected to be self-signed: issuer=%s subject=%s", leaf.Issuer, leaf.Subject)
	}
}
