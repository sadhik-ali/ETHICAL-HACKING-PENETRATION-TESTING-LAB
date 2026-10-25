package scanner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// handlerHardened is the reference target used by the scan tests: correct
// headers and a correctly flagged cookie.
func handlerHardened() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "camera=()")
		h.Set("Cache-Control", "no-store")
		http.SetCookie(w, &http.Cookie{Name: "theme", Value: "dark", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		http.Redirect(w, r, "/app", http.StatusFound)
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, _ *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "camera=()")
		http.SetCookie(w, &http.Cookie{Name: "session_id", Value: "opaque", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		w.Write([]byte("<html><body>hardened</body></html>"))
	})
	return mux
}

func handlerInsecure() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
		w.Header().Set("X-Powered-By", "PHP/7.4.3")
		http.SetCookie(w, &http.Cookie{Name: "session_id", Value: "abc123", Path: "/"})
		w.Write([]byte("<html><body>insecure</body></html>"))
	})
	return mux
}

func TestScanInsecureLoopbackTarget(t *testing.T) {
	server := httptest.NewServer(handlerInsecure())
	defer server.Close()

	result, err := New(DefaultOptions()).Scan(server.URL)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if result.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", result.StatusCode)
	}
	if len(result.Errors) != 0 {
		t.Errorf("unexpected errors: %v", result.Errors)
	}

	got := checksIn(result.Findings)
	for _, check := range []string{
		"plain-http",
		"content-security-policy",
		"clickjacking-protection",
		"x-content-type-options",
		"server-version-disclosure",
		"x-powered-by-disclosure",
		"cookie-httponly",
		"cookie-secure",
		"cookie-samesite",
	} {
		if _, ok := got[check]; !ok {
			t.Errorf("missing expected finding %q; got %+v", check, result.Findings)
		}
	}
	if result.TLS != nil {
		t.Errorf("TLS details must be absent for a plaintext target")
	}
}

func TestScanHardenedHTTPSTarget(t *testing.T) {
	server := httptest.NewTLSServer(handlerHardened())
	defer server.Close()

	result, err := New(DefaultOptions()).Scan(server.URL)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if result.TLS == nil {
		t.Fatalf("TLS details missing")
	}
	if !strings.HasSuffix(result.FinalURL, "/app") {
		t.Errorf("FinalURL = %q, want the /app target after following the redirect", result.FinalURL)
	}
	if len(result.SetCookies) != 2 {
		t.Errorf("expected cookies from both redirect hops, got %v", result.SetCookies)
	}

	// The self-signed httptest certificate is the only expected finding.
	for _, finding := range result.Findings {
		if finding.Severity == SeverityHigh && finding.Check != "tls-chain-untrusted" && finding.Check != "tls-hostname-mismatch" {
			t.Errorf("unexpected high-severity finding on a hardened target: %+v", finding)
		}
	}
	if _, ok := checksIn(result.Findings)["plain-http"]; ok {
		t.Errorf("HTTPS target must not report plain-http")
	}
	if _, ok := checksIn(result.Findings)["tls-protocol"]; ok {
		t.Errorf("TLS 1.3 handshake must not raise the tls-protocol note")
	}
}

func TestScanFollowsRedirectLimitAndRecordsCookieFromFirstHop(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.SetCookie(w, &http.Cookie{Name: "first-hop", Value: "1", Path: "/"})
			http.Redirect(w, r, "/start", http.StatusFound)
			return
		}
		w.Write([]byte("end"))
	}))
	defer server.Close()

	scan := New(Options{Timeout: 3 * time.Second, MaxRedirects: 2})
	result, err := scan.Scan(server.URL + "/start")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(result.Errors) == 0 {
		t.Errorf("expected a redirect-limit error")
	}
	if len(result.SetCookies) == 0 {
		t.Errorf("cookies from earlier hops should still be inspected")
	}
}

func TestScanUnreachableTargetRecordsError(t *testing.T) {
	server := httptest.NewServer(handlerHardened())
	closed := server.URL
	server.Close()

	result, err := New(Options{Timeout: 2 * time.Second, MaxRedirects: 1}).Scan(closed)
	if err != nil {
		t.Fatalf("an unreachable target must not fail the run: %v", err)
	}
	if len(result.Errors) == 0 {
		t.Errorf("expected an error entry for the failed request")
	}
	if _, ok := checksIn(result.Findings)["reachability"]; !ok {
		t.Errorf("expected a reachability finding, got %+v", result.Findings)
	}
	if result.Findings == nil {
		t.Errorf("Findings must be an empty slice so JSON renders [] rather than null")
	}
}

func TestScanRejectsBadTargets(t *testing.T) {
	scan := New(DefaultOptions())
	for _, target := range []string{"", "ftp://localhost/files", "localhost:8080", "http://"} {
		if _, err := scan.Scan(target); err == nil {
			t.Errorf("Scan(%q) should fail", target)
		}
	}
}

func TestAuthorizeAllowsLoopbackWithoutConfirmation(t *testing.T) {
	auth, err := Authorize([]string{"http://127.0.0.1:8080/insecure"}, false, "")
	if err != nil {
		t.Fatalf("loopback targets must not require -authorized: %v", err)
	}
	if !auth.LoopbackOnly || auth.Confirmed {
		t.Errorf("unexpected authorization state: %+v", auth)
	}
}

func TestBuildReportSummaryAndJSON(t *testing.T) {
	server := httptest.NewServer(handlerInsecure())
	defer server.Close()

	result, err := New(DefaultOptions()).Scan(server.URL)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	auth, err := Authorize([]string{server.URL}, false, "authorized lab run, ticket LAB-1")
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	report := BuildReport([]TargetResult{result}, auth)

	if report.Summary.Targets != 1 {
		t.Errorf("Summary.Targets = %d, want 1", report.Summary.Targets)
	}
	if report.Summary.Findings != len(result.Findings) {
		t.Errorf("Summary.Findings = %d, want %d", report.Summary.Findings, len(result.Findings))
	}
	if report.Summary.HighestRisk != SeverityHigh {
		t.Errorf("Summary.HighestRisk = %q, want %q", report.Summary.HighestRisk, SeverityHigh)
	}
	if report.Tool != ToolName || report.Version != Version {
		t.Errorf("tool identity = %q %q", report.Tool, report.Version)
	}
	if report.Authorization.OperatorNote != "authorized lab run, ticket LAB-1" {
		t.Errorf("operator note lost: %+v", report.Authorization)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	data, err := report.Write(path)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	var decoded Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	if decoded.ScopeNote == "" || !strings.Contains(decoded.ScopeNote, "written permission") {
		t.Errorf("scope note must state the authorization rule, got %q", decoded.ScopeNote)
	}
	if decoded.Summary.BySeverity["high"] == 0 {
		t.Errorf("by_severity.high should be counted, got %+v", decoded.Summary.BySeverity)
	}
	if len(decoded.Targets) != 1 || len(decoded.Targets[0].Findings) == 0 {
		t.Fatalf("targets/findings lost in round trip: %+v", decoded.Targets)
	}

	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read written report: %v", err)
	}
	if !strings.HasSuffix(string(onDisk), "}\n") {
		t.Errorf("report file should end with the closing brace and a newline")
	}

	text := report.RenderText()
	for _, want := range []string{"HIGH", "plain-http", "Authorization", "Scope"} {
		if !strings.Contains(strings.ToUpper(text), strings.ToUpper(want)) {
			t.Errorf("RenderText missing %q\n%s", want, text)
		}
	}
}

func TestBuildReportCleanTarget(t *testing.T) {
	server := httptest.NewTLSServer(handlerHardened())
	defer server.Close()

	result, err := New(Options{Timeout: 3 * time.Second, MaxRedirects: 3, SkipTLSProbe: true}).Scan(server.URL)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	report := BuildReport([]TargetResult{result}, Authorization{LoopbackOnly: true, Targets: []string{result.URL}})
	if report.Summary.Findings != 0 {
		t.Fatalf("hardened target with the TLS probe skipped should be clean, got %+v", result.Findings)
	}
	if report.Summary.HighestRisk != "none" {
		t.Errorf("HighestRisk = %q, want none", report.Summary.HighestRisk)
	}
	if !strings.Contains(report.RenderText(), "no findings") {
		t.Errorf("clean target should render a no-findings block")
	}
	if _, err := report.Marshal(); err != nil {
		t.Fatalf("Marshal: %v", err)
	}
}
