package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sadhik-ali/Ethical-Hacking-Penetration-Testing-Lab/internal/scanner"
)

func labHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc", Path: "/"})
		w.Write([]byte("<html><body>lab</body></html>"))
	})
}

func TestRunJSONOutputAndReportFile(t *testing.T) {
	server := httptest.NewServer(labHandler())
	defer server.Close()

	dir := t.TempDir()
	out := filepath.Join(dir, "report.json")

	var stdout, stderr bytes.Buffer
	if err := run([]string{"-format", "json", "-out", out, server.URL}, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v (%s)", err, stderr.String())
	}

	var report scanner.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("-format json must print a report: %v\n%s", err, stdout.String())
	}
	if report.Summary.Targets != 1 || report.Summary.Findings == 0 {
		t.Errorf("unexpected summary: %+v", report.Summary)
	}
	if !report.Authorization.LoopbackOnly {
		t.Errorf("httptest binds loopback, so LoopbackOnly should be true: %+v", report.Authorization)
	}

	onDisk, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("-out file missing: %v", err)
	}
	if !bytes.Contains(onDisk, []byte(`"findings"`)) {
		t.Errorf("written report lacks findings: %s", onDisk)
	}
	if !strings.Contains(stderr.String(), out) {
		t.Errorf("JSON mode should report the output path on stderr, got %q", stderr.String())
	}
	if strings.Contains(stdout.String(), "written to") {
		t.Errorf("stdout must stay a single JSON document in -format json mode")
	}
}

func TestRunTextOutputByDefault(t *testing.T) {
	server := httptest.NewServer(labHandler())
	defer server.Close()

	var stdout, stderr bytes.Buffer
	if err := run([]string{server.URL}, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v (%s)", err, stderr.String())
	}
	text := stdout.String()
	for _, want := range []string{"secscan", server.URL, "cookie-httponly", "summary"} {
		if !strings.Contains(text, want) {
			t.Errorf("text output missing %q\n%s", want, text)
		}
	}
	if strings.Contains(text, `"by_severity"`) {
		t.Errorf("default output should be text, not raw JSON")
	}
}

func TestRunQuietSuppressesText(t *testing.T) {
	server := httptest.NewServer(labHandler())
	defer server.Close()

	var stdout, stderr bytes.Buffer
	if err := run([]string{"-quiet", server.URL}, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v (%s)", err, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("-quiet should suppress output, got %q", stdout.String())
	}
}

func TestRunRefusesNonLoopbackWithoutAuthorized(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"https://example.invalid"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("scanning an external host without -authorized must be refused")
	}
	if !strings.Contains(err.Error(), "written permission") {
		t.Errorf("unexpected refusal message: %v", err)
	}
}

func TestRunMultipleTargets(t *testing.T) {
	first := httptest.NewServer(labHandler())
	defer first.Close()
	second := httptest.NewServer(labHandler())
	defer second.Close()

	var stdout, stderr bytes.Buffer
	if err := run([]string{"-format", "json", first.URL, second.URL}, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v (%s)", err, stderr.String())
	}
	var report scanner.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if report.Summary.Targets != 2 || len(report.Targets) != 2 {
		t.Errorf("expected two targets in the report, got %+v", report.Summary)
	}
}

func TestRunRequiresTarget(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(nil, &stdout, &stderr); err == nil {
		t.Fatal("expected an error when no target is given")
	}
	if !strings.Contains(stderr.String(), "USAGE") {
		t.Errorf("usage should be printed on stderr, got %q", stderr.String())
	}
}

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"-version"}, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := strings.TrimSpace(stdout.String()); got != scanner.ToolName+" "+scanner.Version {
		t.Errorf("-version printed %q, want %q", got, scanner.ToolName+" "+scanner.Version)
	}
}

func TestRunUnknownFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"-nope", "http://127.0.0.1"}, &stdout, &stderr); err == nil {
		t.Fatal("unknown flags should be an error")
	}
}
