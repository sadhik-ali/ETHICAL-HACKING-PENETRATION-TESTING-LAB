package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Severity levels used by every check in this package.
const (
	SeverityInfo   = "info"
	SeverityLow    = "low"
	SeverityMedium = "medium"
	SeverityHigh   = "high"
)

// Finding is a single observation about a target, phrased so it can go straight
// into a report without further editing.
type Finding struct {
	Check       string `json:"check"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Detail      string `json:"detail"`
	Evidence    string `json:"evidence,omitempty"`
	Remediation string `json:"remediation,omitempty"`
	Reference   string `json:"reference,omitempty"`
}

// TLSDetails describes what the TLS layer of an HTTPS response looked like.
type TLSDetails struct {
	Protocol      string `json:"protocol"`
	ServerName    string `json:"server_name"`
	Issuer        string `json:"issuer"`
	Subject       string `json:"subject"`
	SerialNumber  string `json:"serial_number"`
	NotBefore     string `json:"not_before"`
	NotAfter      string `json:"not_after"`
	DaysRemaining int    `json:"days_remaining"`
	HostnameValid bool   `json:"hostname_valid"`
	ChainVerified bool   `json:"chain_verified"`
	// HandshakeVerificationSkipped is always true for probes: verification is
	// performed explicitly by the probe so unusable certificates can still be
	// described in the report instead of aborting the scan.
	HandshakeVerificationSkipped bool     `json:"handshake_verification_skipped"`
	SANEntries                   []string `json:"san_entries,omitempty"`
	VerifyError                  string   `json:"verify_error,omitempty"`
}

// TargetResult holds everything observed for one URL.
type TargetResult struct {
	URL            string              `json:"url"`
	FinalURL       string              `json:"final_url"`
	Method         string              `json:"method"`
	StatusCode     int                 `json:"status_code"`
	AccessedAt     string              `json:"accessed_at"`
	ElapsedMillis  int64               `json:"elapsed_ms"`
	TLS            *TLSDetails         `json:"tls,omitempty"`
	ResponseHeader map[string][]string `json:"response_headers,omitempty"`
	SetCookies     []string            `json:"set_cookie_headers,omitempty"`
	Findings       []Finding           `json:"findings"`
	Errors         []string            `json:"errors,omitempty"`
}

// Summary is the count-based headline of a report.
type Summary struct {
	Targets     int            `json:"targets"`
	Findings    int            `json:"findings"`
	BySeverity  map[string]int `json:"by_severity"`
	ByCheck     map[string]int `json:"by_check"`
	HighestRisk string         `json:"highest_severity"`
	Errors      int            `json:"errors"`
}

// Report is the JSON document written by -out.
type Report struct {
	Tool          string         `json:"tool"`
	Version       string         `json:"version"`
	GeneratedAt   string         `json:"generated_at"`
	ScopeNote     string         `json:"scope_note"`
	Authorization Authorization  `json:"authorization"`
	Summary       Summary        `json:"summary"`
	Targets       []TargetResult `json:"targets"`
}

// Authorization records what the operator asserted about the scan scope, so an
// exported report always carries its own permission statement.
type Authorization struct {
	LoopbackOnly bool     `json:"loopback_only"`
	Confirmed    bool     `json:"written_permission_confirmed"`
	OperatorNote string   `json:"operator_note,omitempty"`
	Targets      []string `json:"targets"`
}

const scopeNote = "Passive, non-intrusive inspection of HTTP response headers, cookies and TLS certificates. " +
	"No exploitation, fuzzing, credential testing, port scanning or denial-of-service behaviour. " +
	"Point it only at systems you own or have written permission to test."

var severityRank = map[string]int{
	SeverityHigh:   0,
	SeverityMedium: 1,
	SeverityLow:    2,
	SeverityInfo:   3,
}

func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		left, right := severityRank[findings[i].Severity], severityRank[findings[j].Severity]
		if left != right {
			return left < right
		}
		return findings[i].Check < findings[j].Check
	})
}

// BuildReport assembles the JSON document, including the severity summary.
func BuildReport(results []TargetResult, auth Authorization) Report {
	summary := Summary{
		Targets:     len(results),
		BySeverity:  map[string]int{},
		ByCheck:     map[string]int{},
		HighestRisk: "none",
	}
	for _, result := range results {
		summary.Findings += len(result.Findings)
		summary.Errors += len(result.Errors)
		for _, finding := range result.Findings {
			summary.BySeverity[finding.Severity]++
			summary.ByCheck[finding.Check]++
		}
	}
	for _, level := range []string{SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo} {
		if summary.BySeverity[level] > 0 {
			summary.HighestRisk = level
			break
		}
	}
	return Report{
		Tool:          ToolName,
		Version:       Version,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		ScopeNote:     scopeNote,
		Authorization: auth,
		Summary:       summary,
		Targets:       results,
	}
}

// Marshal renders a report as indented JSON for file or stdout output.
func (r Report) Marshal() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// Write saves the report as JSON and returns the encoded bytes.
func (r Report) Write(path string) ([]byte, error) {
	data, err := r.Marshal()
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return nil, fmt.Errorf("write report %s: %w", path, err)
	}
	return data, nil
}

// RenderText produces the human-readable terminal view of a report.
func (r Report) RenderText() string {
	var out strings.Builder
	fmt.Fprintf(&out, "%s v%s - passive web security check\n", r.Tool, r.Version)
	fmt.Fprintf(&out, "generated: %s\n", r.GeneratedAt)
	fmt.Fprintf(&out, "authorization: targets=%s, loopback-only=%t, written-permission=%t\n",
		strings.Join(r.Authorization.Targets, ", "), r.Authorization.LoopbackOnly, r.Authorization.Confirmed)
	fmt.Fprintf(&out, "scope: %s\n", r.ScopeNote)

	for _, target := range r.Targets {
		fmt.Fprintf(&out, "\n=== %s\n", target.URL)
		fmt.Fprintf(&out, "    final url:    %s (HTTP %d, %d ms)\n", target.FinalURL, target.StatusCode, target.ElapsedMillis)
		if target.TLS != nil {
			fmt.Fprintf(&out, "    tls:          %s, subject=%s, issuer=%s, valid to %s (%d days), chain-verified=%t\n",
				target.TLS.Protocol, target.TLS.Subject, target.TLS.Issuer, target.TLS.NotAfter,
				target.TLS.DaysRemaining, target.TLS.ChainVerified)
			if target.TLS.HandshakeVerificationSkipped {
				fmt.Fprintln(&out, "    note:         certificate trust was evaluated by the probe, not the browser-style handshake")
			}
		}
		for _, message := range target.Errors {
			fmt.Fprintf(&out, "    error:        %s\n", message)
		}
		if len(target.Findings) == 0 {
			fmt.Fprintln(&out, "    no findings")
			continue
		}
		fmt.Fprintf(&out, "    findings:     %d\n", len(target.Findings))
		for _, finding := range target.Findings {
			fmt.Fprintf(&out, "      [%-6s] %s\n", strings.ToUpper(finding.Severity), finding.Title)
			fmt.Fprintf(&out, "                 check: %s | %s\n", finding.Check, finding.Detail)
			if finding.Evidence != "" {
				fmt.Fprintf(&out, "                 evidence: %s\n", finding.Evidence)
			}
			if finding.Remediation != "" {
				fmt.Fprintf(&out, "                 fix: %s\n", finding.Remediation)
			}
		}
	}

	fmt.Fprintf(&out, "\n--- summary: %d target(s), %d finding(s), highest severity: %s\n",
		r.Summary.Targets, r.Summary.Findings, r.Summary.HighestRisk)
	for _, level := range []string{SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo} {
		fmt.Fprintf(&out, "    %-6s %d\n", level, r.Summary.BySeverity[level])
	}
	return out.String()
}
