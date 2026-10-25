package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// ToolName and Version appear in every generated report.
	ToolName = "secscan"
	Version  = "0.1.0"
)

// UserAgent identifies the tool in request headers.
const UserAgent = "secscan/" + Version + " (ethical-hacking-lab; passive header check)"

// Options controls one scan run.
type Options struct {
	Timeout      time.Duration
	MaxRedirects int
	SkipTLSProbe bool
}

// DefaultOptions suits localhost lab targets.
func DefaultOptions() Options {
	return Options{Timeout: 5 * time.Second, MaxRedirects: 5}
}

// Scanner performs passive HTTP/TLS inspection. It never submits payloads,
// fuzzes parameters, or attempts authentication.
type Scanner struct {
	opts Options
}

// New builds a Scanner with validated options.
func New(opts Options) *Scanner {
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.MaxRedirects < 0 {
		opts.MaxRedirects = 5
	}
	return &Scanner{opts: opts}
}

// Scan fetches target and runs every check against the response.
func (s *Scanner) Scan(target string) (TargetResult, error) {
	parsed, err := url.Parse(strings.TrimSpace(target))
	if err != nil {
		return TargetResult{}, fmt.Errorf("invalid target %q: %w", target, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return TargetResult{}, fmt.Errorf("target %q must use http:// or https://", target)
	}
	if parsed.Host == "" {
		return TargetResult{}, fmt.Errorf("target %q has no host", target)
	}

	result := TargetResult{
		URL:        parsed.String(),
		Method:     http.MethodGet,
		AccessedAt: time.Now().UTC().Format(time.RFC3339),
		Findings:   []Finding{},
	}
	started := time.Now()

	client := &http.Client{
		Timeout: s.opts.Timeout,
		Jar:     nil,
		Transport: &http.Transport{
			// Certificate trust is judged by the TLS probe, which verifies hostname,
			// chain, expiry and key strength explicitly. Accepting untrusted
			// certificates here is what lets a pen tester still read the headers of
			// a misissued host instead of returning nothing.
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10},
			DisableKeepAlives:   true,
			MaxIdleConnsPerHost: -1,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	current := parsed
	var seenRedirects []*http.Response
	for hops := 0; hops <= s.opts.MaxRedirects; hops++ {
		resp, err := s.fetch(client, hops, current)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("request to %s failed: %v", current, err))
			result.Findings = append(result.Findings, unreachableFinding(current, err, time.Since(started)))
			break
		}
		if hops == s.opts.MaxRedirects && isRedirect(resp) {
			result.Errors = append(result.Errors, fmt.Sprintf("stopped after %d redirects at %s", s.opts.MaxRedirects, current))
			resp.Body.Close()
			break
		}
		// Headers are fully buffered by client.Do, so the body is discarded here;
		// this tool never reads response content.
		resp.Body.Close()
		seenRedirects = append(seenRedirects, resp)
		if !isRedirect(resp) {
			current = resp.Request.URL
			break
		}
		next, err := resp.Location()
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("redirect from %s has an unusable Location: %v", resp.Request.URL, err))
			current = resp.Request.URL
			break
		}
		current = next
	}

	if len(seenRedirects) > 0 {
		last := seenRedirects[len(seenRedirects)-1]
		result.FinalURL = last.Request.URL.String()
		result.StatusCode = last.StatusCode
		result.ResponseHeader = last.Header.Clone()
		for _, resp := range seenRedirects {
			result.SetCookies = append(result.SetCookies, resp.Header["Set-Cookie"]...)
		}
	}

	usesTLS := current.Scheme == "https"
	ctx := HeaderContext{UsesTLS: usesTLS}
	if last := latestResponse(seenRedirects); last != nil {
		result.Findings = append(result.Findings, CheckHeaders(last, ctx)...)
	}
	result.Findings = append(result.Findings, CheckCookies(result.SetCookies, current.Scheme, current.Hostname())...)
	result.Findings = append(result.Findings, transportFindings(current, usesTLS)...)

	if usesTLS {
		if last := latestResponse(seenRedirects); last != nil && last.TLS != nil {
			result.Findings = append(result.Findings, CheckTLSProtocolVersion(last.TLS.Version)...)
		}
		if !s.opts.SkipTLSProbe {
			s.probeTLS(&result, current)
		}
	}

	result.ElapsedMillis = time.Since(started).Milliseconds()
	sortFindings(result.Findings)
	return result, nil
}

func (s *Scanner) fetch(client *http.Client, hops int, where *url.URL) (*http.Response, error) {
	// client.Timeout bounds the whole exchange, so the request context is not
	// cancelled here: cancelling would abort the still-open response body.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, where.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "*/*")
	if hops == 0 {
		req.Header.Set("Cache-Control", "no-cache")
	}
	return client.Do(req)
}

func (s *Scanner) probeTLS(result *TargetResult, where *url.URL) {
	host := where.Port()
	if host == "" {
		host = "443"
	}
	addr := net.JoinHostPort(where.Hostname(), host)
	probe, err := InspectTLS(addr, where.Hostname(), s.opts.Timeout)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("tls probe of %s failed: %v", addr, err))
		result.Findings = append(result.Findings, Finding{
			Check:       "tls-handshake",
			Severity:    SeverityMedium,
			Title:       "TLS handshake failed or was refused",
			Detail:      err.Error(),
			Evidence:    addr,
			Remediation: "Confirm the listener requires TLS 1.2 or newer and presents a certificate for this host.",
			Reference:   "https://datatracker.ietf.org/doc/html/rfc8446",
		})
		return
	}
	result.TLS = &probe.Details
	result.Findings = append(result.Findings, probe.Findings...)
}

func transportFindings(where *url.URL, usesTLS bool) []Finding {
	if usesTLS {
		return nil
	}
	return []Finding{{
		Check:       "plain-http",
		Severity:    SeverityHigh,
		Title:       "Target served over unencrypted HTTP",
		Detail:      fmt.Sprintf("Content fetched from %s travels in plaintext: credentials, session cookies and page data are readable by anyone on the path.", where),
		Evidence:    where.String(),
		Remediation: "Serve the site over HTTPS only and redirect HTTP to HTTPS with 301.",
		Reference:   "https://owasp.org/www-project-top-ten/",
	}}
}

func unreachableFinding(where *url.URL, err error, elapsed time.Duration) Finding {
	return Finding{
		Check:       "reachability",
		Severity:    SeverityInfo,
		Title:       "Target did not respond to the inspection request",
		Detail:      fmt.Sprintf("%v after %s", err, elapsed.Round(time.Millisecond)),
		Evidence:    where.String(),
		Remediation: "Start the lab target (see README) or check the URL, port and firewall rules.",
	}
}

func latestResponse(responses []*http.Response) *http.Response {
	if len(responses) == 0 {
		return nil
	}
	return responses[len(responses)-1]
}

func isRedirect(resp *http.Response) bool {
	return resp.StatusCode >= 301 && resp.StatusCode <= 308 && resp.Header.Get("Location") != ""
}

// IsLoopback reports whether host addresses only this machine.
func IsLoopback(host string) bool {
	host = strings.TrimSpace(strings.Trim(strings.TrimPrefix(host, "["), "]"))
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
