package scanner

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

const refTLS = "https://datatracker.ietf.org/doc/html/rfc5280"

// TLSProbe is the result of one direct TLS handshake against a target.
type TLSProbe struct {
	Details  TLSDetails
	Findings []Finding
}

// InspectTLS performs a read-only handshake to addr (host:port) and evaluates
// the certificate chain the server presents. Verification is performed
// explicitly rather than by the handshake so that an invalid chain still yields
// a reportable result instead of an error.
func InspectTLS(addr string, host string, timeout time.Duration) (*TLSProbe, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	probe := &TLSProbe{}
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("server %s completed the TLS handshake without presenting a certificate", addr)
	}

	leaf := state.PeerCertificates[0]
	now := time.Now()

	probe.Details = TLSDetails{
		Protocol:      tlsVersionName(state.Version),
		ServerName:    host,
		Issuer:        certName(leaf.Issuer),
		Subject:       certName(leaf.Subject),
		SerialNumber:  leaf.SerialNumber.String(),
		NotBefore:     leaf.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:      leaf.NotAfter.UTC().Format(time.RFC3339),
		DaysRemaining: int(time.Until(leaf.NotAfter) / (24 * time.Hour)),
		// The probe dials without handshake verification and verifies the chain
		// explicitly below, so a misissued certificate still produces a report.
		HandshakeVerificationSkipped: true,
		SANEntries:                   leaf.DNSNames,
	}

	if err := leaf.VerifyHostname(host); err != nil {
		probe.Findings = append(probe.Findings, Finding{
			Check:       "tls-hostname-mismatch",
			Severity:    SeverityHigh,
			Title:       "Certificate does not match the requested hostname",
			Detail:      fmt.Sprintf("%s", err),
			Evidence:    fmt.Sprintf("Subject: %s | DNS SANs: %s", probe.Details.Subject, strings.Join(leaf.DNSNames, ", ")),
			Remediation: "Issue or renew a certificate whose Subject Alternative Name covers the host being scanned.",
			Reference:   refTLS,
		})
	} else {
		probe.Details.HostnameValid = true
	}

	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       host,
		Intermediates: chainPool(state.PeerCertificates[1:]),
	}); err != nil {
		probe.Details.VerifyError = err.Error()
		severity := SeverityHigh
		title := "Certificate chain cannot be verified against trusted roots"
		if isSelfSigned(leaf) {
			severity = SeverityMedium
			title = "Self-signed certificate (no trusted issuer)"
		}
		probe.Findings = append(probe.Findings, Finding{
			Check:       "tls-chain-untrusted",
			Severity:    severity,
			Title:       title,
			Detail:      err.Error(),
			Evidence:    "Issuer: " + probe.Details.Issuer,
			Remediation: "Install a certificate from a public CA, or distribute your internal CA root to clients. Self-signed material is acceptable only inside an isolated lab.",
			Reference:   refTLS,
		})
	} else {
		probe.Details.ChainVerified = true
	}

	probe.Findings = append(probe.Findings, validityFindings(leaf, now)...)
	probe.Findings = append(probe.Findings, strengthFindings(leaf)...)

	if state.HandshakeComplete && len(state.PeerCertificates) > 1 {
		if intermediateNotSent(state.PeerCertificates) {
			probe.Findings = append(probe.Findings, Finding{
				Check:       "tls-intermediates",
				Severity:    SeverityLow,
				Title:       "Incomplete certificate chain served by the host",
				Detail:      "The chain contains no intermediate between leaf and root; some clients cannot fetch missing intermediates and will reject the connection.",
				Evidence:    fmt.Sprintf("chain length: %d", len(state.PeerCertificates)),
				Remediation: "Serve the full leaf + intermediate chain and leave the root out.",
				Reference:   refTLS,
			})
		}
	}

	sortFindings(probe.Findings)
	return probe, nil
}

func validityFindings(leaf *x509.Certificate, now time.Time) []Finding {
	var findings []Finding
	switch {
	case now.After(leaf.NotAfter):
		findings = append(findings, Finding{
			Check:       "tls-expired",
			Severity:    SeverityHigh,
			Title:       "Certificate is expired",
			Detail:      fmt.Sprintf("Expired at %s, which is %d day(s) ago. Browsers block the connection and users learn to click through warnings.", leaf.NotAfter.UTC().Format(time.RFC3339), int(now.Sub(leaf.NotAfter)/(24*time.Hour))),
			Evidence:    "NotAfter: " + leaf.NotAfter.UTC().Format(time.RFC3339),
			Remediation: "Renew and deploy the certificate, and add automated renewal.",
			Reference:   refTLS,
		})
	case now.Before(leaf.NotBefore):
		findings = append(findings, Finding{
			Check:       "tls-not-yet-valid",
			Severity:    SeverityHigh,
			Title:       "Certificate is not valid yet",
			Detail:      fmt.Sprintf("Validity starts at %s. Host clocks set behind that instant reject the chain.", leaf.NotBefore.UTC().Format(time.RFC3339)),
			Evidence:    "NotBefore: " + leaf.NotBefore.UTC().Format(time.RFC3339),
			Remediation: "Check server clock/NTP synchronisation, or deploy a certificate that is already inside its validity window.",
			Reference:   refTLS,
		})
	case time.Until(leaf.NotAfter) <= 30*24*time.Hour:
		findings = append(findings, Finding{
			Check:       "tls-expiring-soon",
			Severity:    SeverityMedium,
			Title:       fmt.Sprintf("Certificate expires in %d day(s)", int(time.Until(leaf.NotAfter)/(24*time.Hour))),
			Detail:      "Certificates within a month of expiry commonly lapse silently and cause outages and warning pages.",
			Evidence:    "NotAfter: " + leaf.NotAfter.UTC().Format(time.RFC3339),
			Remediation: "Renew now and automate renewal (for example ACME/certbot with a timer).",
			Reference:   refTLS,
		})
	}
	return findings
}

func strengthFindings(leaf *x509.Certificate) []Finding {
	var findings []Finding

	sig := strings.ToLower(leaf.SignatureAlgorithm.String())
	if strings.Contains(sig, "md5") || strings.Contains(sig, "sha1") {
		findings = append(findings, Finding{
			Check:       "tls-weak-signature",
			Severity:    SeverityHigh,
			Title:       fmt.Sprintf("Certificate uses the deprecated %s signature algorithm", leaf.SignatureAlgorithm.String()),
			Detail:      "MD5 and SHA-1 certificate signatures are collision-broken and are rejected by current browsers.",
			Evidence:    "SignatureAlgorithm: " + leaf.SignatureAlgorithm.String(),
			Remediation: "Reissue with SHA-256 or better.",
			Reference:   "https://cwe.mitre.org/data/definitions/327.html",
		})
	}

	switch key := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		if bits := key.N.BitLen(); bits < 2048 {
			findings = append(findings, Finding{
				Check:       "tls-weak-key",
				Severity:    SeverityHigh,
				Title:       fmt.Sprintf("RSA key is only %d bits", bits),
				Detail:      "RSA keys under 2048 bits are considered breakable with concentrated compute and fail baseline compliance checks.",
				Evidence:    fmt.Sprintf("public key algorithm: %s, size: %d bits", leaf.PublicKeyAlgorithm.String(), bits),
				Remediation: "Reissue with RSA 2048 bits or higher, or an ECDSA P-256 key.",
				Reference:   "https://cwe.mitre.org/data/definitions/326.html",
			})
		}
	case *ecdsa.PublicKey:
		if bits := key.Curve.Params().BitSize; bits < 224 {
			findings = append(findings, Finding{
				Check:       "tls-weak-key",
				Severity:    SeverityMedium,
				Title:       fmt.Sprintf("ECDSA curve provides only %d bits of security", bits),
				Detail:      "Curves below P-256 are not considered strong for TLS authentication.",
				Evidence:    fmt.Sprintf("curve size: %d bits", bits),
				Remediation: "Use P-256 (prime256v1) or P-384.",
				Reference:   "https://cwe.mitre.org/data/definitions/326.html",
			})
		}
	}

	if len(leaf.DNSNames) == 0 && leaf.Subject.CommonName == "" {
		findings = append(findings, Finding{
			Check:       "tls-no-identity",
			Severity:    SeverityMedium,
			Title:       "Certificate has no DNS SAN or Common Name",
			Detail:      "Without an identifying name the certificate cannot be matched to a host, so clients reject it.",
			Remediation: "Reissue with a Subject Alternative Name of type DNS.",
			Reference:   refTLS,
		})
	}
	return findings
}

// CheckTLSProtocolVersion reports the negotiated protocol of an HTTPS response.
func CheckTLSProtocolVersion(version uint16) []Finding {
	var findings []Finding
	switch version {
	case tls.VersionTLS10:
		findings = append(findings, Finding{
			Check:       "tls-old-protocol",
			Severity:    SeverityHigh,
			Title:       fmt.Sprintf("Negotiated legacy protocol %s", tlsVersionName(version)),
			Detail:      "SSLv3 and TLS 1.0 are deprecated and vulnerable to downgrade and padding-oracle attacks (POODLE, BEAST).",
			Evidence:    tlsVersionName(version),
			Remediation: "Disable SSLv3/TLS 1.0/1.1 on the listener; require TLS 1.2 minimum.",
			Reference:   "https://datatracker.ietf.org/doc/html/rfc8996",
		})
	case tls.VersionTLS11:
		findings = append(findings, Finding{
			Check:       "tls-old-protocol",
			Severity:    SeverityMedium,
			Title:       "Negotiated TLS 1.1",
			Detail:      "TLS 1.1 is deprecated by RFC 8996 and removed from current browser stacks.",
			Evidence:    tlsVersionName(version),
			Remediation: "Restrict the listener to TLS 1.2 and TLS 1.3.",
			Reference:   "https://datatracker.ietf.org/doc/html/rfc8996",
		})
	case tls.VersionTLS12:
		findings = append(findings, Finding{
			Check:       "tls-protocol",
			Severity:    SeverityInfo,
			Title:       "Negotiated TLS 1.2",
			Detail:      "Acceptable, but TLS 1.3 removes obsolete cipher and handshake weaknesses.",
			Evidence:    tlsVersionName(version),
			Remediation: "Enable TLS 1.3 where the server supports it.",
			Reference:   "https://datatracker.ietf.org/doc/html/rfc8446",
		})
	}
	return findings
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", version)
	}
}

func certName(name interface{ String() string }) string {
	return strings.TrimSpace(name.String())
}

func isSelfSigned(leaf *x509.Certificate) bool {
	return leaf.Issuer.String() == leaf.Subject.String()
}

func intermediateNotSent(chain []*x509.Certificate) bool {
	last := chain[len(chain)-1]
	return len(chain) == 1 && last.Subject.String() != last.Issuer.String()
}

func chainPool(intermediates []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range intermediates {
		pool.AddCert(cert)
	}
	return pool
}
