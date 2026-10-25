package scanner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestInspectTLSTestServerCertificate(t *testing.T) {
	server := httptest.NewTLSServer(handlerHardened())
	defer server.Close()

	// httptest binds 127.0.0.1, so this probe never leaves the machine.
	addr := strings.TrimPrefix(server.URL, "https://")
	probe, err := InspectTLS(addr, "127.0.0.1", 5*time.Second)
	if err != nil {
		t.Fatalf("InspectTLS: %v", err)
	}

	if !probe.Details.HostnameValid {
		t.Errorf("expected the test certificate to cover 127.0.0.1, details: %+v", probe.Details)
	}
	if probe.Details.ChainVerified {
		t.Errorf("the httptest certificate is self-signed and must not verify against system roots")
	}
	if probe.Details.NotAfter == "" || probe.Details.SerialNumber == "" || probe.Details.Issuer == "" {
		t.Errorf("certificate metadata missing: %+v", probe.Details)
	}
	if probe.Details.DaysRemaining < 0 {
		t.Errorf("DaysRemaining = %d, want a future expiry", probe.Details.DaysRemaining)
	}

	got := checksIn(probe.Findings)
	finding, ok := got["tls-chain-untrusted"]
	if !ok {
		t.Fatalf("expected a tls-chain-untrusted finding, got %+v", probe.Findings)
	}
	if finding.Severity != SeverityMedium {
		t.Errorf("self-signed certificate severity = %q, want %q", finding.Severity, SeverityMedium)
	}
	if probe.Details.VerifyError == "" {
		t.Errorf("VerifyError should record why the chain was rejected")
	}
}

func TestInspectTLSHostnameMismatch(t *testing.T) {
	server := httptest.NewTLSServer(handlerHardened())
	defer server.Close()

	addr := strings.TrimPrefix(server.URL, "https://")
	probe, err := InspectTLS(addr, "unlisted-host.example", 5*time.Second)
	if err != nil {
		t.Fatalf("InspectTLS: %v", err)
	}
	got := checksIn(probe.Findings)
	if got["tls-hostname-mismatch"].Severity != SeverityHigh {
		t.Fatalf("expected a high tls-hostname-mismatch finding, got %+v", probe.Findings)
	}
	if probe.Details.HostnameValid {
		t.Errorf("HostnameValid must be false on a mismatch")
	}
}

func TestInspectTLSRefusesNonTLSPort(t *testing.T) {
	server := httptest.NewServer(handlerHardened())
	defer server.Close()

	if _, err := InspectTLS(strings.TrimPrefix(server.URL, "http://"), "127.0.0.1", 2*time.Second); err == nil {
		t.Fatalf("expected an error probing a plaintext listener")
	}
}

func TestValidityFindings(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
		wantCheck string
		wantSev   string
	}{
		{"expired", now.Add(-400 * 24 * time.Hour), now.Add(-24 * time.Hour), "tls-expired", SeverityHigh},
		{"not yet valid", now.Add(24 * time.Hour), now.Add(300 * 24 * time.Hour), "tls-not-yet-valid", SeverityHigh},
		{"expiring soon", now.Add(-time.Hour), now.Add(30 * 24 * time.Hour), "tls-expiring-soon", SeverityMedium},
		{"long lived", now.Add(-time.Hour), now.Add(400 * 24 * time.Hour), "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert := &x509.Certificate{
				Subject:            pkix.Name{CommonName: "lab.example"},
				DNSNames:           []string{"lab.example"},
				NotBefore:          tc.notBefore,
				NotAfter:           tc.notAfter,
				PublicKeyAlgorithm: x509.ECDSA,
				PublicKey:          &ecdsa.PublicKey{Curve: elliptic.P256()},
				SignatureAlgorithm: x509.ECDSAWithSHA256,
			}
			findings := checksIn(validityFindings(cert, now))
			if tc.wantCheck == "" {
				if len(findings) != 0 {
					t.Fatalf("expected no validity findings, got %+v", findings)
				}
				return
			}
			if findings[tc.wantCheck].Severity != tc.wantSev {
				t.Fatalf("check %q severity = %q, want %q (got %+v)", tc.wantCheck, findings[tc.wantCheck].Severity, tc.wantSev, findings)
			}
		})
	}
}

func TestStrengthFindings(t *testing.T) {
	cases := []struct {
		name      string
		cert      *x509.Certificate
		wantCheck string
	}{
		{
			name:      "rsa 1024 is weak",
			cert:      signedCert(x509.SHA256WithRSA, &rsa.PublicKey{N: bits(1024)}),
			wantCheck: "tls-weak-key",
		},
		{
			name:      "rsa 2048 is acceptable",
			cert:      signedCert(x509.SHA256WithRSA, &rsa.PublicKey{N: bits(2048)}),
			wantCheck: "",
		},
		{
			name:      "sha1 signature is deprecated",
			cert:      signedCert(x509.SHA1WithRSA, &rsa.PublicKey{N: bits(2048)}),
			wantCheck: "tls-weak-signature",
		},
		{
			name:      "md5 signature is deprecated",
			cert:      signedCert(x509.MD5WithRSA, &rsa.PublicKey{N: bits(2048)}),
			wantCheck: "tls-weak-signature",
		},
		{
			name:      "ecdsa p256 is acceptable",
			cert:      signedCert(x509.ECDSAWithSHA256, &ecdsa.PublicKey{Curve: elliptic.P256()}),
			wantCheck: "",
		},
		{
			name:      "certificate with no identity",
			cert:      &x509.Certificate{PublicKey: &ecdsa.PublicKey{Curve: elliptic.P256()}, SignatureAlgorithm: x509.ECDSAWithSHA256},
			wantCheck: "tls-no-identity",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			found := checksIn(strengthFindings(tc.cert))
			if tc.wantCheck == "" {
				if len(found) != 0 {
					t.Fatalf("expected no strength findings, got %+v", found)
				}
				return
			}
			if _, ok := found[tc.wantCheck]; !ok {
				t.Fatalf("expected %s, got %+v", tc.wantCheck, found)
			}
		})
	}
}

func TestCheckTLSProtocolVersion(t *testing.T) {
	cases := []struct {
		version   uint16
		wantSev   string
		wantCheck string
	}{
		{tls.VersionTLS10, SeverityHigh, "tls-old-protocol"},
		{tls.VersionTLS11, SeverityMedium, "tls-old-protocol"},
		{tls.VersionTLS12, SeverityInfo, "tls-protocol"},
		{tls.VersionTLS13, "", ""},
	}
	for _, tc := range cases {
		findings := checksIn(CheckTLSProtocolVersion(tc.version))
		if tc.wantCheck == "" {
			if len(findings) != 0 {
				t.Errorf("version 0x%04x: expected no findings, got %+v", tc.version, findings)
			}
			continue
		}
		if findings[tc.wantCheck].Severity != tc.wantSev {
			t.Errorf("version 0x%04x: %s severity = %q, want %q", tc.version, tc.wantCheck, findings[tc.wantCheck].Severity, tc.wantSev)
		}
	}
}

func TestTLSVersionName(t *testing.T) {
	cases := map[uint16]string{
		tls.VersionTLS10: "TLS 1.0",
		tls.VersionTLS11: "TLS 1.1",
		tls.VersionTLS12: "TLS 1.2",
		tls.VersionTLS13: "TLS 1.3",
		0x0099:           "unknown (0x0099)",
	}
	for version, want := range cases {
		if got := tlsVersionName(version); got != want {
			t.Errorf("tlsVersionName(0x%04x) = %q, want %q", version, got, want)
		}
	}
}

func signedCert(alg x509.SignatureAlgorithm, key any) *x509.Certificate {
	return &x509.Certificate{
		Subject:            pkix.Name{CommonName: "lab.example"},
		Issuer:             pkix.Name{CommonName: "lab-ca"},
		DNSNames:           []string{"lab.example"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(365 * 24 * time.Hour),
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          key,
		SignatureAlgorithm: alg,
	}
}

func bits(size int) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(size-1))
}
