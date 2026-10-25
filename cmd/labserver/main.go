package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const labUsage = `labserver - intentionally weak local target for practising secscan

USAGE
  go run ./cmd/labserver [-addr 127.0.0.1:8080] [-https]

ROUTES
  /                hardened reference page (correct headers and cookies)
  /insecure        missing every security header, version banners on
  /login           session cookie with no HttpOnly / Secure / SameSite
  /redirect        drops security headers while bouncing to /insecure
  /bad-csp         CSP present but useless (unsafe-inline + unsafe-eval)

The server binds to loopback unless -allow-non-loopback is passed, because an
intentionally vulnerable target must never be reachable by other machines.
`

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "address to listen on")
	useTLS := flag.Bool("https", false, "serve TLS with an ephemeral self-signed certificate")
	expose := flag.Bool("allow-non-loopback", false, "permit binding outside loopback (not recommended)")
	flag.Usage = func() { fmt.Fprint(os.Stderr, labUsage) }
	flag.Parse()

	if err := guardBind(*addr, *expose); err != nil {
		log.Fatal(err)
	}

	mux := buildMux()

	scheme, server := "http", &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	if *useTLS {
		cert, err := selfSignedCert()
		if err != nil {
			log.Fatal(err)
		}
		server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{*cert}}
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s/", scheme, *addr)
	log.Printf("lab target listening on %s (ctrl-c to stop)", url)
	log.Printf("try: go run ./cmd/secscan %s%s", url, "insecure")

	if *useTLS {
		if err := server.ListenAndServeTLS("", ""); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func buildMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", home)
	mux.HandleFunc("/insecure", insecure)
	mux.HandleFunc("/login", login)
	mux.HandleFunc("/redirect", redirect)
	mux.HandleFunc("/bad-csp", badCSP)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	return mux
}

func guardBind(addr string, expose bool) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid -addr %q: %w", addr, err)
	}
	if port == "" {
		return fmt.Errorf("invalid -addr %q: port is required", addr)
	}
	if host == "0.0.0.0" || host == "" || host == "::" || !isLoopbackHost(host) {
		if !expose {
			return fmt.Errorf("refusing to bind %q: this target is deliberately vulnerable.\n"+
				"Use -addr 127.0.0.1:8080, or -allow-non-loopback if you really mean to expose it.", addr)
		}
		log.Printf("WARNING: serving a deliberately vulnerable target on %s", addr)
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func home(w http.ResponseWriter, _ *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'")
	h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	h.Set("Cache-Control", "no-store")
	h.Set("Server", "labserver")
	writePage(w, "hardened reference page", "Every check in this lab should pass or report only informational findings here.")
}

func insecure(w http.ResponseWriter, _ *http.Request) {
	h := w.Header()
	h.Set("Server", "Apache/2.4.41 (Ubuntu)")
	h.Set("X-Powered-By", "PHP/7.4.3")
	writePage(w, "insecure page", "No security headers at all, plus software version banners for fingerprinting.")
}

func login(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Server", "nginx/1.18.0")
	h.Set("X-Powered-By", "Express")
	// Deliberately unsafe: readable by JavaScript, sent over plaintext, cross-site.
	http.SetCookie(w, &http.Cookie{Name: "session_id", Value: "abc123def456", Path: "/", Domain: "localhost"})
	http.SetCookie(w, &http.Cookie{Name: "remember_me", Value: "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.", Path: "/"})
	http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: "deadbeef", SameSite: http.SameSiteNoneMode})
	writePage(w, "login page", "Three cookies are set here: session_id, remember_me and csrf_token.")
}

func redirect(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "tracking", Value: "seen-1", Path: "/"})
	http.Redirect(w, r, "/insecure", http.StatusFound)
}

func badCSP(w http.ResponseWriter, _ *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval'")
	h.Set("X-Content-Type-Options", "nosniff; charset=utf-8")
	h.Set("Strict-Transport-Security", "max-age=60")
	h.Set("X-Frame-Options", "ALLOWALL")
	writePage(w, "misconfigured CSP page", "The headers exist, but each one is weakened or malformed.")
}

func writePage(w http.ResponseWriter, title, blurb string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<!doctype html><html><head><title>%s</title></head><body><h1>%s</h1><p>%s</p></body></html>\n", title, title, blurb)
}

// selfSignedCert builds a throwaway certificate valid for localhost/127.0.0.1.
// It is intentionally short-lived so the scanner reports an expiring-soon finding.
func selfSignedCert() (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "secscan-lab", Organization: []string{"Ethical Hacking Lab"}},
		Issuer:                pkix.Name{CommonName: "secscan-lab", Organization: []string{"Ethical Hacking Lab"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(72 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
