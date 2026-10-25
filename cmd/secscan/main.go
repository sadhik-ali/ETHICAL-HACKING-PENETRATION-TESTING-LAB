package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/sadhik-ali/Ethical-Hacking-Penetration-Testing-Lab/internal/scanner"
)

const usage = `secscan - passive web security header, cookie and TLS certificate checker

USAGE
  secscan [flags] <url> [more urls...]

EXAMPLES (localhost lab only)
  go run ./cmd/secscan http://127.0.0.1:8080/insecure
  go run ./cmd/secscan -out report.json http://localhost:8080/login
  go run ./cmd/labserver                      # start the vulnerable lab target

FLAGS
`

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("secscan", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprint(stderr, usage)
		flags.PrintDefaults()
		fmt.Fprintf(stderr, "\nScope rules\n"+
			"  - Loopback targets (localhost, 127.0.0.1, ::1) are always allowed.\n"+
			"  - Any other host requires -authorized, asserting written permission to test it.\n"+
			"  - This tool is passive: it reads headers, cookies and certificates only.\n")
	}

	var (
		outPath    = flags.String("out", "", "write the JSON report to this path")
		format     = flags.String("format", "text", "output format: text or json")
		timeout    = flags.Duration("timeout", 5*time.Second, "per-request timeout")
		maxHop     = flags.Int("max-redirects", 5, "maximum redirects to follow")
		authorized = flags.Bool("authorized", false, "confirm written permission to test a non-loopback target")
		note       = flags.String("note", "", "free-text scope/reference note stored in the report")
		skipTLS    = flags.Bool("skip-tls-probe", false, "skip the direct TLS handshake probe (https targets only)")
		quiet      = flags.Bool("quiet", false, "suppress the text summary")
		showVer    = flags.Bool("version", false, "print version and exit")
	)

	if err := flags.Parse(args); err != nil {
		return err
	}
	if *showVer {
		fmt.Fprintf(stdout, "%s %s\n", scanner.ToolName, scanner.Version)
		return nil
	}
	targets := flags.Args()
	if len(targets) == 0 {
		flags.Usage()
		return fmt.Errorf("no target supplied")
	}

	auth, err := scanner.Authorize(targets, *authorized, *note)
	if err != nil {
		return err
	}

	scan := scanner.New(scanner.Options{
		Timeout:      *timeout,
		MaxRedirects: *maxHop,
		SkipTLSProbe: *skipTLS,
	})

	results := make([]scanner.TargetResult, 0, len(targets))
	for _, target := range targets {
		result, err := scan.Scan(target)
		if err != nil {
			return fmt.Errorf("scan %s: %w", target, err)
		}
		results = append(results, result)
	}

	report := scanner.BuildReport(results, auth)

	if *format == "json" {
		data, err := report.Marshal()
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, string(data))
	} else if !*quiet {
		fmt.Fprint(stdout, report.RenderText())
	}

	if *outPath != "" {
		if _, err := report.Write(*outPath); err != nil {
			return err
		}
		// Keep stdout a single clean document in JSON mode.
		statusOut := stderr
		if *format != "json" && !*quiet {
			statusOut = stdout
		}
		if !*quiet {
			fmt.Fprintf(statusOut, "\nJSON report written to %s\n", *outPath)
		}
	}
	return nil
}
