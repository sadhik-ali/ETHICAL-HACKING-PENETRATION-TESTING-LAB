package scanner

import (
	"fmt"
	"net/url"
	"strings"
)

// Authorize validates that a scan may proceed and returns the statement to
// embed in the report. Loopback targets are always allowed because they can only
// reach this machine; anything else requires the operator to confirm written
// permission with the -authorized flag.
func Authorize(rawTargets []string, confirmed bool, note string) (Authorization, error) {
	auth := Authorization{
		OperatorNote: strings.TrimSpace(note),
		Targets:      make([]string, 0, len(rawTargets)),
		Confirmed:    confirmed,
		LoopbackOnly: true,
	}
	if len(rawTargets) == 0 {
		return auth, fmt.Errorf("no target supplied")
	}

	var external []string
	for _, raw := range rawTargets {
		parsed, err := url.Parse(strings.TrimSpace(raw))
		if err != nil {
			return auth, fmt.Errorf("invalid target %q: %w", raw, err)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return auth, fmt.Errorf("target %q must use http:// or https://", raw)
		}
		if parsed.Host == "" {
			return auth, fmt.Errorf("target %q has no host", raw)
		}
		auth.Targets = append(auth.Targets, parsed.String())
		host := parsed.Hostname()
		if !IsLoopback(host) {
			auth.LoopbackOnly = false
			external = append(external, host)
		}
	}

	if !auth.LoopbackOnly && !confirmed {
		return auth, fmt.Errorf("refusing to scan non-loopback target(s): %s\n\n"+
			"Only test systems you own or have written permission to assess.\n"+
			"Re-run with -authorized to confirm that permission, or use -h to see the scope rules.",
			strings.Join(external, ", "))
	}
	return auth, nil
}
