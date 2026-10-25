package scanner

import (
	"strings"
	"testing"
)

func TestAuthorizeRejectsNonLoopbackWithoutConfirmation(t *testing.T) {
	_, err := Authorize([]string{"https://shop.customer.example"}, false, "")
	if err == nil {
		t.Fatal("expected a non-loopback target to be refused without -authorized")
	}
	if !strings.Contains(err.Error(), "written permission") {
		t.Errorf("error should explain the permission rule, got: %v", err)
	}
}

func TestAuthorizeAcceptsNonLoopbackWithConfirmation(t *testing.T) {
	auth, err := Authorize([]string{"https://shop.customer.example", "http://127.0.0.1:8080/"}, true, "engagement 2026-10, signed scope PDF")
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if auth.LoopbackOnly {
		t.Errorf("LoopbackOnly must be false once an external host is in scope")
	}
	if !auth.Confirmed || auth.OperatorNote == "" {
		t.Errorf("confirmation and note must be recorded: %+v", auth)
	}
	if len(auth.Targets) != 2 {
		t.Errorf("Targets = %v, want both entries", auth.Targets)
	}
}

func TestAuthorizeValidatesInput(t *testing.T) {
	cases := []struct {
		name    string
		targets []string
	}{
		{"no targets", nil},
		{"missing scheme", []string{"127.0.0.1:8080"}},
		{"unsupported scheme", []string{"ftp://127.0.0.1/files"}},
		{"no host", []string{"http://"}},
		{"mixed valid and invalid", []string{"http://127.0.0.1:8080", "gopher://127.0.0.1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Authorize(tc.targets, true, ""); err == nil {
				t.Errorf("Authorize(%v) should fail", tc.targets)
			}
		})
	}
}

func TestAuthorizeNormalisesTargets(t *testing.T) {
	auth, err := Authorize([]string{"  http://LOCALHOST:8080/insecure  "}, false, "  ")
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if auth.Targets[0] != "http://LOCALHOST:8080/insecure" {
		t.Errorf("target = %q, want surrounding spaces trimmed", auth.Targets[0])
	}
	if auth.OperatorNote != "" {
		t.Errorf("blank note should be normalised to empty, got %q", auth.OperatorNote)
	}
	if !auth.LoopbackOnly {
		t.Errorf("localhost must count as loopback")
	}
}
