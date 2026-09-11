//go:build !linux

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestUnsupportedServerPlatformRefusesBeforeReadiness(t *testing.T) {
	var output bytes.Buffer
	err := runWithContext(nil, &output, syncOpenedDirectory, context.Background())
	if err == nil || !strings.Contains(err.Error(), "supports Linux only") {
		t.Fatalf("unsupported-platform error = %v, want explicit Linux-only refusal", err)
	}
	if output.Len() != 0 {
		t.Fatalf("unsupported platform emitted readiness: %s", output.String())
	}
}
