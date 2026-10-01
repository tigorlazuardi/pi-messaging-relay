//go:build linux

package acceptance_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestRelayRejectsFIFOSecretFileWithoutBlocking(t *testing.T) {
	binary := buildRelay(t)
	stateDirectory := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(stateDirectory, 0o700); err != nil {
		t.Fatalf("create state directory: %v", err)
	}
	secretPath := filepath.Join(stateDirectory, "relay.secret")
	if err := unix.Mkfifo(secretPath, 0o600); err != nil {
		t.Fatalf("create secret FIFO: %v", err)
	}
	if err := os.Chmod(secretPath, 0o600); err != nil {
		t.Fatalf("set secret FIFO permissions: %v", err)
	}

	command := exec.Command(binary, "--state-dir", stateDirectory, "--secret-file", secretPath)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start relay: %v", err)
	}
	waiter := newProcessWaiter(command)
	t.Cleanup(func() {
		if err := waiter.terminate(acceptanceTimeout); err != nil {
			t.Errorf("clean up relay process: %v", err)
		}
	})

	const startupDeadline = 2 * time.Second
	waitErr, exited := waiter.wait(startupDeadline)
	if !exited {
		killErr := waiter.terminate(acceptanceTimeout)
		t.Fatalf("relay blocked on secret FIFO beyond %s; kill result: %v", startupDeadline, killErr)
	}
	if waitErr == nil {
		t.Fatal("relay accepted a secret FIFO; want exit code 1")
	}
	var exitErr *exec.ExitError
	if !errors.As(waitErr, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("relay FIFO startup result = %v, want exit code 1", waitErr)
	}
	if strings.Contains(stdout.String(), `"event":"server_ready"`) {
		t.Fatalf("relay reported readiness for secret FIFO: %s", stdout.String())
	}

	var event processEvent
	if err := json.Unmarshal(bytes.TrimSpace(stderr.Bytes()), &event); err != nil {
		t.Fatalf("decode FIFO startup failure event %q: %v", stderr.String(), err)
	}
	if event.Level != "error" || event.Event != "server_failed" ||
		!strings.Contains(event.Reason, "regular file") {
		t.Fatalf("FIFO startup failure is not actionable: %+v", event)
	}
}
