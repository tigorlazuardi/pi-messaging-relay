package acceptance_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

const acceptanceTimeout = 10 * time.Second

type processEvent struct {
	Level    string `json:"level"`
	Event    string `json:"event"`
	Address  string `json:"address"`
	StateDir string `json:"state_dir"`
	Result   string `json:"result"`
	Reason   string `json:"reason"`
}

func TestRelayProcessLifecycle(t *testing.T) {
	binary := buildRelay(t)

	stateDirectories := make(map[string]string)
	for _, testCase := range []struct {
		name   string
		signal os.Signal
	}{
		{name: "SIGINT", signal: os.Interrupt},
		{name: "SIGTERM", signal: syscall.SIGTERM},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			stateDirectories[testCase.name] = assertGracefulLifecycle(t, binary, testCase.signal)
		})
	}
	sigintStateDirectory, ranSIGINT := stateDirectories["SIGINT"]
	sigtermStateDirectory, ranSIGTERM := stateDirectories["SIGTERM"]
	if ranSIGINT && ranSIGTERM && sigintStateDirectory == sigtermStateDirectory {
		t.Fatalf("relay processes shared temporary state directory %q", sigintStateDirectory)
	}

	t.Run("rejects non-loopback listen address", func(t *testing.T) {
		contextDeadline := time.Now().Add(acceptanceTimeout)
		command := exec.Command(binary, "--listen", "0.0.0.0:0")
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
		waitErr := waitUntil(t, waiter, time.Until(contextDeadline))
		if waitErr == nil {
			t.Fatal("relay accepted a non-loopback listen address; want exit code 1")
		}
		var exitErr *exec.ExitError
		if !errors.As(waitErr, &exitErr) {
			t.Fatalf("relay failed without an exit status for non-loopback address; want exit code 1: %v", waitErr)
		}
		if exitErr.ExitCode() != 1 {
			t.Fatalf("relay exited with code %d for non-loopback address; want 1: %v", exitErr.ExitCode(), waitErr)
		}
		if strings.Contains(stdout.String(), `"event":"server_ready"`) {
			t.Fatalf("relay reported readiness for non-loopback address: %s", stdout.String())
		}

		var event processEvent
		if err := json.Unmarshal(bytes.TrimSpace(stderr.Bytes()), &event); err != nil {
			t.Fatalf("decode startup failure event %q: %v", stderr.String(), err)
		}
		if event.Event != "server_failed" || !strings.Contains(event.Reason, "loopback") {
			t.Fatalf("unexpected startup failure event: %+v", event)
		}
	})
}

func assertGracefulLifecycle(t *testing.T, binary string, terminationSignal os.Signal) string {
	t.Helper()

	stateParent := t.TempDir()
	command := exec.Command(binary)
	command.Env = append(
		command.Environ(),
		"TMPDIR="+stateParent,
		"TMP="+stateParent,
		"TEMP="+stateParent,
	)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("capture relay stdout: %v", err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start relay: %v", err)
	}
	waiter := newProcessWaiter(command)
	// t.TempDir registered parent removal before this cleanup. LIFO cleanup
	// therefore terminates and reaps the child before removing its state parent.
	t.Cleanup(func() {
		if err := waiter.terminate(acceptanceTimeout); err != nil {
			t.Errorf("clean up relay process: %v", err)
		}
	})

	scanner := bufio.NewScanner(stdout)
	ready := readEvent(t, scanner, acceptanceTimeout)
	if err := validateTestStateDirectory(ready.StateDir, stateParent); err != nil {
		t.Fatalf("readiness state directory %q is invalid: %v", ready.StateDir, err)
	}
	if ready.Level != "info" || ready.Event != "server_ready" {
		t.Fatalf("unexpected readiness event: %+v", ready)
	}
	host, _, err := net.SplitHostPort(ready.Address)
	if err != nil {
		t.Fatalf("readiness address %q is invalid: %v", ready.Address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		t.Fatalf("relay selected non-loopback address %q", ready.Address)
	}
	if info, err := os.Stat(ready.StateDir); err != nil {
		t.Fatalf("temporary state directory is unavailable: %v", err)
	} else if !info.IsDir() {
		t.Fatalf("temporary state path %q is not a directory", ready.StateDir)
	}

	connection, err := net.DialTimeout("tcp", ready.Address, time.Second)
	if err != nil {
		t.Fatalf("connect to ready relay at %s: %v", ready.Address, err)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("close readiness probe: %v", err)
	}

	if err := command.Process.Signal(terminationSignal); err != nil {
		t.Fatalf("signal relay: %v", err)
	}
	stopped := readEvent(t, scanner, acceptanceTimeout)
	if stopped.Level != "info" || stopped.Event != "server_stopped" || stopped.Result != "graceful" {
		t.Fatalf("unexpected shutdown event: %+v; stderr: %s", stopped, stderr.String())
	}
	if stopped.Address != ready.Address {
		t.Fatalf("shutdown address %q differs from readiness address %q", stopped.Address, ready.Address)
	}
	if err := waitUntil(t, waiter, acceptanceTimeout); err != nil {
		t.Fatalf("relay did not exit successfully: %v; stderr: %s", err, stderr.String())
	}

	if _, err := os.Stat(ready.StateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary state directory remains after shutdown: %v", err)
	}
	rebound, err := net.Listen("tcp", ready.Address)
	if err != nil {
		t.Fatalf("listener %s was not released: %v", ready.Address, err)
	}
	if err := rebound.Close(); err != nil {
		t.Fatalf("close rebound listener: %v", err)
	}
	return ready.StateDir
}

func buildRelay(t *testing.T) string {
	t.Helper()

	moduleRoot := filepath.Clean("..")
	binary := filepath.Join(t.TempDir(), "pi-messaging-relay-server")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	command := exec.Command("go", "build", "-o", binary, "./cmd/pi-messaging-relay-server")
	command.Dir = moduleRoot
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build real relay process: %v\n%s", err, output)
	}
	return binary
}

func readEvent(t *testing.T, scanner *bufio.Scanner, timeout time.Duration) processEvent {
	t.Helper()

	type scanResult struct {
		line string
		err  error
	}
	result := make(chan scanResult, 1)
	go func() {
		if !scanner.Scan() {
			err := scanner.Err()
			if err == nil {
				err = errors.New("process output closed")
			}
			result <- scanResult{err: err}
			return
		}
		result <- scanResult{line: scanner.Text()}
	}()

	select {
	case scanned := <-result:
		if scanned.err != nil {
			t.Fatalf("read process event: %v", scanned.err)
		}
		var event processEvent
		if err := json.Unmarshal([]byte(scanned.line), &event); err != nil {
			t.Fatalf("decode process event %q: %v", scanned.line, err)
		}
		return event
	case <-time.After(timeout):
		t.Fatalf("timed out after %s waiting for process event", timeout)
		return processEvent{}
	}
}

type processWaiter struct {
	command *exec.Cmd
	done    chan struct{}
	err     error
}

func newProcessWaiter(command *exec.Cmd) *processWaiter {
	waiter := &processWaiter{
		command: command,
		done:    make(chan struct{}),
	}
	go func() {
		waiter.err = command.Wait()
		close(waiter.done)
	}()
	return waiter
}

func (waiter *processWaiter) wait(timeout time.Duration) (error, bool) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-waiter.done:
		return waiter.err, true
	case <-timer.C:
		return nil, false
	}
}

func (waiter *processWaiter) terminate(timeout time.Duration) error {
	select {
	case <-waiter.done:
		return nil
	default:
	}

	killErr := waiter.command.Process.Kill()
	if errors.Is(killErr, os.ErrProcessDone) {
		killErr = nil
	}
	if _, exited := waiter.wait(timeout); !exited {
		if killErr != nil {
			return fmt.Errorf("kill relay: %w; process was not reaped within %s", killErr, timeout)
		}
		return fmt.Errorf("relay was not reaped within %s after kill", timeout)
	}
	if killErr != nil {
		return fmt.Errorf("kill relay: %w", killErr)
	}
	return nil
}

func waitUntil(t *testing.T, waiter *processWaiter, timeout time.Duration) error {
	t.Helper()

	if err, exited := waiter.wait(timeout); exited {
		return err
	}
	if err := waiter.terminate(acceptanceTimeout); err != nil {
		return fmt.Errorf("timed out after %s: %w", timeout, err)
	}
	return fmt.Errorf("timed out after %s", timeout)
}

func validateTestStateDirectory(stateDir, stateParent string) error {
	cleanStateDir := filepath.Clean(stateDir)
	cleanStateParent := filepath.Clean(stateParent)
	if !filepath.IsAbs(stateDir) || stateDir != cleanStateDir {
		return errors.New("must be a clean absolute path")
	}
	if !filepath.IsAbs(stateParent) || filepath.Dir(cleanStateDir) != cleanStateParent {
		return fmt.Errorf("must be directly beneath test-owned parent %q", cleanStateParent)
	}
	name := filepath.Base(cleanStateDir)
	const prefix = "pi-messaging-relay-"
	if !strings.HasPrefix(name, prefix) || len(name) == len(prefix) {
		return fmt.Errorf("must have prefix %q and a generated suffix", prefix)
	}
	return nil
}
