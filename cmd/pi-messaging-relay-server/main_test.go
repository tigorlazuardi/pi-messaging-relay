package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type writerFunc func([]byte) (int, error)

func (write writerFunc) Write(data []byte) (int, error) {
	return write(data)
}

func TestRunPreservesPrimaryAndFallbackCleanupFailures(t *testing.T) {
	stateParent := t.TempDir()
	movedStateParent := filepath.Join(t.TempDir(), "state-parent")
	t.Setenv("TMPDIR", stateParent)
	t.Setenv("TMP", stateParent)
	t.Setenv("TEMP", stateParent)

	primaryErr := errors.New("readiness output failed")
	var sabotageErr error
	sabotaged := false
	restoreStateParent := func() error {
		if !sabotaged {
			return nil
		}
		if err := os.Remove(stateParent); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Rename(movedStateParent, stateParent); err != nil {
			return err
		}
		sabotaged = false
		return nil
	}
	t.Cleanup(func() {
		if err := restoreStateParent(); err != nil {
			t.Errorf("restore test state parent: %v", err)
		}
	})

	output := writerFunc(func([]byte) (int, error) {
		if err := os.Rename(stateParent, movedStateParent); err != nil {
			sabotageErr = err
			return 0, err
		}
		sabotaged = true
		if err := os.WriteFile(stateParent, []byte("blocks child removal"), 0o600); err != nil {
			sabotageErr = err
			return 0, err
		}
		return 0, primaryErr
	})

	runErr := run(nil, output)
	if err := restoreStateParent(); err != nil {
		t.Fatalf("restore test state parent: %v", err)
	}
	if sabotageErr != nil {
		t.Fatalf("arrange cleanup failure: %v", sabotageErr)
	}
	if !errors.Is(runErr, primaryErr) {
		t.Fatalf("run error does not preserve primary failure: %v", runErr)
	}
	if !strings.Contains(runErr.Error(), "report readiness: readiness output failed") {
		t.Fatalf("run error lacks actionable primary context: %v", runErr)
	}
	if !strings.Contains(runErr.Error(), "remove temporary state directory:") {
		t.Fatalf("run error lacks fallback cleanup failure: %v", runErr)
	}
}
