package main

import (
	"errors"
	"os"
	"testing"
	"time"
)

func openTestStateDirectory(t *testing.T, path string) *stateDirectory {
	t.Helper()
	if err := os.Chmod(path, 0o700); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("secure test state directory: %v", err)
	}
	state, err := prepareStateDirectoryWithSync(path, syncOpenedDirectory)
	if err != nil {
		t.Fatalf("open test state directory: %v", err)
	}
	t.Cleanup(func() {
		if err := state.close(); err != nil {
			t.Errorf("close test state directory: %v", err)
		}
	})
	return state
}

func newTestPairingService(
	t *testing.T,
	statePath string,
	codeFilePath string,
	logger *eventLogger,
	reportFatal func(error),
) (*pairingService, error) {
	t.Helper()
	return newPairingService(openTestStateDirectory(t, statePath), codeFilePath, logger, reportFatal)
}

func newTestPairingServiceWithClock(
	t *testing.T,
	statePath string,
	codeFilePath string,
	logger *eventLogger,
	reportFatal func(error),
	now func() time.Time,
) (*pairingService, error) {
	t.Helper()
	return newPairingServiceWithClock(
		openTestStateDirectory(t, statePath),
		codeFilePath,
		logger,
		reportFatal,
		now,
	)
}

func loadTestAllowlist(t *testing.T, statePath string) (allowlist, error) {
	t.Helper()
	return loadAllowlist(openTestStateDirectory(t, statePath))
}

func persistTestAllowlist(t *testing.T, statePath string, value allowlist) error {
	t.Helper()
	return persistAllowlist(openTestStateDirectory(t, statePath), value)
}
