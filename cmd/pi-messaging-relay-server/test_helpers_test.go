package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
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

// writeTestSecretFile installs one operator-owned secret child inside the state
// directory with the guarded 0600 form.
func writeTestSecretFile(t *testing.T, statePath, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(statePath, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write secret fixture: %v", err)
	}
	if err := os.Chmod(filepath.Join(statePath, name), 0o600); err != nil {
		t.Fatalf("secure secret fixture: %v", err)
	}
}
