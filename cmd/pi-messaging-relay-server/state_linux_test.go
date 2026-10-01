//go:build linux

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRelayRejectsUntrustedDurableStateAncestorsBeforeReadiness(t *testing.T) {
	t.Run("ancestor symlink", func(t *testing.T) {
		root := t.TempDir()
		realParent := filepath.Join(root, "real-parent")
		if err := os.Mkdir(realParent, 0o700); err != nil {
			t.Fatalf("create real parent: %v", err)
		}
		alias := filepath.Join(root, "alias")
		if err := os.Symlink(realParent, alias); err != nil {
			t.Fatalf("create ancestor symlink: %v", err)
		}
		assertStateStartupRejectedBeforeReadiness(t, filepath.Join(alias, "state"))
	})

	t.Run("attacker-writable non-sticky ancestor", func(t *testing.T) {
		root := t.TempDir()
		writable := filepath.Join(root, "writable")
		if err := os.Mkdir(writable, 0o700); err != nil {
			t.Fatalf("create writable ancestor: %v", err)
		}
		if err := os.Chmod(writable, 0o777); err != nil {
			t.Fatalf("make ancestor attacker-writable: %v", err)
		}
		assertStateStartupRejectedBeforeReadiness(t, filepath.Join(writable, "state"))
	})

	t.Run("sticky shared ancestor", func(t *testing.T) {
		root := t.TempDir()
		shared := filepath.Join(root, "shared")
		if err := os.Mkdir(shared, 0o700); err != nil {
			t.Fatalf("create shared ancestor: %v", err)
		}
		if err := os.Chmod(shared, os.ModeSticky|0o777); err != nil {
			t.Fatalf("make ancestor sticky: %v", err)
		}
		state, err := prepareStateDirectoryWithSync(filepath.Join(shared, "state"), syncOpenedDirectory)
		if err != nil {
			t.Fatalf("prepare state below sticky ancestor: %v", err)
		}
		if err := state.close(); err != nil {
			t.Fatalf("close state below sticky ancestor: %v", err)
		}
	})
}

func TestRelayRejectsSecretPathsOutsideRetainedStateBeforeReadiness(t *testing.T) {
	t.Run("external valid parent", func(t *testing.T) {
		root := t.TempDir()
		statePath := filepath.Join(root, "state")
		externalParent := filepath.Join(root, "external")
		if err := os.Mkdir(statePath, 0o700); err != nil {
			t.Fatalf("create state directory: %v", err)
		}
		if err := os.Mkdir(externalParent, 0o700); err != nil {
			t.Fatalf("create external parent: %v", err)
		}
		secretPath := filepath.Join(externalParent, "relay.secret")
		if err := os.WriteFile(secretPath, []byte("external-secret\n"), 0o600); err != nil {
			t.Fatalf("create external secret: %v", err)
		}

		assertSecretPathRejectedBeforeReadiness(t, statePath, secretPath)
		got, err := os.ReadFile(secretPath)
		if err != nil {
			t.Fatalf("read external secret after rejection: %v", err)
		}
		if string(got) != "external-secret\n" {
			t.Fatalf("rejected external path changed the secret file: %q", got)
		}
	})

	t.Run("lexical parent escape", func(t *testing.T) {
		root := t.TempDir()
		statePath := filepath.Join(root, "state")
		if err := os.Mkdir(statePath, 0o700); err != nil {
			t.Fatalf("create state directory: %v", err)
		}
		escapedPath := filepath.Join(root, "escaped-secret")
		want := []byte("keep-this-file\n")
		if err := os.WriteFile(escapedPath, want, 0o600); err != nil {
			t.Fatalf("create escaped target file: %v", err)
		}
		configured := statePath + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "escaped-secret"

		assertSecretPathRejectedBeforeReadiness(t, statePath, configured)
		got, err := os.ReadFile(escapedPath)
		if err != nil {
			t.Fatalf("read escaped target after rejection: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("rejected lexical escape changed target file: %q", got)
		}
	})

	t.Run("parent traversal that cleans inside state", func(t *testing.T) {
		statePath := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(statePath, 0o700); err != nil {
			t.Fatalf("create state directory: %v", err)
		}
		configured := statePath + string(os.PathSeparator) + "nested" + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "relay.secret"
		assertSecretPathRejectedBeforeReadiness(t, statePath, configured)
	})

	t.Run("filesystem root", func(t *testing.T) {
		statePath := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(statePath, 0o700); err != nil {
			t.Fatalf("create state directory: %v", err)
		}
		assertSecretPathRejectedBeforeReadiness(t, statePath, string(os.PathSeparator))
	})
}

func assertSecretPathRejectedBeforeReadiness(t *testing.T, statePath, secretPath string) {
	t.Helper()
	terminationContext, cancel := contextWithImmediateCancellation()
	defer cancel()
	var output bytes.Buffer

	err := runWithContext(
		[]string{"--state-dir", statePath, "--secret-file", secretPath},
		&output,
		syncOpenedDirectory,
		terminationContext,
	)
	if err == nil || !strings.Contains(err.Error(), "must be a direct child of the state directory") {
		t.Fatalf("secret path rejection = %v, want direct-child error", err)
	}
	if output.Len() != 0 {
		t.Fatalf("relay emitted readiness for rejected secret path: %s", output.String())
	}
}

func assertStateStartupRejectedBeforeReadiness(t *testing.T, statePath string) {
	t.Helper()
	terminationContext, cancel := contextWithImmediateCancellation()
	defer cancel()
	var output bytes.Buffer

	err := runWithContext(
		[]string{"--state-dir", statePath},
		&output,
		syncOpenedDirectory,
		terminationContext,
	)

	if err == nil {
		t.Fatal("relay accepted untrusted durable state ancestry")
	}
	if output.Len() != 0 {
		t.Fatalf("relay emitted readiness for untrusted durable state ancestry: %s", output.String())
	}
}

func TestRetainedStateDirectoryHandleDefeatsFinalPathReplacement(t *testing.T) {
	root := t.TempDir()
	configured := filepath.Join(root, "state")
	if err := os.Mkdir(configured, 0o700); err != nil {
		t.Fatalf("create original state directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configured, "relay.secret"), []byte("retained-secret"), 0o600); err != nil {
		t.Fatalf("write retained secret: %v", err)
	}

	injectedDirectory := filepath.Join(root, "injected")
	if err := os.Mkdir(injectedDirectory, 0o700); err != nil {
		t.Fatalf("create injected state directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(injectedDirectory, "relay.secret"), []byte("injected-secret"), 0o600); err != nil {
		t.Fatalf("write injected secret: %v", err)
	}
	injectedBefore, err := os.ReadFile(filepath.Join(injectedDirectory, "relay.secret"))
	if err != nil {
		t.Fatalf("read injected secret before replacement: %v", err)
	}

	state, err := prepareStateDirectoryWithSync(configured, syncOpenedDirectory)
	if err != nil {
		t.Fatalf("prepare original state directory: %v", err)
	}
	t.Cleanup(func() {
		if err := state.close(); err != nil {
			t.Errorf("close retained state handle: %v", err)
		}
	})
	retainedPath := filepath.Join(root, "retained-original")
	if err := os.Rename(configured, retainedPath); err != nil {
		t.Fatalf("rename validated state directory: %v", err)
	}
	if err := os.Symlink(injectedDirectory, configured); err != nil {
		t.Fatalf("replace configured path with injected symlink: %v", err)
	}

	secret, err := loadServerSecret(state, filepath.Join(configured, "relay.secret"))
	if err != nil {
		t.Fatalf("load secret through retained directory handle: %v", err)
	}
	if secret != "retained-secret" {
		t.Fatalf("loaded secret = %q, want the retained original", secret)
	}
	injectedAfter, err := os.ReadFile(filepath.Join(injectedDirectory, "relay.secret"))
	if err != nil {
		t.Fatalf("read injected secret after replacement: %v", err)
	}
	if !bytes.Equal(injectedAfter, injectedBefore) {
		t.Fatal("path replacement redirected the secret read into the injected directory")
	}
}

func TestStateDirectoryCloseIsIdempotent(t *testing.T) {
	state, err := prepareStateDirectoryWithSync(filepath.Join(t.TempDir(), "state"), syncOpenedDirectory)
	if err != nil {
		t.Fatalf("prepare state directory: %v", err)
	}
	if err := state.close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := state.close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if _, _, err := state.openStateChild("relay.secret"); err == nil {
		t.Fatal("closed state directory handle remained usable")
	}
}

func contextWithImmediateCancellation() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx, cancel
}
