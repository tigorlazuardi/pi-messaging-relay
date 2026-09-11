//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
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

func TestRelayRejectsPairingCodePathsOutsideRetainedStateBeforeReadiness(t *testing.T) {
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
		codePath := filepath.Join(externalParent, "pairing-code")

		assertPairingCodePathRejectedBeforeReadiness(t, statePath, codePath)
		if _, err := os.Stat(codePath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("external pairing code path was created: %v", err)
		}
	})

	t.Run("substitutable ancestor", func(t *testing.T) {
		root := t.TempDir()
		statePath := filepath.Join(root, "state")
		target := filepath.Join(root, "target")
		if err := os.Mkdir(statePath, 0o700); err != nil {
			t.Fatalf("create state directory: %v", err)
		}
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatalf("create substitution target: %v", err)
		}
		codePath := filepath.Join(target, "pairing-code")
		want := []byte("operator-owned\n")
		if err := os.WriteFile(codePath, want, 0o600); err != nil {
			t.Fatalf("create protected target file: %v", err)
		}
		alias := filepath.Join(root, "substitutable")
		if err := os.Symlink(target, alias); err != nil {
			t.Fatalf("create substitutable ancestor: %v", err)
		}

		assertPairingCodePathRejectedBeforeReadiness(t, statePath, filepath.Join(alias, "pairing-code"))
		got, err := os.ReadFile(codePath)
		if err != nil {
			t.Fatalf("read protected target after rejection: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("rejected substitutable path changed target file: %q", got)
		}
	})

	t.Run("lexical parent escape", func(t *testing.T) {
		root := t.TempDir()
		statePath := filepath.Join(root, "state")
		if err := os.Mkdir(statePath, 0o700); err != nil {
			t.Fatalf("create state directory: %v", err)
		}
		escapedPath := filepath.Join(root, "escaped-code")
		want := []byte("keep-this-file\n")
		if err := os.WriteFile(escapedPath, want, 0o600); err != nil {
			t.Fatalf("create escaped target file: %v", err)
		}
		configured := statePath + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "escaped-code"

		assertPairingCodePathRejectedBeforeReadiness(t, statePath, configured)
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
		configured := statePath + string(os.PathSeparator) + "nested" + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "pairing-code"
		assertPairingCodePathRejectedBeforeReadiness(t, statePath, configured)
		if _, err := os.Stat(filepath.Join(statePath, "pairing-code")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("parent-traversing pairing code path was created: %v", err)
		}
	})

	t.Run("filesystem root", func(t *testing.T) {
		statePath := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(statePath, 0o700); err != nil {
			t.Fatalf("create state directory: %v", err)
		}
		assertPairingCodePathRejectedBeforeReadiness(t, statePath, string(os.PathSeparator))
	})
}

func assertPairingCodePathRejectedBeforeReadiness(t *testing.T, statePath, codePath string) {
	t.Helper()
	terminationContext, cancel := contextWithImmediateCancellation()
	defer cancel()
	var output bytes.Buffer

	err := runWithContext(
		[]string{"--state-dir", statePath, "--pairing-code-file", codePath},
		&output,
		syncOpenedDirectory,
		terminationContext,
	)
	if err == nil || !strings.Contains(err.Error(), "must be a direct child of the state directory") {
		t.Fatalf("pairing code path rejection = %v, want direct-child error", err)
	}
	if output.Len() != 0 {
		t.Fatalf("relay emitted readiness for rejected pairing code path: %s", output.String())
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
	trusted := allowlistWithGeneratedKey(t, "cli_MDEyMzQ1Njc4OWFi", "2026-09-11T12:34:56Z")
	writeAllowlistFixture(t, configured, trusted)

	injectedDirectory := filepath.Join(root, "injected")
	if err := os.Mkdir(injectedDirectory, 0o700); err != nil {
		t.Fatalf("create injected state directory: %v", err)
	}
	injected := allowlistWithGeneratedKey(t, "cli_YWJjZGVmZ2hpamts", "2026-09-11T12:35:56Z")
	writeAllowlistFixture(t, injectedDirectory, injected)
	injectedBefore, err := os.ReadFile(filepath.Join(injectedDirectory, allowlistFilename))
	if err != nil {
		t.Fatalf("read injected allowlist before replacement: %v", err)
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

	stored, err := loadAllowlist(state)
	if err != nil {
		t.Fatalf("load allowlist through retained directory handle: %v", err)
	}
	if len(stored.Clients) != 1 || stored.Clients[0].ClientID != trusted.Clients[0].ClientID {
		t.Fatalf("loaded authorization = %+v, want retained original %+v", stored.Clients, trusted.Clients)
	}
	if stored.Clients[0].PublicKey == injected.Clients[0].PublicKey {
		t.Fatal("injected public key loaded after final-directory replacement")
	}
	removeCode, err := state.writePairingCodeFile("pairing-code", "retained-secret")
	if err != nil {
		t.Fatalf("write pairing code through retained directory handle: %v", err)
	}
	if _, err := os.Stat(filepath.Join(retainedPath, "pairing-code")); err != nil {
		t.Fatalf("pairing code was not written to retained directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(injectedDirectory, "pairing-code")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pairing code reached injected directory: %v", err)
	}
	if err := removeCode(); err != nil {
		t.Fatalf("remove retained pairing code: %v", err)
	}

	next := allowlist{
		Version: stored.Version,
		Clients: append(append([]allowlistClient(nil), stored.Clients...),
			allowlistWithGeneratedKey(t, "cli_bW5vcHFyc3R1dnd4", "2026-09-11T12:36:56Z").Clients[0]),
	}
	if err := persistAllowlist(state, next); err != nil {
		t.Fatalf("persist through retained directory handle: %v", err)
	}
	retained, err := os.ReadFile(filepath.Join(retainedPath, allowlistFilename))
	if err != nil {
		t.Fatalf("read retained allowlist: %v", err)
	}
	if !bytes.Contains(retained, []byte(next.Clients[1].PublicKey)) {
		t.Fatal("retained directory did not receive allowlist replacement")
	}
	injectedAfter, err := os.ReadFile(filepath.Join(injectedDirectory, allowlistFilename))
	if err != nil {
		t.Fatalf("read injected allowlist after persistence: %v", err)
	}
	if !bytes.Equal(injectedAfter, injectedBefore) {
		t.Fatal("path replacement redirected persistence into injected directory")
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
	if _, err := loadAllowlist(state); err == nil {
		t.Fatal("closed state directory handle remained usable")
	}
}

func allowlistWithGeneratedKey(t *testing.T, clientID, pairedAt string) allowlist {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate public key fixture: %v", err)
	}
	return allowlist{
		Version: 1,
		Clients: []allowlistClient{{
			ClientID:  clientID,
			PublicKey: "ed25519:" + base64.StdEncoding.EncodeToString(publicKey),
			PairedAt:  pairedAt,
		}},
	}
}

func writeAllowlistFixture(t *testing.T, directory string, value allowlist) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("encode allowlist fixture: %v", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(filepath.Join(directory, allowlistFilename), data, 0o600); err != nil {
		t.Fatalf("write allowlist fixture: %v", err)
	}
}

func contextWithImmediateCancellation() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx, cancel
}

func TestPairingCodePublicationCompletesShortWritesAndRemovesRelativeToState(t *testing.T) {
	state, err := prepareStateDirectoryWithSync(filepath.Join(t.TempDir(), "state"), syncOpenedDirectory)
	if err != nil {
		t.Fatalf("prepare state directory: %v", err)
	}
	t.Cleanup(func() { _ = state.close() })
	write := state.operations.write
	state.operations.write = func(file *os.File, data []byte) (int, error) {
		if len(data) > 3 {
			data = data[:3]
		}
		return write(file, data)
	}

	remove, err := state.writePairingCodeFile("pairing-code", "sensitive-code")
	if err != nil {
		t.Fatalf("publish pairing code through short writes: %v", err)
	}
	contents, err := os.ReadFile(filepath.Join(state.path, "pairing-code"))
	if err != nil {
		t.Fatalf("read pairing code after short writes: %v", err)
	}
	if string(contents) != "sensitive-code\n" {
		t.Fatalf("pairing code after short writes = %q", contents)
	}
	if err := remove(); err != nil {
		t.Fatalf("remove pairing code relative to retained state: %v", err)
	}
	if _, err := os.Stat(filepath.Join(state.path, "pairing-code")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed pairing code remains: %v", err)
	}
}

func TestPairingCodePublicationJoinsPrimaryAndRelativeCleanupFailures(t *testing.T) {
	state, err := prepareStateDirectoryWithSync(filepath.Join(t.TempDir(), "state"), syncOpenedDirectory)
	if err != nil {
		t.Fatalf("prepare state directory: %v", err)
	}
	t.Cleanup(func() { _ = state.close() })
	primary := errors.New("injected pairing code sync failure")
	cleanup := errors.New("injected pairing code unlink failure")
	state.operations.syncFile = func(*os.File) error { return primary }
	state.operations.unlink = func(string, int) error { return cleanup }

	remove, err := state.writePairingCodeFile("pairing-code", "sensitive-code")
	if remove != nil {
		t.Fatal("failed pairing code publication returned cleanup ownership")
	}
	if !errors.Is(err, primary) || !errors.Is(err, cleanup) {
		t.Fatalf("pairing code publication error = %v, want joined sync and cleanup failures", err)
	}
	if !strings.Contains(err.Error(), "sync pairing code file") ||
		!strings.Contains(err.Error(), "remove incomplete pairing code file") {
		t.Fatalf("pairing code publication error lacks operation context: %v", err)
	}
	if strings.Contains(err.Error(), "sensitive-code") {
		t.Fatalf("pairing code publication error exposed raw code: %v", err)
	}
}

func TestStatePersistenceCompletesShortWrites(t *testing.T) {
	state, err := prepareStateDirectoryWithSync(filepath.Join(t.TempDir(), "state"), syncOpenedDirectory)
	if err != nil {
		t.Fatalf("prepare state directory: %v", err)
	}
	t.Cleanup(func() { _ = state.close() })
	write := state.operations.write
	state.operations.write = func(file *os.File, data []byte) (int, error) {
		if len(data) > 3 {
			data = data[:3]
		}
		return write(file, data)
	}
	want := allowlistWithGeneratedKey(t, "cli_MDEyMzQ1Njc4OWFi", "2026-09-11T12:34:56Z")

	if err := persistAllowlist(state, want); err != nil {
		t.Fatalf("persist through deterministic short writes: %v", err)
	}
	got, err := loadAllowlist(state)
	if err != nil {
		t.Fatalf("load short-write result: %v", err)
	}
	if len(got.Clients) != 1 || got.Clients[0] != want.Clients[0] {
		t.Fatalf("short-write result = %+v, want %+v", got, want)
	}
	entries, err := os.ReadDir(state.path)
	if err != nil {
		t.Fatalf("list state after short writes: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != allowlistFilename {
		t.Fatalf("state contains temporary artifacts after short writes: %v", entries)
	}
}

func TestStatePersistenceCleansTemporaryFileAfterSettledFailures(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		inject func(state *stateDirectory, failure error)
	}{
		{
			name: "file close",
			inject: func(state *stateDirectory, failure error) {
				closeFile := state.operations.closeFile
				state.operations.closeFile = func(file *os.File) error {
					return errors.Join(closeFile(file), failure)
				}
			},
		},
		{
			name: "rename",
			inject: func(state *stateDirectory, failure error) {
				state.operations.rename = func(string, string) error { return failure }
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			state, err := prepareStateDirectoryWithSync(filepath.Join(t.TempDir(), "state"), syncOpenedDirectory)
			if err != nil {
				t.Fatalf("prepare state directory: %v", err)
			}
			t.Cleanup(func() { _ = state.close() })
			failure := errors.New("injected " + testCase.name + " failure")
			testCase.inject(state, failure)

			err = persistAllowlist(state, allowlist{Version: 1, Clients: []allowlistClient{}})
			if !errors.Is(err, failure) {
				t.Fatalf("persist error = %v, want %v", err, failure)
			}
			entries, readErr := os.ReadDir(state.path)
			if readErr != nil {
				t.Fatalf("list state after failure: %v", readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("state contains temporary artifacts after failure: %v", entries)
			}
		})
	}
}

func TestStatePersistenceJoinsPrimaryAndCleanupFailures(t *testing.T) {
	state, err := prepareStateDirectoryWithSync(filepath.Join(t.TempDir(), "state"), syncOpenedDirectory)
	if err != nil {
		t.Fatalf("prepare state directory: %v", err)
	}
	t.Cleanup(func() { _ = state.close() })
	primary := errors.New("injected state sync failure")
	cleanup := errors.New("injected temporary unlink failure")
	state.operations.syncFile = func(*os.File) error { return primary }
	state.operations.unlink = func(string, int) error { return cleanup }

	err = persistAllowlist(state, allowlist{Version: 1, Clients: []allowlistClient{}})
	if !errors.Is(err, primary) || !errors.Is(err, cleanup) {
		t.Fatalf("persist error = %v, want joined sync and cleanup failures", err)
	}
	if !strings.Contains(err.Error(), "sync temporary allowlist") ||
		!strings.Contains(err.Error(), "remove temporary allowlist") {
		t.Fatalf("persist error lacks operation context: %v", err)
	}
}
