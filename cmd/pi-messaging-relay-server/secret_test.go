package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadServerSecretTrustMatrix(t *testing.T) {
	const secretName = "relay.secret"
	cases := []struct {
		name    string
		arrange func(t *testing.T, statePath string)
		want    string
	}{
		{
			name: "valid secret with surrounding ASCII whitespace",
			arrange: func(t *testing.T, statePath string) {
				writeTestSecretFile(t, statePath, secretName, " \t\nshared-secret-value \r\n")
			},
			want: "shared-secret-value",
		},
		{
			name: "exactly 512 byte secret",
			arrange: func(t *testing.T, statePath string) {
				writeTestSecretFile(t, statePath, secretName, strings.Repeat("s", maxSecretBytes))
			},
			want: strings.Repeat("s", maxSecretBytes),
		},
		{
			name: "empty flag selects auth off",
			arrange: func(t *testing.T, statePath string) {
				writeTestSecretFile(t, statePath, secretName, "unused")
			},
			want: "",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			state := openTestStateDirectory(t, filepath.Join(t.TempDir(), "state"))
			testCase.arrange(t, state.path)
			configured := ""
			if testCase.name != "empty flag selects auth off" {
				configured = filepath.Join(state.path, secretName)
			}
			secret, err := loadServerSecret(state, configured)
			if err != nil {
				t.Fatalf("load server secret: %v", err)
			}
			if secret != testCase.want {
				t.Fatalf("secret = %q, want %q", secret, testCase.want)
			}
		})
	}

	rejections := []struct {
		name    string
		arrange func(t *testing.T, statePath string)
		wantErr string
	}{
		{
			name:    "missing file with flag set",
			arrange: func(t *testing.T, statePath string) {},
			wantErr: "no such file",
		},
		{
			name: "group-readable mode",
			arrange: func(t *testing.T, statePath string) {
				path := filepath.Join(statePath, secretName)
				writeTestSecretFile(t, statePath, secretName, "secret-value")
				if err := os.Chmod(path, 0o640); err != nil {
					t.Fatalf("loosen secret mode: %v", err)
				}
			},
			wantErr: "0600",
		},
		{
			name: "other-writable mode",
			arrange: func(t *testing.T, statePath string) {
				path := filepath.Join(statePath, secretName)
				writeTestSecretFile(t, statePath, secretName, "secret-value")
				if err := os.Chmod(path, 0o602); err != nil {
					t.Fatalf("loosen secret mode: %v", err)
				}
			},
			wantErr: "0600",
		},
		{
			name: "symlink to a guarded file",
			arrange: func(t *testing.T, statePath string) {
				target := filepath.Join(t.TempDir(), "outside-secret")
				if err := os.WriteFile(target, []byte("secret-value"), 0o600); err != nil {
					t.Fatalf("write symlink target: %v", err)
				}
				if err := os.Symlink(target, filepath.Join(statePath, secretName)); err != nil {
					t.Fatalf("plant secret symlink: %v", err)
				}
			},
			wantErr: "too many levels of symbolic links",
		},
		{
			name: "directory instead of a regular file",
			arrange: func(t *testing.T, statePath string) {
				if err := os.Mkdir(filepath.Join(statePath, secretName), 0o600); err != nil {
					t.Fatalf("create directory fixture: %v", err)
				}
			},
			wantErr: "0600",
		},
		{
			name: "empty trimmed value",
			arrange: func(t *testing.T, statePath string) {
				writeTestSecretFile(t, statePath, secretName, " \t\r\n")
			},
			wantErr: "1 through 512",
		},
		{
			name: "secret above 512 bytes",
			arrange: func(t *testing.T, statePath string) {
				writeTestSecretFile(t, statePath, secretName, strings.Repeat("s", maxSecretBytes+1))
			},
			wantErr: "1 through 512",
		},
		{
			name: "file read above 4096 bytes",
			arrange: func(t *testing.T, statePath string) {
				writeTestSecretFile(t, statePath, secretName, strings.Repeat("s", maxSecretFileReadBytes+1))
			},
			wantErr: "4096",
		},
		{
			name: "invalid UTF-8",
			arrange: func(t *testing.T, statePath string) {
				path := filepath.Join(statePath, secretName)
				if err := os.WriteFile(path, []byte{'a', 0xff, 'b'}, 0o600); err != nil {
					t.Fatalf("write invalid UTF-8 secret: %v", err)
				}
				if err := os.Chmod(path, 0o600); err != nil {
					t.Fatalf("secure invalid UTF-8 secret: %v", err)
				}
			},
			wantErr: "UTF-8",
		},
		{
			name: "NUL byte",
			arrange: func(t *testing.T, statePath string) {
				path := filepath.Join(statePath, secretName)
				if err := os.WriteFile(path, []byte("a\x00b"), 0o600); err != nil {
					t.Fatalf("write NUL secret: %v", err)
				}
				if err := os.Chmod(path, 0o600); err != nil {
					t.Fatalf("secure NUL secret: %v", err)
				}
			},
			wantErr: "NUL",
		},
	}
	for _, testCase := range rejections {
		t.Run(testCase.name, func(t *testing.T) {
			state := openTestStateDirectory(t, filepath.Join(t.TempDir(), "state"))
			testCase.arrange(t, state.path)
			secret, err := loadServerSecret(state, filepath.Join(state.path, secretName))
			if err == nil {
				t.Fatalf("unsafe secret accepted: %q", secret)
			}
			if !strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("rejection = %v, want it to mention %q", err, testCase.wantErr)
			}
		})
	}
}

func TestSecretFilePathMustBeDirectStateChild(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "state")
	if err := os.Mkdir(statePath, 0o700); err != nil {
		t.Fatalf("create state directory: %v", err)
	}
	external := filepath.Join(root, "external")
	if err := os.Mkdir(external, 0o700); err != nil {
		t.Fatalf("create external directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(external, "relay.secret"), []byte("x"), 0o600); err != nil {
		t.Fatalf("create external secret: %v", err)
	}

	for name, configured := range map[string]string{
		"state root itself":    statePath,
		"external parent":      filepath.Join(external, "relay.secret"),
		"parent traversal":     filepath.Join(statePath, "..", "escaped.secret"),
		"nested child":         filepath.Join(statePath, "nested", "relay.secret"),
		"lexical inner escape": statePath + string(os.PathSeparator) + "nested" + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "relay.secret",
		"empty name":           filepath.Join(statePath, ""),
	} {
		t.Run(name, func(t *testing.T) {
			state := openTestStateDirectory(t, statePath)
			secret, err := loadServerSecret(state, configured)
			if err == nil || secret != "" {
				t.Fatalf("path %q accepted: secret %q err %v", configured, secret, err)
			}
			if !strings.Contains(err.Error(), "direct child of the state directory") {
				t.Fatalf("rejection = %v, want direct-child failure", err)
			}
		})
	}
}

func TestSecretFileFailureFailsStartupBeforeReadiness(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(statePath, 0o700); err != nil {
		t.Fatalf("create state directory: %v", err)
	}
	secretPath := filepath.Join(statePath, "relay.secret")
	if err := os.WriteFile(secretPath, []byte("shared-secret"), 0o644); err != nil {
		t.Fatalf("write permissive secret: %v", err)
	}
	terminationContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	var output bytes.Buffer
	runErr := runWithContext(
		[]string{"--state-dir", statePath, "--secret-file", secretPath},
		&output,
		syncOpenedDirectory,
		terminationContext,
	)
	if runErr == nil || !strings.Contains(runErr.Error(), "0600") {
		t.Fatalf("startup error = %v, want guarded-file failure", runErr)
	}
	if output.Len() != 0 {
		t.Fatalf("server emitted readiness before the secret failure: %s", output.String())
	}
	if _, err := os.Stat(filepath.Join(statePath, "allowlist.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("startup created v1 persistence state: %v", err)
	}
}

func TestServerReadyReportsAuthMode(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		withFile bool
		wantAuth string
	}{
		{name: "auth off without a secret file", withFile: false, wantAuth: authModeOff},
		{name: "auth secret with a guarded secret file", withFile: true, wantAuth: authModeSecret},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			statePath := filepath.Join(t.TempDir(), "state")
			if err := os.Mkdir(statePath, 0o700); err != nil {
				t.Fatalf("create state directory: %v", err)
			}
			args := []string{"--state-dir", statePath}
			if testCase.withFile {
				writeTestSecretFile(t, statePath, "relay.secret", "shared-secret")
				args = append(args, "--secret-file", filepath.Join(statePath, "relay.secret"))
			}
			terminationContext, cancelTermination := context.WithCancel(context.Background())
			defer cancelTermination()
			output := newEventChannel()
			runDone := make(chan error, 1)
			go func() {
				runDone <- runWithContext(args, output, syncOpenedDirectory, terminationContext)
			}()

			select {
			case event := <-output.events:
				if event.Event != "server_ready" {
					t.Fatalf("first event = %q, want server_ready", event.Event)
				}
				if event.Auth != testCase.wantAuth {
					t.Fatalf("server_ready auth = %q, want %q", event.Auth, testCase.wantAuth)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("timed out waiting for server_ready")
			}
			cancelTermination()
			select {
			case <-runDone:
			case <-time.After(shutdownTimeout + eventWriteTimeout):
				t.Fatal("server did not stop after termination")
			}
		})
	}
}

type eventChannel struct {
	events chan logEvent
}

func newEventChannel() *eventChannel {
	return &eventChannel{events: make(chan logEvent, 8)}
}

func (channel *eventChannel) Write(data []byte) (int, error) {
	var event logEvent
	if err := json.Unmarshal(data, &event); err != nil {
		return 0, err
	}
	select {
	case channel.events <- event:
	default:
	}
	return len(data), nil
}
