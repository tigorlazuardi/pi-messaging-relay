package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPairEndpointRejectsMalformedTrustBoundaryInput(t *testing.T) {
	_, publicKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate public key fixture: %v", err)
	}
	encodedKey := "ed25519:" + base64.StdEncoding.EncodeToString(publicKey)

	testCases := []struct {
		name        string
		contentType string
		body        string
		wantStatus  int
		wantError   string
	}{
		{
			name:        "requires JSON content type",
			contentType: "text/plain",
			body:        `{}`,
			wantStatus:  http.StatusBadRequest,
			wantError:   "invalid_request",
		},
		{
			name:        "rejects unknown field",
			contentType: "application/json",
			body:        fmt.Sprintf(`{"pairing_code":"value","client_public_key":%q,"role":"admin"}`, encodedKey),
			wantStatus:  http.StatusBadRequest,
			wantError:   "invalid_request",
		},
		{
			name:        "rejects duplicate field",
			contentType: "application/json",
			body:        fmt.Sprintf(`{"pairing_code":"one","pairing_code":"two","client_public_key":%q}`, encodedKey),
			wantStatus:  http.StatusBadRequest,
			wantError:   "invalid_request",
		},
		{
			name:        "rejects wrong field type",
			contentType: "application/json",
			body:        fmt.Sprintf(`{"pairing_code":7,"client_public_key":%q}`, encodedKey),
			wantStatus:  http.StatusBadRequest,
			wantError:   "invalid_request",
		},
		{
			name:        "rejects invalid Ed25519 key",
			contentType: "application/json",
			body:        `{"pairing_code":"value","client_public_key":"ed25519:dG9vLXNob3J0"}`,
			wantStatus:  http.StatusBadRequest,
			wantError:   "invalid_client_public_key",
		},
		{
			name:        "rejects bounded request overflow",
			contentType: "application/json",
			body:        `{"pairing_code":"` + strings.Repeat("x", maxPairRequestBytes) + `","client_public_key":"ed25519:dG9vLXNob3J0"}`,
			wantStatus:  http.StatusBadRequest,
			wantError:   "invalid_request",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			stateDir := t.TempDir()
			if err := os.Chmod(stateDir, 0o700); err != nil {
				t.Fatalf("secure state fixture: %v", err)
			}
			var logs bytes.Buffer
			logger := newEventLogger(&logs)
			t.Cleanup(func() {
				if err := logger.close(); err != nil {
					t.Errorf("close event logger: %v", err)
				}
			})
			service, err := newPairingService(stateDir, "", logger, func(err error) {
				t.Fatalf("unexpected fatal pairing runtime failure: %v", err)
			})
			if err != nil {
				t.Fatalf("create pairing service: %v", err)
			}
			request := httptest.NewRequest(http.MethodPost, "/v1/pair", strings.NewReader(testCase.body))
			request.Header.Set("Content-Type", testCase.contentType)
			response := httptest.NewRecorder()

			service.handlePair(response, request)

			if response.Code != testCase.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", response.Code, testCase.wantStatus, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), `"error":"`+testCase.wantError+`"`) {
				t.Fatalf("response lacks stable error %q: %s", testCase.wantError, response.Body.String())
			}
			if _, err := os.Stat(filepath.Join(stateDir, allowlistFilename)); !os.IsNotExist(err) {
				t.Fatalf("rejected request persisted allowlist state: %v", err)
			}
			if strings.Contains(logs.String(), "value") || strings.Contains(logs.String(), "one") || strings.Contains(logs.String(), "two") {
				t.Fatalf("structured log exposed request authentication material: %s", logs.String())
			}
			if !strings.Contains(logs.String(), `"pairing_code":"<redacted>"`) || !strings.Contains(logs.String(), `"private_key":"<redacted>"`) {
				t.Fatalf("structured log lacks redacted authentication fields: %s", logs.String())
			}
		})
	}
}

func TestPairingAuditFailuresReachFatalReporter(t *testing.T) {
	auditFailure := errors.New("injected audit failure")
	failingLogger := newEventLogger(writerFunc(func([]byte) (int, error) {
		return 0, auditFailure
	}))
	t.Cleanup(func() {
		if err := failingLogger.close(); err != nil {
			t.Errorf("close failing event logger: %v", err)
		}
	})

	t.Run("rejection", func(t *testing.T) {
		reporter := newFatalRuntimeReporter()
		service, err := newPairingService(t.TempDir(), "", failingLogger, reporter.report)
		if err != nil {
			t.Fatalf("create pairing service: %v", err)
		}
		request := httptest.NewRequest(http.MethodPost, "/v1/pair", strings.NewReader(`{}`))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()

		service.handlePair(response, request)

		select {
		case <-reporter.reported:
			fatalErr := reporter.err()
			if !errors.Is(fatalErr, auditFailure) || !strings.Contains(fatalErr.Error(), "pair_rejected") {
				t.Fatalf("fatal rejection audit error = %v", fatalErr)
			}
		default:
			t.Fatal("rejection audit failure did not reach runtime owner")
		}
	})

	t.Run("cleanup and accepted event", func(t *testing.T) {
		stateDir := t.TempDir()
		reporter := newFatalRuntimeReporter()
		service, err := newPairingService(stateDir, "", failingLogger, reporter.report)
		if err != nil {
			t.Fatalf("create pairing service: %v", err)
		}
		service.removeCodeFile = func() error { return errors.New("injected code cleanup failure") }
		publicKey, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate public key fixture: %v", err)
		}
		body := fmt.Sprintf(
			`{"pairing_code":%q,"client_public_key":%q}`,
			service.code,
			"ed25519:"+base64.StdEncoding.EncodeToString(publicKey),
		)
		request := httptest.NewRequest(http.MethodPost, "/v1/pair", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()

		service.handlePair(response, request)

		if response.Code != http.StatusCreated {
			t.Fatalf("pair status = %d, want 201; body: %s", response.Code, response.Body.String())
		}
		select {
		case <-reporter.reported:
			fatalErr := reporter.err()
			if !errors.Is(fatalErr, auditFailure) ||
				!strings.Contains(fatalErr.Error(), "pairing_code_channel_cleanup_failed") {
				t.Fatalf("fatal cleanup audit error = %v", fatalErr)
			}
		default:
			t.Fatal("cleanup audit failure did not reach runtime owner")
		}
		stored, err := loadAllowlist(stateDir)
		if err != nil {
			t.Fatalf("load durable allowlist: %v", err)
		}
		if len(stored.Clients) != 1 {
			t.Fatalf("durable clients = %d, want 1", len(stored.Clients))
		}
	})
}

func TestPairingCodeFileFailurePreservesIncompleteCleanupError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pairing-code")
	primaryFailure := errors.New("injected pairing code write failure")
	cleanupFailure := errors.New("injected incomplete file removal failure")
	secret := "sensitive-raw-pairing-code"
	t.Cleanup(func() {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Errorf("remove residual pairing code fixture: %v", err)
		}
	})

	cleanup, err := writePairingCodeFileWithOperations(path, secret, pairingCodeFileOperations{
		write: func(writer io.Writer, value string) (int, error) {
			written, writeErr := io.WriteString(writer, value)
			if writeErr != nil {
				t.Fatalf("write primary-failure fixture: %v", writeErr)
			}
			return written, primaryFailure
		},
		sync: func(*os.File) error {
			t.Fatal("sync ran after injected write failure")
			return nil
		},
		close: func(file *os.File) error { return file.Close() },
		remove: func(string) error {
			return cleanupFailure
		},
	})

	if cleanup != nil {
		t.Fatal("failed pairing code publication returned a cleanup owner")
	}
	if !errors.Is(err, primaryFailure) || !errors.Is(err, cleanupFailure) {
		t.Fatalf("combined error = %v, want primary and cleanup failures", err)
	}
	if !strings.Contains(err.Error(), "write pairing code file") ||
		!strings.Contains(err.Error(), "remove incomplete pairing code file") {
		t.Fatalf("combined error lacks actionable contexts: %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("combined error exposed raw pairing code: %v", err)
	}
	contents, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("read deliberately residual pairing code fixture: %v", readErr)
	}
	if string(contents) != secret+"\n" {
		t.Fatalf("residual fixture contents changed unexpectedly")
	}
}

func TestPairingCodeFileIsExclusiveAndPrivate(t *testing.T) {
	parent := t.TempDir()
	logger := newEventLogger(os.Stderr)
	t.Cleanup(func() {
		if err := logger.close(); err != nil {
			t.Errorf("close event logger: %v", err)
		}
	})
	if _, err := newPairingService(
		parent,
		filepath.Join(parent, allowlistFilename),
		logger,
		func(error) {},
	); err == nil {
		t.Fatal("pairing service accepted the allowlist path as the raw-code channel")
	}
	path := filepath.Join(parent, "pairing-code")
	if err := os.WriteFile(path, []byte("operator-owned\n"), 0o600); err != nil {
		t.Fatalf("create existing operator file: %v", err)
	}

	if _, err := writePairingCodeFile(path, "new-secret"); err == nil {
		t.Fatal("pairing code writer overwrote an existing file")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read existing operator file: %v", err)
	}
	if string(contents) != "operator-owned\n" {
		t.Fatalf("existing operator file changed: %q", contents)
	}

	createdPath := filepath.Join(parent, "created-code")
	cleanup, err := writePairingCodeFile(createdPath, "secret")
	if err != nil {
		t.Fatalf("write pairing code channel: %v", err)
	}
	info, err := os.Stat(createdPath)
	if err != nil {
		t.Fatalf("inspect pairing code channel: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("pairing code channel permissions = %o, want 600", info.Mode().Perm())
	}
	if err := cleanup(); err != nil {
		t.Fatalf("remove pairing code channel: %v", err)
	}
}
