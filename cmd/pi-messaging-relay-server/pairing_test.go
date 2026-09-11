package main

import (
	"bytes"
	"context"
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
	"sync"
	"testing"
	"time"
)

const (
	pairingHTTPTestTimeout = 2 * time.Second
	maxPairResponseBytes   = 4096
)

var errPairResponseTooLarge = errors.New("pair response exceeded documented size limit")

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
			service, err := newTestPairingService(t, stateDir, "", logger, func(err error) {
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
		service, err := newTestPairingService(t, t.TempDir(), "", failingLogger, reporter.report)
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
		service, err := newTestPairingService(t, stateDir, "", failingLogger, reporter.report)
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
		stored, err := loadTestAllowlist(t, stateDir)
		if err != nil {
			t.Fatalf("load durable allowlist: %v", err)
		}
		if len(stored.Clients) != 1 {
			t.Fatalf("durable clients = %d, want 1", len(stored.Clients))
		}
	})
}

func TestPairingHTTPRejectsInvalidExpiredAndReusedCodes(t *testing.T) {
	createdAt := time.Date(2026, time.September, 10, 12, 0, 0, 0, time.UTC)
	const stableRejection = "{\"error\":\"pairing_code_invalid\",\"message\":\"Pairing code is invalid or expired\"}\n"

	t.Run("well-formed invalid code", func(t *testing.T) {
		harness := newPairingHTTPHarness(t, createdAt)
		invalidCode := strings.Repeat("A", 32)
		if invalidCode == harness.code {
			invalidCode = strings.Repeat("B", 32)
		}

		status, body := harness.post(t, invalidCode)

		if status != http.StatusUnauthorized || body != stableRejection {
			t.Fatalf("invalid-code response = (%d, %q), want (401, %q)", status, body, stableRejection)
		}
		harness.assertRejectedWithoutAllowlistEntry(t, invalidCode, body)
	})

	t.Run("one nanosecond before deadline remains valid", func(t *testing.T) {
		harness := newPairingHTTPHarness(t, createdAt)
		harness.clock.set(createdAt.Add(pairingCodeLifetime - time.Nanosecond))

		status, body := harness.post(t, harness.code)

		if status != http.StatusCreated {
			t.Fatalf("pre-deadline response = (%d, %q), want 201", status, body)
		}
		stored, err := loadTestAllowlist(t, harness.stateDir)
		if err != nil {
			t.Fatalf("load pre-deadline allowlist: %v", err)
		}
		if len(stored.Clients) != 1 {
			t.Fatalf("pre-deadline allowlist entries = %d, want 1", len(stored.Clients))
		}
	})

	t.Run("exact ten-minute deadline is expired", func(t *testing.T) {
		harness := newPairingHTTPHarness(t, createdAt)
		code := harness.code
		harness.clock.set(createdAt.Add(pairingCodeLifetime))

		status, body := harness.post(t, code)

		if status != http.StatusUnauthorized || body != stableRejection {
			t.Fatalf("deadline response = (%d, %q), want (401, %q)", status, body, stableRejection)
		}
		harness.assertRejectedWithoutAllowlistEntry(t, code, body)
	})

	t.Run("consumed code returns the same rejection without a second entry", func(t *testing.T) {
		harness := newPairingHTTPHarness(t, createdAt)
		code := harness.code

		firstStatus, firstBody := harness.post(t, code)
		if firstStatus != http.StatusCreated {
			t.Fatalf("initial response = (%d, %q), want 201", firstStatus, firstBody)
		}
		secondStatus, secondBody := harness.post(t, code)
		if secondStatus != http.StatusUnauthorized || secondBody != stableRejection {
			t.Fatalf("reuse response = (%d, %q), want (401, %q)", secondStatus, secondBody, stableRejection)
		}
		stored, err := loadTestAllowlist(t, harness.stateDir)
		if err != nil {
			t.Fatalf("load allowlist after reuse: %v", err)
		}
		if len(stored.Clients) != 1 {
			t.Fatalf("allowlist entries after reuse = %d, want 1", len(stored.Clients))
		}
		if _, err := os.Stat(filepath.Join(harness.stateDir, "pairing-code")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("consumed pairing code file remains: %v", err)
		}
		harness.assertNoCodeLeak(t, code, secondBody)
	})
}

type pairingHTTPHarness struct {
	service         *pairingService
	stateDir        string
	clock           *pairingTestClock
	logs            *bytes.Buffer
	server          *httptest.Server
	client          *http.Client
	key             string
	code            string
	privateMaterial string
}

type pairingTestClock struct {
	mu  sync.RWMutex
	now time.Time
}

func (clock *pairingTestClock) current() time.Time {
	clock.mu.RLock()
	defer clock.mu.RUnlock()
	return clock.now
}

func (clock *pairingTestClock) set(now time.Time) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = now
}

func newPairingHTTPHarness(t *testing.T, createdAt time.Time) *pairingHTTPHarness {
	t.Helper()
	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatalf("secure state fixture: %v", err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate public key fixture: %v", err)
	}
	harness := &pairingHTTPHarness{
		stateDir:        stateDir,
		clock:           &pairingTestClock{now: createdAt},
		logs:            &bytes.Buffer{},
		key:             "ed25519:" + base64.StdEncoding.EncodeToString(publicKey),
		privateMaterial: base64.StdEncoding.EncodeToString(privateKey),
	}
	logger := newEventLogger(harness.logs)
	t.Cleanup(func() {
		if err := logger.close(); err != nil {
			t.Errorf("close event logger: %v", err)
		}
	})
	harness.service, err = newTestPairingServiceWithClock(t,
		stateDir,
		filepath.Join(stateDir, "pairing-code"),
		logger,
		func(err error) { t.Fatalf("unexpected fatal pairing runtime failure: %v", err) },
		harness.clock.current,
	)
	if err != nil {
		t.Fatalf("create pairing service: %v", err)
	}
	t.Cleanup(func() {
		if err := harness.service.closeCodeChannel(); err != nil {
			t.Errorf("close pairing code channel: %v", err)
		}
	})
	publishedCode, err := os.ReadFile(filepath.Join(stateDir, "pairing-code"))
	if err != nil {
		t.Fatalf("read published pairing code fixture: %v", err)
	}
	harness.code = strings.TrimSpace(string(publishedCode))
	if len(harness.code) != 32 {
		t.Fatalf("published pairing code length = %d, want 32", len(harness.code))
	}
	harness.server, harness.client = newBoundedPairingHTTPTestServer(
		t,
		http.HandlerFunc(harness.service.handlePair),
	)
	return harness
}

func newBoundedPairingHTTPTestServer(t *testing.T, handler http.Handler) (*httptest.Server, *http.Client) {
	t.Helper()
	server := httptest.NewServer(handler)
	transport := &http.Transport{}
	client := &http.Client{Transport: transport}
	t.Cleanup(func() {
		client.CloseIdleConnections()
		transport.CloseIdleConnections()
		server.CloseClientConnections()
		closed := make(chan struct{})
		go func() {
			server.Close()
			close(closed)
		}()
		timer := time.NewTimer(pairingHTTPTestTimeout)
		defer timer.Stop()
		select {
		case <-closed:
		case <-timer.C:
			t.Errorf("close pairing HTTP test server within %s", pairingHTTPTestTimeout)
		}
	})
	return server, client
}

func (harness *pairingHTTPHarness) post(t *testing.T, code string) (int, string) {
	t.Helper()
	body := fmt.Sprintf(`{"pairing_code":%q,"client_public_key":%q}`, code, harness.key)
	status, mediaType, responseBody, err := doBoundedPairingHTTPRequest(
		harness.client,
		harness.server.URL+"/v1/pair",
		body,
	)
	if err != nil {
		t.Fatalf("complete pair request within bounds: %v", err)
	}
	if mediaType != "application/json" {
		t.Fatalf("pair response content type = %q, want application/json", mediaType)
	}
	return status, responseBody
}

func doBoundedPairingHTTPRequest(client *http.Client, endpoint, body string) (int, string, string, error) {
	requestContext, cancel := context.WithTimeout(context.Background(), pairingHTTPTestTimeout)
	request, err := http.NewRequestWithContext(
		requestContext,
		http.MethodPost,
		endpoint,
		strings.NewReader(body),
	)
	if err != nil {
		cancel()
		return 0, "", "", fmt.Errorf("create pair request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		cancel()
		return 0, "", "", fmt.Errorf("send pair request within %s: %w", pairingHTTPTestTimeout, err)
	}
	defer func() {
		cancel()
		_ = response.Body.Close()
	}()
	responseBody, err := readBoundedPairResponse(response.Body)
	if err != nil {
		return 0, "", "", fmt.Errorf("read bounded pair response: %w", err)
	}
	return response.StatusCode, response.Header.Get("Content-Type"), responseBody, nil
}

func readBoundedPairResponse(body io.Reader) (string, error) {
	responseBody, err := io.ReadAll(io.LimitReader(body, maxPairResponseBytes+1))
	if err != nil {
		return "", err
	}
	if len(responseBody) > maxPairResponseBytes {
		return "", errPairResponseTooLarge
	}
	return string(responseBody), nil
}

func TestReadBoundedPairResponseRejectsOverflow(t *testing.T) {
	_, err := readBoundedPairResponse(strings.NewReader(strings.Repeat("x", maxPairResponseBytes+1)))
	if !errors.Is(err, errPairResponseTooLarge) {
		t.Fatalf("over-limit pair response error = %v, want %v", err, errPairResponseTooLarge)
	}
}

func TestBoundedPairingHTTPRequestTimesOutStalledHandler(t *testing.T) {
	releaseHandler := make(chan struct{})
	server, client := newBoundedPairingHTTPTestServer(t, http.HandlerFunc(func(
		_ http.ResponseWriter,
		_ *http.Request,
	) {
		<-releaseHandler
	}))

	_, _, _, err := doBoundedPairingHTTPRequest(client, server.URL+"/v1/pair", `{}`)
	close(releaseHandler)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalled pair request error = %v, want %v", err, context.DeadlineExceeded)
	}
}

func (harness *pairingHTTPHarness) assertRejectedWithoutAllowlistEntry(
	t *testing.T,
	submittedCode, responseBody string,
) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(harness.stateDir, allowlistFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected request persisted allowlist state: %v", err)
	}
	harness.assertNoCodeLeak(t, submittedCode, responseBody)
}

func (harness *pairingHTTPHarness) assertNoCodeLeak(t *testing.T, submittedCode, responseBody string) {
	t.Helper()
	for name, output := range map[string]string{
		"response":       responseBody,
		"structured log": harness.logs.String(),
	} {
		if strings.Contains(output, submittedCode) ||
			strings.Contains(output, harness.code) ||
			strings.Contains(output, harness.privateMaterial) {
			t.Fatalf("%s exposed pairing code or private material: %s", name, output)
		}
	}
	if !strings.Contains(harness.logs.String(), `"event":"pair_rejected"`) ||
		!strings.Contains(harness.logs.String(), `"reason":"pairing_code_invalid"`) ||
		!strings.Contains(harness.logs.String(), `"pairing_code":"<redacted>"`) ||
		!strings.Contains(harness.logs.String(), `"private_key":"<redacted>"`) {
		t.Fatalf("structured log lacks stable rejection and redacted authentication fields: %s", harness.logs.String())
	}
}

func TestLoadAllowlistRejectsUnsafeOrAmbiguousRestartState(t *testing.T) {
	publicOne, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate first public key fixture: %v", err)
	}
	publicTwo, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate second public key fixture: %v", err)
	}
	encodedOne := "ed25519:" + base64.StdEncoding.EncodeToString(publicOne)
	encodedTwo := "ed25519:" + base64.StdEncoding.EncodeToString(publicTwo)
	validClient := fmt.Sprintf(
		`{"client_id":"cli_MDEyMzQ1Njc4OWFi","client_public_key":%q,"paired_at":"2026-09-11T12:34:56.123456789Z"}`,
		encodedOne,
	)

	for _, testCase := range []struct {
		name string
		body string
	}{
		{
			name: "duplicate top-level field",
			body: fmt.Sprintf(`{"version":1,"version":1,"clients":[%s]}`, validClient),
		},
		{
			name: "duplicate client field",
			body: fmt.Sprintf(
				`{"version":1,"clients":[{"client_id":"cli_MDEyMzQ1Njc4OWFi","client_public_key":%q,"client_public_key":%q,"paired_at":"2026-09-11T12:34:56Z"}]}`,
				encodedOne,
				encodedTwo,
			),
		},
		{
			name: "duplicate client id",
			body: fmt.Sprintf(
				`{"version":1,"clients":[%s,{"client_id":"cli_MDEyMzQ1Njc4OWFi","client_public_key":%q,"paired_at":"2026-09-11T12:35:56Z"}]}`,
				validClient,
				encodedTwo,
			),
		},
		{
			name: "duplicate public key",
			body: fmt.Sprintf(
				`{"version":1,"clients":[%s,{"client_id":"cli_YWJjZGVmZ2hpamts","client_public_key":%q,"paired_at":"2026-09-11T12:35:56Z"}]}`,
				validClient,
				encodedOne,
			),
		},
		{
			name: "unknown client metadata",
			body: fmt.Sprintf(
				`{"version":1,"clients":[{"client_id":"cli_MDEyMzQ1Njc4OWFi","client_public_key":%q,"paired_at":"2026-09-11T12:34:56Z","role":"admin"}]}`,
				encodedOne,
			),
		},
		{
			name: "non-canonical pairing timestamp offset",
			body: fmt.Sprintf(
				`{"version":1,"clients":[{"client_id":"cli_MDEyMzQ1Njc4OWFi","client_public_key":%q,"paired_at":"2026-09-11T12:34:56+00:00"}]}`,
				encodedOne,
			),
		},
		{
			name: "non-canonical pairing timestamp precision",
			body: fmt.Sprintf(
				`{"version":1,"clients":[{"client_id":"cli_MDEyMzQ1Njc4OWFi","client_public_key":%q,"paired_at":"2026-09-11T12:34:56.1200Z"}]}`,
				encodedOne,
			),
		},
		{
			name: "partial JSON",
			body: `{"version":1,"clients":[`,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			stateDir := t.TempDir()
			if err := os.Chmod(stateDir, 0o700); err != nil {
				t.Fatalf("secure state fixture: %v", err)
			}
			if err := os.WriteFile(filepath.Join(stateDir, allowlistFilename), []byte(testCase.body), 0o600); err != nil {
				t.Fatalf("write allowlist fixture: %v", err)
			}

			if _, err := loadTestAllowlist(t, stateDir); err == nil {
				t.Fatal("unsafe or ambiguous allowlist loaded successfully")
			}
		})
	}

	for _, testCase := range []struct {
		name  string
		setup func(t *testing.T, path string)
	}{
		{
			name: "group-readable file",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(`{"version":1,"clients":[]}`), 0o640); err != nil {
					t.Fatalf("write permissive allowlist: %v", err)
				}
			},
		},
		{
			name: "directory at file path",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatalf("create directory allowlist: %v", err)
				}
			},
		},
		{
			name: "symbolic link",
			setup: func(t *testing.T, path string) {
				t.Helper()
				target := filepath.Join(t.TempDir(), "target.json")
				if err := os.WriteFile(target, []byte(`{"version":1,"clients":[]}`), 0o600); err != nil {
					t.Fatalf("write symlink target: %v", err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatalf("create allowlist symlink: %v", err)
				}
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			stateDir := t.TempDir()
			path := filepath.Join(stateDir, allowlistFilename)
			testCase.setup(t, path)
			if _, err := loadTestAllowlist(t, stateDir); err == nil {
				t.Fatal("unsafe allowlist file loaded successfully")
			}
		})
	}

	t.Run("bounded read", func(t *testing.T) {
		stateDir := t.TempDir()
		if err := os.Chmod(stateDir, 0o700); err != nil {
			t.Fatalf("secure state fixture: %v", err)
		}
		path := filepath.Join(stateDir, allowlistFilename)
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
		if err != nil {
			t.Fatalf("create oversized allowlist fixture: %v", err)
		}
		if err := file.Truncate(maxAllowlistBytes + 1); err != nil {
			_ = file.Close()
			t.Fatalf("size oversized allowlist fixture: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("close oversized allowlist fixture: %v", err)
		}

		if _, err := loadTestAllowlist(t, stateDir); !errors.Is(err, errAllowlistTooLarge) {
			t.Fatalf("oversized allowlist error = %v, want %v", err, errAllowlistTooLarge)
		}
	})
}

func TestPairingRefusesToPersistAnAlreadyAllowlistedPublicKey(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatalf("secure state fixture: %v", err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate public key fixture: %v", err)
	}
	encodedKey := "ed25519:" + base64.StdEncoding.EncodeToString(publicKey)
	existing := allowlist{
		Version: 1,
		Clients: []allowlistClient{{
			ClientID:  "cli_MDEyMzQ1Njc4OWFi",
			PublicKey: encodedKey,
			PairedAt:  "2026-09-11T12:34:56Z",
		}},
	}
	if err := persistTestAllowlist(t, stateDir, existing); err != nil {
		t.Fatalf("persist existing identity fixture: %v", err)
	}
	before, err := os.ReadFile(filepath.Join(stateDir, allowlistFilename))
	if err != nil {
		t.Fatalf("read existing identity fixture: %v", err)
	}
	logger := newEventLogger(io.Discard)
	t.Cleanup(func() {
		if err := logger.close(); err != nil {
			t.Errorf("close event logger: %v", err)
		}
	})
	service, err := newTestPairingService(t, stateDir, "", logger, func(error) {})
	if err != nil {
		t.Fatalf("load existing identity: %v", err)
	}
	code := service.code

	if _, err := service.accept(pairRequest{PairingCode: code, ClientPublicKey: encodedKey}, time.Now()); err == nil {
		t.Fatal("duplicate public key was accepted")
	}
	if service.code != code {
		t.Fatal("failed duplicate pairing consumed current pairing code")
	}
	after, err := os.ReadFile(filepath.Join(stateDir, allowlistFilename))
	if err != nil {
		t.Fatalf("read identity after duplicate attempt: %v", err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("duplicate public key attempt changed durable allowlist")
	}
}

func TestPairingCodePathIsRejectedBeforeTokenGeneration(t *testing.T) {
	state := openTestStateDirectory(t, t.TempDir())
	externalPath := filepath.Join(t.TempDir(), "pairing-code")
	generated := false

	service, err := newPairingServiceWithClockAndToken(
		state,
		externalPath,
		nil,
		func(error) {},
		time.Now,
		func(int) (string, error) {
			generated = true
			return "", errors.New("token generator must not run")
		},
	)
	if service != nil || err == nil {
		t.Fatalf("external pairing code path result = (%v, %v), want rejection", service, err)
	}
	if generated {
		t.Fatal("pairing code was generated before path rejection")
	}
	if _, err := os.Stat(externalPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("external pairing code path was created: %v", err)
	}
}

func TestPairingCodeFileIsExclusiveAndPrivate(t *testing.T) {
	stateDir := t.TempDir()
	logger := newEventLogger(io.Discard)
	t.Cleanup(func() {
		if err := logger.close(); err != nil {
			t.Errorf("close event logger: %v", err)
		}
	})
	if _, err := newTestPairingService(t,
		stateDir,
		filepath.Join(stateDir, allowlistFilename),
		logger,
		func(error) {},
	); err == nil {
		t.Fatal("pairing service accepted the allowlist as the raw-code channel")
	}

	path := filepath.Join(stateDir, "pairing-code")
	if err := os.WriteFile(path, []byte("operator-owned\n"), 0o600); err != nil {
		t.Fatalf("create existing operator file: %v", err)
	}
	if _, err := newTestPairingService(t, stateDir, path, logger, func(error) {}); err == nil {
		t.Fatal("pairing service overwrote an existing direct-child file")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read existing operator file: %v", err)
	}
	if string(contents) != "operator-owned\n" {
		t.Fatalf("existing operator file changed: %q", contents)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove operator file fixture: %v", err)
	}

	service, err := newTestPairingService(t, stateDir, path, logger, func(error) {})
	if err != nil {
		t.Fatalf("create direct-child pairing code channel: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("inspect direct-child pairing code channel: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("pairing code channel permissions = %o, want 600", info.Mode().Perm())
	}
	if err := service.closeCodeChannel(); err != nil {
		t.Fatalf("remove direct-child pairing code channel: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("closed pairing code channel remains: %v", err)
	}
}
