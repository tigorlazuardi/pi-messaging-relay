package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

func TestSessionAuthenticationDeadlineClosesSilentPeer(t *testing.T) {
	var logs bytes.Buffer
	logger := newEventLogger(&logs)
	t.Cleanup(func() {
		if err := logger.close(); err != nil {
			t.Errorf("close event logger: %v", err)
		}
	})
	reporter := newFatalRuntimeReporter()
	pairing, err := newPairingService(t.TempDir(), "", logger, reporter.report)
	if err != nil {
		t.Fatalf("create pairing service: %v", err)
	}
	registry := newSessionConnectionRegistry()
	service := newSessionAuthService(pairing, registry, logger, reporter.report)
	service.authTimeout = 50 * time.Millisecond
	server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
	t.Cleanup(server.Close)

	dialContext, cancelDial := context.WithTimeout(context.Background(), time.Second)
	defer cancelDial()
	connection, _, err := websocket.Dial(
		dialContext,
		"ws"+strings.TrimPrefix(server.URL, "http"),
		nil,
	)
	if err != nil {
		t.Fatalf("dial test WebSocket: %v", err)
	}
	t.Cleanup(func() { _ = connection.CloseNow() })
	var challenge challengeEnvelope
	if err := wsjson.Read(dialContext, connection, &challenge); err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	started := time.Now()
	_, _, err = connection.Reader(dialContext)
	if err == nil {
		t.Fatal("silent peer remained open after authentication deadline")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("silent peer retained beyond bounded test deadline: %s", elapsed)
	}
	settleContext, cancelSettle := context.WithTimeout(context.Background(), time.Second)
	defer cancelSettle()
	if err := registry.closeAndWait(settleContext); err != nil {
		t.Fatalf("settle timed-out session: %v", err)
	}
	if !strings.Contains(logs.String(), `"event":"auth_rejected"`) ||
		!strings.Contains(logs.String(), `"reason":"invalid_hello"`) ||
		!strings.Contains(logs.String(), `"nonce":"<redacted>"`) {
		t.Fatalf("deadline rejection log is incomplete: %s", logs.String())
	}
}

func TestSessionAuditFailureReachesFatalRuntimeOwner(t *testing.T) {
	auditFailure := errors.New("injected session audit failure")
	logger := newEventLogger(writerFunc(func([]byte) (int, error) {
		return 0, auditFailure
	}))
	t.Cleanup(func() {
		if err := logger.close(); err != nil {
			t.Errorf("close failing event logger: %v", err)
		}
	})
	reporter := newFatalRuntimeReporter()
	service := &sessionAuthService{logger: logger, reportFatal: reporter.report}

	service.writeAudit(logEvent{Event: "auth_rejected"})

	select {
	case <-reporter.reported:
		if !errors.Is(reporter.err(), auditFailure) ||
			!strings.Contains(reporter.err().Error(), "auth_rejected") {
			t.Fatalf("fatal session audit error = %v", reporter.err())
		}
	default:
		t.Fatal("session audit failure did not reach fatal runtime owner")
	}
}

func TestSessionCapacityRejectsBeforeUpgradeAndShutdownOwnsReservedPeer(t *testing.T) {
	var logs bytes.Buffer
	logger := newEventLogger(&logs)
	t.Cleanup(func() { _ = logger.close() })
	reporter := newFatalRuntimeReporter()
	pairing, err := newPairingService(t.TempDir(), "", logger, reporter.report)
	if err != nil {
		t.Fatalf("create pairing service: %v", err)
	}
	registry := newSessionConnectionRegistryWithLimit(1)
	service := newSessionAuthService(pairing, registry, logger, reporter.report)
	server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
	t.Cleanup(server.Close)
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	first, _, err := websocket.Dial(ctx, endpoint, nil)
	if err != nil {
		t.Fatalf("dial capacity-owning connection: %v", err)
	}
	t.Cleanup(func() { _ = first.CloseNow() })
	var challenge challengeEnvelope
	if err := wsjson.Read(ctx, first, &challenge); err != nil {
		t.Fatalf("read first challenge: %v", err)
	}

	excess, response, err := websocket.Dial(ctx, endpoint, nil)
	if excess != nil {
		_ = excess.CloseNow()
		t.Fatal("capacity rejection unexpectedly upgraded WebSocket")
	}
	if err == nil {
		t.Fatal("capacity rejection returned no dial error")
	}
	if response == nil || response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("capacity response = %#v, want HTTP 503", response)
	}
	_ = response.Body.Close()

	settleContext, cancelSettle := context.WithTimeout(context.Background(), time.Second)
	defer cancelSettle()
	if err := registry.closeAndWait(settleContext); err != nil {
		t.Fatalf("settle registry-owned nonresponsive peer: %v", err)
	}
	if !strings.Contains(logs.String(), `"event":"session_capacity_rejected"`) ||
		!strings.Contains(logs.String(), `"reason":"connection_capacity_reached"`) {
		t.Fatalf("capacity rejection log is incomplete: %s", logs.String())
	}
}

func TestConcurrentDuplicateActiveRouteFailsClosedForSameAndDifferentInstallationKeys(t *testing.T) {
	var logs bytes.Buffer
	logger := newEventLogger(&logs)
	t.Cleanup(func() { _ = logger.close() })
	reporter := newFatalRuntimeReporter()
	pairing, err := newPairingService(t.TempDir(), "", logger, reporter.report)
	if err != nil {
		t.Fatalf("create pairing service: %v", err)
	}
	publicOne, privateOne, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate first installation key: %v", err)
	}
	publicTwo, privateTwo, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate second installation key: %v", err)
	}
	encodedOne := "ed25519:" + base64.StdEncoding.EncodeToString(publicOne)
	encodedTwo := "ed25519:" + base64.StdEncoding.EncodeToString(publicTwo)
	pairing.mu.Lock()
	pairing.allowlist.Clients = []allowlistClient{
		{ClientID: "cli_first", PublicKey: encodedOne},
		{ClientID: "cli_second", PublicKey: encodedTwo},
	}
	pairing.mu.Unlock()

	registry := newSessionConnectionRegistryWithLimit(4)
	service := newSessionAuthService(pairing, registry, logger, reporter.report)
	server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
	t.Cleanup(server.Close)
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")
	const routeID = "01993ca1-1111-7aaa-8aaa-111111111111"

	original, err := openAuthenticatedTestSession(endpoint, privateOne, encodedOne, routeID, "host", "/same")
	if err != nil {
		t.Fatalf("authenticate original route owner: %v", err)
	}
	t.Cleanup(func() { _ = original.CloseNow() })

	type collision struct {
		connection *websocket.Conn
		err        error
	}
	results := make(chan collision, 2)
	var started sync.WaitGroup
	started.Add(2)
	attempt := func(privateKey ed25519.PrivateKey, publicKey, hostname, cwd string) {
		defer started.Done()
		connection, err := openAuthenticatedTestSession(endpoint, privateKey, publicKey, routeID, hostname, cwd)
		results <- collision{connection: connection, err: err}
	}
	go attempt(privateOne, encodedOne, "host", "/same")
	go attempt(privateTwo, encodedTwo, "other-host", "/different")
	started.Wait()
	close(results)
	for result := range results {
		if result.connection != nil {
			_ = result.connection.CloseNow()
			t.Fatal("duplicate route received a welcome")
		}
		if result.err == nil {
			t.Fatal("duplicate route did not fail closed")
		}
	}

	_ = original.CloseNow()
	settleContext, cancelSettle := context.WithTimeout(context.Background(), time.Second)
	defer cancelSettle()
	if err := registry.closeAndWait(settleContext); err != nil {
		t.Fatalf("settle unique active route registry: %v", err)
	}
	if count := strings.Count(logs.String(), `"reason":"route_conflict"`); count != 2 {
		t.Fatalf("route conflict log count = %d, want 2; logs: %s", count, logs.String())
	}
	if count := strings.Count(logs.String(), `"event":"auth_accepted"`); count != 1 {
		t.Fatalf("accepted route count = %d, want original only; logs: %s", count, logs.String())
	}
}

func openAuthenticatedTestSession(
	endpoint string,
	privateKey ed25519.PrivateKey,
	publicKey string,
	routeID string,
	hostname string,
	cwd string,
) (*websocket.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	connection, _, err := websocket.Dial(ctx, endpoint, nil)
	if err != nil {
		return nil, err
	}
	var challenge challengeEnvelope
	if err := wsjson.Read(ctx, connection, &challenge); err != nil {
		_ = connection.CloseNow()
		return nil, fmt.Errorf("read challenge: %w", err)
	}
	hello := helloEnvelope{
		Version:   1,
		Type:      "hello",
		RequestID: "01993c79-8ad7-79fa-83e3-9789dcaca168",
		Payload: helloPayload{
			ClientPublicKey: publicKey,
			RouteID:         routeID,
			Hostname:        hostname,
			CWD:             cwd,
		},
	}
	hello.Payload.Signature = base64.StdEncoding.EncodeToString(
		ed25519.Sign(privateKey, helloTranscript(challenge.Payload.Nonce, hello)),
	)
	if err := wsjson.Write(ctx, connection, map[string]any{
		"v":          hello.Version,
		"type":       hello.Type,
		"request_id": hello.RequestID,
		"payload": map[string]string{
			"client_public_key": hello.Payload.ClientPublicKey,
			"route_id":          hello.Payload.RouteID,
			"hostname":          hello.Payload.Hostname,
			"cwd":               hello.Payload.CWD,
			"signature":         hello.Payload.Signature,
		},
	}); err != nil {
		_ = connection.CloseNow()
		return nil, fmt.Errorf("write hello: %w", err)
	}
	var welcome welcomeEnvelope
	if err := wsjson.Read(ctx, connection, &welcome); err != nil {
		_ = connection.CloseNow()
		return nil, fmt.Errorf("read welcome: %w", err)
	}
	if welcome.Type != "welcome" {
		_ = connection.CloseNow()
		return nil, fmt.Errorf("unexpected auth response %q", welcome.Type)
	}
	return connection, nil
}

func TestHelloTranscriptIsDomainSeparatedLengthPrefixedAndExcludesSignature(t *testing.T) {
	hello := helloEnvelope{
		Version:   1,
		Type:      "hello",
		RequestID: "01993c79-8ad7-79fa-83e3-9789dcaca168",
		Payload: helloPayload{
			ClientPublicKey: "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			RouteID:         "01993ca1-1111-7aaa-8aaa-111111111111",
			Hostname:        "høst",
			CWD:             "/srv/@#",
			Signature:       "signature-is-excluded",
		},
	}
	want := "pi-messaging-relay-auth-v1\n" +
		"nonce:11:nonce-value\n" +
		"request_id:36:01993c79-8ad7-79fa-83e3-9789dcaca168\n" +
		"client_public_key:52:ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n" +
		"route_id:36:01993ca1-1111-7aaa-8aaa-111111111111\n" +
		"hostname:5:høst\n" +
		"cwd:7:/srv/@#\n"

	got := string(helloTranscript("nonce-value", hello))
	if got != want {
		t.Fatalf("transcript = %q, want %q", got, want)
	}
	hello.Payload.Signature = "different-signature"
	if changed := string(helloTranscript("nonce-value", hello)); changed != want {
		t.Fatalf("signature changed transcript: %q", changed)
	}
}

func TestHelloSignatureBindsChallengeAndAllRouteMetadata(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key fixture: %v", err)
	}
	hello := helloEnvelope{
		Version:   1,
		Type:      "hello",
		RequestID: "01993c79-8ad7-79fa-83e3-9789dcaca168",
		Payload: helloPayload{
			ClientPublicKey: "ed25519:" + base64.StdEncoding.EncodeToString(publicKey),
			RouteID:         "01993ca1-1111-7aaa-8aaa-111111111111",
			Hostname:        "host",
			CWD:             "/srv/project",
		},
	}
	hello.Payload.Signature = base64.StdEncoding.EncodeToString(
		ed25519.Sign(privateKey, helloTranscript("fresh-nonce", hello)),
	)
	if !verifyHelloSignature(publicKey, "fresh-nonce", hello) {
		t.Fatal("valid transcript signature was rejected")
	}

	mutations := map[string]func(*helloEnvelope){
		"request id": func(value *helloEnvelope) { value.RequestID = "01993c79-8ad8-79fa-83e3-9789dcaca168" },
		"public key": func(value *helloEnvelope) { value.Payload.ClientPublicKey = "ed25519:" + strings.Repeat("A", 43) + "=" },
		"route id":   func(value *helloEnvelope) { value.Payload.RouteID = "01993ca1-1112-7aaa-8aaa-111111111111" },
		"hostname":   func(value *helloEnvelope) { value.Payload.Hostname = "other-host" },
		"cwd":        func(value *helloEnvelope) { value.Payload.CWD = "/srv/other" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := hello
			mutate(&changed)
			if verifyHelloSignature(publicKey, "fresh-nonce", changed) {
				t.Fatal("signature remained valid after transcript metadata mutation")
			}
		})
	}
	if verifyHelloSignature(publicKey, "other-nonce", hello) {
		t.Fatal("signature remained valid for a different challenge")
	}
}

func TestHelloValidationRequiresUUIDv7AndBoundedDisplayMetadata(t *testing.T) {
	valid := helloPayload{
		ClientPublicKey: "ed25519:" + base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
		RouteID:         "01993ca1-1111-7aaa-8aaa-111111111111",
		Hostname:        "host",
		CWD:             "/srv/project",
		Signature:       base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
	}
	if err := validateHelloPayload(valid); err != nil {
		t.Fatalf("valid hello payload rejected: %v", err)
	}

	invalidRoute := valid
	invalidRoute.RouteID = "01993ca1-1111-4aaa-8aaa-111111111111"
	if err := validateHelloPayload(invalidRoute); err == nil {
		t.Fatal("UUIDv4 route was accepted")
	}
	overlongCWD := valid
	overlongCWD.CWD = strings.Repeat("x", maxCWDBytes+1)
	if err := validateHelloPayload(overlongCWD); err == nil {
		t.Fatal("over-limit cwd was accepted")
	}
	overlongHostname := valid
	overlongHostname.Hostname = strings.Repeat("x", maxHostnameBytes+1)
	if err := validateHelloPayload(overlongHostname); err == nil {
		t.Fatal("over-limit hostname was accepted")
	}
}
