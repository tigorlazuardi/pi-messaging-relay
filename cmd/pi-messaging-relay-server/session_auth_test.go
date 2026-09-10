package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
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

func TestSessionAndProtocolAuditFailureReachesFatalRuntimeOwner(t *testing.T) {
	for _, event := range []string{"auth_rejected", "protocol_rejected", "operation_denied", "operation_settled"} {
		t.Run(event, func(t *testing.T) {
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

			service.writeAudit(logEvent{Event: event})

			select {
			case <-reporter.reported:
				if !errors.Is(reporter.err(), auditFailure) ||
					!strings.Contains(reporter.err().Error(), event) {
					t.Fatalf("fatal %s audit error = %v", event, reporter.err())
				}
			default:
				t.Fatalf("%s audit failure did not reach fatal runtime owner", event)
			}
		})
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

func TestAuthenticatedWebSocketProtocolBoundary(t *testing.T) {
	const (
		requestID  = "01993c84-5d38-7d75-8bc1-f945bfa42cdf"
		messageID  = "01993c84-fc2b-7e1c-af99-61b8118ac6df"
		deliveryID = "01993c85-d827-7cd9-966c-07aa3ee42e47"
	)

	var logs bytes.Buffer
	logger := newEventLogger(&logs)
	t.Cleanup(func() { _ = logger.close() })
	reporter := newFatalRuntimeReporter()
	pairing, err := newPairingService(t.TempDir(), "", logger, reporter.report)
	if err != nil {
		t.Fatalf("create pairing service: %v", err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate installation key: %v", err)
	}
	encodedKey := "ed25519:" + base64.StdEncoding.EncodeToString(publicKey)
	pairing.mu.Lock()
	pairing.allowlist.Clients = []allowlistClient{{ClientID: "cli_protocol", PublicKey: encodedKey}}
	pairing.mu.Unlock()

	registry := newSessionConnectionRegistry()
	service := newSessionAuthService(pairing, registry, logger, reporter.report)
	var dispatched atomic.Int32
	var listDispatched atomic.Bool
	var receivedDispatched atomic.Bool
	service.dispatchOperation = func(_ context.Context, _ *authenticatedSession, operation clientOperation) (operationResponse, bool, error) {
		if operation.List != nil {
			listDispatched.Store(true)
			return operationResponse{}, false, nil
		}
		if operation.Received != nil {
			receivedDispatched.Store(true)
			return operationResponse{}, false, nil
		}
		if operation.Type != "send" || operation.Send == nil {
			return operationResponse{}, false, nil
		}
		status := "denied"
		reason := "not_authorized"
		outcome := "denied"
		code := "not_authorized"
		if dispatched.Add(1) == 2 {
			status = "received"
			reason = ""
			outcome = "settled"
			code = "received"
		}
		return operationResponse{
			Type: "send_result",
			Payload: sendResultPayload{
				MessageID: operation.Send.MessageID,
				Status:    status,
				Reason:    reason,
			},
			Outcome: outcome,
			Code:    code,
		}, true, nil
	}
	server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
	t.Cleanup(server.Close)
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")

	validSend := fmt.Sprintf(`{"v":1,"type":"send","request_id":%q,"payload":{"message_id":%q,"to":"/srv/peer@host#01993ca2-2222-7bbb-9bbb-222222222222","body":"safe-body"}}`, requestID, messageID)
	cases := []struct {
		name          string
		messageType   websocket.MessageType
		frame         string
		code          string
		wantRequestID bool
	}{
		{name: "malformed JSON", messageType: websocket.MessageText, frame: `{"v":`, code: "invalid_frame"},
		{name: "trailing JSON", messageType: websocket.MessageText, frame: validSend + `{}`, code: "invalid_frame"},
		{name: "invalid UTF-8", messageType: websocket.MessageText, frame: string([]byte{0xff, 0xfe}), code: "invalid_frame"},
		{name: "duplicate envelope key", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"send","type":"list","request_id":%q,"payload":{}}`, requestID), code: "invalid_envelope", wantRequestID: true},
		{name: "duplicate request key", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"list","request_id":%q,"request_id":%q,"payload":{}}`, requestID, requestID), code: "invalid_envelope"},
		{name: "duplicate typed payload key", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"send","request_id":%q,"payload":{"message_id":%q,"message_id":%q,"to":"peer","body":"x"}}`, requestID, messageID, messageID), code: "invalid_envelope", wantRequestID: true},
		{name: "duplicate nested body key", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"send","request_id":%q,"payload":{"message_id":%q,"to":"peer","body":{"nested":{"same":1,"same":2}}}}`, requestID, messageID), code: "invalid_envelope", wantRequestID: true},
		{name: "unknown envelope field", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"list","request_id":%q,"payload":{},"extra":true}`, requestID), code: "invalid_envelope", wantRequestID: true},
		{name: "unknown payload field", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"list","request_id":%q,"payload":{"extra":true}}`, requestID), code: "invalid_envelope", wantRequestID: true},
		{name: "array envelope", messageType: websocket.MessageText, frame: `[]`, code: "invalid_envelope"},
		{name: "null envelope", messageType: websocket.MessageText, frame: `null`, code: "invalid_envelope"},
		{name: "scalar envelope", messageType: websocket.MessageText, frame: `true`, code: "invalid_envelope"},
		{name: "binary frame", messageType: websocket.MessageBinary, frame: validSend, code: "invalid_frame"},
		{name: "unsupported major", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":2,"type":"list","request_id":%q,"payload":{}}`, requestID), code: "unsupported_protocol", wantRequestID: true},
		{name: "noninteger major", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1.0,"type":"list","request_id":%q,"payload":{}}`, requestID), code: "invalid_envelope", wantRequestID: true},
		{name: "unknown type", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"future","request_id":%q,"payload":{}}`, requestID), code: "invalid_envelope", wantRequestID: true},
		{name: "wrong-direction type", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"message","request_id":%q,"payload":{}}`, requestID), code: "invalid_envelope", wantRequestID: true},
		{name: "list payload null", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"list","request_id":%q,"payload":null}`, requestID), code: "invalid_envelope", wantRequestID: true},
		{name: "list payload array", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"list","request_id":%q,"payload":[]}`, requestID), code: "invalid_envelope", wantRequestID: true},
		{name: "send missing body", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"send","request_id":%q,"payload":{"message_id":%q,"to":"peer"}}`, requestID, messageID), code: "invalid_envelope", wantRequestID: true},
		{name: "send scalar payload", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"send","request_id":%q,"payload":1}`, requestID), code: "invalid_envelope", wantRequestID: true},
		{name: "send wrong address type", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"send","request_id":%q,"payload":{"message_id":%q,"to":12,"body":"x"}}`, requestID, messageID), code: "invalid_envelope", wantRequestID: true},
		{name: "send oversized address", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"send","request_id":%q,"payload":{"message_id":%q,"to":%q,"body":"x"}}`, requestID, messageID, strings.Repeat("a", maxAddressBytes+1)), code: "invalid_envelope", wantRequestID: true},
		{name: "send body array", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"send","request_id":%q,"payload":{"message_id":%q,"to":"peer","body":[]}}`, requestID, messageID), code: "invalid_envelope", wantRequestID: true},
		{name: "send body null", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"send","request_id":%q,"payload":{"message_id":%q,"to":"peer","body":null}}`, requestID, messageID), code: "invalid_envelope", wantRequestID: true},
		{name: "send empty address", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"send","request_id":%q,"payload":{"message_id":%q,"to":"","body":"x"}}`, requestID, messageID), code: "invalid_envelope", wantRequestID: true},
		{name: "send unknown field", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"send","request_id":%q,"payload":{"message_id":%q,"to":"peer","body":"x","extra":1}}`, requestID, messageID), code: "invalid_envelope", wantRequestID: true},
		{name: "received missing delivery", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"received","request_id":%q,"payload":{"message_id":%q}}`, requestID, messageID), code: "invalid_envelope", wantRequestID: true},
		{name: "received scalar payload", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"received","request_id":%q,"payload":"ack"}`, requestID), code: "invalid_envelope", wantRequestID: true},
		{name: "received unknown field", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"received","request_id":%q,"payload":{"delivery_id":%q,"message_id":%q,"extra":1}}`, requestID, deliveryID, messageID), code: "invalid_envelope", wantRequestID: true},
		{name: "invalid request UUIDv7", messageType: websocket.MessageText, frame: `{"v":1,"type":"list","request_id":"01993c84-5d38-4d75-8bc1-f945bfa42cdf","payload":{}}`, code: "invalid_envelope"},
		{name: "invalid message UUIDv7", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"send","request_id":%q,"payload":{"message_id":"01993c84-fc2b-4e1c-af99-61b8118ac6df","to":"peer","body":"x"}}`, requestID), code: "invalid_envelope", wantRequestID: true},
		{name: "invalid re UUIDv7", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"send","request_id":%q,"payload":{"message_id":%q,"to":"peer","body":"x","re":"nope"}}`, requestID, messageID), code: "invalid_envelope", wantRequestID: true},
		{name: "invalid delivery UUIDv7", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"received","request_id":%q,"payload":{"delivery_id":"nope","message_id":%q}}`, requestID, messageID), code: "invalid_envelope", wantRequestID: true},
	}

	for index, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			connection, err := openAuthenticatedTestSession(endpoint, privateKey, encodedKey, fmt.Sprintf("01993ca1-1111-7aaa-8aaa-%012x", index+1), "host", "/protocol")
			if err != nil {
				t.Fatalf("authenticate protocol client: %v", err)
			}
			t.Cleanup(func() { _ = connection.CloseNow() })
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := connection.Write(ctx, testCase.messageType, []byte(testCase.frame)); err != nil {
				t.Fatalf("write invalid frame: %v", err)
			}
			responseType, responseData, err := connection.Read(ctx)
			if err != nil {
				t.Fatalf("read protocol error: %v", err)
			}
			if responseType != websocket.MessageText {
				t.Fatalf("protocol response frame type = %v", responseType)
			}
			var response websocketErrorEnvelope
			if err := json.Unmarshal(responseData, &response); err != nil {
				t.Fatalf("decode protocol error: %v", err)
			}
			var responseFields map[string]json.RawMessage
			if err := json.Unmarshal(responseData, &responseFields); err != nil {
				t.Fatalf("inspect protocol error: %v", err)
			}
			if response.Version != 1 || response.Type != "error" || response.Payload.Code != testCase.code || !response.Payload.Close {
				t.Fatalf("protocol response = %+v", response)
			}
			_, hasRequestID := responseFields["request_id"]
			if testCase.wantRequestID && (response.RequestID != requestID || !hasRequestID) {
				t.Fatalf("request_id = %q (present %t), want safe correlation %q", response.RequestID, hasRequestID, requestID)
			}
			if !testCase.wantRequestID && hasRequestID {
				t.Fatalf("unsafe request_id unexpectedly returned: %s", responseData)
			}
			if _, _, err := connection.Reader(ctx); err == nil {
				t.Fatal("peer remained open after protocol rejection")
			}
		})
	}

	t.Run("exact frame ceiling dispatches and denial keeps connection open", func(t *testing.T) {
		connection, err := openAuthenticatedTestSession(endpoint, privateKey, encodedKey, "01993ca1-1111-7aaa-8aaa-999999999999", "host", "/protocol")
		if err != nil {
			t.Fatalf("authenticate protocol client: %v", err)
		}
		defer connection.CloseNow()
		prefix := fmt.Sprintf(`{"v":1,"type":"send","request_id":%q,"payload":{"message_id":%q,"to":"peer","body":"`, requestID, messageID)
		suffix := `"}}`
		exact := prefix + strings.Repeat("x", maxFrameBytes-len(prefix)-len(suffix)) + suffix
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		validList := fmt.Sprintf(`{"v":1,"type":"list","request_id":%q,"payload":{}}`, requestID)
		validReceived := fmt.Sprintf(`{"v":1,"type":"received","request_id":%q,"payload":{"delivery_id":%q,"message_id":%q}}`, requestID, deliveryID, messageID)
		for _, operation := range []string{validList, validReceived} {
			if err := connection.Write(ctx, websocket.MessageText, []byte(operation)); err != nil {
				t.Fatalf("write valid operation: %v", err)
			}
		}
		operations := []string{
			exact,
			fmt.Sprintf(`{"v":1,"type":"send","request_id":%q,"payload":{"message_id":%q,"to":"peer","body":{"nested":{"allowed":true}}}}`, requestID, messageID),
		}
		wantStatuses := []string{"denied", "received"}
		for attempt, wantStatus := range wantStatuses {
			if err := connection.Write(ctx, websocket.MessageText, []byte(operations[attempt])); err != nil {
				t.Fatalf("write valid operation %d: %v", attempt, err)
			}
			var response operationResponseEnvelope
			if err := wsjson.Read(ctx, connection, &response); err != nil {
				t.Fatalf("read operation denial %d: %v", attempt, err)
			}
			payload, err := json.Marshal(response.Payload)
			if err != nil {
				t.Fatalf("encode denial payload: %v", err)
			}
			if response.Version != 1 || response.Type != "send_result" || response.RequestID != requestID || !strings.Contains(string(payload), `"status":"`+wantStatus+`"`) {
				t.Fatalf("operation denial %d = %+v", attempt, response)
			}
		}
		if !listDispatched.Load() || !receivedDispatched.Load() {
			t.Fatalf("valid typed operations did not all reach dispatcher: list=%t received=%t", listDispatched.Load(), receivedDispatched.Load())
		}
	})

	t.Run("fragmented oversized message closes", func(t *testing.T) {
		connection, err := openAuthenticatedTestSession(endpoint, privateKey, encodedKey, "01993ca1-1111-7aaa-8aaa-888888888888", "host", "/protocol")
		if err != nil {
			t.Fatalf("authenticate protocol client: %v", err)
		}
		defer connection.CloseNow()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		writer, err := connection.Writer(ctx, websocket.MessageText)
		if err != nil {
			t.Fatalf("open fragmented writer: %v", err)
		}
		chunk := bytes.Repeat([]byte("x"), 64*1024)
		for written := 0; written <= maxFrameBytes; written += len(chunk) {
			if _, err := writer.Write(chunk); err != nil {
				break
			}
		}
		_ = writer.Close()
		messageType, reader, err := connection.Reader(ctx)
		if err == nil {
			if messageType != websocket.MessageText {
				t.Fatalf("oversized response type = %v", messageType)
			}
			var response websocketErrorEnvelope
			if err := json.NewDecoder(reader).Decode(&response); err != nil {
				t.Fatalf("decode oversized protocol error: %v", err)
			}
			if response.Payload.Code != "invalid_frame" || !response.Payload.Close || response.RequestID != "" {
				t.Fatalf("oversized protocol response = %+v", response)
			}
			if _, _, err := connection.Reader(ctx); err == nil {
				t.Fatal("oversized fragmented message left peer open after error")
			}
		}
	})

	settleContext, cancelSettle := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelSettle()
	if err := registry.closeAndWait(settleContext); err != nil {
		t.Fatalf("settle protocol test connections: %v", err)
	}

	if strings.Contains(logs.String(), "safe-body") || strings.Contains(logs.String(), strings.Repeat("x", 64)) {
		t.Fatalf("protocol logs exposed frame/body content: %s", logs.String())
	}
	if !strings.Contains(logs.String(), `"event":"protocol_rejected"`) ||
		!strings.Contains(logs.String(), `"event":"operation_denied"`) ||
		!strings.Contains(logs.String(), `"event":"operation_settled"`) ||
		!strings.Contains(logs.String(), `"request_id":"`+requestID+`"`) {
		t.Fatalf("protocol telemetry incomplete: %s", logs.String())
	}
}

func TestAuthenticatedWebSocketJSONNestingBoundary(t *testing.T) {
	const (
		requestID = "01993c84-5d38-7d75-8bc1-f945bfa42cdf"
		messageID = "01993c84-fc2b-7e1c-af99-61b8118ac6df"
	)

	var logs bytes.Buffer
	logger := newEventLogger(&logs)
	t.Cleanup(func() { _ = logger.close() })
	reporter := newFatalRuntimeReporter()
	pairing, err := newPairingService(t.TempDir(), "", logger, reporter.report)
	if err != nil {
		t.Fatalf("create pairing service: %v", err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate installation key: %v", err)
	}
	encodedKey := "ed25519:" + base64.StdEncoding.EncodeToString(publicKey)
	pairing.mu.Lock()
	pairing.allowlist.Clients = []allowlistClient{{ClientID: "cli_depth", PublicKey: encodedKey}}
	pairing.mu.Unlock()

	registry := newSessionConnectionRegistry()
	service := newSessionAuthService(pairing, registry, logger, reporter.report)
	var dispatched atomic.Int32
	service.dispatchOperation = func(_ context.Context, _ *authenticatedSession, operation clientOperation) (operationResponse, bool, error) {
		dispatched.Add(1)
		return operationResponse{
			Type: "send_result",
			Payload: sendResultPayload{
				MessageID: operation.Send.MessageID,
				Status:    "denied",
				Reason:    "not_authorized",
			},
			Outcome: "denied",
			Code:    "not_authorized",
		}, true, nil
	}
	server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
	t.Cleanup(server.Close)
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")

	bodyFrame := func(totalDepth int, duplicateAtDeepestObject bool) string {
		// Envelope, payload, and body objects occupy depths 1 through 3.
		arrayDepth := totalDepth - 3
		value := "true"
		if duplicateAtDeepestObject {
			arrayDepth--
			value = `{"same":1,"same":2}`
		}
		body := `{"value":` + strings.Repeat("[", arrayDepth) + value + strings.Repeat("]", arrayDepth) + `}`
		return fmt.Sprintf(`{"v":1,"type":"send","request_id":%q,"payload":{"message_id":%q,"to":"peer","body":%s}}`, requestID, messageID, body)
	}
	rootArray := func(depth int) string {
		return strings.Repeat("[", depth) + "null" + strings.Repeat("]", depth)
	}
	cases := []struct {
		name         string
		frame        string
		responseType string
		code         string
	}{
		{name: "root array at exact ceiling", frame: rootArray(maxJSONNestingDepth), code: "invalid_envelope"},
		{name: "root array one above ceiling", frame: rootArray(maxJSONNestingDepth + 1), code: "invalid_frame"},
		{name: "root array far above ceiling", frame: rootArray(4096), code: "invalid_frame"},
		{name: "nested body at exact ceiling", frame: bodyFrame(maxJSONNestingDepth, false), responseType: "send_result"},
		{name: "duplicate object at exact ceiling", frame: bodyFrame(maxJSONNestingDepth, true), code: "invalid_envelope"},
		{name: "nested body one above ceiling", frame: bodyFrame(maxJSONNestingDepth+1, false), code: "invalid_frame"},
		{name: "nested body far above ceiling", frame: bodyFrame(4096, false), code: "invalid_frame"},
	}
	for index, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			connection, err := openAuthenticatedTestSession(
				endpoint,
				privateKey,
				encodedKey,
				fmt.Sprintf("01993ca1-1111-7aaa-8aaa-%012x", index+100),
				"host",
				"/depth",
			)
			if err != nil {
				t.Fatalf("authenticate depth client: %v", err)
			}
			defer connection.CloseNow()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := connection.Write(ctx, websocket.MessageText, []byte(testCase.frame)); err != nil {
				t.Fatalf("write nesting frame: %v", err)
			}
			_, responseData, err := connection.Read(ctx)
			if err != nil {
				t.Fatalf("read nesting response: %v", err)
			}
			var response operationResponseEnvelope
			if err := json.Unmarshal(responseData, &response); err != nil {
				t.Fatalf("decode nesting response: %v", err)
			}
			if testCase.responseType != "" {
				if response.Type != testCase.responseType || response.RequestID != requestID {
					t.Fatalf("accepted nesting response = %s", responseData)
				}
				return
			}
			payload, err := json.Marshal(response.Payload)
			if err != nil {
				t.Fatalf("encode nesting error payload: %v", err)
			}
			if response.Type != "error" || !strings.Contains(string(payload), `"code":"`+testCase.code+`"`) {
				t.Fatalf("nesting rejection = %s", responseData)
			}
			if _, _, err := connection.Reader(ctx); err == nil {
				t.Fatal("nesting rejection left peer open")
			}
		})
	}

	settleContext, cancelSettle := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelSettle()
	if err := registry.closeAndWait(settleContext); err != nil {
		t.Fatalf("settle nesting test connections: %v", err)
	}
	if got := dispatched.Load(); got != 1 {
		t.Fatalf("nesting dispatcher count = %d, want exact-boundary body only", got)
	}
	select {
	case <-reporter.reported:
		t.Fatalf("nesting rejection caused fatal runtime failure: %v", reporter.err())
	default:
	}
}

func TestInvalidDispatcherResponseReachesFatalOwnerWithoutWireOrAuditLeak(t *testing.T) {
	const (
		requestID  = "01993c84-5d38-7d75-8bc1-f945bfa42cdf"
		messageID  = "01993c84-fc2b-7e1c-af99-61b8118ac6df"
		bodyMarker = "dispatcher-body-must-not-leak"
	)

	var logs bytes.Buffer
	logger := newEventLogger(&logs)
	t.Cleanup(func() { _ = logger.close() })
	reporter := newFatalRuntimeReporter()
	var fatalReports atomic.Int32
	reportFatal := func(err error) {
		fatalReports.Add(1)
		reporter.report(err)
	}
	pairing, err := newPairingService(t.TempDir(), "", logger, reportFatal)
	if err != nil {
		t.Fatalf("create pairing service: %v", err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate installation key: %v", err)
	}
	encodedKey := "ed25519:" + base64.StdEncoding.EncodeToString(publicKey)
	pairing.mu.Lock()
	pairing.allowlist.Clients = []allowlistClient{{ClientID: "cli_invalid_response", PublicKey: encodedKey}}
	pairing.mu.Unlock()

	registry := newSessionConnectionRegistry()
	service := newSessionAuthService(pairing, registry, logger, reportFatal)
	service.dispatchOperation = func(_ context.Context, _ *authenticatedSession, _ clientOperation) (operationResponse, bool, error) {
		return operationResponse{
			Type: "send_result",
			Payload: struct {
				Body    string        `json:"body"`
				Invalid chan struct{} `json:"invalid"`
			}{Body: bodyMarker, Invalid: make(chan struct{})},
			Outcome: "settled",
			Code:    "received",
		}, true, nil
	}
	server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
	t.Cleanup(server.Close)
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")
	connection, err := openAuthenticatedTestSession(
		endpoint,
		privateKey,
		encodedKey,
		"01993ca1-1111-7aaa-8aaa-777777777777",
		"host",
		"/invalid-response",
	)
	if err != nil {
		t.Fatalf("authenticate invalid-response client: %v", err)
	}
	defer connection.CloseNow()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	frame := fmt.Sprintf(`{"v":1,"type":"send","request_id":%q,"payload":{"message_id":%q,"to":"peer","body":%q}}`, requestID, messageID, bodyMarker)
	if err := connection.Write(ctx, websocket.MessageText, []byte(frame)); err != nil {
		t.Fatalf("write operation with invalid dispatcher response: %v", err)
	}
	select {
	case <-reporter.reported:
	case <-ctx.Done():
		t.Fatalf("wait for fatal response ownership: %v", ctx.Err())
	}
	_, responseData, readErr := connection.Read(ctx)
	if readErr == nil {
		t.Fatalf("invalid dispatcher response reached wire: %s", responseData)
	}
	if len(responseData) != 0 || strings.Contains(readErr.Error(), bodyMarker) {
		t.Fatalf("invalid dispatcher response leaked body: data=%q error=%v", responseData, readErr)
	}

	settleContext, cancelSettle := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelSettle()
	if err := registry.closeAndWait(settleContext); err != nil {
		t.Fatalf("settle invalid-response connection: %v", err)
	}
	fatalErr := reporter.err()
	if fatalReports.Load() != 1 || fatalErr == nil ||
		!strings.Contains(fatalErr.Error(), "prepare send operation response") ||
		!strings.Contains(fatalErr.Error(), requestID) {
		t.Fatalf("fatal response ownership = count %d, error %v", fatalReports.Load(), fatalErr)
	}
	if strings.Contains(fatalErr.Error(), bodyMarker) || strings.Contains(logs.String(), bodyMarker) {
		t.Fatalf("dispatcher response body leaked: fatal=%v logs=%s", fatalErr, logs.String())
	}
	if strings.Contains(logs.String(), `"event":"operation_settled"`) ||
		strings.Contains(logs.String(), `"event":"operation_denied"`) {
		t.Fatalf("invalid dispatcher response emitted misleading operation event: %s", logs.String())
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
