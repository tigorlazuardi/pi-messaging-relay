package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

const testSecret = "unit-test-shared-secret"

func TestSessionEstablishmentDeadlineClosesSilentPeer(t *testing.T) {
	var logs bytes.Buffer
	logger := newEventLogger(&logs)
	t.Cleanup(func() {
		if err := logger.close(); err != nil {
			t.Errorf("close event logger: %v", err)
		}
	})
	reporter := newFatalRuntimeReporter()
	registry := newSessionConnectionRegistry()
	service := newSessionAuthService("", registry, logger, reporter.report)
	service.establishmentTimeout = 50 * time.Millisecond
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
	started := time.Now()
	_, _, err = connection.Reader(dialContext)
	if err == nil {
		t.Fatal("silent peer remained open after establishment deadline")
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
		!strings.Contains(logs.String(), `"reason":"invalid_hello"`) {
		t.Fatalf("deadline rejection log is incomplete: %s", logs.String())
	}
	if strings.Contains(logs.String(), `"request_id"`) {
		t.Fatalf("incomplete hello rejection invented request correlation: %s", logs.String())
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
	registry := newSessionConnectionRegistryWithLimit(1)
	service := newSessionAuthService("", registry, logger, reporter.report)
	server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
	t.Cleanup(server.Close)
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	first, err := openEstablishedTestSession(ctx, endpoint, "", "01993ca1-1111-7aaa-8aaa-111111111111", "host", "/first")
	if err != nil {
		t.Fatalf("open capacity-owning connection: %v", err)
	}
	t.Cleanup(func() { _ = first.CloseNow() })

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

func TestUpgradeAuthorizationUsesOneClosedRejectionSpelling(t *testing.T) {
	var logs bytes.Buffer
	logger := newEventLogger(&logs)
	t.Cleanup(func() { _ = logger.close() })
	reporter := newFatalRuntimeReporter()
	registry := newSessionConnectionRegistry()
	service := newSessionAuthService(testSecret, registry, logger, reporter.report)
	server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
	t.Cleanup(server.Close)

	longWrongValue := strings.Repeat("x", maxAuthorizationHeaderValue+1)
	cases := []struct {
		name   string
		header string
	}{
		{name: "missing header", header: ""},
		{name: "non-bearer scheme", header: "Basic dXNlcjpwYXNz"},
		{name: "scheme only", header: "Bearer"},
		{name: "wrong secret", header: "Bearer " + testSecret + "-wrong"},
		{name: "case-sensitive secret bytes", header: "Bearer " + strings.ToUpper(testSecret)},
		{name: "over-limit value", header: "Bearer " + longWrongValue},
		{name: "over-limit value without scheme", header: longWrongValue},
	}
	var referenceStatus int
	var referenceBody string
	for index, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatalf("build upgrade request: %v", err)
			}
			if testCase.header != "" {
				request.Header.Set("Authorization", testCase.header)
			}
			request.Header.Set("Upgrade", "websocket")
			request.Header.Set("Connection", "Upgrade")
			request.Header.Set("Sec-WebSocket-Version", "13")
			request.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
			response, err := server.Client().Do(request)
			if err != nil {
				t.Fatalf("submit upgrade request: %v", err)
			}
			body, readErr := io.ReadAll(response.Body)
			closeErr := response.Body.Close()
			if err := errors.Join(readErr, closeErr); err != nil {
				t.Fatalf("read rejection: %v", err)
			}
			if response.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", response.StatusCode)
			}
			if got := response.Header.Get("Content-Type"); got != "application/json" {
				t.Fatalf("content type = %q, want application/json", got)
			}
			if got := response.Header.Get("WWW-Authenticate"); got != "Bearer" {
				t.Fatalf("www-authenticate = %q, want Bearer", got)
			}
			if index == 0 {
				referenceStatus = response.StatusCode
				referenceBody = string(body)
				if referenceBody != `{"error":"not_authorized","message":"Authentication is required"}` {
					t.Fatalf("rejection body = %q", referenceBody)
				}
				return
			}
			if response.StatusCode != referenceStatus || string(body) != referenceBody {
				t.Fatalf("rejection differs from closed spelling: status %d body %q", response.StatusCode, body)
			}
		})
	}
	if count := strings.Count(logs.String(), `"event":"auth_rejected"`); count != len(cases) {
		t.Fatalf("auth_rejected count = %d, want %d; logs: %s", count, len(cases), logs.String())
	}
	if strings.Contains(logs.String(), testSecret) {
		t.Fatalf("rejection log exposed the secret: %s", logs.String())
	}
	settleContext, cancelSettle := context.WithTimeout(context.Background(), time.Second)
	defer cancelSettle()
	if err := registry.closeAndWait(settleContext); err != nil {
		t.Fatalf("settle authorization test registry: %v", err)
	}
}

func TestUpgradeAuthorizationAcceptsCaseInsensitiveBearerScheme(t *testing.T) {
	var logs bytes.Buffer
	logger := newEventLogger(&logs)
	t.Cleanup(func() { _ = logger.close() })
	reporter := newFatalRuntimeReporter()
	registry := newSessionConnectionRegistry()
	service := newSessionAuthService(testSecret, registry, logger, reporter.report)
	server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
	t.Cleanup(server.Close)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")
	for name, scheme := range map[string]string{
		"canonical": "Bearer",
		"lowercase": "bearer",
		"uppercase": "BEARER",
		"mixed":     "BeArEr",
	} {
		t.Run(name, func(t *testing.T) {
			connection, err := openEstablishedTestSession(
				ctx, endpoint, scheme+" "+testSecret,
				fmt.Sprintf("01993ca1-1111-7aaa-8aaa-%012x", len(scheme)), "host", "/scheme",
			)
			if err != nil {
				t.Fatalf("authenticate with %s scheme: %v", name, err)
			}
			_ = connection.CloseNow()
		})
	}
}

func TestAuthOffAcceptsEveryUpgradeRegardlessOfHeaders(t *testing.T) {
	var logs bytes.Buffer
	logger := newEventLogger(&logs)
	t.Cleanup(func() { _ = logger.close() })
	reporter := newFatalRuntimeReporter()
	registry := newSessionConnectionRegistry()
	service := newSessionAuthService("", registry, logger, reporter.report)
	server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
	t.Cleanup(server.Close)
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for index, header := range []string{
		"",
		"Bearer " + testSecret,
		"Bearer completely-wrong",
		"Basic dXNlcjpwYXNz",
	} {
		connection, err := openEstablishedTestSession(
			ctx, endpoint, header,
			fmt.Sprintf("01993ca1-2222-7bbb-9bbb-%012x", index), "host", "/auth-off",
		)
		if err != nil {
			t.Fatalf("auth-off upgrade rejected with header %q: %v", header, err)
		}
		_ = connection.CloseNow()
	}
	settleContext, cancelSettle := context.WithTimeout(context.Background(), time.Second)
	defer cancelSettle()
	if err := registry.closeAndWait(settleContext); err != nil {
		t.Fatalf("settle auth-off connections: %v", err)
	}
	if strings.Contains(logs.String(), `"reason":"not_authorized"`) {
		t.Fatalf("auth-off server rejected an upgrade: %s", logs.String())
	}
}

func TestAuthorizationRunsBeforeCapacityAccounting(t *testing.T) {
	var logs bytes.Buffer
	logger := newEventLogger(&logs)
	t.Cleanup(func() { _ = logger.close() })
	reporter := newFatalRuntimeReporter()
	registry := newSessionConnectionRegistryWithLimit(1)
	service := newSessionAuthService(testSecret, registry, logger, reporter.report)
	server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
	t.Cleanup(server.Close)
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	occupant, err := openEstablishedTestSession(
		ctx, endpoint, "Bearer "+testSecret,
		"01993ca1-3333-7ccc-8ccc-111111111111", "host", "/occupied",
	)
	if err != nil {
		t.Fatalf("occupy the single capacity slot: %v", err)
	}
	t.Cleanup(func() { _ = occupant.CloseNow() })

	// A rejected request must not consume the tracked slot: it reports the
	// authorization failure, never the capacity rejection.
	_, unauthorized, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Bearer wrong"}},
	})
	if unauthorized == nil || err == nil {
		t.Fatal("unauthorized dial unexpectedly upgraded")
	}
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d, want 401 even at full capacity", unauthorized.StatusCode)
	}
	_ = unauthorized.Body.Close()
	if strings.Contains(logs.String(), `"event":"session_capacity_rejected"`) {
		t.Fatalf("rejected authorization consumed capacity: %s", logs.String())
	}

	_, saturated, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Bearer " + testSecret}},
	})
	if saturated == nil || err == nil {
		t.Fatal("authorized dial at full capacity unexpectedly upgraded")
	}
	if saturated.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("authorized status = %d, want 503 after authorization", saturated.StatusCode)
	}
	_ = saturated.Body.Close()
	if !strings.Contains(logs.String(), `"event":"session_capacity_rejected"`) {
		t.Fatalf("authorized capacity rejection missing: %s", logs.String())
	}
}

func TestConcurrentDuplicateActiveRouteFailsClosedForSameAndDifferentAddresses(t *testing.T) {
	var logs bytes.Buffer
	logger := newEventLogger(&logs)
	t.Cleanup(func() { _ = logger.close() })
	reporter := newFatalRuntimeReporter()
	registry := newSessionConnectionRegistryWithLimit(4)
	service := newSessionAuthService("", registry, logger, reporter.report)
	server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
	t.Cleanup(server.Close)
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")
	const routeID = "01993ca1-1111-7aaa-8aaa-111111111111"

	original, err := openEstablishedTestSession(nil, endpoint, "", routeID, "host", "/same")
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
	attempt := func(hostname, cwd string) {
		defer started.Done()
		connection, err := openEstablishedTestSession(nil, endpoint, "", routeID, hostname, cwd)
		results <- collision{connection: connection, err: err}
	}
	// Same route UUID with different metadata, and a different route UUID that
	// composes the same complete address, must both close without a welcome.
	go attempt("other-host", "/different")
	go attempt("host", "/same")
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
	const helloRequestID = "01993c79-8ad7-79fa-83e3-9789dcaca168"
	if count := strings.Count(logs.String(), `"request_id":"`+helloRequestID+`"`); count != 3 {
		t.Fatalf("complete hello request correlation count = %d, want accepted plus two conflicts; logs: %s", count, logs.String())
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
	registry := newSessionConnectionRegistry()
	service := newSessionAuthService("", registry, logger, reporter.report)
	var dispatched atomic.Int32
	listCursors := make(chan string, 2)
	var receivedDispatched atomic.Bool
	service.dispatchOperation = func(_ context.Context, _ *authenticatedSession, operation clientOperation) (operationResponse, bool, error) {
		if operation.List != nil {
			listCursors <- operation.List.AfterAddress
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
	overLimitCursor := "cur_" + base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("a", maxAddressBytes+1)))
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
		{name: "empty list cursor", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"list","request_id":%q,"payload":{"cursor":""}}`, requestID), code: "invalid_envelope", wantRequestID: true},
		{name: "empty decoded list cursor", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"list","request_id":%q,"payload":{"cursor":"cur_"}}`, requestID), code: "invalid_envelope", wantRequestID: true},
		{name: "bad list cursor prefix", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"list","request_id":%q,"payload":{"cursor":"cGVlcg"}}`, requestID), code: "invalid_envelope", wantRequestID: true},
		{name: "bad list cursor alphabet", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"list","request_id":%q,"payload":{"cursor":"cur_cGVl+g"}}`, requestID), code: "invalid_envelope", wantRequestID: true},
		{name: "padded list cursor", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"list","request_id":%q,"payload":{"cursor":"cur_cGVlcg=="}}`, requestID), code: "invalid_envelope", wantRequestID: true},
		{name: "noncanonical list cursor", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"list","request_id":%q,"payload":{"cursor":"cur_cGVlcj"}}`, requestID), code: "invalid_envelope", wantRequestID: true},
		{name: "invalid UTF-8 list cursor", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"list","request_id":%q,"payload":{"cursor":"cur__w"}}`, requestID), code: "invalid_envelope", wantRequestID: true},
		{name: "over-limit list cursor", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"list","request_id":%q,"payload":{"cursor":%q}}`, requestID, overLimitCursor), code: "invalid_envelope", wantRequestID: true},
		{name: "wrong scalar list cursor", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"list","request_id":%q,"payload":{"cursor":12}}`, requestID), code: "invalid_envelope", wantRequestID: true},
		{name: "duplicate list cursor", messageType: websocket.MessageText, frame: fmt.Sprintf(`{"v":1,"type":"list","request_id":%q,"payload":{"cursor":"cur_cGVlcg","cursor":"cur_cGVlcg"}}`, requestID), code: "invalid_envelope", wantRequestID: true},
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
			connection, err := openEstablishedTestSession(nil, endpoint, "", fmt.Sprintf("01993ca1-1111-7aaa-8aaa-%012x", index+1), "host", "/protocol")
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
		connection, err := openEstablishedTestSession(nil, endpoint, "", "01993ca1-1111-7aaa-8aaa-999999999999", "host", "/protocol")
		if err != nil {
			t.Fatalf("authenticate protocol client: %v", err)
		}
		defer connection.CloseNow()
		prefix := fmt.Sprintf(`{"v":1,"type":"send","request_id":%q,"payload":{"message_id":%q,"to":"peer","body":"`, requestID, messageID)
		suffix := `"}}`
		exact := prefix + strings.Repeat("x", maxFrameBytes-len(prefix)-len(suffix)) + suffix
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		maximumAddress := strings.Repeat("a", maxAddressBytes)
		maximumCursor := "cur_" + base64.RawURLEncoding.EncodeToString([]byte(maximumAddress))
		if len(maximumCursor) != maxCursorBytes {
			t.Fatalf("maximum cursor length = %d, want %d", len(maximumCursor), maxCursorBytes)
		}
		validFirstList := fmt.Sprintf(`{"v":1,"type":"list","request_id":%q,"payload":{}}`, requestID)
		validNextList := fmt.Sprintf(`{"v":1,"type":"list","request_id":%q,"payload":{"cursor":%q}}`, requestID, maximumCursor)
		validReceived := fmt.Sprintf(`{"v":1,"type":"received","request_id":%q,"payload":{"delivery_id":%q,"message_id":%q}}`, requestID, deliveryID, messageID)
		for _, operation := range []string{validFirstList, validNextList, validReceived} {
			if err := connection.Write(ctx, websocket.MessageText, []byte(operation)); err != nil {
				t.Fatalf("write valid operation: %v", err)
			}
		}
		const secondMessageID = "01993c84-fc2b-7e1c-af99-61b8118ac6e0"
		operations := []string{
			exact,
			fmt.Sprintf(`{"v":1,"type":"send","request_id":%q,"payload":{"message_id":%q,"to":"peer","body":{"nested":{"allowed":true}}}}`, requestID, secondMessageID),
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
		if firstCursor, nextCursor := <-listCursors, <-listCursors; firstCursor != "" || nextCursor != maximumAddress {
			t.Fatalf("decoded list navigation values = (%q, %q)", firstCursor, nextCursor)
		}
		if !receivedDispatched.Load() {
			t.Fatal("valid received operation did not reach dispatcher")
		}
	})

	t.Run("fragmented oversized message closes", func(t *testing.T) {
		connection, err := openEstablishedTestSession(nil, endpoint, "", "01993ca1-1111-7aaa-8aaa-888888888888", "host", "/protocol")
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

	if strings.Contains(logs.String(), "safe-body") ||
		strings.Contains(logs.String(), "cur_cGVlcg") ||
		strings.Contains(logs.String(), strings.Repeat("x", 64)) {
		t.Fatalf("protocol logs exposed frame, cursor, or body content: %s", logs.String())
	}
	if !strings.Contains(logs.String(), `"event":"protocol_rejected"`) ||
		!strings.Contains(logs.String(), `"event":"operation_denied"`) ||
		!strings.Contains(logs.String(), `"event":"send_settled"`) ||
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
	registry := newSessionConnectionRegistry()
	service := newSessionAuthService("", registry, logger, reporter.report)
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
			connection, err := openEstablishedTestSession(
				nil,
				endpoint,
				"",
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
	registry := newSessionConnectionRegistry()
	service := newSessionAuthService("", registry, logger, reportFatal)
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
	connection, err := openEstablishedTestSession(
		nil, endpoint, "", "01993ca1-1111-7aaa-8aaa-777777777777", "host", "/invalid-response",
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

func TestHelloEstablishmentAcceptsOnlyClosedUnsignedPayload(t *testing.T) {
	const routeID = "01993ca1-4444-7ddd-8ddd-111111111111"
	var logs bytes.Buffer
	logger := newEventLogger(&logs)
	t.Cleanup(func() { _ = logger.close() })
	reporter := newFatalRuntimeReporter()
	registry := newSessionConnectionRegistry()
	service := newSessionAuthService("", registry, logger, reporter.report)
	server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
	t.Cleanup(server.Close)
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")

	helloFrame := func(payload string) string {
		return fmt.Sprintf(
			`{"v":1,"type":"hello","request_id":"01993c79-8ad7-79fa-83e3-9789dcaca168","payload":%s}`,
			payload,
		)
	}
	validPayload := fmt.Sprintf(`{"route_id":%q,"hostname":"host","cwd":"/establishment"}`, routeID)

	// The unchanged unsigned establishment still completes with exactly the
	// closed payload and returns the unchanged welcome limits.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	connection, _, err := websocket.Dial(ctx, endpoint, nil)
	if err != nil {
		t.Fatalf("dial establishment client: %v", err)
	}
	t.Cleanup(func() { _ = connection.CloseNow() })
	if err := wsjson.Write(ctx, connection, json.RawMessage(helloFrame(validPayload))); err != nil {
		t.Fatalf("write unsigned hello: %v", err)
	}
	var welcome welcomeEnvelope
	if err := wsjson.Read(ctx, connection, &welcome); err != nil {
		t.Fatalf("read welcome after unsigned hello: %v", err)
	}
	if welcome.Type != "welcome" || welcome.Version != 1 ||
		welcome.Payload.HeartbeatMS != heartbeatMilliseconds ||
		welcome.Payload.MaxBodyBytes != maxBodyBytes ||
		welcome.Payload.SelfAddress != "/establishment@host#"+routeID {
		t.Fatalf("welcome = %+v", welcome)
	}
	_ = connection.CloseNow()

	// v1 authentication fields are now unknown fields; a v1 client fails closed.
	legacyPayload := fmt.Sprintf(
		`{"route_id":%q,"hostname":"host","cwd":"/legacy","client_public_key":"ed25519:AAAA","signature":"AAAA"}`,
		routeID,
	)
	invalidHellos := map[string]string{
		"legacy signed fields":  helloFrame(legacyPayload),
		"missing cwd":           helloFrame(fmt.Sprintf(`{"route_id":%q,"hostname":"host"}`, routeID)),
		"unknown field":         helloFrame(fmt.Sprintf(`{"route_id":%q,"hostname":"host","cwd":"/x","extra":1}`, routeID)),
		"empty hostname":        helloFrame(fmt.Sprintf(`{"route_id":%q,"hostname":"","cwd":"/x"}`, routeID)),
		"non-UUIDv7 route":      helloFrame(`{"route_id":"01993ca1-4444-4ddd-8ddd-111111111111","hostname":"host","cwd":"/x"}`),
		"oversized cwd":         helloFrame(fmt.Sprintf(`{"route_id":%q,"hostname":"host","cwd":%q}`, routeID, strings.Repeat("x", maxCWDBytes+1))),
		"oversized hostname":    helloFrame(fmt.Sprintf(`{"route_id":%q,"hostname":%q,"cwd":"/x"}`, routeID, strings.Repeat("x", maxHostnameBytes+1))),
		"non-object payload":    helloFrame(`[]`),
		"envelope wrong type":   `{"v":1,"type":"challenge","request_id":"01993c79-8ad7-79fa-83e3-9789dcaca168","payload":{}}`,
		"non-UUIDv7 request id": fmt.Sprintf(`{"v":1,"type":"hello","request_id":"nope","payload":%s}`, validPayload),
	}
	for name, frame := range invalidHellos {
		t.Run(name, func(t *testing.T) {
			dialCtx, cancelDial := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancelDial()
			attempt, _, dialErr := websocket.Dial(dialCtx, endpoint, nil)
			if dialErr != nil {
				t.Fatalf("dial rejected-hello client: %v", dialErr)
			}
			defer attempt.CloseNow()
			if err := wsjson.Write(dialCtx, attempt, json.RawMessage(frame)); err != nil {
				t.Fatalf("write invalid hello: %v", err)
			}
			if _, _, err := attempt.Reader(dialCtx); err == nil {
				t.Fatal("invalid hello received a welcome or stayed open")
			}
		})
	}

	settleContext, cancelSettle := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelSettle()
	if err := registry.closeAndWait(settleContext); err != nil {
		t.Fatalf("settle establishment clients: %v", err)
	}
	// Audit writes drain through the logger worker after handler settlement.
	for count := 0; ; count = strings.Count(logs.String(), `"reason":"invalid_hello"`) {
		if count == len(invalidHellos) {
			break
		}
		select {
		case <-time.After(10 * time.Millisecond):
		case <-settleContext.Done():
			t.Fatalf("invalid_hello count = %d, want %d; logs: %s", count, len(invalidHellos), logs.String())
		}
	}
	if count := strings.Count(logs.String(), `"event":"auth_accepted"`); count != 1 {
		t.Fatalf("auth_accepted count = %d, want the one valid establishment; logs: %s", count, logs.String())
	}
}

// openEstablishedTestSession dials /v1/connect with an optional Authorization
// header value, completes the unsigned hello, and requires the welcome.
func openEstablishedTestSession(
	ctx context.Context,
	endpoint string,
	authorization string,
	routeID string,
	hostname string,
	cwd string,
) (*websocket.Conn, error) {
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
	}
	options := &websocket.DialOptions{}
	if authorization != "" {
		options.HTTPHeader = http.Header{"Authorization": []string{authorization}}
	}
	connection, _, err := websocket.Dial(ctx, endpoint, options)
	if err != nil {
		return nil, err
	}
	if err := wsjson.Write(ctx, connection, map[string]any{
		"v":          1,
		"type":       "hello",
		"request_id": "01993c79-8ad7-79fa-83e3-9789dcaca168",
		"payload": map[string]string{
			"route_id": routeID,
			"hostname": hostname,
			"cwd":      cwd,
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
		return nil, fmt.Errorf("unexpected establishment response %q", welcome.Type)
	}
	return connection, nil
}

func TestHelloValidationRequiresUUIDv7AndBoundedDisplayMetadata(t *testing.T) {
	valid := helloPayload{
		RouteID:  "01993ca1-1111-7aaa-8aaa-111111111111",
		Hostname: "host",
		CWD:      "/srv/project",
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
	emptyHostname := valid
	emptyHostname.Hostname = ""
	if err := validateHelloPayload(emptyHostname); err == nil {
		t.Fatal("empty hostname was accepted")
	}
}
