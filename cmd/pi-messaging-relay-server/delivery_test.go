package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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

type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (buffer *lockedBuffer) Write(data []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.Write(data)
}

func (buffer *lockedBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.String()
}

func TestDeliverySettlesOnlyAfterExactRecipientAcknowledgement(t *testing.T) {
	const bodyMarker = "delivery-body-must-stay-redacted"
	var logs lockedBuffer
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
	pairing.allowlist.Clients = []allowlistClient{{ClientID: "cli_delivery", PublicKey: encodedKey}}
	pairing.mu.Unlock()

	registry := newSessionConnectionRegistryWithLimit(4)
	service := newSessionAuthService(pairing, registry, logger, reporter.report)
	dispatcher := newDeliveryDispatcher(registry)
	service.dispatchOperation = dispatcher.dispatch
	server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
	defer server.Close()
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")
	open := func(routeID, cwd string) *websocket.Conn {
		t.Helper()
		connection, err := openAuthenticatedTestSession(endpoint, privateKey, encodedKey, routeID, "host", cwd)
		if err != nil {
			t.Fatalf("authenticate %s: %v", cwd, err)
		}
		return connection
	}
	sender := open("01993ca1-1111-7aaa-8aaa-111111111111", "/sender")
	recipient := open("01993ca1-2222-7aaa-8aaa-222222222222", "/recipient")
	attacker := open("01993ca1-3333-7aaa-8aaa-333333333333", "/attacker")
	defer sender.CloseNow()
	defer recipient.CloseNow()
	defer attacker.CloseNow()
	publicationDeadline := time.Now().Add(time.Second)
	for !strings.Contains(logs.String(), `"address":"/attacker@host#01993ca1-3333-7aaa-8aaa-333333333333"`) && time.Now().Before(publicationDeadline) {
		time.Sleep(time.Millisecond)
	}
	if !strings.Contains(logs.String(), `"address":"/attacker@host#01993ca1-3333-7aaa-8aaa-333333333333"`) {
		t.Fatal("authenticated sessions did not publish before delivery")
	}

	const (
		requestID = "01993c84-5d38-7d75-8bc1-f945bfa42cdf"
		messageID = "01993c84-fc2b-7e1c-af99-61b8118ac6df"
	)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	const objectBodyMarker = "object-delivery-body-must-stay-private"
	objectFrame := fmt.Sprintf(`{"v":1,"type":"send","request_id":"01993c83-1111-7aaa-8aaa-111111111111","payload":{"message_id":"01993c83-2222-7aaa-8aaa-222222222222","to":%q,"body":{"private":%q}}}`,
		"/recipient@host#01993ca1-2222-7aaa-8aaa-222222222222", objectBodyMarker)
	if err := sender.Write(ctx, websocket.MessageText, []byte(objectFrame)); err != nil {
		t.Fatalf("write accepted object send: %v", err)
	}
	if err := sender.Write(ctx, websocket.MessageText, []byte(`{"v":1,"type":"list","request_id":"01993c83-3333-7aaa-8aaa-333333333333","payload":{}}`)); err != nil {
		t.Fatalf("write list after object send: %v", err)
	}
	var roster operationResponseEnvelope
	if err := wsjson.Read(ctx, sender, &roster); err != nil || roster.Type != "roster" {
		t.Fatalf("object send damaged sender session: response=%+v error=%v", roster, err)
	}
	sendFrame := fmt.Sprintf(`{"v":1,"type":"send","request_id":%q,"payload":{"message_id":%q,"to":%q,"body":%q}}`,
		requestID, messageID, "/recipient@host#01993ca1-2222-7aaa-8aaa-222222222222", bodyMarker)
	if err := sender.Write(ctx, websocket.MessageText, []byte(sendFrame)); err != nil {
		t.Fatalf("write send: %v", err)
	}
	var offer messageEnvelope
	if err := wsjson.Read(ctx, recipient, &offer); err != nil {
		t.Fatalf("read recipient offer: %v", err)
	}
	if offer.Version != 1 || offer.Type != "message" || offer.Payload.MessageID != messageID ||
		offer.Payload.From != "/sender@host#01993ca1-1111-7aaa-8aaa-111111111111" ||
		offer.Payload.To != "/recipient@host#01993ca1-2222-7aaa-8aaa-222222222222" ||
		string(offer.Payload.Body) != `"`+bodyMarker+`"` || !isUUIDv7(offer.Payload.DeliveryID) {
		t.Fatalf("delivery offer = %+v", offer)
	}

	ack := func(connection *websocket.Conn, request, delivery, message string) {
		t.Helper()
		frame := fmt.Sprintf(`{"v":1,"type":"received","request_id":%q,"payload":{"delivery_id":%q,"message_id":%q}}`,
			request, delivery, message)
		if err := connection.Write(ctx, websocket.MessageText, []byte(frame)); err != nil {
			t.Fatalf("write ACK: %v", err)
		}
	}
	ack(attacker, "01993c86-1111-7aaa-8aaa-111111111111", offer.Payload.DeliveryID, messageID)
	if err := attacker.Write(ctx, websocket.MessageText, []byte(`{"v":1,"type":"list","request_id":"01993c86-1111-7aaa-8aaa-222222222222","payload":{}}`)); err != nil {
		t.Fatalf("write list after wrong-session ACK: %v", err)
	}
	var attackerRoster operationResponseEnvelope
	if err := wsjson.Read(ctx, attacker, &attackerRoster); err != nil || attackerRoster.Type != "roster" {
		t.Fatalf("wrong-session ACK damaged healthy connection: response=%+v error=%v", attackerRoster, err)
	}
	ack(recipient, "01993c86-2222-7aaa-8aaa-222222222222", "01993c85-d827-7cd9-966c-07aa3ee42e47", messageID)
	ack(recipient, "01993c86-3333-7aaa-8aaa-333333333333", offer.Payload.DeliveryID, messageID)

	var result operationResponseEnvelope
	if err := wsjson.Read(ctx, sender, &result); err != nil {
		t.Fatalf("read sender result: %v", err)
	}
	encodedPayload, err := json.Marshal(result.Payload)
	if err != nil {
		t.Fatalf("encode result payload: %v", err)
	}
	if result.Version != 1 || result.Type != "send_result" || result.RequestID != requestID ||
		string(encodedPayload) != `{"message_id":"`+messageID+`","status":"received"}` {
		t.Fatalf("sender result = %+v payload=%s", result, encodedPayload)
	}

	deadline := time.Now().Add(time.Second)
	for !strings.Contains(logs.String(), `"message_id":"`+messageID+`"`) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if strings.Contains(logs.String(), bodyMarker) || strings.Contains(logs.String(), objectBodyMarker) ||
		!strings.Contains(logs.String(), `"event":"send_settled"`) ||
		!strings.Contains(logs.String(), `"body":"<redacted>"`) ||
		!strings.Contains(logs.String(), `"delivery_id":"`+offer.Payload.DeliveryID+`"`) ||
		!strings.Contains(logs.String(), `"sender_route":"`+offer.Payload.From+`"`) ||
		!strings.Contains(logs.String(), `"recipient_route":"`+offer.Payload.To+`"`) ||
		!strings.Contains(logs.String(), `"status":"received"`) {
		t.Fatalf("delivery telemetry not safely correlated: %s", logs.String())
	}
	select {
	case <-reporter.reported:
		t.Fatalf("ordinary wrong ACK caused fatal runtime failure: %v", reporter.err())
	default:
	}

	const pendingRequestID = "01993c87-4444-7aaa-8aaa-444444444444"
	pendingFrame := fmt.Sprintf(`{"v":1,"type":"send","request_id":%q,"payload":{"message_id":"01993c87-5555-7aaa-8aaa-555555555555","to":%q,"body":"pending"}}`,
		pendingRequestID, offer.Payload.To)
	if err := sender.Write(ctx, websocket.MessageText, []byte(pendingFrame)); err != nil {
		t.Fatalf("write pending send before shutdown: %v", err)
	}
	var pendingOffer messageEnvelope
	if err := wsjson.Read(ctx, recipient, &pendingOffer); err != nil {
		t.Fatalf("read pending offer before shutdown: %v", err)
	}
	shutdownStarted := time.Now()
	shutdown, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	if err := registry.closeAndWait(shutdown); err != nil {
		t.Fatalf("bounded registry shutdown: %v", err)
	}
	if elapsed := time.Since(shutdownStarted); elapsed >= time.Second {
		t.Fatalf("pending delivery delayed shutdown by %s", elapsed)
	}
}

func TestGeneratedServerUUIDv7IsCanonicalAndFresh(t *testing.T) {
	first, err := generateServerUUIDv7(time.UnixMilli(1_757_564_800_000))
	if err != nil {
		t.Fatalf("generate first UUID: %v", err)
	}
	second, err := generateServerUUIDv7(time.UnixMilli(1_757_564_800_000))
	if err != nil {
		t.Fatalf("generate second UUID: %v", err)
	}
	if !isUUIDv7(first) || !isUUIDv7(second) || first == second {
		t.Fatalf("generated UUIDs = %q, %q", first, second)
	}
}
