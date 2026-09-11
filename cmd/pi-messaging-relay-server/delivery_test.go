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
	mu      sync.Mutex
	buffer  bytes.Buffer
	changed chan struct{}
}

func (buffer *lockedBuffer) Write(data []byte) (int, error) {
	buffer.mu.Lock()
	written, err := buffer.buffer.Write(data)
	buffer.mu.Unlock()
	if buffer.changed != nil {
		select {
		case buffer.changed <- struct{}{}:
		default:
		}
	}
	return written, err
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

	const (
		objectBodyMarker = "object-delivery-body-must-stay-private"
		objectRequestID  = "01993c83-1111-7aaa-8aaa-111111111111"
		objectMessageID  = "01993c83-2222-7aaa-8aaa-222222222222"
	)
	objectFrame := fmt.Sprintf(`{"v":1,"type":"send","request_id":%q,"payload":{"message_id":%q,"to":%q,"body":{"private":%q,"2":"two","10":"ten"}}}`,
		objectRequestID, objectMessageID, "/recipient@host#01993ca1-2222-7aaa-8aaa-222222222222", objectBodyMarker)
	if err := sender.Write(ctx, websocket.MessageText, []byte(objectFrame)); err != nil {
		t.Fatalf("write accepted object send: %v", err)
	}
	var objectOffer messageEnvelope
	if err := wsjson.Read(ctx, recipient, &objectOffer); err != nil {
		t.Fatalf("read object recipient offer: %v", err)
	}
	if objectOffer.Payload.MessageID != objectMessageID ||
		string(objectOffer.Payload.Body) != `{"private":"`+objectBodyMarker+`","2":"two","10":"ten"}` {
		t.Fatalf("object delivery offer = %+v body=%s", objectOffer, objectOffer.Payload.Body)
	}
	objectACK := fmt.Sprintf(`{"v":1,"type":"received","request_id":"01993c83-3333-7aaa-8aaa-333333333333","payload":{"delivery_id":%q,"message_id":%q}}`,
		objectOffer.Payload.DeliveryID, objectMessageID)
	if err := recipient.Write(ctx, websocket.MessageText, []byte(objectACK)); err != nil {
		t.Fatalf("acknowledge object offer: %v", err)
	}
	var objectResult operationResponseEnvelope
	if err := wsjson.Read(ctx, sender, &objectResult); err != nil {
		t.Fatalf("read object sender result: %v", err)
	}
	encodedObjectResult, err := json.Marshal(objectResult.Payload)
	if err != nil || objectResult.Type != "send_result" || objectResult.RequestID != objectRequestID ||
		string(encodedObjectResult) != `{"message_id":"`+objectMessageID+`","status":"received"}` {
		t.Fatalf("object sender result = %+v payload=%s error=%v", objectResult, encodedObjectResult, err)
	}
	if err := sender.Write(ctx, websocket.MessageText, []byte(`{"v":1,"type":"list","request_id":"01993c83-4444-7aaa-8aaa-444444444444","payload":{}}`)); err != nil {
		t.Fatalf("write list after object settlement: %v", err)
	}
	var roster operationResponseEnvelope
	if err := wsjson.Read(ctx, sender, &roster); err != nil || roster.Type != "roster" {
		t.Fatalf("object settlement damaged sender session: response=%+v error=%v", roster, err)
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

func TestOfflineDestinationSettlesWithoutDeliveryWorkAndKeepsSenderUsable(t *testing.T) {
	const bodyMarker = "offline-body-must-stay-redacted"
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
	pairing.allowlist.Clients = []allowlistClient{{ClientID: "cli_offline", PublicKey: encodedKey}}
	pairing.mu.Unlock()

	registry := newSessionConnectionRegistryWithLimit(3)
	service := newSessionAuthService(pairing, registry, logger, reporter.report)
	dispatcher := newDeliveryDispatcher(registry)
	service.dispatchOperation = dispatcher.dispatch
	server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
	defer server.Close()
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")
	open := func(routeID, cwd string) *websocket.Conn {
		t.Helper()
		connection, openErr := openAuthenticatedTestSession(endpoint, privateKey, encodedKey, routeID, "host", cwd)
		if openErr != nil {
			t.Fatalf("authenticate %s: %v", cwd, openErr)
		}
		return connection
	}

	sender := open("01993ca1-4111-7aaa-8aaa-111111111111", "/sender")
	defer sender.CloseNow()
	departed := open("01993ca1-4222-7aaa-8aaa-222222222222", "/departed")
	departedAddress := "/departed@host#01993ca1-4222-7aaa-8aaa-222222222222"
	if err := departed.Close(websocket.StatusNormalClosure, "test departure"); err != nil {
		t.Fatalf("close formerly published recipient: %v", err)
	}
	publicationDeadline := time.Now().Add(time.Second)
	for !strings.Contains(logs.String(), `"event":"session_disconnected"`) && time.Now().Before(publicationDeadline) {
		time.Sleep(time.Millisecond)
	}
	if !strings.Contains(logs.String(), `"address":"`+departedAddress+`"`) ||
		!strings.Contains(logs.String(), `"event":"session_disconnected"`) {
		t.Fatalf("recipient departure was not observed: %s", logs.String())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	neverPublishedAddress := "/never-published@host#01993ca1-4333-7aaa-8aaa-333333333333"
	type offlineCase struct {
		requestID string
		messageID string
		address   string
	}
	cases := []offlineCase{
		{
			requestID: "01993ca1-4444-7aaa-8aaa-444444444444",
			messageID: "01993ca1-4555-7aaa-8aaa-555555555555",
			address:   departedAddress,
		},
		{
			requestID: "01993ca1-4666-7aaa-8aaa-666666666666",
			messageID: "01993ca1-4777-7aaa-8aaa-777777777777",
			address:   neverPublishedAddress,
		},
	}
	for _, current := range cases {
		frame := fmt.Sprintf(`{"v":1,"type":"send","request_id":%q,"payload":{"message_id":%q,"to":%q,"body":%q}}`,
			current.requestID, current.messageID, current.address, bodyMarker)
		if err := sender.Write(ctx, websocket.MessageText, []byte(frame)); err != nil {
			t.Fatalf("write offline send to %q: %v", current.address, err)
		}
		messageType, response, readErr := sender.Read(ctx)
		if readErr != nil {
			t.Fatalf("read offline result for %q: %v", current.address, readErr)
		}
		expected := `{"v":1,"type":"send_result","request_id":"` + current.requestID +
			`","payload":{"message_id":"` + current.messageID + `","status":"timeout","reason":"offline"}}`
		if messageType != websocket.MessageText || string(response) != expected {
			t.Fatalf("offline result = type %d %s, want %s", messageType, response, expected)
		}
	}

	if err := sender.Write(ctx, websocket.MessageText, []byte(`{"v":1,"type":"list","request_id":"01993ca1-4888-7aaa-8aaa-888888888888","payload":{}}`)); err != nil {
		t.Fatalf("write list after offline results: %v", err)
	}
	var roster operationResponseEnvelope
	if err := wsjson.Read(ctx, sender, &roster); err != nil || roster.Type != "roster" ||
		roster.RequestID != "01993ca1-4888-7aaa-8aaa-888888888888" {
		t.Fatalf("offline settlements damaged sender session: response=%+v error=%v", roster, err)
	}

	logDeadline := time.Now().Add(time.Second)
	for !strings.Contains(logs.String(), `"message_id":"`+cases[1].messageID+`"`) && time.Now().Before(logDeadline) {
		time.Sleep(time.Millisecond)
	}
	for _, current := range cases {
		var settlement map[string]any
		for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
			var event map[string]any
			if json.Unmarshal([]byte(line), &event) == nil && event["event"] == "send_settled" &&
				event["message_id"] == current.messageID {
				settlement = event
				break
			}
		}
		if settlement == nil || settlement["result"] != "settled" || settlement["reason"] != "offline" ||
			settlement["code"] != "offline" || settlement["request_id"] != current.requestID ||
			settlement["sender_route"] != "/sender@host#01993ca1-4111-7aaa-8aaa-111111111111" ||
			settlement["recipient_route"] != current.address || settlement["status"] != "timeout" ||
			settlement["body"] != redacted {
			t.Fatalf("offline telemetry for %q = %#v", current.address, settlement)
		}
		if _, exists := settlement["delivery_id"]; exists {
			t.Fatalf("offline telemetry generated delivery_id: %#v", settlement)
		}
	}
	if strings.Contains(logs.String(), bodyMarker) {
		t.Fatalf("offline telemetry leaked body: %s", logs.String())
	}
	select {
	case <-reporter.reported:
		t.Fatalf("offline result caused fatal runtime failure: %v", reporter.err())
	default:
	}
}

func TestDeliveryACKDeadlineSettlesTimeoutOnceAndKeepsConnectionsUsable(t *testing.T) {
	const bodyMarker = "ack-timeout-body-must-stay-redacted"
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
	pairing.allowlist.Clients = []allowlistClient{{ClientID: "cli_ack_timeout", PublicKey: encodedKey}}
	pairing.mu.Unlock()

	registry := newSessionConnectionRegistryWithLimit(3)
	service := newSessionAuthService(pairing, registry, logger, reporter.report)
	dispatcher := newDeliveryDispatcher(registry)
	createdDeadlines := make(chan chan time.Time, 2)
	requestedDurations := make(chan time.Duration, 2)
	stoppedDeadlines := make(chan struct{}, 2)
	dispatcher.deadlineFactory = func(duration time.Duration) deliveryDeadline {
		expired := make(chan time.Time, 1)
		requestedDurations <- duration
		createdDeadlines <- expired
		return deliveryDeadline{
			expired: expired,
			stop: func() bool {
				stoppedDeadlines <- struct{}{}
				return true
			},
		}
	}
	service.dispatchOperation = dispatcher.dispatch
	server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
	defer server.Close()
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")
	open := func(routeID, cwd string) *websocket.Conn {
		t.Helper()
		connection, openErr := openAuthenticatedTestSession(endpoint, privateKey, encodedKey, routeID, "host", cwd)
		if openErr != nil {
			t.Fatalf("authenticate %s: %v", cwd, openErr)
		}
		return connection
	}
	sender := open("01993ca1-5111-7aaa-8aaa-111111111111", "/sender")
	recipient := open("01993ca1-5222-7aaa-8aaa-222222222222", "/recipient")
	defer sender.CloseNow()
	defer recipient.CloseNow()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	const (
		requestID       = "01993ca1-5333-7aaa-8aaa-333333333333"
		messageID       = "01993ca1-5444-7aaa-8aaa-444444444444"
		secondRequestID = "01993ca1-5555-7aaa-8aaa-555555555555"
		secondMessageID = "01993ca1-5666-7aaa-8aaa-666666666666"
	)
	recipientAddress := "/recipient@host#01993ca1-5222-7aaa-8aaa-222222222222"
	senderAddress := "/sender@host#01993ca1-5111-7aaa-8aaa-111111111111"
	writeSend := func(request, message string) {
		t.Helper()
		frame := fmt.Sprintf(`{"v":1,"type":"send","request_id":%q,"payload":{"message_id":%q,"to":%q,"body":%q}}`,
			request, message, recipientAddress, bodyMarker)
		if writeErr := sender.Write(ctx, websocket.MessageText, []byte(frame)); writeErr != nil {
			t.Fatalf("write send: %v", writeErr)
		}
	}
	writeACK := func(delivery, message, request string) {
		t.Helper()
		frame := fmt.Sprintf(`{"v":1,"type":"received","request_id":%q,"payload":{"delivery_id":%q,"message_id":%q}}`,
			request, delivery, message)
		if writeErr := recipient.Write(ctx, websocket.MessageText, []byte(frame)); writeErr != nil {
			t.Fatalf("write ACK: %v", writeErr)
		}
	}

	writeSend(requestID, messageID)
	var offer messageEnvelope
	if err := wsjson.Read(ctx, recipient, &offer); err != nil {
		t.Fatalf("read unacknowledged offer: %v", err)
	}
	if offer.Payload.MessageID != messageID || string(offer.Payload.Body) != `"`+bodyMarker+`"` {
		t.Fatalf("unacknowledged offer = %+v", offer)
	}
	var expired chan time.Time
	select {
	case duration := <-requestedDurations:
		if duration != 5*time.Second {
			t.Fatalf("ACK deadline = %s, want exactly 5s", duration)
		}
	case <-ctx.Done():
		t.Fatal("deadline factory was not called")
	}
	select {
	case expired = <-createdDeadlines:
	case <-ctx.Done():
		t.Fatal("deadline trigger was not captured")
	}

	type socketRead struct {
		messageType websocket.MessageType
		data        []byte
		err         error
	}
	readResult := make(chan socketRead, 1)
	go func() {
		messageType, data, readErr := sender.Read(ctx)
		readResult <- socketRead{messageType: messageType, data: data, err: readErr}
	}()
	select {
	case early := <-readResult:
		t.Fatalf("sender result arrived before deadline trigger: type=%d data=%s error=%v", early.messageType, early.data, early.err)
	case <-time.After(25 * time.Millisecond):
	}
	expired <- time.Now()
	var timeoutResult socketRead
	select {
	case timeoutResult = <-readResult:
	case <-ctx.Done():
		t.Fatal("sender did not receive timeout result")
	}
	expectedTimeout := `{"v":1,"type":"send_result","request_id":"` + requestID +
		`","payload":{"message_id":"` + messageID + `","status":"timeout","reason":"ack_timeout"}}`
	if timeoutResult.err != nil || timeoutResult.messageType != websocket.MessageText || string(timeoutResult.data) != expectedTimeout {
		t.Fatalf("timeout result = type %d %s error=%v, want %s", timeoutResult.messageType, timeoutResult.data, timeoutResult.err, expectedTimeout)
	}
	select {
	case <-stoppedDeadlines:
	case <-ctx.Done():
		t.Fatal("expired deadline was not stopped during cleanup")
	}

	writeACK(offer.Payload.DeliveryID, messageID, "01993ca1-5777-7aaa-8aaa-777777777777")
	if err := recipient.Write(ctx, websocket.MessageText, []byte(`{"v":1,"type":"list","request_id":"01993ca1-5888-7aaa-8aaa-888888888888","payload":{}}`)); err != nil {
		t.Fatalf("write recipient list after late ACK: %v", err)
	}
	var recipientRoster operationResponseEnvelope
	if err := wsjson.Read(ctx, recipient, &recipientRoster); err != nil || recipientRoster.Type != "roster" ||
		recipientRoster.RequestID != "01993ca1-5888-7aaa-8aaa-888888888888" {
		t.Fatalf("late ACK damaged recipient connection: response=%+v error=%v", recipientRoster, err)
	}

	writeSend(secondRequestID, secondMessageID)
	var secondOffer messageEnvelope
	if err := wsjson.Read(ctx, recipient, &secondOffer); err != nil {
		t.Fatalf("read offer after timeout capacity recovery: %v", err)
	}
	if secondOffer.Payload.MessageID != secondMessageID || secondOffer.Payload.DeliveryID == offer.Payload.DeliveryID {
		t.Fatalf("second offer = %+v", secondOffer)
	}
	select {
	case duration := <-requestedDurations:
		if duration != 5*time.Second {
			t.Fatalf("second ACK deadline = %s, want exactly 5s", duration)
		}
	case <-ctx.Done():
		t.Fatal("second deadline factory was not called")
	}
	select {
	case <-createdDeadlines:
	case <-ctx.Done():
		t.Fatal("second deadline trigger was not captured")
	}
	writeACK(secondOffer.Payload.DeliveryID, secondMessageID, "01993ca1-5999-7aaa-8aaa-999999999999")
	messageType, receivedData, err := sender.Read(ctx)
	expectedReceived := `{"v":1,"type":"send_result","request_id":"` + secondRequestID +
		`","payload":{"message_id":"` + secondMessageID + `","status":"received"}}`
	if err != nil || messageType != websocket.MessageText || string(receivedData) != expectedReceived {
		t.Fatalf("received result after timeout = type %d %s error=%v, want %s", messageType, receivedData, err, expectedReceived)
	}
	select {
	case <-stoppedDeadlines:
	case <-ctx.Done():
		t.Fatal("acknowledged deadline was not stopped during cleanup")
	}

	logDeadline := time.Now().Add(time.Second)
	for !strings.Contains(logs.String(), `"message_id":"`+secondMessageID+`"`) && time.Now().Before(logDeadline) {
		time.Sleep(time.Millisecond)
	}
	var settlements []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var event map[string]any
		if json.Unmarshal([]byte(line), &event) == nil && event["event"] == "send_settled" && event["message_id"] == messageID {
			settlements = append(settlements, event)
		}
	}
	if len(settlements) != 1 {
		t.Fatalf("timeout settlement count = %d, want 1: %s", len(settlements), logs.String())
	}
	settlement := settlements[0]
	if settlement["level"] != "info" || settlement["result"] != "settled" ||
		settlement["reason"] != "ack_timeout" || settlement["code"] != "ack_timeout" ||
		settlement["type"] != "send" || settlement["request_id"] != requestID ||
		settlement["message_id"] != messageID || settlement["delivery_id"] != offer.Payload.DeliveryID ||
		settlement["sender_route"] != senderAddress || settlement["recipient_route"] != recipientAddress ||
		settlement["status"] != "timeout" || settlement["body"] != redacted {
		t.Fatalf("timeout telemetry = %#v", settlement)
	}
	if _, ok := settlement["latency_ms"].(float64); !ok {
		t.Fatalf("timeout latency is not numeric: %#v", settlement["latency_ms"])
	}
	if strings.Contains(logs.String(), bodyMarker) {
		t.Fatalf("timeout telemetry leaked body: %s", logs.String())
	}
	select {
	case <-reporter.reported:
		t.Fatalf("ACK timeout or late ACK caused fatal runtime failure: %v", reporter.err())
	default:
	}
}

func TestReadyDeadlineCannotRelabelAcknowledgementOrRecipientCancellation(t *testing.T) {
	const bodyMarker = "boundary-body-must-stay-redacted"
	logs := lockedBuffer{changed: make(chan struct{}, 1)}
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
	pairing.allowlist.Clients = []allowlistClient{{ClientID: "cli_deadline_boundary", PublicKey: encodedKey}}
	pairing.mu.Unlock()

	type deadlineRequest struct {
		duration time.Duration
		release  chan struct{}
	}
	deadlineRequests := make(chan deadlineRequest, 2)
	registry := newSessionConnectionRegistryWithLimit(3)
	service := newSessionAuthService(pairing, registry, logger, reporter.report)
	dispatcher := newDeliveryDispatcher(registry)
	dispatcher.deadlineFactory = func(duration time.Duration) deliveryDeadline {
		release := make(chan struct{})
		deadlineRequests <- deadlineRequest{duration: duration, release: release}
		<-release
		expired := make(chan time.Time, 1)
		expired <- time.Now()
		return deliveryDeadline{expired: expired, stop: func() bool { return true }}
	}
	service.dispatchOperation = dispatcher.dispatch
	server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
	defer server.Close()
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")
	open := func(routeID, cwd string) *websocket.Conn {
		t.Helper()
		connection, openErr := openAuthenticatedTestSession(endpoint, privateKey, encodedKey, routeID, "host", cwd)
		if openErr != nil {
			t.Fatalf("authenticate %s: %v", cwd, openErr)
		}
		return connection
	}

	sender := open("01993ca1-6111-7aaa-8aaa-111111111111", "/sender")
	recipient := open("01993ca1-6222-7aaa-8aaa-222222222222", "/recipient")
	observer := open("01993ca1-6333-7aaa-8aaa-333333333333", "/observer")
	defer sender.CloseNow()
	defer observer.CloseNow()
	defer recipient.CloseNow()

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	const recipientAddress = "/recipient@host#01993ca1-6222-7aaa-8aaa-222222222222"
	type rosterEnvelope struct {
		Version   int           `json:"v"`
		Type      string        `json:"type"`
		RequestID string        `json:"request_id"`
		Payload   rosterPayload `json:"payload"`
	}
	list := func(connection *websocket.Conn, requestID string) rosterEnvelope {
		t.Helper()
		frame := fmt.Sprintf(`{"v":1,"type":"list","request_id":%q,"payload":{}}`, requestID)
		if writeErr := connection.Write(ctx, websocket.MessageText, []byte(frame)); writeErr != nil {
			t.Fatalf("write list %s: %v", requestID, writeErr)
		}
		var response rosterEnvelope
		if readErr := wsjson.Read(ctx, connection, &response); readErr != nil {
			t.Fatalf("read list %s: %v", requestID, readErr)
		}
		if response.Version != 1 || response.Type != "roster" || response.RequestID != requestID {
			t.Fatalf("list %s response = %+v", requestID, response)
		}
		return response
	}
	containsRecipient := func(response rosterEnvelope) bool {
		for _, peer := range response.Payload.Peers {
			if peer.Address == recipientAddress {
				return true
			}
		}
		return false
	}
	if response := list(observer, "01993ca1-6444-7aaa-8aaa-444444444444"); !containsRecipient(response) {
		t.Fatalf("recipient was not publicly visible before boundary sends: %+v", response)
	}

	writeSend := func(requestID, messageID string) {
		t.Helper()
		frame := fmt.Sprintf(`{"v":1,"type":"send","request_id":%q,"payload":{"message_id":%q,"to":%q,"body":%q}}`,
			requestID, messageID, recipientAddress, bodyMarker)
		if writeErr := sender.Write(ctx, websocket.MessageText, []byte(frame)); writeErr != nil {
			t.Fatalf("write send %s: %v", requestID, writeErr)
		}
	}
	readOffer := func(messageID string) messageEnvelope {
		t.Helper()
		var offer messageEnvelope
		if readErr := wsjson.Read(ctx, recipient, &offer); readErr != nil {
			t.Fatalf("read offer %s: %v", messageID, readErr)
		}
		if offer.Version != 1 || offer.Type != "message" || offer.Payload.MessageID != messageID {
			t.Fatalf("offer %s = %+v", messageID, offer)
		}
		return offer
	}
	awaitDeadline := func() deadlineRequest {
		t.Helper()
		select {
		case request := <-deadlineRequests:
			if request.duration != 5*time.Second {
				t.Fatalf("ACK deadline = %s, want exactly 5s", request.duration)
			}
			return request
		case <-ctx.Done():
			t.Fatal("deadline factory did not enter")
			return deadlineRequest{}
		}
	}

	const (
		ackRequestID = "01993ca1-6555-7aaa-8aaa-555555555555"
		ackMessageID = "01993ca1-6666-7aaa-8aaa-666666666666"
	)
	writeSend(ackRequestID, ackMessageID)
	ackOffer := readOffer(ackMessageID)
	ackDeadline := awaitDeadline()
	ackFrame := fmt.Sprintf(`{"v":1,"type":"received","request_id":"01993ca1-6777-7aaa-8aaa-777777777777","payload":{"delivery_id":%q,"message_id":%q}}`,
		ackOffer.Payload.DeliveryID, ackMessageID)
	if err := recipient.Write(ctx, websocket.MessageText, []byte(ackFrame)); err != nil {
		t.Fatalf("write boundary ACK: %v", err)
	}
	list(recipient, "01993ca1-6888-7aaa-8aaa-888888888888")
	close(ackDeadline.release)
	messageType, data, err := sender.Read(ctx)
	expectedReceived := `{"v":1,"type":"send_result","request_id":"` + ackRequestID +
		`","payload":{"message_id":"` + ackMessageID + `","status":"received"}}`
	if err != nil || messageType != websocket.MessageText || string(data) != expectedReceived {
		t.Fatalf("both-ready ACK result = type %d %s error=%v, want %s", messageType, data, err, expectedReceived)
	}

	const (
		cancelRequestID = "01993ca1-6999-7aaa-8aaa-999999999999"
		cancelMessageID = "01993ca1-6aaa-7aaa-8aaa-aaaaaaaaaaaa"
	)
	writeSend(cancelRequestID, cancelMessageID)
	readOffer(cancelMessageID)
	cancelDeadline := awaitDeadline()
	if err := recipient.Close(websocket.StatusNormalClosure, "boundary cancellation"); err != nil {
		t.Fatalf("close recipient at deadline boundary: %v", err)
	}
	recipientDisconnected := func() bool {
		for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
			var event map[string]any
			if json.Unmarshal([]byte(line), &event) == nil && event["event"] == "session_disconnected" &&
				event["address"] == recipientAddress {
				return true
			}
		}
		return false
	}
	for !recipientDisconnected() {
		select {
		case <-logs.changed:
		case <-ctx.Done():
			t.Fatalf("recipient cancellation was not publicly observed: %s", logs.String())
		}
	}
	if response := list(observer, "01993ca1-6bbb-7aaa-8aaa-bbbbbbbbbbbb"); containsRecipient(response) {
		t.Fatalf("cancelled recipient remained publicly visible: %+v", response)
	}
	close(cancelDeadline.release)
	list(sender, "01993ca1-6ccc-7aaa-8aaa-cccccccccccc")

	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var event map[string]any
		if json.Unmarshal([]byte(line), &event) == nil && event["event"] == "send_settled" &&
			event["message_id"] == cancelMessageID {
			t.Fatalf("recipient cancellation was relabelled as settled: %#v", event)
		}
	}
	if strings.Contains(logs.String(), bodyMarker) {
		t.Fatalf("boundary telemetry leaked body: %s", logs.String())
	}
	select {
	case <-reporter.reported:
		t.Fatalf("deadline boundary caused fatal runtime failure: %v", reporter.err())
	default:
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
