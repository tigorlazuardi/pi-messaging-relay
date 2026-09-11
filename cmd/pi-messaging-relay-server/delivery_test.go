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

}

func TestDeliveryShutdownPreservesFirstPendingOwner(t *testing.T) {
	tests := []struct {
		name        string
		cancelFirst bool
	}{
		{name: "shutdown first emits no send result"},
		{name: "recipient cancellation first remains settled", cancelFirst: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const (
				requestID        = "01993c87-4444-7aaa-8aaa-444444444444"
				messageID        = "01993c87-5555-7aaa-8aaa-555555555555"
				recipientRouteID = "01993c87-6666-7aaa-8aaa-666666666666"
				recipientAddress = "/recipient@host#" + recipientRouteID
				listRequestID    = "01993c87-7777-7aaa-8aaa-777777777777"
				bodyMarker       = "shutdown-owner-body-must-stay-redacted"
			)
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
			pairing.allowlist.Clients = []allowlistClient{{ClientID: "cli_shutdown_owner", PublicKey: encodedKey}}
			pairing.mu.Unlock()

			registry := newSessionConnectionRegistryWithLimit(2)
			service := newSessionAuthService(pairing, registry, logger, reporter.report)
			server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
			t.Cleanup(server.Close)
			endpoint := "ws" + strings.TrimPrefix(server.URL, "http")
			open := func(routeID, cwd string) *websocket.Conn {
				t.Helper()
				connection, openErr := openAuthenticatedTestSession(endpoint, privateKey, encodedKey, routeID, "host", cwd)
				if openErr != nil {
					t.Fatalf("authenticate %s: %v", cwd, openErr)
				}
				return connection
			}
			sender := open("01993c87-8888-7aaa-8aaa-888888888888", "/sender")
			recipient := open(recipientRouteID, "/recipient")
			t.Cleanup(func() { _ = sender.CloseNow() })
			t.Cleanup(func() { _ = recipient.CloseNow() })

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			awaitEvent := func(name string, matches func(map[string]any) bool) map[string]any {
				t.Helper()
				for {
					for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
						var event map[string]any
						if json.Unmarshal([]byte(line), &event) == nil && event["event"] == name && matches(event) {
							return event
						}
					}
					select {
					case <-logs.changed:
					case <-ctx.Done():
						t.Fatalf("timed out waiting for %s: %s", name, logs.String())
					}
				}
			}
			awaitEvent("auth_accepted", func(event map[string]any) bool { return event["address"] == recipientAddress })

			sendFrame := fmt.Sprintf(`{"v":1,"type":"send","request_id":%q,"payload":{"message_id":%q,"to":%q,"body":%q}}`,
				requestID, messageID, recipientAddress, bodyMarker)
			if err := sender.Write(ctx, websocket.MessageText, []byte(sendFrame)); err != nil {
				t.Fatalf("write pending send: %v", err)
			}
			var offer messageEnvelope
			if err := wsjson.Read(ctx, recipient, &offer); err != nil {
				t.Fatalf("read pending offer: %v", err)
			}
			if offer.Payload.MessageID != messageID || !isUUIDv7(offer.Payload.DeliveryID) {
				t.Fatalf("pending offer = %+v", offer)
			}

			beginShutdown := func() {
				t.Helper()
				const callers = 8
				start := make(chan struct{})
				var wait sync.WaitGroup
				wait.Add(callers)
				for range callers {
					go func() {
						defer wait.Done()
						<-start
						registry.beginShutdown()
					}()
				}
				close(start)
				wait.Wait()
			}
			closeRecipient := func() {
				t.Helper()
				if err := recipient.Close(websocket.StatusNormalClosure, "pending owner boundary"); err != nil {
					t.Fatalf("close recipient: %v", err)
				}
				awaitEvent("session_disconnected", func(event map[string]any) bool {
					return event["address"] == recipientAddress
				})
			}
			if test.cancelFirst {
				closeRecipient()
				beginShutdown()
			} else {
				beginShutdown()
				closeRecipient()
			}

			listFrame := fmt.Sprintf(`{"v":1,"type":"list","request_id":%q,"payload":{}}`, listRequestID)
			if err := sender.Write(ctx, websocket.MessageText, []byte(listFrame)); err != nil {
				t.Fatalf("write list shutdown barrier: %v", err)
			}
			if test.cancelFirst {
				messageType, data, readErr := sender.Read(ctx)
				expected := `{"v":1,"type":"send_result","request_id":"` + requestID +
					`","payload":{"message_id":"` + messageID + `","status":"timeout","reason":"recipient_disconnected"}}`
				if readErr != nil || messageType != websocket.MessageText || string(data) != expected {
					t.Fatalf("recipient-owned result = type %d %s error=%v, want %s", messageType, data, readErr, expected)
				}
			}
			var roster operationResponseEnvelope
			if err := wsjson.Read(ctx, sender, &roster); err != nil || roster.Version != 1 ||
				roster.Type != "roster" || roster.RequestID != listRequestID {
				t.Fatalf("shutdown list barrier = %+v error=%v", roster, err)
			}
			awaitEvent("operation_settled", func(event map[string]any) bool {
				return event["request_id"] == listRequestID
			})

			var settlements []map[string]any
			for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
				var event map[string]any
				if json.Unmarshal([]byte(line), &event) == nil && event["event"] == "send_settled" &&
					event["message_id"] == messageID {
					settlements = append(settlements, event)
				}
			}
			if !test.cancelFirst && len(settlements) != 0 {
				t.Fatalf("shutdown-owned send settlements = %#v", settlements)
			}
			if test.cancelFirst {
				if len(settlements) != 1 {
					t.Fatalf("recipient-owned settlement count = %d, want 1: %s", len(settlements), logs.String())
				}
				settlement := settlements[0]
				if settlement["request_id"] != requestID || settlement["delivery_id"] != offer.Payload.DeliveryID ||
					settlement["reason"] != "recipient_disconnected" || settlement["code"] != "recipient_disconnected" ||
					settlement["status"] != "timeout" || settlement["body"] != redacted {
					t.Fatalf("recipient-owned settlement = %#v", settlement)
				}
			}
			if strings.Contains(logs.String(), bodyMarker) {
				t.Fatalf("pending owner telemetry leaked body: %s", logs.String())
			}
			select {
			case <-reporter.reported:
				t.Fatalf("pending owner boundary caused fatal runtime failure: %v", reporter.err())
			default:
			}
		})
	}
}

func TestOversizedOfferPreservesPostInstallOwner(t *testing.T) {
	tests := []struct {
		name        string
		cancelFirst bool
	}{
		{name: "shutdown owner emits no send result"},
		{name: "recipient cancellation owner remains settled", cancelFirst: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const (
				senderRouteID    = "01993ca4-1111-7aaa-8aaa-111111111111"
				recipientRouteID = "01993ca4-2222-7aaa-8aaa-222222222222"
				requestID        = "01993ca4-3333-7aaa-8aaa-333333333333"
				messageID        = "01993ca4-4444-7aaa-8aaa-444444444444"
				listRequestID    = "01993ca4-5555-7aaa-8aaa-555555555555"
				bodyMarker       = "oversized-offer-owner-body-must-stay-redacted"
				inboundBytes     = 524288
				outboundBytes    = 528691
			)
			senderCWD := strings.Repeat("c", maxCWDBytes)
			senderHostname := strings.Repeat("h", maxHostnameBytes)
			senderAddress := senderCWD + "@" + senderHostname + "#" + senderRouteID
			recipientAddress := "/recipient@host#" + recipientRouteID

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
			pairing.allowlist.Clients = []allowlistClient{{ClientID: "cli_oversized_offer_owner", PublicKey: encodedKey}}
			pairing.mu.Unlock()

			registry := newSessionConnectionRegistryWithLimit(2)
			service := newSessionAuthService(pairing, registry, logger, reporter.report)
			dispatcher := newDeliveryDispatcher(registry)
			offerInstalled := make(chan struct{})
			releaseOffer := make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(releaseOffer) }) }
			defer release()
			dispatcher.beforeRecipientOffer = func() {
				close(offerInstalled)
				<-releaseOffer
			}
			service.dispatchOperation = dispatcher.dispatch
			server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
			t.Cleanup(server.Close)
			endpoint := "ws" + strings.TrimPrefix(server.URL, "http")
			open := func(routeID, hostname, cwd string) *websocket.Conn {
				t.Helper()
				connection, openErr := openAuthenticatedTestSession(endpoint, privateKey, encodedKey, routeID, hostname, cwd)
				if openErr != nil {
					t.Fatalf("authenticate route %s: %v", routeID, openErr)
				}
				return connection
			}
			sender := open(senderRouteID, senderHostname, senderCWD)
			recipient := open(recipientRouteID, "host", "/recipient")
			t.Cleanup(func() { _ = sender.CloseNow() })
			t.Cleanup(func() { _ = recipient.CloseNow() })

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			awaitEvent := func(name string, matches func(map[string]any) bool) map[string]any {
				t.Helper()
				for {
					for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
						var event map[string]any
						if json.Unmarshal([]byte(line), &event) == nil && event["event"] == name && matches(event) {
							return event
						}
					}
					select {
					case <-logs.changed:
					case <-ctx.Done():
						t.Fatalf("timed out waiting for %s: %s", name, logs.String())
					}
				}
			}
			awaitEvent("auth_accepted", func(event map[string]any) bool { return event["address"] == recipientAddress })

			buildSendFrame := func(body string) []byte {
				t.Helper()
				encodedBody, encodeErr := json.Marshal(body)
				if encodeErr != nil {
					t.Fatalf("encode boundary body: %v", encodeErr)
				}
				return []byte(fmt.Sprintf(`{"v":1,"type":"send","request_id":%q,"payload":{"message_id":%q,"to":%q,"body":%s}}`,
					requestID, messageID, recipientAddress, encodedBody))
			}
			body := bodyMarker
			body += strings.Repeat("x", maxFrameBytes-len(buildSendFrame(body)))
			frame := buildSendFrame(body)
			if len(frame) != inboundBytes || len(frame) > maxFrameBytes {
				t.Fatalf("legal inbound send size = %d, want exactly %d and <= %d", len(frame), inboundBytes, maxFrameBytes)
			}
			encodedBody, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("encode expected offer body: %v", err)
			}
			expectedOffer, err := json.Marshal(messageEnvelope{
				Version: 1,
				Type:    "message",
				Payload: messagePayload{
					DeliveryID: "01993ca4-6666-7aaa-8aaa-666666666666",
					MessageID:  messageID,
					From:       senderAddress,
					To:         recipientAddress,
					Body:       json.RawMessage(encodedBody),
				},
			})
			if err != nil {
				t.Fatalf("encode expected outbound offer: %v", err)
			}
			if len(expectedOffer) != outboundBytes || len(expectedOffer) <= maxFrameBytes {
				t.Fatalf("relay-created outbound offer size = %d, want exactly %d and > %d", len(expectedOffer), outboundBytes, maxFrameBytes)
			}

			if err := sender.Write(ctx, websocket.MessageText, frame); err != nil {
				t.Fatalf("write legal boundary send: %v", err)
			}
			select {
			case <-offerInstalled:
			case <-ctx.Done():
				t.Fatal("post-install offer boundary was not reached")
			}
			if test.cancelFirst {
				if err := recipient.Close(websocket.StatusNormalClosure, "claim oversized offer"); err != nil {
					t.Fatalf("close recipient at post-install boundary: %v", err)
				}
				awaitEvent("session_disconnected", func(event map[string]any) bool {
					return event["address"] == recipientAddress
				})
			} else {
				registry.beginShutdown()
			}
			release()

			listFrame := fmt.Sprintf(`{"v":1,"type":"list","request_id":%q,"payload":{}}`, listRequestID)
			if err := sender.Write(ctx, websocket.MessageText, []byte(listFrame)); err != nil {
				t.Fatalf("write post-owner list barrier: %v", err)
			}
			if test.cancelFirst {
				messageType, data, readErr := sender.Read(ctx)
				expected := `{"v":1,"type":"send_result","request_id":"` + requestID +
					`","payload":{"message_id":"` + messageID + `","status":"timeout","reason":"recipient_disconnected"}}`
				if readErr != nil || messageType != websocket.MessageText || string(data) != expected {
					t.Fatalf("recipient-owned oversized result = type %d %s error=%v, want %s", messageType, data, readErr, expected)
				}
			}
			var roster operationResponseEnvelope
			if err := wsjson.Read(ctx, sender, &roster); err != nil || roster.Version != 1 ||
				roster.Type != "roster" || roster.RequestID != listRequestID {
				t.Fatalf("post-owner list barrier = %+v error=%v", roster, err)
			}
			awaitEvent("operation_settled", func(event map[string]any) bool {
				return event["request_id"] == listRequestID
			})

			var settlements []map[string]any
			for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
				var event map[string]any
				if json.Unmarshal([]byte(line), &event) == nil && event["event"] == "send_settled" &&
					event["message_id"] == messageID {
					settlements = append(settlements, event)
				}
			}
			if test.cancelFirst {
				if len(settlements) != 1 {
					t.Fatalf("recipient-owned oversized settlement count = %d, want 1: %s", len(settlements), logs.String())
				}
				settlement := settlements[0]
				if settlement["level"] != "info" || settlement["result"] != "settled" || settlement["type"] != "send" ||
					settlement["request_id"] != requestID || settlement["message_id"] != messageID ||
					settlement["sender_route"] != senderAddress || settlement["recipient_route"] != recipientAddress ||
					settlement["reason"] != "recipient_disconnected" || settlement["code"] != "recipient_disconnected" ||
					settlement["status"] != "timeout" || settlement["body"] != redacted ||
					!isUUIDv7(fmt.Sprint(settlement["delivery_id"])) {
					t.Fatalf("recipient-owned oversized settlement = %#v", settlement)
				}
				if _, ok := settlement["latency_ms"].(float64); !ok {
					t.Fatalf("recipient-owned oversized settlement latency = %#v", settlement["latency_ms"])
				}
			} else if len(settlements) != 0 {
				t.Fatalf("shutdown-owned oversized settlements = %#v", settlements)
			}
			if strings.Contains(logs.String(), bodyMarker) {
				t.Fatalf("oversized owner telemetry leaked body fixture: %s", logs.String())
			}
			select {
			case <-reporter.reported:
				t.Fatalf("oversized owner boundary caused fatal runtime failure: %v", reporter.err())
			default:
			}
		})
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
	messageType, data, err = sender.Read(ctx)
	expectedDisconnected := `{"v":1,"type":"send_result","request_id":"` + cancelRequestID +
		`","payload":{"message_id":"` + cancelMessageID + `","status":"timeout","reason":"recipient_disconnected"}}`
	if err != nil || messageType != websocket.MessageText || string(data) != expectedDisconnected {
		t.Fatalf("both-ready recipient disconnect result = type %d %s error=%v, want %s", messageType, data, err, expectedDisconnected)
	}
	list(sender, "01993ca1-6ccc-7aaa-8aaa-cccccccccccc")

	var cancellationSettlements []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var event map[string]any
		if json.Unmarshal([]byte(line), &event) == nil && event["event"] == "send_settled" &&
			event["message_id"] == cancelMessageID {
			cancellationSettlements = append(cancellationSettlements, event)
		}
	}
	if len(cancellationSettlements) != 1 {
		t.Fatalf("recipient disconnect settlement count = %d, want 1: %s", len(cancellationSettlements), logs.String())
	}
	cancellationSettlement := cancellationSettlements[0]
	if cancellationSettlement["result"] != "settled" || cancellationSettlement["reason"] != "recipient_disconnected" ||
		cancellationSettlement["code"] != "recipient_disconnected" || cancellationSettlement["request_id"] != cancelRequestID ||
		cancellationSettlement["message_id"] != cancelMessageID || cancellationSettlement["status"] != "timeout" ||
		cancellationSettlement["body"] != redacted {
		t.Fatalf("recipient disconnect telemetry = %#v", cancellationSettlement)
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

func TestOfferWriteFailureAfterRecipientUnpublishesReturnsRecipientDisconnected(t *testing.T) {
	const (
		requestID        = "01993ca3-1111-7aaa-8aaa-111111111111"
		messageID        = "01993ca3-2222-7aaa-8aaa-222222222222"
		recipientAddress = "/recipient@host#01993ca3-3333-7aaa-8aaa-333333333333"
		bodyMarker       = "write-failure-body-must-stay-redacted"
	)
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
	pairing.allowlist.Clients = []allowlistClient{{ClientID: "cli_write_failure", PublicKey: encodedKey}}
	pairing.mu.Unlock()

	registry := newSessionConnectionRegistryWithLimit(2)
	service := newSessionAuthService(pairing, registry, logger, reporter.report)
	dispatcher := newDeliveryDispatcher(registry)
	writeReached := make(chan struct{})
	releaseWrite := make(chan struct{})
	dispatcher.beforeRecipientOffer = func() {
		close(writeReached)
		<-releaseWrite
	}
	service.dispatchOperation = dispatcher.dispatch
	server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
	t.Cleanup(server.Close)
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")
	open := func(routeID, cwd string) *websocket.Conn {
		t.Helper()
		connection, openErr := openAuthenticatedTestSession(endpoint, privateKey, encodedKey, routeID, "host", cwd)
		if openErr != nil {
			t.Fatalf("authenticate %s: %v", cwd, openErr)
		}
		return connection
	}
	sender := open("01993ca3-4444-7aaa-8aaa-444444444444", "/sender")
	recipient := open("01993ca3-3333-7aaa-8aaa-333333333333", "/recipient")
	t.Cleanup(func() { _ = sender.CloseNow() })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	awaitEvent := func(name string, matches func(map[string]any) bool) map[string]any {
		t.Helper()
		for {
			for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
				var event map[string]any
				if json.Unmarshal([]byte(line), &event) == nil && event["event"] == name && matches(event) {
					return event
				}
			}
			select {
			case <-logs.changed:
			case <-ctx.Done():
				t.Fatalf("timed out waiting for %s: %s", name, logs.String())
			}
		}
	}
	awaitEvent("auth_accepted", func(event map[string]any) bool { return event["address"] == recipientAddress })
	frame := fmt.Sprintf(`{"v":1,"type":"send","request_id":%q,"payload":{"message_id":%q,"to":%q,"body":%q}}`,
		requestID, messageID, recipientAddress, bodyMarker)
	if err := sender.Write(ctx, websocket.MessageText, []byte(frame)); err != nil {
		t.Fatalf("write send before recipient unpublish: %v", err)
	}
	select {
	case <-writeReached:
	case <-ctx.Done():
		t.Fatal("recipient write boundary was not reached")
	}
	if err := recipient.CloseNow(); err != nil {
		t.Fatalf("force-close recipient before offer write: %v", err)
	}
	awaitEvent("session_disconnected", func(event map[string]any) bool { return event["address"] == recipientAddress })
	close(releaseWrite)

	messageType, data, readErr := sender.Read(ctx)
	expected := `{"v":1,"type":"send_result","request_id":"` + requestID +
		`","payload":{"message_id":"` + messageID + `","status":"timeout","reason":"recipient_disconnected"}}`
	if readErr != nil || messageType != websocket.MessageText || string(data) != expected {
		t.Fatalf("write-failure result = type %d %s error=%v, want %s", messageType, data, readErr, expected)
	}
	settlement := awaitEvent("send_settled", func(event map[string]any) bool { return event["message_id"] == messageID })
	if settlement["code"] != "recipient_disconnected" || settlement["status"] != "timeout" ||
		settlement["body"] != redacted || !isUUIDv7(fmt.Sprint(settlement["delivery_id"])) ||
		strings.Contains(logs.String(), bodyMarker) {
		t.Fatalf("write-failure telemetry = %#v logs=%s", settlement, logs.String())
	}
	listFrame := `{"v":1,"type":"list","request_id":"01993ca3-5555-7aaa-8aaa-555555555555","payload":{}}`
	if err := sender.Write(ctx, websocket.MessageText, []byte(listFrame)); err != nil {
		t.Fatalf("write list after offer write failure: %v", err)
	}
	var roster operationResponseEnvelope
	if err := wsjson.Read(ctx, sender, &roster); err != nil || roster.Type != "roster" {
		t.Fatalf("sender unusable after offer write failure: response=%+v error=%v", roster, err)
	}
	select {
	case <-reporter.reported:
		t.Fatalf("offer write failure caused fatal runtime failure: %v", reporter.err())
	default:
	}
}

func TestRecipientDisconnectSettlesEverySenderWithoutReplayAndKeepsSocketsUsable(t *testing.T) {
	const (
		recipientRouteID = "01993ca2-1111-7aaa-8aaa-111111111111"
		recipientAddress = "/recipient@host#" + recipientRouteID
		senderOneAddress = "/sender-one@host#01993ca2-2222-7aaa-8aaa-222222222222"
		senderTwoAddress = "/sender-two@host#01993ca2-3333-7aaa-8aaa-333333333333"
	)
	bodyMarkers := []string{"recipient-disconnect-private-one", "recipient-disconnect-private-two"}
	requestIDs := []string{
		"01993ca2-4444-7aaa-8aaa-444444444444",
		"01993ca2-5555-7aaa-8aaa-555555555555",
	}
	messageIDs := []string{
		"01993ca2-6666-7aaa-8aaa-666666666666",
		"01993ca2-7777-7aaa-8aaa-777777777777",
	}

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
	pairing.allowlist.Clients = []allowlistClient{{ClientID: "cli_recipient_disconnect", PublicKey: encodedKey}}
	pairing.mu.Unlock()

	registry := newSessionConnectionRegistryWithLimit(4)
	service := newSessionAuthService(pairing, registry, logger, reporter.report)
	server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
	t.Cleanup(server.Close)
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")
	open := func(routeID, cwd string) *websocket.Conn {
		t.Helper()
		connection, openErr := openAuthenticatedTestSession(endpoint, privateKey, encodedKey, routeID, "host", cwd)
		if openErr != nil {
			t.Fatalf("authenticate %s: %v", cwd, openErr)
		}
		return connection
	}

	recipient := open(recipientRouteID, "/recipient")
	senderOne := open("01993ca2-2222-7aaa-8aaa-222222222222", "/sender-one")
	senderTwo := open("01993ca2-3333-7aaa-8aaa-333333333333", "/sender-two")
	t.Cleanup(func() { _ = senderOne.CloseNow() })
	t.Cleanup(func() { _ = senderTwo.CloseNow() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	awaitLog := func(name string, matches func(map[string]any) bool) map[string]any {
		t.Helper()
		for {
			for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
				var event map[string]any
				if json.Unmarshal([]byte(line), &event) == nil && event["event"] == name && matches(event) {
					return event
				}
			}
			select {
			case <-logs.changed:
			case <-ctx.Done():
				t.Fatalf("timed out waiting for %s: %s", name, logs.String())
			}
		}
	}
	awaitLog("auth_accepted", func(event map[string]any) bool { return event["address"] == senderTwoAddress })

	senders := []*websocket.Conn{senderOne, senderTwo}
	for index, sender := range senders {
		frame := fmt.Sprintf(`{"v":1,"type":"send","request_id":%q,"payload":{"message_id":%q,"to":%q,"body":%q}}`,
			requestIDs[index], messageIDs[index], recipientAddress, bodyMarkers[index])
		if err := sender.Write(ctx, websocket.MessageText, []byte(frame)); err != nil {
			t.Fatalf("write pending send %d: %v", index, err)
		}
	}
	offers := make(map[string]messageEnvelope, len(senders))
	for range senders {
		var offer messageEnvelope
		if err := wsjson.Read(ctx, recipient, &offer); err != nil {
			t.Fatalf("read pending recipient offer: %v", err)
		}
		offers[offer.Payload.MessageID] = offer
	}
	if len(offers) != 2 || offers[messageIDs[0]].Payload.DeliveryID == offers[messageIDs[1]].Payload.DeliveryID {
		t.Fatalf("distinct pending offers = %#v", offers)
	}
	if err := recipient.Close(websocket.StatusNormalClosure, "recipient unavailable before ACK"); err != nil {
		t.Fatalf("close recipient before ACK: %v", err)
	}
	awaitLog("session_disconnected", func(event map[string]any) bool { return event["address"] == recipientAddress })

	for index, sender := range senders {
		messageType, data, readErr := sender.Read(ctx)
		expected := `{"v":1,"type":"send_result","request_id":"` + requestIDs[index] +
			`","payload":{"message_id":"` + messageIDs[index] + `","status":"timeout","reason":"recipient_disconnected"}}`
		if readErr != nil || messageType != websocket.MessageText || string(data) != expected {
			t.Fatalf("recipient disconnect result %d = type %d %s error=%v, want %s", index, messageType, data, readErr, expected)
		}
	}

	settlements := make(map[string][]map[string]any, len(messageIDs))
	for _, messageID := range messageIDs {
		awaitLog("send_settled", func(event map[string]any) bool { return event["message_id"] == messageID })
	}
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var event map[string]any
		if json.Unmarshal([]byte(line), &event) == nil && event["event"] == "send_settled" {
			for _, messageID := range messageIDs {
				if event["message_id"] == messageID {
					settlements[messageID] = append(settlements[messageID], event)
				}
			}
		}
	}
	for index, messageID := range messageIDs {
		if len(settlements[messageID]) != 1 {
			t.Fatalf("settlement count for %s = %d, want 1: %s", messageID, len(settlements[messageID]), logs.String())
		}
		settlement := settlements[messageID][0]
		if settlement["level"] != "info" || settlement["result"] != "settled" ||
			settlement["reason"] != "recipient_disconnected" || settlement["code"] != "recipient_disconnected" ||
			settlement["type"] != "send" || settlement["request_id"] != requestIDs[index] ||
			settlement["delivery_id"] != offers[messageID].Payload.DeliveryID ||
			settlement["recipient_route"] != recipientAddress || settlement["status"] != "timeout" ||
			settlement["body"] != redacted {
			t.Fatalf("recipient disconnect telemetry for %s = %#v", messageID, settlement)
		}
		wantSender := senderOneAddress
		if index == 1 {
			wantSender = senderTwoAddress
		}
		if settlement["sender_route"] != wantSender {
			t.Fatalf("sender route for %s = %#v, want %s", messageID, settlement["sender_route"], wantSender)
		}
		if _, ok := settlement["latency_ms"].(float64); !ok {
			t.Fatalf("latency for %s is not numeric: %#v", messageID, settlement["latency_ms"])
		}
	}
	for _, marker := range bodyMarkers {
		if strings.Contains(logs.String(), marker) {
			t.Fatalf("recipient disconnect telemetry leaked body marker %q: %s", marker, logs.String())
		}
	}

	list := func(connection *websocket.Conn, requestID string) {
		t.Helper()
		frame := fmt.Sprintf(`{"v":1,"type":"list","request_id":%q,"payload":{}}`, requestID)
		if err := connection.Write(ctx, websocket.MessageText, []byte(frame)); err != nil {
			t.Fatalf("write list %s: %v", requestID, err)
		}
		var response operationResponseEnvelope
		if err := wsjson.Read(ctx, connection, &response); err != nil || response.Type != "roster" || response.RequestID != requestID {
			t.Fatalf("read list %s = %+v error=%v", requestID, response, err)
		}
	}
	list(senderOne, "01993ca2-8888-7aaa-8aaa-888888888888")
	list(senderTwo, "01993ca2-9999-7aaa-8aaa-999999999999")

	reconnected := open(recipientRouteID, "/recipient")
	t.Cleanup(func() { _ = reconnected.CloseNow() })
	awaitLog("auth_accepted", func(event map[string]any) bool {
		return event["address"] == recipientAddress && strings.Count(logs.String(), `"address":"`+recipientAddress+`"`) >= 3
	})
	list(reconnected, "01993ca2-aaaa-7aaa-8aaa-aaaaaaaaaaaa")
	for index, messageID := range messageIDs {
		staleACK := fmt.Sprintf(`{"v":1,"type":"received","request_id":"01993ca2-bbb%d-7aaa-8aaa-bbbbbbbbbbb%d","payload":{"delivery_id":%q,"message_id":%q}}`,
			index, index, offers[messageID].Payload.DeliveryID, messageID)
		if err := reconnected.Write(ctx, websocket.MessageText, []byte(staleACK)); err != nil {
			t.Fatalf("write stale ACK %d: %v", index, err)
		}
	}
	list(reconnected, "01993ca2-cccc-7aaa-8aaa-cccccccccccc")

	freshRequestIDs := []string{
		"01993ca2-dddd-7aaa-8aaa-dddddddddddd",
		"01993ca2-eeee-7aaa-8aaa-eeeeeeeeeeee",
	}
	freshMessageIDs := []string{
		"01993ca2-f111-7aaa-8aaa-fffffffffff1",
		"01993ca2-f222-7aaa-8aaa-fffffffffff2",
	}
	for index, sender := range senders {
		frame := fmt.Sprintf(`{"v":1,"type":"send","request_id":%q,"payload":{"message_id":%q,"to":%q,"body":"fresh"}}`,
			freshRequestIDs[index], freshMessageIDs[index], recipientAddress)
		if err := sender.Write(ctx, websocket.MessageText, []byte(frame)); err != nil {
			t.Fatalf("write fresh send %d: %v", index, err)
		}
	}
	freshOffers := make(map[string]messageEnvelope, len(senders))
	for range senders {
		var offer messageEnvelope
		if err := wsjson.Read(ctx, reconnected, &offer); err != nil {
			t.Fatalf("read fresh offer: %v", err)
		}
		freshOffers[offer.Payload.MessageID] = offer
	}
	for index, messageID := range freshMessageIDs {
		offer := freshOffers[messageID]
		if !isUUIDv7(offer.Payload.DeliveryID) || offer.Payload.DeliveryID == offers[messageIDs[index]].Payload.DeliveryID {
			t.Fatalf("fresh offer %s = %+v", messageID, offer)
		}
		ack := fmt.Sprintf(`{"v":1,"type":"received","request_id":"01993ca3-000%d-7aaa-8aaa-00000000000%d","payload":{"delivery_id":%q,"message_id":%q}}`,
			index, index, offer.Payload.DeliveryID, messageID)
		if err := reconnected.Write(ctx, websocket.MessageText, []byte(ack)); err != nil {
			t.Fatalf("ACK fresh offer %d: %v", index, err)
		}
	}
	for index, sender := range senders {
		messageType, data, readErr := sender.Read(ctx)
		expected := `{"v":1,"type":"send_result","request_id":"` + freshRequestIDs[index] +
			`","payload":{"message_id":"` + freshMessageIDs[index] + `","status":"received"}}`
		if readErr != nil || messageType != websocket.MessageText || string(data) != expected {
			t.Fatalf("fresh result %d = type %d %s error=%v, want %s", index, messageType, data, readErr, expected)
		}
	}
	select {
	case <-reporter.reported:
		t.Fatalf("recipient lifecycle caused fatal runtime failure: %v", reporter.err())
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
