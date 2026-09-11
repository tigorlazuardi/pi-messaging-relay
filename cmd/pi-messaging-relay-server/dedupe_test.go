package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

type dedupeTestHarness struct {
	t          *testing.T
	ctx        context.Context
	cancel     context.CancelFunc
	server     *httptest.Server
	logger     *eventLogger
	logs       *lockedBuffer
	reporter   *fatalRuntimeReporter
	service    *sessionAuthService
	dispatcher *deliveryDispatcher
	privateKey ed25519.PrivateKey
	encodedKey string
}

func newDedupeTestHarness(t *testing.T) *dedupeTestHarness {
	t.Helper()
	logs := &lockedBuffer{changed: make(chan struct{}, 1)}
	logger := newEventLogger(logs)
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
	pairing.allowlist.Clients = []allowlistClient{{ClientID: "cli_dedupe", PublicKey: encodedKey}}
	pairing.mu.Unlock()
	registry := newSessionConnectionRegistryWithLimit(4)
	service := newSessionAuthService(pairing, registry, logger, reporter.report)
	dispatcher := newDeliveryDispatcher(registry)
	service.dispatchOperation = dispatcher.dispatch
	server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	harness := &dedupeTestHarness{
		t: t, ctx: ctx, cancel: cancel, server: server, logger: logger, logs: logs,
		reporter: reporter, service: service, dispatcher: dispatcher, privateKey: privateKey, encodedKey: encodedKey,
	}
	t.Cleanup(func() {
		cancel()
		server.Close()
		_ = logger.close()
	})
	return harness
}

func (h *dedupeTestHarness) open(routeID, cwd string) *websocket.Conn {
	h.t.Helper()
	endpoint := "ws" + strings.TrimPrefix(h.server.URL, "http")
	connection, err := openAuthenticatedTestSession(
		endpoint, h.privateKey, h.encodedKey, routeID, "host", cwd,
	)
	if err != nil {
		h.t.Fatalf("authenticate %s: %v", cwd, err)
	}
	h.t.Cleanup(func() { _ = connection.CloseNow() })
	address := cwd + "@host#" + routeID
	for !strings.Contains(h.logs.String(), `"address":"`+address+`"`) {
		select {
		case <-h.logs.changed:
		case <-h.ctx.Done():
			h.t.Fatalf("session %s did not publish: %s", address, h.logs.String())
		}
	}
	return connection
}

func rawSendFrame(requestID, messageID, to, body, re string) []byte {
	encodedRe := ""
	if re != "" {
		encodedRe = fmt.Sprintf(`,"re":%q`, re)
	}
	return []byte(fmt.Sprintf(
		`{"v":1,"type":"send","request_id":%q,"payload":{"message_id":%q,"to":%q,"body":%s%s}}`,
		requestID, messageID, to, body, encodedRe,
	))
}

func readResponse(t *testing.T, ctx context.Context, connection *websocket.Conn) operationResponseEnvelope {
	t.Helper()
	var response operationResponseEnvelope
	if err := wsjson.Read(ctx, connection, &response); err != nil {
		t.Fatalf("read operation response: %v", err)
	}
	return response
}

func responsePayload(t *testing.T, response operationResponseEnvelope) string {
	t.Helper()
	encoded, err := json.Marshal(response.Payload)
	if err != nil {
		t.Fatalf("encode response payload: %v", err)
	}
	return string(encoded)
}

func TestRepeatedSendFrameIsIdempotentConflictAwareAndSessionIsolated(t *testing.T) {
	h := newDedupeTestHarness(t)
	sender := h.open("01993ca1-1111-7aaa-8aaa-111111111111", "/sender")
	recipient := h.open("01993ca1-2222-7aaa-8aaa-222222222222", "/recipient")
	otherSender := h.open("01993ca1-3333-7aaa-8aaa-333333333333", "/other")
	const (
		recipientAddress = "/recipient@host#01993ca1-2222-7aaa-8aaa-222222222222"
		messageID        = "01993c84-fc2b-7e1c-af99-61b8118ac6df"
		requestOne       = "01993c84-0001-7000-8000-000000000001"
		requestRetry     = "01993c84-0002-7000-8000-000000000002"
	)

	first := rawSendFrame(requestOne, messageID, recipientAddress,
		`{"escaped":"same","nested":{"n":1,"array":[true,null]}}`, "")
	if err := sender.Write(h.ctx, websocket.MessageText, first); err != nil {
		t.Fatalf("write first send: %v", err)
	}
	var offer messageEnvelope
	if err := wsjson.Read(h.ctx, recipient, &offer); err != nil {
		t.Fatalf("read first offer: %v", err)
	}
	// Different whitespace, member order, escape spelling, and numeric spelling are one JSON value.
	retry := rawSendFrame(requestRetry, messageID, recipientAddress,
		` { "nested" : { "array" : [true,null], "n" : 1.0 }, "escaped" : "s\u0061me" } `, "")
	if err := sender.Write(h.ctx, websocket.MessageText, retry); err != nil {
		t.Fatalf("write exact pending retry: %v", err)
	}
	ack := fmt.Sprintf(
		`{"v":1,"type":"received","request_id":"01993c84-0003-7000-8000-000000000003","payload":{"delivery_id":%q,"message_id":%q}}`,
		offer.Payload.DeliveryID, messageID,
	)
	if err := recipient.Write(h.ctx, websocket.MessageText, []byte(ack)); err != nil {
		t.Fatalf("acknowledge offer: %v", err)
	}
	responses := map[string]operationResponseEnvelope{}
	for range 2 {
		response := readResponse(t, h.ctx, sender)
		responses[response.RequestID] = response
	}
	for _, requestID := range []string{requestOne, requestRetry} {
		response := responses[requestID]
		if response.Type != "send_result" || responsePayload(t, response) !=
			`{"message_id":"`+messageID+`","status":"received"}` {
			t.Fatalf("response for %s = %+v payload=%s", requestID, response, responsePayload(t, response))
		}
	}

	settledRequest := "01993c84-0004-7000-8000-000000000004"
	if err := sender.Write(h.ctx, websocket.MessageText,
		rawSendFrame(settledRequest, messageID, recipientAddress,
			`{"nested":{"array":[true,null],"n":1},"escaped":"same"}`, "")); err != nil {
		t.Fatalf("write settled duplicate: %v", err)
	}
	settled := readResponse(t, h.ctx, sender)
	if settled.RequestID != settledRequest || responsePayload(t, settled) !=
		`{"message_id":"`+messageID+`","status":"received"}` {
		t.Fatalf("settled duplicate response = %+v payload=%s", settled, responsePayload(t, settled))
	}

	conflicts := []struct {
		name      string
		requestID string
		to        string
		body      string
		re        string
	}{
		{name: "destination", requestID: "01993c84-0005-7000-8000-000000000005", to: "/different", body: `{"escaped":"same","nested":{"n":1,"array":[true,null]}}`},
		{name: "re presence", requestID: "01993c84-0006-7000-8000-000000000006", to: recipientAddress, body: `{"escaped":"same","nested":{"n":1,"array":[true,null]}}`, re: "01993c80-40de-79d7-9b2c-1349f88bb408"},
		{name: "body", requestID: "01993c84-0007-7000-8000-000000000007", to: recipientAddress, body: `{"escaped":"changed","nested":{"n":1,"array":[true,null]}}`},
	}
	for _, conflict := range conflicts {
		t.Run(conflict.name, func(t *testing.T) {
			if err := sender.Write(h.ctx, websocket.MessageText,
				rawSendFrame(conflict.requestID, messageID, conflict.to, conflict.body, conflict.re)); err != nil {
				t.Fatalf("write conflict: %v", err)
			}
			response := readResponse(t, h.ctx, sender)
			if response.RequestID != conflict.requestID || responsePayload(t, response) !=
				`{"message_id":"`+messageID+`","reason":"message_id_conflict","status":"denied"}` {
				t.Fatalf("conflict response = %+v payload=%s", response, responsePayload(t, response))
			}
		})
	}

	otherRequest := "01993c84-0008-7000-8000-000000000008"
	if err := otherSender.Write(h.ctx, websocket.MessageText,
		rawSendFrame(otherRequest, messageID, recipientAddress, `"independent"`, "")); err != nil {
		t.Fatalf("write isolated send: %v", err)
	}
	var otherOffer messageEnvelope
	if err := wsjson.Read(h.ctx, recipient, &otherOffer); err != nil {
		t.Fatalf("read isolated offer: %v", err)
	}
	if otherOffer.Payload.DeliveryID == offer.Payload.DeliveryID || otherOffer.Payload.MessageID != messageID {
		t.Fatalf("isolated offer = %+v", otherOffer)
	}
	otherACK := fmt.Sprintf(
		`{"v":1,"type":"received","request_id":"01993c84-0009-7000-8000-000000000009","payload":{"delivery_id":%q,"message_id":%q}}`,
		otherOffer.Payload.DeliveryID, messageID,
	)
	if err := recipient.Write(h.ctx, websocket.MessageText, []byte(otherACK)); err != nil {
		t.Fatalf("acknowledge isolated offer: %v", err)
	}
	if response := readResponse(t, h.ctx, otherSender); response.RequestID != otherRequest {
		t.Fatalf("isolated result = %+v", response)
	}

	for index, connection := range []*websocket.Conn{sender, recipient, otherSender} {
		requestID := fmt.Sprintf("01993c85-%04x-7aaa-8aaa-%012x", index+1, index+1)
		if err := connection.Write(h.ctx, websocket.MessageText, []byte(fmt.Sprintf(
			`{"v":1,"type":"list","request_id":%q,"payload":{}}`, requestID,
		))); err != nil {
			t.Fatalf("write health list %d: %v", index, err)
		}
		if response := readResponse(t, h.ctx, connection); response.Type != "roster" || response.RequestID != requestID {
			t.Fatalf("health response %d = %+v", index, response)
		}
	}

	logs := h.logs.String()
	if strings.Contains(logs, "same") || strings.Contains(logs, "changed") ||
		!strings.Contains(logs, `"event":"operation_denied"`) ||
		!strings.Contains(logs, `"reason":"message_id_conflict"`) ||
		!strings.Contains(logs, `"body":"<redacted>"`) ||
		strings.Count(logs, `"event":"send_settled"`) != 2 {
		t.Fatalf("dedupe telemetry invalid: %s", logs)
	}
	select {
	case <-h.reporter.reported:
		t.Fatalf("dedupe caused fatal runtime failure: %v", h.reporter.err())
	default:
	}
}

func TestOversizedBodyDenialPrecedesDedupeAndKeepsSessionsUsable(t *testing.T) {
	h := newDedupeTestHarness(t)
	sender := h.open("01993ca6-1111-7aaa-8aaa-111111111111", "/sender")
	recipient := h.open("01993ca6-2222-7aaa-8aaa-222222222222", "/recipient")
	recipient.SetReadLimit(maxFrameBytes)
	const (
		recipientAddress = "/recipient@host#01993ca6-2222-7aaa-8aaa-222222222222"
		retainedID       = "01993ca6-3001-7aaa-8aaa-000000000001"
		freshID          = "01993ca6-3002-7aaa-8aaa-000000000002"
	)
	serializedString := func(marker string, bytes int) string {
		t.Helper()
		body := `"` + marker + strings.Repeat("x", bytes-len(marker)-2) + `"`
		if len(body) != bytes {
			t.Fatalf("serialized body bytes = %d, want %d", len(body), bytes)
		}
		return body
	}
	ackOffer := func(offer messageEnvelope, messageID, requestID string) {
		t.Helper()
		ack := fmt.Sprintf(
			`{"v":1,"type":"received","request_id":%q,"payload":{"delivery_id":%q,"message_id":%q}}`,
			requestID, offer.Payload.DeliveryID, messageID,
		)
		if err := recipient.Write(h.ctx, websocket.MessageText, []byte(ack)); err != nil {
			t.Fatalf("acknowledge body-boundary offer: %v", err)
		}
	}

	const exactMarker = "exact-body-private-marker"
	exactBody := " \n" + serializedString(exactMarker, maxBodyBytes) + "\t"
	if err := sender.Write(h.ctx, websocket.MessageText, rawSendFrame(
		"01993ca6-4001-7aaa-8aaa-000000000001", retainedID, recipientAddress, exactBody, "",
	)); err != nil {
		t.Fatalf("write exact-limit body: %v", err)
	}
	var exactOffer messageEnvelope
	if err := wsjson.Read(h.ctx, recipient, &exactOffer); err != nil {
		t.Fatalf("read exact-limit offer: %v", err)
	}
	if len(exactOffer.Payload.Body) != maxBodyBytes || exactOffer.Payload.MessageID != retainedID {
		t.Fatalf("exact-limit offer body bytes = %d message=%s", len(exactOffer.Payload.Body), exactOffer.Payload.MessageID)
	}
	ackOffer(exactOffer, retainedID, "01993ca6-5001-7aaa-8aaa-000000000001")
	if response := readResponse(t, h.ctx, sender); responsePayload(t, response) !=
		`{"message_id":"`+retainedID+`","status":"received"}` {
		t.Fatalf("exact-limit response = %+v payload=%s", response, responsePayload(t, response))
	}

	const oversizedMarker = "oversized-body-private-marker"
	oversizedBody := "\t" + serializedString(oversizedMarker, maxBodyBytes+1) + " \n"
	assertDenied := func(requestID, messageID string) {
		t.Helper()
		if err := sender.Write(h.ctx, websocket.MessageText,
			rawSendFrame(requestID, messageID, recipientAddress, oversizedBody, "")); err != nil {
			t.Fatalf("write oversized body: %v", err)
		}
		response := readResponse(t, h.ctx, sender)
		if response.RequestID != requestID || response.Type != "send_result" || responsePayload(t, response) !=
			`{"message_id":"`+messageID+`","reason":"body_too_large","status":"denied"}` {
			t.Fatalf("oversized response = %+v payload=%s", response, responsePayload(t, response))
		}
	}

	// Body denial wins over an existing retained identity and does not mutate it.
	assertDenied("01993ca6-4002-7aaa-8aaa-000000000002", retainedID)
	if err := sender.Write(h.ctx, websocket.MessageText, rawSendFrame(
		"01993ca6-4003-7aaa-8aaa-000000000003", retainedID, recipientAddress, exactBody, "",
	)); err != nil {
		t.Fatalf("write retained legal duplicate: %v", err)
	}
	if response := readResponse(t, h.ctx, sender); responsePayload(t, response) !=
		`{"message_id":"`+retainedID+`","status":"received"}` {
		t.Fatalf("retained result after oversized body = %+v payload=%s", response, responsePayload(t, response))
	}

	// An unknown oversized identity creates no record; list and a later legal send remain usable.
	assertDenied("01993ca6-4004-7aaa-8aaa-000000000004", freshID)
	const listRequestID = "01993ca6-4005-7aaa-8aaa-000000000005"
	if err := sender.Write(h.ctx, websocket.MessageText, []byte(fmt.Sprintf(
		`{"v":1,"type":"list","request_id":%q,"payload":{}}`, listRequestID,
	))); err != nil {
		t.Fatalf("write list after oversized denial: %v", err)
	}
	if response := readResponse(t, h.ctx, sender); response.Type != "roster" || response.RequestID != listRequestID {
		t.Fatalf("list after oversized denial = %+v", response)
	}
	if err := sender.Write(h.ctx, websocket.MessageText, rawSendFrame(
		"01993ca6-4006-7aaa-8aaa-000000000006", freshID, recipientAddress, `"legal"`, "",
	)); err != nil {
		t.Fatalf("write legal body after oversized denial: %v", err)
	}
	var freshOffer messageEnvelope
	if err := wsjson.Read(h.ctx, recipient, &freshOffer); err != nil {
		t.Fatalf("read pollution-free legal offer: %v", err)
	}
	if freshOffer.Payload.MessageID != freshID || string(freshOffer.Payload.Body) != `"legal"` {
		t.Fatalf("pollution-free offer = %+v body=%s", freshOffer, freshOffer.Payload.Body)
	}
	ackOffer(freshOffer, freshID, "01993ca6-5002-7aaa-8aaa-000000000002")
	if response := readResponse(t, h.ctx, sender); responsePayload(t, response) !=
		`{"message_id":"`+freshID+`","status":"received"}` {
		t.Fatalf("legal response after oversized denial = %+v payload=%s", response, responsePayload(t, response))
	}

	deadline := time.Now().Add(time.Second)
	for strings.Count(h.logs.String(), `"reason":"body_too_large"`) < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	logs := h.logs.String()
	if strings.Contains(logs, exactMarker) || strings.Contains(logs, oversizedMarker) {
		t.Fatalf("oversized body telemetry leaked body fixture: %s", logs)
	}
	denials := 0
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("decode telemetry line: %v", err)
		}
		if event["event"] != "operation_denied" || event["reason"] != "body_too_large" {
			continue
		}
		denials++
		if event["result"] != "denied" || event["code"] != "body_too_large" ||
			event["type"] != "send" || event["status"] != "denied" ||
			event["sender_route"] != "/sender@host#01993ca6-1111-7aaa-8aaa-111111111111" ||
			event["body"] != redacted || event["request_id"] == nil || event["message_id"] == nil {
			t.Fatalf("oversized body denial telemetry = %#v", event)
		}
		if _, exists := event["recipient_route"]; exists {
			t.Fatalf("oversized denial derived recipient route: %#v", event)
		}
	}
	if denials != 2 {
		t.Fatalf("oversized body denial event count = %d, want 2: %s", denials, logs)
	}
	select {
	case <-h.reporter.reported:
		t.Fatalf("oversized body caused fatal runtime failure: %v", h.reporter.err())
	default:
	}
}

func TestRecipientDedupeWindowEvictsOldestSettledInsertionAt1025(t *testing.T) {
	h := newDedupeTestHarness(t)
	sender := h.open("01993ca2-1111-7aaa-8aaa-111111111111", "/sender")
	recipient := h.open("01993ca2-2222-7aaa-8aaa-222222222222", "/recipient")
	const recipientAddress = "/recipient@host#01993ca2-2222-7aaa-8aaa-222222222222"
	messageID := func(index int) string {
		return fmt.Sprintf("01993c90-%04x-7aaa-8aaa-%012x", index, index)
	}
	requestID := func(index int) string {
		return fmt.Sprintf("01993c91-%04x-7aaa-8aaa-%012x", index, index)
	}

	for index := 1; index <= 1025; index++ {
		if err := sender.Write(h.ctx, websocket.MessageText,
			rawSendFrame(requestID(index), messageID(index), recipientAddress, fmt.Sprintf(`{"index":%d}`, index), "")); err != nil {
			t.Fatalf("write send %d: %v", index, err)
		}
		var offer messageEnvelope
		if err := wsjson.Read(h.ctx, recipient, &offer); err != nil {
			t.Fatalf("read offer %d: %v", index, err)
		}
		ack := fmt.Sprintf(
			`{"v":1,"type":"received","request_id":%q,"payload":{"delivery_id":%q,"message_id":%q}}`,
			fmt.Sprintf("01993c92-%04x-7aaa-8aaa-%012x", index, index), offer.Payload.DeliveryID, messageID(index),
		)
		if err := recipient.Write(h.ctx, websocket.MessageText, []byte(ack)); err != nil {
			t.Fatalf("acknowledge offer %d: %v", index, err)
		}
		if response := readResponse(t, h.ctx, sender); response.RequestID != requestID(index) {
			t.Fatalf("result %d = %+v", index, response)
		}
	}

	// ID 2 remains retained: an identical frame replays its result, while changed
	// body conflicts, and neither produces a recipient offer.
	retainedReplayRequest := "01993c93-0001-7aaa-8aaa-000000000001"
	if err := sender.Write(h.ctx, websocket.MessageText,
		rawSendFrame(retainedReplayRequest, messageID(2), recipientAddress, `{"index":2}`, "")); err != nil {
		t.Fatalf("write retained duplicate: %v", err)
	}
	retainedReplay := readResponse(t, h.ctx, sender)
	if retainedReplay.RequestID != retainedReplayRequest || responsePayload(t, retainedReplay) !=
		`{"message_id":"`+messageID(2)+`","status":"received"}` {
		t.Fatalf("retained replay = %+v payload=%s", retainedReplay, responsePayload(t, retainedReplay))
	}
	retainedConflictRequest := "01993c93-0002-7aaa-8aaa-000000000002"
	if err := sender.Write(h.ctx, websocket.MessageText,
		rawSendFrame(retainedConflictRequest, messageID(2), recipientAddress, `{"index":9999}`, "")); err != nil {
		t.Fatalf("write retained conflict: %v", err)
	}
	retainedConflict := readResponse(t, h.ctx, sender)
	if retainedConflict.RequestID != retainedConflictRequest || responsePayload(t, retainedConflict) !=
		`{"message_id":"`+messageID(2)+`","reason":"message_id_conflict","status":"denied"}` {
		t.Fatalf("retained conflict = %+v payload=%s", retainedConflict, responsePayload(t, retainedConflict))
	}

	// ID 1 was the deterministic oldest settled insertion and is a new logical send.
	evictedRequest := "01993c93-0003-7aaa-8aaa-000000000003"
	if err := sender.Write(h.ctx, websocket.MessageText,
		rawSendFrame(evictedRequest, messageID(1), recipientAddress, `{"index":1}`, "")); err != nil {
		t.Fatalf("write evicted send: %v", err)
	}
	var evictedOffer messageEnvelope
	if err := wsjson.Read(h.ctx, recipient, &evictedOffer); err != nil {
		t.Fatalf("read evicted-ID new offer: %v", err)
	}
	if evictedOffer.Payload.MessageID != messageID(1) {
		t.Fatalf("retained ID produced an offer before evicted ID: %+v", evictedOffer)
	}
	ack := fmt.Sprintf(
		`{"v":1,"type":"received","request_id":"01993c93-0004-7aaa-8aaa-000000000004","payload":{"delivery_id":%q,"message_id":%q}}`,
		evictedOffer.Payload.DeliveryID, messageID(1),
	)
	if err := recipient.Write(h.ctx, websocket.MessageText, []byte(ack)); err != nil {
		t.Fatalf("acknowledge evicted-ID offer: %v", err)
	}
	if response := readResponse(t, h.ctx, sender); response.RequestID != evictedRequest {
		t.Fatalf("evicted-ID result = %+v", response)
	}
}

func TestThirdPendingDuplicateFailsClosedWithoutSecondOffer(t *testing.T) {
	h := newDedupeTestHarness(t)
	sender := h.open("01993ca3-1111-7aaa-8aaa-111111111111", "/sender")
	recipient := h.open("01993ca3-2222-7aaa-8aaa-222222222222", "/recipient")
	const (
		recipientAddress = "/recipient@host#01993ca3-2222-7aaa-8aaa-222222222222"
		messageID        = "01993c94-0001-7aaa-8aaa-000000000001"
	)
	if err := sender.Write(h.ctx, websocket.MessageText,
		rawSendFrame("01993c94-0002-7aaa-8aaa-000000000002", messageID, recipientAddress, `"same"`, "")); err != nil {
		t.Fatalf("write original: %v", err)
	}
	var offer messageEnvelope
	if err := wsjson.Read(h.ctx, recipient, &offer); err != nil {
		t.Fatalf("read original offer: %v", err)
	}
	for index := 3; index <= 4; index++ {
		if err := sender.Write(h.ctx, websocket.MessageText,
			rawSendFrame(fmt.Sprintf("01993c94-%04x-7aaa-8aaa-%012x", index, index), messageID, recipientAddress, `"same"`, "")); err != nil {
			t.Fatalf("write duplicate %d: %v", index, err)
		}
	}
	if _, _, err := sender.Read(h.ctx); err == nil {
		t.Fatal("third pending duplicate did not close sender")
	}

	lateACK := fmt.Sprintf(
		`{"v":1,"type":"received","request_id":"01993c94-0005-7aaa-8aaa-000000000005","payload":{"delivery_id":%q,"message_id":%q}}`,
		offer.Payload.DeliveryID, messageID,
	)
	if err := recipient.Write(h.ctx, websocket.MessageText, []byte(lateACK)); err != nil {
		t.Fatalf("write harmless late ACK: %v", err)
	}
	const listRequest = "01993c94-0006-7aaa-8aaa-000000000006"
	if err := recipient.Write(h.ctx, websocket.MessageText, []byte(
		`{"v":1,"type":"list","request_id":"`+listRequest+`","payload":{}}`,
	)); err != nil {
		t.Fatalf("write recipient health list: %v", err)
	}
	if response := readResponse(t, h.ctx, recipient); response.Type != "roster" || response.RequestID != listRequest {
		t.Fatalf("recipient saw duplicate offer or unhealthy response: %+v", response)
	}
}

func TestOfflineAndLostRecipientCurrentResultStaysStableForOneRetry(t *testing.T) {
	h := newDedupeTestHarness(t)
	sender := h.open("01993ca4-1111-7aaa-8aaa-111111111111", "/sender")
	const (
		recipientRoute   = "01993ca4-2222-7aaa-8aaa-222222222222"
		recipientAddress = "/recipient@host#" + recipientRoute
		messageID        = "01993c95-0001-7aaa-8aaa-000000000001"
	)
	writeSend := func(requestID string) {
		t.Helper()
		if err := sender.Write(h.ctx, websocket.MessageText,
			rawSendFrame(requestID, messageID, recipientAddress, `"same"`, "")); err != nil {
			t.Fatalf("write send %s: %v", requestID, err)
		}
	}
	writeSend("01993c95-0002-7aaa-8aaa-000000000002")
	offline := readResponse(t, h.ctx, sender)
	if responsePayload(t, offline) != `{"message_id":"`+messageID+`","reason":"offline","status":"timeout"}` {
		t.Fatalf("offline result = %+v payload=%s", offline, responsePayload(t, offline))
	}

	recipient := h.open(recipientRoute, "/recipient")
	writeSend("01993c95-0003-7aaa-8aaa-000000000003")
	if retry := readResponse(t, h.ctx, sender); responsePayload(t, retry) != responsePayload(t, offline) {
		t.Fatalf("offline retry changed after recipient appeared: %+v payload=%s", retry, responsePayload(t, retry))
	}

	settleNewOffer := func(requestID, ackRequestID string) messageEnvelope {
		t.Helper()
		writeSend(requestID)
		var offer messageEnvelope
		if err := wsjson.Read(h.ctx, recipient, &offer); err != nil {
			t.Fatalf("read new offer: %v", err)
		}
		ack := fmt.Sprintf(
			`{"v":1,"type":"received","request_id":%q,"payload":{"delivery_id":%q,"message_id":%q}}`,
			ackRequestID, offer.Payload.DeliveryID, messageID,
		)
		if err := recipient.Write(h.ctx, websocket.MessageText, []byte(ack)); err != nil {
			t.Fatalf("acknowledge new offer: %v", err)
		}
		if result := readResponse(t, h.ctx, sender); responsePayload(t, result) !=
			`{"message_id":"`+messageID+`","status":"received"}` {
			t.Fatalf("new offer result = %+v payload=%s", result, responsePayload(t, result))
		}
		return offer
	}
	firstOffer := settleNewOffer(
		"01993c95-0004-7aaa-8aaa-000000000004",
		"01993c95-0005-7aaa-8aaa-000000000005",
	)
	_ = recipient.CloseNow()
	for !strings.Contains(h.logs.String(), `"event":"session_disconnected","address":"`+recipientAddress+`"`) {
		select {
		case <-h.logs.changed:
		case <-h.ctx.Done():
			t.Fatal("recipient did not leave registry")
		}
	}

	recipient = h.open(recipientRoute, "/recipient")
	writeSend("01993c95-0006-7aaa-8aaa-000000000006")
	if retry := readResponse(t, h.ctx, sender); responsePayload(t, retry) !=
		`{"message_id":"`+messageID+`","status":"received"}` {
		t.Fatalf("received retry changed after recipient reauthentication: %+v payload=%s", retry, responsePayload(t, retry))
	}
	secondOffer := settleNewOffer(
		"01993c95-0007-7aaa-8aaa-000000000007",
		"01993c95-0008-7aaa-8aaa-000000000008",
	)
	if secondOffer.Payload.DeliveryID == firstOffer.Payload.DeliveryID {
		t.Fatalf("new logical send reused delivery ID: %s", secondOffer.Payload.DeliveryID)
	}
}

func TestPendingMessageIDConflictsDenyWithoutChangingOriginal(t *testing.T) {
	const (
		recipientAddress = "/recipient@host#01993ca5-2222-7aaa-8aaa-222222222222"
		originalRe       = "01993c96-0001-7aaa-8aaa-000000000001"
	)
	cases := []struct {
		name string
		to   string
		body string
		re   string
	}{
		{name: "destination", to: "/different", body: `{"same":true}`, re: originalRe},
		{name: "re absence", to: recipientAddress, body: `{"same":true}`},
		{name: "re value", to: recipientAddress, body: `{"same":true}`, re: "01993c96-0002-7aaa-8aaa-000000000002"},
		{name: "body", to: recipientAddress, body: `{"same":false}`, re: originalRe},
	}
	for index, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			h := newDedupeTestHarness(t)
			sender := h.open("01993ca5-1111-7aaa-8aaa-111111111111", "/sender")
			recipient := h.open("01993ca5-2222-7aaa-8aaa-222222222222", "/recipient")
			messageID := fmt.Sprintf("01993c97-%04x-7aaa-8aaa-%012x", index+1, index+1)
			originalRequest := fmt.Sprintf("01993c98-%04x-7aaa-8aaa-%012x", index+1, index+1)
			conflictRequest := fmt.Sprintf("01993c99-%04x-7aaa-8aaa-%012x", index+1, index+1)
			if err := sender.Write(h.ctx, websocket.MessageText,
				rawSendFrame(originalRequest, messageID, recipientAddress, `{"same":true}`, originalRe)); err != nil {
				t.Fatalf("write original: %v", err)
			}
			var offer messageEnvelope
			if err := wsjson.Read(h.ctx, recipient, &offer); err != nil {
				t.Fatalf("read original offer: %v", err)
			}
			if err := sender.Write(h.ctx, websocket.MessageText,
				rawSendFrame(conflictRequest, messageID, test.to, test.body, test.re)); err != nil {
				t.Fatalf("write pending conflict: %v", err)
			}
			conflict := readResponse(t, h.ctx, sender)
			if conflict.RequestID != conflictRequest || responsePayload(t, conflict) !=
				`{"message_id":"`+messageID+`","reason":"message_id_conflict","status":"denied"}` {
				t.Fatalf("pending conflict = %+v payload=%s", conflict, responsePayload(t, conflict))
			}

			ack := fmt.Sprintf(
				`{"v":1,"type":"received","request_id":"01993c9a-0001-7aaa-8aaa-000000000001","payload":{"delivery_id":%q,"message_id":%q}}`,
				offer.Payload.DeliveryID, messageID,
			)
			if err := recipient.Write(h.ctx, websocket.MessageText, []byte(ack)); err != nil {
				t.Fatalf("acknowledge original: %v", err)
			}
			original := readResponse(t, h.ctx, sender)
			if original.RequestID != originalRequest || responsePayload(t, original) !=
				`{"message_id":"`+messageID+`","status":"received"}` {
				t.Fatalf("original changed by conflict: %+v payload=%s", original, responsePayload(t, original))
			}
			const listRequest = "01993c9a-0002-7aaa-8aaa-000000000002"
			if err := recipient.Write(h.ctx, websocket.MessageText, []byte(
				`{"v":1,"type":"list","request_id":"`+listRequest+`","payload":{}}`,
			)); err != nil {
				t.Fatalf("write recipient health list: %v", err)
			}
			if response := readResponse(t, h.ctx, recipient); response.Type != "roster" || response.RequestID != listRequest {
				t.Fatalf("conflict created second offer or damaged recipient: %+v", response)
			}
		})
	}
}

func TestACKTimeoutResultIsRetainedWithoutSecondOffer(t *testing.T) {
	h := newDedupeTestHarness(t)
	expired := make(chan time.Time, 1)
	h.dispatcher.deadlineFactory = func(duration time.Duration) deliveryDeadline {
		if duration != 5*time.Second {
			t.Fatalf("ACK deadline = %s", duration)
		}
		return deliveryDeadline{expired: expired, stop: func() bool { return true }}
	}
	sender := h.open("01993ca6-1111-7aaa-8aaa-111111111111", "/sender")
	recipient := h.open("01993ca6-2222-7aaa-8aaa-222222222222", "/recipient")
	const (
		recipientAddress = "/recipient@host#01993ca6-2222-7aaa-8aaa-222222222222"
		messageID        = "01993c9b-0001-7aaa-8aaa-000000000001"
		originalRequest  = "01993c9b-0002-7aaa-8aaa-000000000002"
		retryRequest     = "01993c9b-0003-7aaa-8aaa-000000000003"
	)
	if err := sender.Write(h.ctx, websocket.MessageText,
		rawSendFrame(originalRequest, messageID, recipientAddress, `"same"`, "")); err != nil {
		t.Fatalf("write original: %v", err)
	}
	var offer messageEnvelope
	if err := wsjson.Read(h.ctx, recipient, &offer); err != nil {
		t.Fatalf("read original offer: %v", err)
	}
	expired <- time.Now()
	original := readResponse(t, h.ctx, sender)
	if responsePayload(t, original) !=
		`{"message_id":"`+messageID+`","reason":"ack_timeout","status":"timeout"}` {
		t.Fatalf("ACK-timeout response = %+v payload=%s", original, responsePayload(t, original))
	}
	if err := sender.Write(h.ctx, websocket.MessageText,
		rawSendFrame(retryRequest, messageID, recipientAddress, `"same"`, "")); err != nil {
		t.Fatalf("write retained ACK-timeout duplicate: %v", err)
	}
	retry := readResponse(t, h.ctx, sender)
	if retry.RequestID != retryRequest || responsePayload(t, retry) != responsePayload(t, original) {
		t.Fatalf("retained ACK-timeout response = %+v payload=%s", retry, responsePayload(t, retry))
	}
	const listRequest = "01993c9b-0004-7aaa-8aaa-000000000004"
	if err := recipient.Write(h.ctx, websocket.MessageText, []byte(
		`{"v":1,"type":"list","request_id":"`+listRequest+`","payload":{}}`,
	)); err != nil {
		t.Fatalf("write recipient health list: %v", err)
	}
	if response := readResponse(t, h.ctx, recipient); response.Type != "roster" || response.RequestID != listRequest {
		t.Fatalf("ACK-timeout duplicate created second offer: %+v", response)
	}
}

func TestPriorVisibleReplayCannotConsumeNextSendRetryResponseCapacity(t *testing.T) {
	h := newDedupeTestHarness(t)
	const (
		recipientAddress = "/recipient@host#01993cb0-2222-7aaa-8aaa-222222222222"
		messageA         = "01993cb1-0001-7aaa-8aaa-000000000001"
		messageB         = "01993cb1-0002-7aaa-8aaa-000000000002"
		replayRequest    = "01993cb2-0001-7aaa-8aaa-000000000001"
		originalBRequest = "01993cb2-0002-7aaa-8aaa-000000000002"
		retryBRequest    = "01993cb2-0003-7aaa-8aaa-000000000003"
	)
	replayWritten := make(chan struct{})
	releaseReplayAudit := make(chan struct{})
	reservedB := make(chan struct{})
	h.service.beforeResponseAudit = func(event logEvent) {
		if event.RequestID != replayRequest {
			return
		}
		close(replayWritten)
		<-releaseReplayAudit
	}
	h.service.afterOperationResponseReservation = func(operation clientOperation) {
		if operation.RequestID == originalBRequest {
			close(reservedB)
		}
	}
	sender := h.open("01993cb0-1111-7aaa-8aaa-111111111111", "/sender")
	recipient := h.open("01993cb0-2222-7aaa-8aaa-222222222222", "/recipient")
	settle := func(requestID, messageID, body string) messageEnvelope {
		t.Helper()
		if err := sender.Write(h.ctx, websocket.MessageText,
			rawSendFrame(requestID, messageID, recipientAddress, body, "")); err != nil {
			t.Fatalf("write send %s: %v", messageID, err)
		}
		var offer messageEnvelope
		if err := wsjson.Read(h.ctx, recipient, &offer); err != nil {
			t.Fatalf("read offer %s: %v", messageID, err)
		}
		ack := fmt.Sprintf(
			`{"v":1,"type":"received","request_id":"01993cb3-0001-7aaa-8aaa-000000000001","payload":{"delivery_id":%q,"message_id":%q}}`,
			offer.Payload.DeliveryID, messageID,
		)
		if err := recipient.Write(h.ctx, websocket.MessageText, []byte(ack)); err != nil {
			t.Fatalf("acknowledge %s: %v", messageID, err)
		}
		return offer
	}
	settle("01993cb2-0004-7aaa-8aaa-000000000004", messageA, `"a"`)
	if response := readResponse(t, h.ctx, sender); response.Payload == nil {
		t.Fatal("missing initial A result")
	}

	if err := sender.Write(h.ctx, websocket.MessageText,
		rawSendFrame(replayRequest, messageA, recipientAddress, `"a"`, "")); err != nil {
		t.Fatalf("write A replay: %v", err)
	}
	if response := readResponse(t, h.ctx, sender); response.RequestID != replayRequest {
		t.Fatalf("A replay response = %+v", response)
	}
	select {
	case <-replayWritten:
	case <-h.ctx.Done():
		t.Fatal("A replay did not reach held audit boundary")
	}

	if err := sender.Write(h.ctx, websocket.MessageText,
		rawSendFrame(originalBRequest, messageB, recipientAddress, `"b"`, "")); err != nil {
		t.Fatalf("write B original: %v", err)
	}
	var offerB messageEnvelope
	if err := wsjson.Read(h.ctx, recipient, &offerB); err != nil {
		t.Fatalf("read B offer: %v", err)
	}
	if err := sender.Write(h.ctx, websocket.MessageText,
		rawSendFrame(retryBRequest, messageB, recipientAddress, `"b"`, "")); err != nil {
		t.Fatalf("write B retry: %v", err)
	}
	ackB := fmt.Sprintf(
		`{"v":1,"type":"received","request_id":"01993cb3-0002-7aaa-8aaa-000000000002","payload":{"delivery_id":%q,"message_id":%q}}`,
		offerB.Payload.DeliveryID, messageB,
	)
	if err := recipient.Write(h.ctx, websocket.MessageText, []byte(ackB)); err != nil {
		t.Fatalf("acknowledge B: %v", err)
	}
	select {
	case <-reservedB:
	case <-time.After(time.Second):
		close(releaseReplayAudit)
		t.Fatal("B original and retry did not reserve response ownership while A remained held")
	}
	close(releaseReplayAudit)

	responses := map[string]operationResponseEnvelope{}
	for range 2 {
		response := readResponse(t, h.ctx, sender)
		responses[response.RequestID] = response
	}
	for _, requestID := range []string{originalBRequest, retryBRequest} {
		if responsePayload(t, responses[requestID]) !=
			`{"message_id":"`+messageB+`","status":"received"}` {
			t.Fatalf("B response %s = %+v", requestID, responses[requestID])
		}
	}
	const healthRequest = "01993cb2-0005-7aaa-8aaa-000000000005"
	if err := sender.Write(h.ctx, websocket.MessageText, []byte(
		`{"v":1,"type":"list","request_id":"`+healthRequest+`","payload":{}}`,
	)); err != nil {
		t.Fatalf("write health list: %v", err)
	}
	if response := readResponse(t, h.ctx, sender); response.Type != "roster" || response.RequestID != healthRequest {
		t.Fatalf("sender unhealthy after bounded response overlap: %+v", response)
	}
}

func TestDelayedRetryKeepsSelectedRecipientDisconnectResultAcrossReauthentication(t *testing.T) {
	h := newDedupeTestHarness(t)
	const (
		recipientRoute   = "01993cb4-2222-7aaa-8aaa-222222222222"
		recipientAddress = "/recipient@host#" + recipientRoute
		messageID        = "01993cb5-0001-7aaa-8aaa-000000000001"
		originalRequest  = "01993cb5-0002-7aaa-8aaa-000000000002"
		retryRequest     = "01993cb5-0003-7aaa-8aaa-000000000003"
	)
	retryAtObservation := make(chan struct{})
	releaseRetry := make(chan struct{})
	h.service.beforeRepeatedSendObservation = func(operation clientOperation) {
		if operation.RequestID != retryRequest {
			return
		}
		close(retryAtObservation)
		<-releaseRetry
	}
	sender := h.open("01993cb4-1111-7aaa-8aaa-111111111111", "/sender")
	recipient := h.open("01993cb4-2222-7aaa-8aaa-222222222222", "/recipient")
	if err := sender.Write(h.ctx, websocket.MessageText,
		rawSendFrame(originalRequest, messageID, recipientAddress, `"same"`, "")); err != nil {
		t.Fatalf("write original: %v", err)
	}
	var originalOffer messageEnvelope
	if err := wsjson.Read(h.ctx, recipient, &originalOffer); err != nil {
		t.Fatalf("read original offer: %v", err)
	}
	if err := sender.Write(h.ctx, websocket.MessageText,
		rawSendFrame(retryRequest, messageID, recipientAddress, `"same"`, "")); err != nil {
		t.Fatalf("write delayed retry: %v", err)
	}
	select {
	case <-retryAtObservation:
	case <-h.ctx.Done():
		t.Fatal("retry did not reach held observation boundary")
	}
	_ = recipient.CloseNow()
	original := readResponse(t, h.ctx, sender)
	if original.RequestID != originalRequest || responsePayload(t, original) !=
		`{"message_id":"`+messageID+`","reason":"recipient_disconnected","status":"timeout"}` {
		t.Fatalf("original disconnect result = %+v payload=%s", original, responsePayload(t, original))
	}

	for !strings.Contains(h.logs.String(), `"event":"session_disconnected","address":"`+recipientAddress+`"`) {
		select {
		case <-h.logs.changed:
		case <-h.ctx.Done():
			t.Fatal("recipient disconnect did not settle")
		}
	}
	newRecipient := h.open(recipientRoute, "/recipient")
	close(releaseRetry)
	retry := readResponse(t, h.ctx, sender)
	if retry.RequestID != retryRequest || responsePayload(t, retry) != responsePayload(t, original) {
		t.Fatalf("delayed retry result = %+v payload=%s", retry, responsePayload(t, retry))
	}

	const recipientHealth = "01993cb5-0005-7aaa-8aaa-000000000005"
	if err := newRecipient.Write(h.ctx, websocket.MessageText, []byte(
		`{"v":1,"type":"list","request_id":"`+recipientHealth+`","payload":{}}`,
	)); err != nil {
		t.Fatalf("write reauthenticated recipient health list: %v", err)
	}
	if response := readResponse(t, h.ctx, newRecipient); response.Type != "roster" || response.RequestID != recipientHealth {
		t.Fatalf("retry created a second offer or damaged recipient: %+v", response)
	}
	const senderHealth = "01993cb5-0006-7aaa-8aaa-000000000006"
	if err := sender.Write(h.ctx, websocket.MessageText, []byte(
		`{"v":1,"type":"list","request_id":"`+senderHealth+`","payload":{}}`,
	)); err != nil {
		t.Fatalf("write sender health list: %v", err)
	}
	if response := readResponse(t, h.ctx, sender); response.Type != "roster" || response.RequestID != senderHealth {
		t.Fatalf("retry damaged sender: %+v", response)
	}
}

func TestNextDistinctOperationAdvancesSingleSenderCurrentTombstone(t *testing.T) {
	h := newDedupeTestHarness(t)
	sender := h.open("01993cb6-1111-7aaa-8aaa-111111111111", "/sender")
	const (
		recipientRoute   = "01993cb6-2222-7aaa-8aaa-222222222222"
		recipientAddress = "/recipient@host#" + recipientRoute
		messageA         = "01993cb7-0001-7aaa-8aaa-000000000001"
	)
	if err := sender.Write(h.ctx, websocket.MessageText,
		rawSendFrame("01993cb8-0001-7aaa-8aaa-000000000001", messageA, recipientAddress, `"same"`, "")); err != nil {
		t.Fatalf("write offline A: %v", err)
	}
	if result := readResponse(t, h.ctx, sender); responsePayload(t, result) !=
		`{"message_id":"`+messageA+`","reason":"offline","status":"timeout"}` {
		t.Fatalf("offline A result = %+v payload=%s", result, responsePayload(t, result))
	}
	const listRequest = "01993cb8-0002-7aaa-8aaa-000000000002"
	if err := sender.Write(h.ctx, websocket.MessageText, []byte(
		`{"v":1,"type":"list","request_id":"`+listRequest+`","payload":{}}`,
	)); err != nil {
		t.Fatalf("write safely ordered list: %v", err)
	}
	if response := readResponse(t, h.ctx, sender); response.Type != "roster" || response.RequestID != listRequest {
		t.Fatalf("ordered list response = %+v", response)
	}

	recipient := h.open(recipientRoute, "/recipient")
	const requestAAgain = "01993cb8-0003-7aaa-8aaa-000000000003"
	if err := sender.Write(h.ctx, websocket.MessageText,
		rawSendFrame(requestAAgain, messageA, recipientAddress, `"same"`, "")); err != nil {
		t.Fatalf("write A after distinct list: %v", err)
	}
	var offer messageEnvelope
	if err := wsjson.Read(h.ctx, recipient, &offer); err != nil {
		t.Fatalf("read A new logical offer: %v", err)
	}
	if offer.Payload.MessageID != messageA {
		t.Fatalf("offered message = %s, want advanced A", offer.Payload.MessageID)
	}
	ack := fmt.Sprintf(
		`{"v":1,"type":"received","request_id":"01993cb8-0004-7aaa-8aaa-000000000004","payload":{"delivery_id":%q,"message_id":%q}}`,
		offer.Payload.DeliveryID, messageA,
	)
	if err := recipient.Write(h.ctx, websocket.MessageText, []byte(ack)); err != nil {
		t.Fatalf("acknowledge A new logical offer: %v", err)
	}
	if result := readResponse(t, h.ctx, sender); responsePayload(t, result) !=
		`{"message_id":"`+messageA+`","status":"received"}` {
		t.Fatalf("A new logical result = %+v payload=%s", result, responsePayload(t, result))
	}
}
