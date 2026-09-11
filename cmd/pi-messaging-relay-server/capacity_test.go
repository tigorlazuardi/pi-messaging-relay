package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

func capacityUUID(kind byte, index int) string {
	return fmt.Sprintf("01993cc%c-%04x-7aaa-8aaa-%012x", kind, index, index)
}

const (
	contractSendCapacity       = 128
	contractFirstDeniedOrdinal = 129
	contractResponseCapacity   = 256
)

func TestAuthenticatedSenderCapacityIsExactRecoverableAndSessionIsolated(t *testing.T) {
	h := newDedupeTestHarness(t)
	sender := h.open("01993cc1-1111-7aaa-8aaa-111111111111", "/sender")
	otherSender := h.open("01993cc1-2222-7aaa-8aaa-222222222222", "/other")
	recipient := h.open("01993cc1-3333-7aaa-8aaa-333333333333", "/recipient")
	const recipientAddress = "/recipient@host#01993cc1-3333-7aaa-8aaa-333333333333"

	for index := range contractFirstDeniedOrdinal {
		frame := rawSendFrame(
			capacityUUID('2', index),
			capacityUUID('3', index),
			recipientAddress,
			fmt.Sprintf(`"private-%d"`, index),
			"",
		)
		if err := sender.Write(h.ctx, websocket.MessageText, frame); err != nil {
			t.Fatalf("stream send %d: %v", index, err)
		}
	}

	offers := make(map[string]messageEnvelope, contractSendCapacity)
	for range contractSendCapacity {
		var offer messageEnvelope
		if err := wsjson.Read(h.ctx, recipient, &offer); err != nil {
			t.Fatalf("read held offer %d: %v", len(offers), err)
		}
		offers[offer.Payload.MessageID] = offer
	}
	if len(offers) != contractSendCapacity {
		t.Fatalf("distinct held offers = %d, want %d", len(offers), contractSendCapacity)
	}

	deniedRequestID := capacityUUID('2', contractFirstDeniedOrdinal-1)
	deniedMessageID := capacityUUID('3', contractFirstDeniedOrdinal-1)
	denied := readResponse(t, h.ctx, sender)
	if denied.RequestID != deniedRequestID || responsePayload(t, denied) !=
		`{"message_id":"`+deniedMessageID+`","reason":"sender_capacity","status":"denied"}` {
		t.Fatalf("capacity denial = %+v payload=%s", denied, responsePayload(t, denied))
	}

	otherRequestID := capacityUUID('4', 1)
	otherMessageID := capacityUUID('5', 1)
	if err := otherSender.Write(h.ctx, websocket.MessageText,
		rawSendFrame(otherRequestID, otherMessageID, recipientAddress, `"independent"`, "")); err != nil {
		t.Fatalf("write independent sender: %v", err)
	}
	var otherOffer messageEnvelope
	if err := wsjson.Read(h.ctx, recipient, &otherOffer); err != nil {
		t.Fatalf("read independent offer: %v", err)
	}
	if otherOffer.Payload.MessageID != otherMessageID {
		t.Fatalf("independent offer = %+v", otherOffer)
	}

	releasedMessageID := capacityUUID('3', 0)
	releasedOffer := offers[releasedMessageID]
	ackFrame := fmt.Sprintf(
		`{"v":1,"type":"received","request_id":%q,"payload":{"delivery_id":%q,"message_id":%q}}`,
		capacityUUID('6', 1), releasedOffer.Payload.DeliveryID, releasedMessageID,
	)
	if err := recipient.Write(h.ctx, websocket.MessageText, []byte(ackFrame)); err != nil {
		t.Fatalf("release one sender slot: %v", err)
	}
	settled := readResponse(t, h.ctx, sender)
	if settled.RequestID != capacityUUID('2', 0) || responsePayload(t, settled) !=
		`{"message_id":"`+releasedMessageID+`","status":"received"}` {
		t.Fatalf("released settlement = %+v payload=%s", settled, responsePayload(t, settled))
	}

	retryRequestID := capacityUUID('7', 1)
	if err := sender.Write(h.ctx, websocket.MessageText,
		rawSendFrame(retryRequestID, deniedMessageID, recipientAddress, `"private-retry"`, "")); err != nil {
		t.Fatalf("retry formerly denied ID: %v", err)
	}
	var retryOffer messageEnvelope
	if err := wsjson.Read(h.ctx, recipient, &retryOffer); err != nil {
		t.Fatalf("read formerly denied retry offer: %v", err)
	}
	if retryOffer.Payload.MessageID != deniedMessageID {
		t.Fatalf("formerly denied ID was not new: %+v", retryOffer)
	}

	for !strings.Contains(h.logs.String(), `"request_id":"`+deniedRequestID+`"`) {
		select {
		case <-h.logs.changed:
		case <-h.ctx.Done():
			t.Fatalf("capacity denial audit not emitted: %s", h.logs.String())
		}
	}
	var denialEvent map[string]any
	for _, line := range strings.Split(strings.TrimSpace(h.logs.String()), "\n") {
		var event map[string]any
		if json.Unmarshal([]byte(line), &event) == nil && event["request_id"] == deniedRequestID {
			denialEvent = event
			break
		}
	}
	if denialEvent["event"] != "operation_denied" || denialEvent["level"] != "warn" ||
		denialEvent["result"] != "denied" || denialEvent["reason"] != "sender_capacity" ||
		denialEvent["code"] != "sender_capacity" || denialEvent["message_id"] != deniedMessageID ||
		denialEvent["sender_route"] != "/sender@host#01993cc1-1111-7aaa-8aaa-111111111111" ||
		denialEvent["status"] != "denied" || denialEvent["body"] != redacted ||
		denialEvent["recipient_route"] != nil || denialEvent["delivery_id"] != nil {
		t.Fatalf("capacity denial audit = %#v", denialEvent)
	}
	for index := range contractFirstDeniedOrdinal {
		if strings.Contains(h.logs.String(), fmt.Sprintf("private-%d", index)) {
			t.Fatalf("capacity telemetry leaked body %d: %s", index, h.logs.String())
		}
	}
}

func awaitLogOccurrences(t *testing.T, h *dedupeTestHarness, fragment string, count int) {
	t.Helper()
	for strings.Count(h.logs.String(), fragment) < count {
		select {
		case <-h.logs.changed:
		case <-h.ctx.Done():
			t.Fatalf("timed out waiting for %d occurrences of %q: %s", count, fragment, h.logs.String())
		}
	}
}

func TestFullSenderObservesDedupeAndBodyPrecedenceWithoutExtraCapacity(t *testing.T) {
	h := newDedupeTestHarness(t)
	sender := h.open("01993cc8-1111-7aaa-8aaa-111111111111", "/sender")
	recipient := h.open("01993cc8-2222-7aaa-8aaa-222222222222", "/recipient")
	const recipientAddress = "/recipient@host#01993cc8-2222-7aaa-8aaa-222222222222"

	offers := make(map[string]messageEnvelope, contractSendCapacity)
	for index := range contractSendCapacity {
		if err := sender.Write(h.ctx, websocket.MessageText, rawSendFrame(
			capacityUUID('8', index), capacityUUID('9', index), recipientAddress,
			fmt.Sprintf(`"dedupe-private-%d"`, index), "",
		)); err != nil {
			t.Fatalf("fill sender capacity %d: %v", index, err)
		}
	}
	for range contractSendCapacity {
		var offer messageEnvelope
		if err := wsjson.Read(h.ctx, recipient, &offer); err != nil {
			t.Fatalf("read capacity offer %d: %v", len(offers), err)
		}
		offers[offer.Payload.MessageID] = offer
	}

	attachedRequest := capacityUUID('a', 1)
	if err := sender.Write(h.ctx, websocket.MessageText, rawSendFrame(
		attachedRequest, capacityUUID('9', 0), recipientAddress, `"dedupe-private-0"`, "",
	)); err != nil {
		t.Fatalf("attach identical retry at capacity: %v", err)
	}
	conflictRequest := capacityUUID('a', 2)
	if err := sender.Write(h.ctx, websocket.MessageText, rawSendFrame(
		conflictRequest, capacityUUID('9', 1), recipientAddress, `"changed"`, "",
	)); err != nil {
		t.Fatalf("submit conflict at capacity: %v", err)
	}
	distinctRequest := capacityUUID('a', 3)
	distinctMessage := capacityUUID('b', 3)
	if err := sender.Write(h.ctx, websocket.MessageText, rawSendFrame(
		distinctRequest, distinctMessage, recipientAddress, `"distinct"`, "",
	)); err != nil {
		t.Fatalf("submit distinct send at capacity: %v", err)
	}

	conflict := readResponse(t, h.ctx, sender)
	if conflict.RequestID != conflictRequest || responsePayload(t, conflict) !=
		`{"message_id":"`+capacityUUID('9', 1)+`","reason":"message_id_conflict","status":"denied"}` {
		t.Fatalf("full-sender conflict = %+v payload=%s", conflict, responsePayload(t, conflict))
	}
	denied := readResponse(t, h.ctx, sender)
	if denied.RequestID != distinctRequest || responsePayload(t, denied) !=
		`{"message_id":"`+distinctMessage+`","reason":"sender_capacity","status":"denied"}` {
		t.Fatalf("full-sender distinct denial = %+v payload=%s", denied, responsePayload(t, denied))
	}

	firstMessage := capacityUUID('9', 0)
	firstOffer := offers[firstMessage]
	ack := fmt.Sprintf(
		`{"v":1,"type":"received","request_id":%q,"payload":{"delivery_id":%q,"message_id":%q}}`,
		capacityUUID('a', 4), firstOffer.Payload.DeliveryID, firstMessage,
	)
	if err := recipient.Write(h.ctx, websocket.MessageText, []byte(ack)); err != nil {
		t.Fatalf("acknowledge attached send: %v", err)
	}
	settledRequests := map[string]bool{}
	for range 2 {
		response := readResponse(t, h.ctx, sender)
		if responsePayload(t, response) != `{"message_id":"`+firstMessage+`","status":"received"}` {
			t.Fatalf("attached settlement = %+v payload=%s", response, responsePayload(t, response))
		}
		settledRequests[response.RequestID] = true
	}
	if !settledRequests[capacityUUID('8', 0)] || !settledRequests[attachedRequest] {
		t.Fatalf("attached settlement correlations = %#v", settledRequests)
	}

	replacementRequest := capacityUUID('a', 5)
	replacementMessage := capacityUUID('b', 5)
	if err := sender.Write(h.ctx, websocket.MessageText, rawSendFrame(
		replacementRequest, replacementMessage, recipientAddress, `"replacement"`, "",
	)); err != nil {
		t.Fatalf("refill released capacity: %v", err)
	}
	var replacementOffer messageEnvelope
	if err := wsjson.Read(h.ctx, recipient, &replacementOffer); err != nil {
		t.Fatalf("read replacement offer: %v", err)
	}
	if replacementOffer.Payload.MessageID != replacementMessage {
		t.Fatalf("replacement offer = %+v", replacementOffer)
	}

	replayRequest := capacityUUID('a', 6)
	if err := sender.Write(h.ctx, websocket.MessageText, rawSendFrame(
		replayRequest, firstMessage, recipientAddress, `"dedupe-private-0"`, "",
	)); err != nil {
		t.Fatalf("replay settled send at capacity: %v", err)
	}
	replay := readResponse(t, h.ctx, sender)
	if replay.RequestID != replayRequest || responsePayload(t, replay) !=
		`{"message_id":"`+firstMessage+`","status":"received"}` {
		t.Fatalf("full-sender replay = %+v payload=%s", replay, responsePayload(t, replay))
	}

	oversizedRequest := capacityUUID('a', 7)
	oversizedMessage := capacityUUID('b', 7)
	oversizedBody := `"` + strings.Repeat("x", maxBodyBytes) + `"`
	if err := sender.Write(h.ctx, websocket.MessageText, rawSendFrame(
		oversizedRequest, oversizedMessage, recipientAddress, oversizedBody, "",
	)); err != nil {
		t.Fatalf("submit oversized body at capacity: %v", err)
	}
	oversized := readResponse(t, h.ctx, sender)
	if oversized.RequestID != oversizedRequest || responsePayload(t, oversized) !=
		`{"message_id":"`+oversizedMessage+`","reason":"body_too_large","status":"denied"}` {
		t.Fatalf("body precedence at capacity = %+v payload=%s", oversized, responsePayload(t, oversized))
	}

	listRequest := capacityUUID('a', 8)
	if err := sender.Write(h.ctx, websocket.MessageText, []byte(
		`{"v":1,"type":"list","request_id":"`+listRequest+`","payload":{}}`,
	)); err != nil {
		t.Fatalf("list while sends are held: %v", err)
	}
	if roster := readResponse(t, h.ctx, sender); roster.Type != "roster" || roster.RequestID != listRequest {
		t.Fatalf("list overlap response = %+v", roster)
	}

	stillFullRequest := capacityUUID('a', 9)
	stillFullMessage := capacityUUID('b', 9)
	if err := sender.Write(h.ctx, websocket.MessageText, rawSendFrame(
		stillFullRequest, stillFullMessage, recipientAddress, `"still-full"`, "",
	)); err != nil {
		t.Fatalf("check capacity after bypass operations: %v", err)
	}
	stillFull := readResponse(t, h.ctx, sender)
	if stillFull.RequestID != stillFullRequest || responsePayload(t, stillFull) !=
		`{"message_id":"`+stillFullMessage+`","reason":"sender_capacity","status":"denied"}` {
		t.Fatalf("capacity changed after bypass operations = %+v payload=%s", stillFull, responsePayload(t, stillFull))
	}
}

func TestRecipientDisconnectReleasesAllSenderCapacityForReconnectRefill(t *testing.T) {
	h := newDedupeTestHarness(t)
	sender := h.open("01993cca-1111-7aaa-8aaa-111111111111", "/sender")
	const (
		recipientRoute   = "01993cca-2222-7aaa-8aaa-222222222222"
		recipientAddress = "/recipient@host#" + recipientRoute
	)
	recipient := h.open(recipientRoute, "/recipient")

	for index := range contractSendCapacity {
		if err := sender.Write(h.ctx, websocket.MessageText, rawSendFrame(
			capacityUUID('c', index), capacityUUID('d', index), recipientAddress,
			fmt.Sprintf(`"disconnect-private-%d"`, index), "",
		)); err != nil {
			t.Fatalf("fill before recipient disconnect %d: %v", index, err)
		}
	}
	for range contractSendCapacity {
		var offer messageEnvelope
		if err := wsjson.Read(h.ctx, recipient, &offer); err != nil {
			t.Fatalf("read pre-disconnect offer: %v", err)
		}
	}
	if err := recipient.Close(websocket.StatusNormalClosure, "capacity recipient disconnect"); err != nil {
		t.Fatalf("disconnect full recipient: %v", err)
	}
	awaitLogOccurrences(t, h, `"event":"session_disconnected","address":"`+recipientAddress+`"`, 1)

	settled := make(map[string]bool, contractSendCapacity)
	for range contractSendCapacity {
		response := readResponse(t, h.ctx, sender)
		payload := responsePayload(t, response)
		if !strings.Contains(payload, `"status":"timeout"`) ||
			!strings.Contains(payload, `"reason":"recipient_disconnected"`) {
			t.Fatalf("recipient disconnect result = %+v payload=%s", response, payload)
		}
		settled[response.RequestID] = true
	}
	if len(settled) != contractSendCapacity {
		t.Fatalf("recipient disconnect correlations = %d, want %d", len(settled), contractSendCapacity)
	}

	reconnected := h.open(recipientRoute, "/recipient")
	awaitLogOccurrences(t, h, `"event":"auth_accepted","address":"`+recipientAddress+`"`, 2)
	for index := range contractFirstDeniedOrdinal {
		if err := sender.Write(h.ctx, websocket.MessageText, rawSendFrame(
			capacityUUID('e', index), capacityUUID('f', index), recipientAddress,
			fmt.Sprintf(`"refill-private-%d"`, index), "",
		)); err != nil {
			t.Fatalf("refill after recipient reconnect %d: %v", index, err)
		}
	}
	for range contractSendCapacity {
		var offer messageEnvelope
		if err := wsjson.Read(h.ctx, reconnected, &offer); err != nil {
			t.Fatalf("read refill offer: %v", err)
		}
	}
	denied := readResponse(t, h.ctx, sender)
	if denied.RequestID != capacityUUID('e', contractFirstDeniedOrdinal-1) || responsePayload(t, denied) !=
		`{"message_id":"`+capacityUUID('f', contractFirstDeniedOrdinal-1)+`","reason":"sender_capacity","status":"denied"}` {
		t.Fatalf("refilled capacity boundary = %+v payload=%s", denied, responsePayload(t, denied))
	}
}

func TestACKTimeoutReleasesEverySenderCapacitySlot(t *testing.T) {
	h := newDedupeTestHarness(t)
	type controlledDeadline struct {
		expired chan time.Time
		once    sync.Once
	}
	deadlines := make(chan *controlledDeadline, contractFirstDeniedOrdinal)
	h.dispatcher.deadlineFactory = func(duration time.Duration) deliveryDeadline {
		if duration != deliveryACKCeiling {
			t.Errorf("ACK deadline = %s, want %s", duration, deliveryACKCeiling)
		}
		controlled := &controlledDeadline{expired: make(chan time.Time)}
		deadlines <- controlled
		return deliveryDeadline{
			expired: controlled.expired,
			stop: func() bool {
				controlled.once.Do(func() { close(controlled.expired) })
				return true
			},
		}
	}

	sender := h.open("01993ccb-1111-7aaa-8aaa-111111111111", "/sender")
	recipient := h.open("01993ccb-2222-7aaa-8aaa-222222222222", "/recipient")
	const recipientAddress = "/recipient@host#01993ccb-2222-7aaa-8aaa-222222222222"
	for index := range contractSendCapacity {
		if err := sender.Write(h.ctx, websocket.MessageText, rawSendFrame(
			capacityUUID('1', 0x200+index), capacityUUID('2', 0x200+index), recipientAddress,
			`"timeout-private"`, "",
		)); err != nil {
			t.Fatalf("fill timeout capacity %d: %v", index, err)
		}
	}
	for range contractSendCapacity {
		var offer messageEnvelope
		if err := wsjson.Read(h.ctx, recipient, &offer); err != nil {
			t.Fatalf("read timeout offer: %v", err)
		}
	}
	controlled := make([]*controlledDeadline, 0, contractSendCapacity)
	for range contractSendCapacity {
		select {
		case deadline := <-deadlines:
			controlled = append(controlled, deadline)
		case <-h.ctx.Done():
			t.Fatal("ACK deadline was not installed")
		}
	}
	for _, deadline := range controlled {
		deadline.once.Do(func() { close(deadline.expired) })
	}
	for range contractSendCapacity {
		response := readResponse(t, h.ctx, sender)
		payload := responsePayload(t, response)
		if !strings.Contains(payload, `"status":"timeout"`) || !strings.Contains(payload, `"reason":"ack_timeout"`) {
			t.Fatalf("ACK timeout result = %+v payload=%s", response, payload)
		}
	}

	nextRequest := capacityUUID('3', 0x300)
	nextMessage := capacityUUID('4', 0x300)
	if err := sender.Write(h.ctx, websocket.MessageText, rawSendFrame(
		nextRequest, nextMessage, recipientAddress, `"after-timeout"`, "",
	)); err != nil {
		t.Fatalf("send after all timeouts: %v", err)
	}
	var nextOffer messageEnvelope
	if err := wsjson.Read(h.ctx, recipient, &nextOffer); err != nil {
		t.Fatalf("read offer after all timeouts: %v", err)
	}
	if nextOffer.Payload.MessageID != nextMessage {
		t.Fatalf("offer after timeout release = %+v", nextOffer)
	}
}

func TestWorstCaseAttachedRetriesShareBoundedResponseSequencing(t *testing.T) {
	h := newDedupeTestHarness(t)
	sender := h.open("01993ccf-1111-7aaa-8aaa-111111111111", "/sender")
	recipient := h.open("01993ccf-2222-7aaa-8aaa-222222222222", "/recipient")
	const recipientAddress = "/recipient@host#01993ccf-2222-7aaa-8aaa-222222222222"

	offers := make([]messageEnvelope, 0, contractSendCapacity)
	expectedRequests := make(map[string]string, contractResponseCapacity)
	for index := range contractSendCapacity {
		requestID := capacityUUID('3', 0xa00+index)
		messageID := capacityUUID('4', 0xa00+index)
		expectedRequests[requestID] = messageID
		if err := sender.Write(h.ctx, websocket.MessageText, rawSendFrame(
			requestID, messageID, recipientAddress, fmt.Sprintf(`"worst-case-%d"`, index), "",
		)); err != nil {
			t.Fatalf("write worst-case original %d: %v", index, err)
		}
	}
	for range contractSendCapacity {
		var offer messageEnvelope
		if err := wsjson.Read(h.ctx, recipient, &offer); err != nil {
			t.Fatalf("read worst-case offer: %v", err)
		}
		offers = append(offers, offer)
	}
	for index := range contractSendCapacity {
		retryRequest := capacityUUID('5', 0xa00+index)
		expectedRequests[retryRequest] = capacityUUID('4', 0xa00+index)
		if err := sender.Write(h.ctx, websocket.MessageText, rawSendFrame(
			retryRequest, capacityUUID('4', 0xa00+index), recipientAddress,
			fmt.Sprintf(`"worst-case-%d"`, index), "",
		)); err != nil {
			t.Fatalf("write worst-case attached retry %d: %v", index, err)
		}
	}
	if len(expectedRequests) != contractResponseCapacity {
		t.Fatalf("public send-result correlations = %d, want %d", len(expectedRequests), contractResponseCapacity)
	}

	deniedRequest := capacityUUID('6', 0xb00)
	deniedMessage := capacityUUID('7', 0xb00)
	capacityAudit := make(chan struct{})
	releaseCapacityAudit := make(chan struct{})
	var capacityAuditOnce sync.Once
	h.service.beforeResponseAudit = func(event logEvent) {
		if event.RequestID != deniedRequest {
			return
		}
		capacityAuditOnce.Do(func() { close(capacityAudit) })
		<-releaseCapacityAudit
	}
	var releaseCapacityAuditOnce sync.Once
	t.Cleanup(func() { releaseCapacityAuditOnce.Do(func() { close(releaseCapacityAudit) }) })
	if err := sender.Write(h.ctx, websocket.MessageText, rawSendFrame(
		deniedRequest, deniedMessage, recipientAddress, `"capacity-contender"`, "",
	)); err != nil {
		t.Fatalf("write 129th send: %v", err)
	}
	select {
	case <-capacityAudit:
	case <-h.ctx.Done():
		t.Fatal("129th denial did not own the active response slot")
	}

	allPartial := make(chan struct{})
	releasePartial := make(chan struct{})
	var partialMu sync.Mutex
	partialCount := 0
	h.service.afterResponseSlotReservation = func(batchSize int, reserved int) {
		if batchSize != 2 || reserved != 1 {
			return
		}
		partialMu.Lock()
		partialCount++
		if partialCount == contractSendCapacity {
			close(allPartial)
		}
		partialMu.Unlock()
		<-releasePartial
	}
	var releasePartialOnce sync.Once
	t.Cleanup(func() { releasePartialOnce.Do(func() { close(releasePartial) }) })

	completedReservations := make(chan struct{})
	var completedMu sync.Mutex
	completedCount := 0
	h.service.afterOperationResponseReservation = func(clientOperation) {
		completedMu.Lock()
		completedCount++
		if completedCount == contractSendCapacity-1 {
			close(completedReservations)
		}
		completedMu.Unlock()
	}
	for index, offer := range offers {
		ack := fmt.Sprintf(
			`{"v":1,"type":"received","request_id":%q,"payload":{"delivery_id":%q,"message_id":%q}}`,
			capacityUUID('9', 0xa00+index), offer.Payload.DeliveryID, offer.Payload.MessageID,
		)
		if err := recipient.Write(h.ctx, websocket.MessageText, []byte(ack)); err != nil {
			t.Fatalf("settle worst-case offer %d: %v", index, err)
		}
	}
	select {
	case <-allPartial:
	case <-h.ctx.Done():
		t.Fatal("all 128 two-response batches did not reserve their first slot")
	}
	releasePartialOnce.Do(func() { close(releasePartial) })
	select {
	case <-completedReservations:
	case <-h.ctx.Done():
		t.Fatal("127 two-response batches did not complete reservation under contention")
	}

	listRequest := capacityUUID('8', 0xb00)
	if err := sender.Write(h.ctx, websocket.MessageText, []byte(
		`{"v":1,"type":"list","request_id":"`+listRequest+`","payload":{}}`,
	)); err != nil {
		t.Fatalf("write list under full response contention: %v", err)
	}
	releaseCapacityAuditOnce.Do(func() { close(releaseCapacityAudit) })

	seenSendResults := make(map[string]bool, contractResponseCapacity)
	seenDenial := false
	seenList := false
	for range contractResponseCapacity + 2 {
		response := readResponse(t, h.ctx, sender)
		switch response.RequestID {
		case deniedRequest:
			if responsePayload(t, response) !=
				`{"message_id":"`+deniedMessage+`","reason":"sender_capacity","status":"denied"}` {
				t.Fatalf("worst-case capacity denial = %+v payload=%s", response, responsePayload(t, response))
			}
			seenDenial = true
		case listRequest:
			if response.Type != "roster" {
				t.Fatalf("worst-case list response = %+v", response)
			}
			seenList = true
		default:
			expectedMessage, expected := expectedRequests[response.RequestID]
			if !expected || response.Type != "send_result" || responsePayload(t, response) !=
				`{"message_id":"`+expectedMessage+`","status":"received"}` {
				t.Fatalf("unexpected worst-case response = %+v payload=%s", response, responsePayload(t, response))
			}
			seenSendResults[response.RequestID] = true
		}
	}
	if len(seenSendResults) != contractResponseCapacity || !seenDenial || !seenList {
		t.Fatalf("worst-case responses: sends=%d denial=%t list=%t", len(seenSendResults), seenDenial, seenList)
	}

	healthRequest := capacityUUID('a', 0xb00)
	if err := sender.Write(h.ctx, websocket.MessageText, []byte(
		`{"v":1,"type":"list","request_id":"`+healthRequest+`","payload":{}}`,
	)); err != nil {
		t.Fatalf("write health list after worst-case responses: %v", err)
	}
	if health := readResponse(t, h.ctx, sender); health.Type != "roster" || health.RequestID != healthRequest {
		t.Fatalf("worst-case sequencing damaged sender = %+v", health)
	}
}

func TestImmediateSendStreamRemainsBoundedAndHealthy(t *testing.T) {
	h := newDedupeTestHarness(t)
	sender := h.open("01993ccd-1111-7aaa-8aaa-111111111111", "/sender")
	const sends = 1024
	writeDone := make(chan error, 1)
	go func() {
		for index := range sends {
			if err := sender.Write(h.ctx, websocket.MessageText, rawSendFrame(
				capacityUUID('b', 0x600+index), capacityUUID('c', 0x600+index),
				"/offline@host#01993ccd-2222-7aaa-8aaa-222222222222", `"stream-private"`, "",
			)); err != nil {
				writeDone <- fmt.Errorf("write immediate send %d: %w", index, err)
				return
			}
		}
		writeDone <- nil
	}()

	responses := make(map[string]bool, sends)
	for range sends {
		response := readResponse(t, h.ctx, sender)
		payload := responsePayload(t, response)
		if !strings.Contains(payload, `"reason":"offline"`) &&
			!strings.Contains(payload, `"reason":"sender_capacity"`) {
			t.Fatalf("immediate stream result = %+v payload=%s", response, payload)
		}
		responses[response.RequestID] = true
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if len(responses) != sends {
		t.Fatalf("immediate stream correlations = %d, want %d", len(responses), sends)
	}

	listRequest := capacityUUID('d', 0x700)
	if err := sender.Write(h.ctx, websocket.MessageText, []byte(
		`{"v":1,"type":"list","request_id":"`+listRequest+`","payload":{}}`,
	)); err != nil {
		t.Fatalf("list after immediate stream: %v", err)
	}
	if roster := readResponse(t, h.ctx, sender); roster.Type != "roster" || roster.RequestID != listRequest {
		t.Fatalf("immediate stream damaged sender = %+v", roster)
	}
}

func TestProtocolFailurePreemptsFullResponseBacklogAndUnpublishesSession(t *testing.T) {
	h := newDedupeTestHarness(t)
	const (
		targetRoute   = "01993cce-1111-7aaa-8aaa-111111111111"
		targetAddress = "/target@host#" + targetRoute
		queuedLists   = 256
	)
	target := h.open(targetRoute, "/target")
	observer := h.open("01993cce-2222-7aaa-8aaa-222222222222", "/observer")
	sender := h.open("01993cce-3333-7aaa-8aaa-333333333333", "/sender")

	firstRequest := capacityUUID('e', 0x800)
	activeAudit := make(chan struct{})
	releaseAudit := make(chan struct{})
	var activeOnce sync.Once
	h.service.beforeResponseAudit = func(event logEvent) {
		if event.RequestID != firstRequest {
			return
		}
		activeOnce.Do(func() { close(activeAudit) })
		<-releaseAudit
	}
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseAudit) }) })

	writeList := func(connection *websocket.Conn, requestID string) error {
		return connection.Write(h.ctx, websocket.MessageText, []byte(
			`{"v":1,"type":"list","request_id":"`+requestID+`","payload":{}}`,
		))
	}
	if err := writeList(target, firstRequest); err != nil {
		t.Fatalf("write active list: %v", err)
	}
	select {
	case <-activeAudit:
	case <-h.ctx.Done():
		t.Fatal("first normal response did not reach active audit")
	}
	for index := 1; index < queuedLists; index++ {
		if err := writeList(target, capacityUUID('e', 0x800+index)); err != nil {
			t.Fatalf("fill response backlog %d: %v", index, err)
		}
	}
	terminalTransitioned := make(chan struct{})
	h.service.afterProtocolTerminalTransition = func() { close(terminalTransitioned) }
	if err := target.Write(h.ctx, websocket.MessageText, []byte(`{"v":`)); err != nil {
		t.Fatalf("write terminal malformed frame: %v", err)
	}

	select {
	case <-terminalTransitioned:
	case <-h.ctx.Done():
		t.Fatal("terminal protocol failure waited behind full response backlog")
	}

	observerList := capacityUUID('f', 0x900)
	if err := writeList(observer, observerList); err != nil {
		t.Fatalf("list after terminal transition: %v", err)
	}
	roster := readResponse(t, h.ctx, observer)
	if roster.RequestID != observerList || strings.Contains(responsePayload(t, roster), targetAddress) {
		t.Fatalf("terminally invalid session remained published: %+v payload=%s", roster, responsePayload(t, roster))
	}

	offlineRequest := capacityUUID('1', 0x900)
	offlineMessage := capacityUUID('2', 0x900)
	if err := sender.Write(h.ctx, websocket.MessageText, rawSendFrame(
		offlineRequest, offlineMessage, targetAddress, `"must-not-offer"`, "",
	)); err != nil {
		t.Fatalf("send after terminal transition: %v", err)
	}
	offline := readResponse(t, h.ctx, sender)
	if offline.RequestID != offlineRequest || responsePayload(t, offline) !=
		`{"message_id":"`+offlineMessage+`","reason":"offline","status":"timeout"}` {
		t.Fatalf("post-terminal route result = %+v payload=%s", offline, responsePayload(t, offline))
	}

	releaseOnce.Do(func() { close(releaseAudit) })
	active := readResponse(t, h.ctx, target)
	if active.RequestID != firstRequest || active.Type != "roster" {
		t.Fatalf("active normal response = %+v", active)
	}
	terminal := readResponse(t, h.ctx, target)
	if terminal.Type != "error" || responsePayload(t, terminal) !=
		`{"close":true,"code":"invalid_frame","message":"Invalid WebSocket frame"}` {
		t.Fatalf("terminal response = %+v payload=%s", terminal, responsePayload(t, terminal))
	}
	var discarded operationResponseEnvelope
	if err := wsjson.Read(h.ctx, target, &discarded); err == nil {
		t.Fatalf("queued normal response survived terminal transition: %+v", discarded)
	}
}

func TestTerminalRevocationFencesPreselectedRecipientOffer(t *testing.T) {
	h := newDedupeTestHarness(t)
	const (
		targetRoute   = "01993cc8-1111-7aaa-8aaa-111111111111"
		targetAddress = "/target@host#" + targetRoute
	)
	sender := h.open("01993cc8-2222-7aaa-8aaa-222222222222", "/sender")
	target := h.open(targetRoute, "/target")

	selected := make(chan struct{})
	releaseSelected := make(chan struct{})
	var selectedOnce sync.Once
	h.dispatcher.registry.beforeSessionWriteLease = func(session *authenticatedSession) {
		if session.Address != targetAddress {
			return
		}
		selectedOnce.Do(func() { close(selected) })
		<-releaseSelected
	}
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseSelected) }) })

	requestID := capacityUUID('8', 0xc00)
	messageID := capacityUUID('9', 0xc00)
	if err := sender.Write(h.ctx, websocket.MessageText, rawSendFrame(
		requestID, messageID, targetAddress, `"fenced-private"`, "",
	)); err != nil {
		t.Fatalf("write preselected send: %v", err)
	}
	select {
	case <-selected:
	case <-h.ctx.Done():
		t.Fatal("recipient offer did not reach final write lease boundary")
	}

	terminalTransitioned := make(chan struct{})
	h.service.afterProtocolTerminalTransition = func() { close(terminalTransitioned) }
	if err := target.Write(h.ctx, websocket.MessageText, []byte(`{"v":`)); err != nil {
		t.Fatalf("write recipient terminal frame: %v", err)
	}
	select {
	case <-terminalTransitioned:
	case <-h.ctx.Done():
		t.Fatal("recipient revocation fence did not complete")
	}

	terminal := readResponse(t, h.ctx, target)
	if terminal.Type != "error" || responsePayload(t, terminal) !=
		`{"close":true,"code":"invalid_frame","message":"Invalid WebSocket frame"}` {
		t.Fatalf("recipient terminal response = %+v payload=%s", terminal, responsePayload(t, terminal))
	}
	releaseOnce.Do(func() { close(releaseSelected) })

	result := readResponse(t, h.ctx, sender)
	if result.RequestID != requestID || responsePayload(t, result) !=
		`{"message_id":"`+messageID+`","reason":"recipient_disconnected","status":"timeout"}` {
		t.Fatalf("fenced sender result = %+v payload=%s", result, responsePayload(t, result))
	}
}

func TestClaimedSendResponseYieldsToTerminalProtocolFailure(t *testing.T) {
	h := newDedupeTestHarness(t)
	sender := h.open("01993cc8-3333-7aaa-8aaa-333333333333", "/sender")
	requestID := capacityUUID('a', 0xc01)
	messageID := capacityUUID('b', 0xc01)

	reserved := make(chan struct{})
	releaseReserved := make(chan struct{})
	var reservedOnce sync.Once
	h.service.afterOperationResponseReservation = func(operation clientOperation) {
		if operation.RequestID != requestID {
			return
		}
		reservedOnce.Do(func() { close(reserved) })
		<-releaseReserved
	}
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseReserved) }) })

	claimed := make(chan struct{})
	var claimedOnce sync.Once
	h.service.afterNormalResponseClaim = func(event logEvent) {
		if event.RequestID == requestID {
			claimedOnce.Do(func() { close(claimed) })
		}
	}
	terminalTransitioned := make(chan struct{})
	h.service.afterProtocolTerminalTransition = func() { close(terminalTransitioned) }

	if err := sender.Write(h.ctx, websocket.MessageText, rawSendFrame(
		requestID, messageID, "/offline@host#01993cc8-4444-7aaa-8aaa-444444444444", `"claimed-private"`, "",
	)); err != nil {
		t.Fatalf("write claimed send: %v", err)
	}
	select {
	case <-reserved:
	case <-h.ctx.Done():
		t.Fatal("send response was not reserved")
	}
	select {
	case <-claimed:
	case <-h.ctx.Done():
		t.Fatal("send response was not claimed before its start gate")
	}
	if err := sender.Write(h.ctx, websocket.MessageText, []byte(`{"v":`)); err != nil {
		t.Fatalf("write terminal frame behind claimed response: %v", err)
	}
	select {
	case <-terminalTransitioned:
	case <-h.ctx.Done():
		t.Fatal("terminal transition did not overtake claimed response")
	}
	releaseOnce.Do(func() { close(releaseReserved) })

	terminal := readResponse(t, h.ctx, sender)
	if terminal.Type != "error" || responsePayload(t, terminal) !=
		`{"close":true,"code":"invalid_frame","message":"Invalid WebSocket frame"}` {
		t.Fatalf("claimed-work terminal response = %+v payload=%s", terminal, responsePayload(t, terminal))
	}
	var discarded operationResponseEnvelope
	if err := wsjson.Read(h.ctx, sender, &discarded); err == nil {
		t.Fatalf("claimed normal response survived terminal transition: %+v", discarded)
	}
	if occurrences := strings.Count(h.logs.String(), `"event":"protocol_rejected"`); occurrences != 1 {
		t.Fatalf("protocol_rejected audit occurrences = %d, want 1: %s", occurrences, h.logs.String())
	}
}

func TestClaimedNormalAuditFailurePreservesTerminalHandoff(t *testing.T) {
	h := newDedupeTestHarness(t)
	sender := h.open("01993cc8-8888-7aaa-8aaa-888888888888", "/sender")
	requestID := capacityUUID('4', 0xc03)
	messageID := capacityUUID('5', 0xc03)
	queuedRequest := capacityUUID('6', 0xc03)

	auditFailure := errors.New("injected one-shot claimed normal audit failure")
	auditLogs := &lockedBuffer{changed: make(chan struct{}, 1)}
	failedNormal := false
	auditLogger := newEventLogger(writerFunc(func(data []byte) (int, error) {
		if !failedNormal && strings.Contains(string(data), `"request_id":"`+requestID+`"`) {
			failedNormal = true
			return 0, auditFailure
		}
		return auditLogs.Write(data)
	}))
	t.Cleanup(func() { _ = auditLogger.close() })
	h.service.logger = auditLogger

	normalAuditReached := make(chan struct{})
	releaseNormalAudit := make(chan struct{})
	var normalAuditOnce sync.Once
	h.service.beforeResponseAudit = func(event logEvent) {
		if event.RequestID != requestID {
			return
		}
		normalAuditOnce.Do(func() { close(normalAuditReached) })
		<-releaseNormalAudit
	}
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseNormalAudit) }) })
	terminalTransitioned := make(chan struct{})
	h.service.afterProtocolTerminalTransition = func() { close(terminalTransitioned) }

	if err := sender.Write(h.ctx, websocket.MessageText, rawSendFrame(
		requestID, messageID, "/offline@host#01993cc8-9999-7aaa-8aaa-999999999999",
		`"audit-private"`, "",
	)); err != nil {
		t.Fatalf("write audit-failing send: %v", err)
	}
	select {
	case <-normalAuditReached:
	case <-h.ctx.Done():
		t.Fatal("claimed normal response did not reach post-write audit")
	}
	if err := sender.Write(h.ctx, websocket.MessageText, []byte(
		`{"v":1,"type":"list","request_id":"`+queuedRequest+`","payload":{}}`,
	)); err != nil {
		t.Fatalf("write queued response behind audit: %v", err)
	}
	if err := sender.Write(h.ctx, websocket.MessageText, []byte(`{"v":`)); err != nil {
		t.Fatalf("write terminal frame during normal audit: %v", err)
	}
	select {
	case <-terminalTransitioned:
	case <-h.ctx.Done():
		t.Fatal("terminal transition did not start during claimed normal audit")
	}
	releaseOnce.Do(func() { close(releaseNormalAudit) })

	select {
	case <-h.reporter.reported:
		if !errors.Is(h.reporter.err(), auditFailure) {
			t.Fatalf("fatal owner error = %v, want injected audit failure", h.reporter.err())
		}
	case <-h.ctx.Done():
		t.Fatal("claimed normal audit failure did not reach fatal owner")
	}
	normal := readResponse(t, h.ctx, sender)
	if normal.RequestID != requestID || responsePayload(t, normal) !=
		`{"message_id":"`+messageID+`","reason":"offline","status":"timeout"}` {
		t.Fatalf("claimed normal write = %+v payload=%s", normal, responsePayload(t, normal))
	}
	terminal := readResponse(t, h.ctx, sender)
	if terminal.Type != "error" || responsePayload(t, terminal) !=
		`{"close":true,"code":"invalid_frame","message":"Invalid WebSocket frame"}` {
		t.Fatalf("audit-failure terminal response = %+v payload=%s", terminal, responsePayload(t, terminal))
	}
	var discarded operationResponseEnvelope
	if err := wsjson.Read(h.ctx, sender, &discarded); err == nil {
		t.Fatalf("queued normal response survived audit-failure terminal handoff: %+v", discarded)
	}
	for !strings.Contains(auditLogs.String(), `"event":"session_disconnected"`) {
		select {
		case <-auditLogs.changed:
		case <-h.ctx.Done():
			t.Fatalf("handler did not settle after audit-failure terminal handoff: %s", auditLogs.String())
		}
	}
	logs := auditLogs.String()
	if occurrences := strings.Count(logs, `"event":"protocol_rejected"`); occurrences != 1 {
		t.Fatalf("protocol_rejected audit occurrences = %d, want 1: %s", occurrences, logs)
	}
	if strings.Contains(logs, queuedRequest) {
		t.Fatalf("queued normal response was audited after terminal transition: %s", logs)
	}
}

func TestNormalWriteRevocationPreservesTerminalHandoff(t *testing.T) {
	h := newDedupeTestHarness(t)
	const (
		senderRoute   = "01993cc8-aaaa-7aaa-8aaa-aaaaaaaaaaaa"
		senderAddress = "/sender@host#" + senderRoute
	)
	sender := h.open(senderRoute, "/sender")
	requestID := capacityUUID('7', 0xc04)
	queuedRequest := capacityUUID('8', 0xc04)

	writeSelected := make(chan struct{})
	releaseWrite := make(chan struct{})
	var selectedOnce sync.Once
	h.dispatcher.registry.beforeSessionWriteLease = func(session *authenticatedSession) {
		if session.Address != senderAddress {
			return
		}
		selectedOnce.Do(func() { close(writeSelected) })
		<-releaseWrite
	}
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseWrite) }) })
	terminalTransitioned := make(chan struct{})
	h.service.afterProtocolTerminalTransition = func() { close(terminalTransitioned) }

	if err := sender.Write(h.ctx, websocket.MessageText, []byte(
		`{"v":1,"type":"list","request_id":"`+requestID+`","payload":{}}`,
	)); err != nil {
		t.Fatalf("write normal response for revocation race: %v", err)
	}
	select {
	case <-writeSelected:
	case <-h.ctx.Done():
		t.Fatal("normal response did not reach final write lease boundary")
	}
	if err := sender.Write(h.ctx, websocket.MessageText, []byte(
		`{"v":1,"type":"list","request_id":"`+queuedRequest+`","payload":{}}`,
	)); err != nil {
		t.Fatalf("write queued response before revocation: %v", err)
	}
	if err := sender.Write(h.ctx, websocket.MessageText, []byte(`{"v":`)); err != nil {
		t.Fatalf("write terminal frame during normal write: %v", err)
	}
	select {
	case <-terminalTransitioned:
	case <-h.ctx.Done():
		t.Fatal("terminal transition did not revoke selected normal write")
	}
	releaseOnce.Do(func() { close(releaseWrite) })

	terminal := readResponse(t, h.ctx, sender)
	if terminal.Type != "error" || responsePayload(t, terminal) !=
		`{"close":true,"code":"invalid_frame","message":"Invalid WebSocket frame"}` {
		t.Fatalf("write-revocation terminal response = %+v payload=%s", terminal, responsePayload(t, terminal))
	}
	var discarded operationResponseEnvelope
	if err := wsjson.Read(h.ctx, sender, &discarded); err == nil {
		t.Fatalf("normal response survived terminal write revocation: %+v", discarded)
	}
	awaitLogOccurrences(t, h, `"event":"session_disconnected","address":"`+senderAddress+`"`, 1)
	logs := h.logs.String()
	if occurrences := strings.Count(logs, `"event":"protocol_rejected"`); occurrences != 1 {
		t.Fatalf("protocol_rejected audit occurrences = %d, want 1: %s", occurrences, logs)
	}
	if strings.Contains(logs, requestID) || strings.Contains(logs, queuedRequest) {
		t.Fatalf("revoked normal response was audited: %s", logs)
	}
	select {
	case <-h.reporter.reported:
		t.Fatalf("terminal-caused normal write error became fatal: %v", h.reporter.err())
	default:
	}
}

func TestReplacementWorkersReserveBeforeEncodingResponses(t *testing.T) {
	h := newDedupeTestHarness(t)
	sender := h.open("01993cc8-5555-7aaa-8aaa-555555555555", "/sender")
	recipient := h.open("01993cc8-6666-7aaa-8aaa-666666666666", "/recipient")
	const recipientAddress = "/recipient@host#01993cc8-6666-7aaa-8aaa-666666666666"

	activeRequest := capacityUUID('c', 0xc02)
	activeAudit := make(chan struct{})
	releaseAudit := make(chan struct{})
	var activeOnce sync.Once
	h.service.beforeResponseAudit = func(event logEvent) {
		if event.RequestID != activeRequest {
			return
		}
		activeOnce.Do(func() { close(activeAudit) })
		<-releaseAudit
	}
	var releaseAuditOnce sync.Once
	t.Cleanup(func() { releaseAuditOnce.Do(func() { close(releaseAudit) }) })

	offers := make([]messageEnvelope, 0, contractSendCapacity)
	for index := range contractSendCapacity {
		if err := sender.Write(h.ctx, websocket.MessageText, rawSendFrame(
			capacityUUID('d', 0xd00+index), capacityUUID('e', 0xd00+index), recipientAddress,
			fmt.Sprintf(`"reservation-%d"`, index), "",
		)); err != nil {
			t.Fatalf("write reservation original %d: %v", index, err)
		}
	}
	for range contractSendCapacity {
		var offer messageEnvelope
		if err := wsjson.Read(h.ctx, recipient, &offer); err != nil {
			t.Fatalf("read reservation offer: %v", err)
		}
		offers = append(offers, offer)
	}
	for index := range contractSendCapacity {
		if err := sender.Write(h.ctx, websocket.MessageText, rawSendFrame(
			capacityUUID('f', 0xd00+index), capacityUUID('e', 0xd00+index), recipientAddress,
			fmt.Sprintf(`"reservation-%d"`, index), "",
		)); err != nil {
			t.Fatalf("write reservation retry %d: %v", index, err)
		}
	}
	if err := sender.Write(h.ctx, websocket.MessageText, []byte(
		`{"v":1,"type":"list","request_id":"`+activeRequest+`","payload":{}}`,
	)); err != nil {
		t.Fatalf("write active response after retries: %v", err)
	}
	select {
	case <-activeAudit:
	case <-h.ctx.Done():
		t.Fatal("active response did not synchronize retries and retain one response slot")
	}

	allPartial := make(chan struct{})
	releasePartial := make(chan struct{})
	var partialMu sync.Mutex
	partialCount := 0
	h.service.afterResponseSlotReservation = func(batchSize int, reserved int) {
		if batchSize != 2 || reserved != 1 {
			return
		}
		partialMu.Lock()
		partialCount++
		if partialCount == contractSendCapacity {
			close(allPartial)
		}
		partialMu.Unlock()
		<-releasePartial
	}
	var releasePartialOnce sync.Once
	t.Cleanup(func() { releasePartialOnce.Do(func() { close(releasePartial) }) })
	completedReservations := make(chan struct{})
	var completedMu sync.Mutex
	completedCount := 0
	h.service.afterOperationResponseReservation = func(clientOperation) {
		completedMu.Lock()
		completedCount++
		if completedCount == contractSendCapacity-1 {
			close(completedReservations)
		}
		completedMu.Unlock()
	}
	for index, offer := range offers {
		ack := fmt.Sprintf(
			`{"v":1,"type":"received","request_id":%q,"payload":{"delivery_id":%q,"message_id":%q}}`,
			capacityUUID('1', 0xe00+index), offer.Payload.DeliveryID, offer.Payload.MessageID,
		)
		if err := recipient.Write(h.ctx, websocket.MessageText, []byte(ack)); err != nil {
			t.Fatalf("settle reservation offer %d: %v", index, err)
		}
	}
	select {
	case <-allPartial:
	case <-h.ctx.Done():
		t.Fatal("all original batches did not hold one reserved slot")
	}
	releasePartialOnce.Do(func() { close(releasePartial) })
	select {
	case <-completedReservations:
	case <-h.ctx.Done():
		t.Fatal("127 original batches did not fill remaining response slots")
	}

	replacementRequests := make(map[string]struct{}, contractSendCapacity-1)
	for index := 0; index < contractSendCapacity-1; index++ {
		replacementRequests[capacityUUID('2', 0xf00+index)] = struct{}{}
	}
	allWaiting := make(chan struct{})
	prepared := make(chan string, 1)
	var waitingMu sync.Mutex
	waitingCount := 0
	h.service.beforeResponseBatchReservation = func(operation clientOperation, batchSize int) {
		if _, replacement := replacementRequests[operation.RequestID]; !replacement || batchSize != 1 {
			return
		}
		waitingMu.Lock()
		waitingCount++
		if waitingCount == contractSendCapacity-1 {
			close(allWaiting)
		}
		waitingMu.Unlock()
	}
	h.service.beforeResponsePreparation = func(operation clientOperation) {
		if _, replacement := replacementRequests[operation.RequestID]; replacement {
			select {
			case prepared <- operation.RequestID:
			default:
			}
		}
	}
	for index := 0; index < contractSendCapacity-1; index++ {
		requestID := capacityUUID('2', 0xf00+index)
		if err := sender.Write(h.ctx, websocket.MessageText, rawSendFrame(
			requestID, capacityUUID('3', 0xf00+index),
			"/offline@host#01993cc8-7777-7aaa-8aaa-777777777777",
			fmt.Sprintf(`"replacement-%d"`, index), "",
		)); err != nil {
			t.Fatalf("write replacement send %d: %v", index, err)
		}
	}
	select {
	case <-allWaiting:
	case <-h.ctx.Done():
		t.Fatal("replacement workers did not all reach response reservation")
	}
	select {
	case requestID := <-prepared:
		t.Fatalf("replacement response %s encoded before owning a response slot", requestID)
	default:
	}

	_ = sender.CloseNow()
	releaseAuditOnce.Do(func() { close(releaseAudit) })
}

func TestSenderDisconnectAbandonsAllCapacityWorkersBeforeSameRouteReconnect(t *testing.T) {
	h := newDedupeTestHarness(t)
	type controlledDeadline struct {
		expired chan time.Time
		stopped chan struct{}
		once    sync.Once
	}
	deadlines := make(chan *controlledDeadline, contractSendCapacity)
	h.dispatcher.deadlineFactory = func(time.Duration) deliveryDeadline {
		controlled := &controlledDeadline{expired: make(chan time.Time), stopped: make(chan struct{})}
		deadlines <- controlled
		return deliveryDeadline{
			expired: controlled.expired,
			stop: func() bool {
				controlled.once.Do(func() { close(controlled.stopped) })
				return true
			},
		}
	}

	const (
		senderRoute      = "01993ccc-1111-7aaa-8aaa-111111111111"
		senderAddress    = "/sender@host#" + senderRoute
		recipientAddress = "/recipient@host#01993ccc-2222-7aaa-8aaa-222222222222"
	)
	sender := h.open(senderRoute, "/sender")
	recipient := h.open("01993ccc-2222-7aaa-8aaa-222222222222", "/recipient")
	offers := make([]messageEnvelope, 0, contractSendCapacity)
	for index := range contractSendCapacity {
		if err := sender.Write(h.ctx, websocket.MessageText, rawSendFrame(
			capacityUUID('5', 0x400+index), capacityUUID('6', 0x400+index), recipientAddress,
			`"abandon-private"`, "",
		)); err != nil {
			t.Fatalf("fill sender before disconnect %d: %v", index, err)
		}
	}
	for range contractSendCapacity {
		var offer messageEnvelope
		if err := wsjson.Read(h.ctx, recipient, &offer); err != nil {
			t.Fatalf("read abandoned offer: %v", err)
		}
		offers = append(offers, offer)
	}
	controlled := make([]*controlledDeadline, 0, contractSendCapacity)
	for range contractSendCapacity {
		select {
		case deadline := <-deadlines:
			controlled = append(controlled, deadline)
		case <-h.ctx.Done():
			t.Fatal("abandoned ACK deadline was not installed")
		}
	}
	if err := sender.Close(websocket.StatusNormalClosure, "abandon full sender"); err != nil {
		t.Fatalf("disconnect full sender: %v", err)
	}
	awaitLogOccurrences(t, h, `"event":"session_disconnected","address":"`+senderAddress+`"`, 1)
	for _, deadline := range controlled {
		select {
		case <-deadline.stopped:
		case <-h.ctx.Done():
			t.Fatal("sender disconnect did not stop every ACK deadline")
		}
	}
	if _, _, err := sender.Read(h.ctx); err == nil {
		t.Fatal("disconnected sender received a public result")
	}

	for index, offer := range offers {
		ack := fmt.Sprintf(
			`{"v":1,"type":"received","request_id":%q,"payload":{"delivery_id":%q,"message_id":%q}}`,
			capacityUUID('7', 0x400+index), offer.Payload.DeliveryID, offer.Payload.MessageID,
		)
		if err := recipient.Write(h.ctx, websocket.MessageText, []byte(ack)); err != nil {
			t.Fatalf("write stale ACK %d: %v", index, err)
		}
	}
	listRequest := capacityUUID('8', 0x500)
	if err := recipient.Write(h.ctx, websocket.MessageText, []byte(
		`{"v":1,"type":"list","request_id":"`+listRequest+`","payload":{}}`,
	)); err != nil {
		t.Fatalf("list after stale ACK stream: %v", err)
	}
	if roster := readResponse(t, h.ctx, recipient); roster.Type != "roster" || roster.RequestID != listRequest {
		t.Fatalf("stale ACK stream damaged recipient = %+v", roster)
	}

	reconnected := h.open(senderRoute, "/sender")
	awaitLogOccurrences(t, h, `"event":"auth_accepted","address":"`+senderAddress+`"`, 2)
	freshRequest := capacityUUID('9', 0x500)
	freshMessage := capacityUUID('a', 0x500)
	if err := reconnected.Write(h.ctx, websocket.MessageText, rawSendFrame(
		freshRequest, freshMessage, recipientAddress, `"fresh-after-abandon"`, "",
	)); err != nil {
		t.Fatalf("send after same-route reconnect: %v", err)
	}
	var freshOffer messageEnvelope
	if err := wsjson.Read(h.ctx, recipient, &freshOffer); err != nil {
		t.Fatalf("read same-route reconnect offer: %v", err)
	}
	if freshOffer.Payload.MessageID != freshMessage {
		t.Fatalf("same-route reconnect offer = %+v", freshOffer)
	}
}
