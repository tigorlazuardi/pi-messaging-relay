package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

const deliveryACKCeiling = 5 * time.Second

type messageEnvelope struct {
	Version int            `json:"v"`
	Type    string         `json:"type"`
	Payload messagePayload `json:"payload"`
}

type messagePayload struct {
	DeliveryID string          `json:"delivery_id"`
	MessageID  string          `json:"message_id"`
	From       string          `json:"from"`
	To         string          `json:"to"`
	Body       json.RawMessage `json:"body"`
	Re         string          `json:"re,omitempty"`
}

type pendingDelivery struct {
	sender       *authenticatedSession
	recipient    *authenticatedSession
	requestID    string
	messageID    string
	deliveryID   string
	acknowledged chan struct{}
	cancelled    chan struct{}
}

type deliveryDispatcher struct {
	registry *sessionConnectionRegistry
	roster   operationDispatcher
	mu       sync.Mutex
	pending  map[string]*pendingDelivery
}

func newDeliveryDispatcher(registry *sessionConnectionRegistry) *deliveryDispatcher {
	dispatcher := &deliveryDispatcher{
		registry: registry,
		roster:   rosterOperationDispatcher(registry),
		pending:  make(map[string]*pendingDelivery),
	}
	registry.onSessionUnavailable = dispatcher.cancelRecipient
	return dispatcher
}

func (dispatcher *deliveryDispatcher) dispatch(
	ctx context.Context,
	session *authenticatedSession,
	operation clientOperation,
) (operationResponse, bool, error) {
	if operation.Type == "list" {
		return dispatcher.roster(ctx, session, operation)
	}
	if operation.Type == "received" && operation.Received != nil {
		dispatcher.receive(session, operation.Received)
		return operationResponse{}, false, nil
	}
	if operation.Type != "send" || operation.Send == nil {
		return operationResponse{}, false, nil
	}
	return dispatcher.send(ctx, session, operation)
}

func (dispatcher *deliveryDispatcher) send(
	ctx context.Context,
	sender *authenticatedSession,
	operation clientOperation,
) (operationResponse, bool, error) {
	if len(operation.Send.Body) > 0 && operation.Send.Body[0] == '{' {
		// Ticket #16 owns object rendering. Keep its accepted wire shape parseable,
		// but create no offer or pending state until deterministic rendering exists.
		return operationResponse{}, false, nil
	}
	recipient, ok := dispatcher.registry.publishedSession(operation.Send.To)
	if !ok {
		// Ticket #18 owns the externally visible offline result. This operation ends
		// without retaining work until that result vocabulary is implemented.
		return operationResponse{}, false, nil
	}
	deliveryID, err := generateServerUUIDv7(time.Now())
	if err != nil {
		return operationResponse{}, false, fmt.Errorf("generate delivery ID: %w", err)
	}
	pending := &pendingDelivery{
		sender:       sender,
		recipient:    recipient,
		requestID:    operation.RequestID,
		messageID:    operation.Send.MessageID,
		deliveryID:   deliveryID,
		acknowledged: make(chan struct{}),
		cancelled:    make(chan struct{}),
	}
	dispatcher.lock()
	if _, collision := dispatcher.pending[deliveryID]; collision {
		dispatcher.unlock()
		return operationResponse{}, false, errors.New("generated duplicate delivery ID")
	}
	dispatcher.pending[deliveryID] = pending
	dispatcher.unlock()

	remove := func() {
		dispatcher.lock()
		if dispatcher.pending[deliveryID] == pending {
			delete(dispatcher.pending, deliveryID)
		}
		dispatcher.unlock()
	}

	frame, err := json.Marshal(messageEnvelope{
		Version: 1,
		Type:    "message",
		Payload: messagePayload{
			DeliveryID: deliveryID,
			MessageID:  operation.Send.MessageID,
			From:       sender.Address,
			To:         operation.Send.To,
			Body:       append(json.RawMessage(nil), operation.Send.Body...),
			Re:         operation.Send.Re,
		},
	})
	if err != nil {
		remove()
		return operationResponse{}, false, errors.New("encode delivery offer")
	}
	if len(frame) > maxFrameBytes {
		remove()
		return operationResponse{}, false, nil
	}
	writeContext, cancelWrite := context.WithTimeout(ctx, protocolResponseWriteTimeout)
	err = dispatcher.registry.writeToSession(writeContext, recipient, frame)
	cancelWrite()
	if err != nil {
		remove()
		// Ticket #20 owns the recipient-disconnected sender result. Socket loss is
		// local and retained work is released now.
		return operationResponse{}, false, nil
	}

	timer := time.NewTimer(deliveryACKCeiling)
	defer timer.Stop()
	select {
	case <-pending.acknowledged:
		return operationResponse{
			Type:           "send_result",
			Payload:        sendResultPayload{MessageID: operation.Send.MessageID, Status: "received"},
			Outcome:        "settled",
			Code:           "received",
			MessageID:      operation.Send.MessageID,
			DeliveryID:     deliveryID,
			SenderRoute:    sender.Address,
			RecipientRoute: recipient.Address,
			Status:         "received",
		}, true, nil
	case <-pending.cancelled:
		remove()
		return operationResponse{}, false, nil
	case <-dispatcher.registry.closingSignal():
		remove()
		return operationResponse{}, false, nil
	case <-ctx.Done():
		remove()
		return operationResponse{}, false, nil
	case <-timer.C:
		// Ticket #19 owns the externally visible ack_timeout result. The internal
		// ceiling already releases capacity and makes a late ACK harmless.
		remove()
		return operationResponse{}, false, nil
	}
}

func (dispatcher *deliveryDispatcher) receive(
	recipient *authenticatedSession,
	ack *receivedOperationPayload,
) {
	dispatcher.lock()
	pending := dispatcher.pending[ack.DeliveryID]
	if pending == nil || pending.recipient != recipient || pending.messageID != ack.MessageID {
		dispatcher.unlock()
		return
	}
	delete(dispatcher.pending, ack.DeliveryID)
	close(pending.acknowledged)
	dispatcher.unlock()
}

func (dispatcher *deliveryDispatcher) cancelRecipient(recipient *authenticatedSession) {
	if recipient == nil {
		return
	}
	dispatcher.lock()
	for deliveryID, pending := range dispatcher.pending {
		if pending.recipient != recipient {
			continue
		}
		delete(dispatcher.pending, deliveryID)
		close(pending.cancelled)
	}
	dispatcher.unlock()
}

func (dispatcher *deliveryDispatcher) lock()   { dispatcher.mu.Lock() }
func (dispatcher *deliveryDispatcher) unlock() { dispatcher.mu.Unlock() }

func generateServerUUIDv7(now time.Time) (string, error) {
	milliseconds := now.UnixMilli()
	if milliseconds < 0 || milliseconds > 0xffffffffffff {
		return "", errors.New("UUIDv7 timestamp is outside 48-bit Unix millisecond range")
	}
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	for index := 5; index >= 0; index-- {
		value[index] = byte(milliseconds)
		milliseconds >>= 8
	}
	value[6] = value[6]&0x0f | 0x70
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}
