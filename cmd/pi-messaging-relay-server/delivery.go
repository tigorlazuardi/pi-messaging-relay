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

type deliveryDeadline struct {
	expired <-chan time.Time
	stop    func() bool
}

type deliveryDispatcher struct {
	registry        *sessionConnectionRegistry
	roster          operationDispatcher
	deadlineFactory func(time.Duration) deliveryDeadline
	mu              sync.Mutex
	pending         map[string]*pendingDelivery
}

func newDeliveryDispatcher(registry *sessionConnectionRegistry) *deliveryDispatcher {
	dispatcher := &deliveryDispatcher{
		registry: registry,
		roster:   rosterOperationDispatcher(registry),
		deadlineFactory: func(duration time.Duration) deliveryDeadline {
			timer := time.NewTimer(duration)
			return deliveryDeadline{expired: timer.C, stop: timer.Stop}
		},
		pending: make(map[string]*pendingDelivery),
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
	recipient, ok := dispatcher.registry.publishedSession(operation.Send.To)
	if !ok {
		return operationResponse{
			Type: "send_result",
			Payload: sendResultPayload{
				MessageID: operation.Send.MessageID,
				Status:    "timeout",
				Reason:    "offline",
			},
			Outcome:        "settled",
			Code:           "offline",
			MessageID:      operation.Send.MessageID,
			SenderRoute:    sender.Address,
			RecipientRoute: operation.Send.To,
			Status:         "timeout",
		}, true, nil
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

	remove := func() bool {
		dispatcher.lock()
		defer dispatcher.unlock()
		if dispatcher.pending[deliveryID] != pending {
			return false
		}
		delete(dispatcher.pending, deliveryID)
		return true
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

	received := func() (operationResponse, bool, error) {
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
	}
	claimedOutcome := func() (operationResponse, bool, error) {
		select {
		case <-pending.acknowledged:
			return received()
		case <-pending.cancelled:
			return operationResponse{}, false, nil
		}
	}

	deadline := dispatcher.deadlineFactory(deliveryACKCeiling)
	defer deadline.stop()
	select {
	case <-pending.acknowledged:
		return received()
	case <-pending.cancelled:
		return operationResponse{}, false, nil
	case <-dispatcher.registry.closingSignal():
		if remove() {
			return operationResponse{}, false, nil
		}
		return claimedOutcome()
	case <-ctx.Done():
		if remove() {
			return operationResponse{}, false, nil
		}
		return claimedOutcome()
	case <-deadline.expired:
		if !remove() {
			return claimedOutcome()
		}
		return operationResponse{
			Type: "send_result",
			Payload: sendResultPayload{
				MessageID: operation.Send.MessageID,
				Status:    "timeout",
				Reason:    "ack_timeout",
			},
			Outcome:        "settled",
			Code:           "ack_timeout",
			MessageID:      operation.Send.MessageID,
			DeliveryID:     deliveryID,
			SenderRoute:    sender.Address,
			RecipientRoute: recipient.Address,
			Status:         "timeout",
		}, true, nil
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
