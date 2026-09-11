package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"
)

const (
	maxAddressBytes              = maxCWDBytes + 1 + maxHostnameBytes + 1 + 36
	maxCursorBytes               = 5856
	maxJSONNestingDepth          = 64
	protocolResponseWriteTimeout = time.Second
	cursorPrefix                 = "cur_"
)

type listOperationPayload struct {
	AfterAddress string
}

type sendOperationPayload struct {
	MessageID    string
	To           string
	Body         json.RawMessage
	Re           string
	RePresent    bool
	BodyTooLarge bool
}

type receivedOperationPayload struct {
	DeliveryID string
	MessageID  string
}

type clientOperation struct {
	Type       string
	RequestID  string
	List       *listOperationPayload
	Send       *sendOperationPayload
	Received   *receivedOperationPayload
	Record     *dedupeRecord
	Dedupe     string
	ObservedAt time.Time
}

type operationResponse struct {
	Type           string
	Payload        any
	Outcome        string
	Code           string
	PeerCount      *int
	MessageID      string
	DeliveryID     string
	SenderRoute    string
	RecipientRoute string
	Status         string
}

type operationResponseEnvelope struct {
	Version   int    `json:"v"`
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	Payload   any    `json:"payload"`
}

type sendResultPayload struct {
	MessageID string `json:"message_id"`
	Status    string `json:"status"`
	Reason    string `json:"reason,omitempty"`
}

type operationDispatcher func(
	context.Context,
	*authenticatedSession,
	clientOperation,
) (operationResponse, bool, error)

type protocolFailure struct {
	Code      string
	Reason    string
	RequestID string
	Type      string
}

func noOperationDispatcher(
	context.Context,
	*authenticatedSession,
	clientOperation,
) (operationResponse, bool, error) {
	return operationResponse{}, false, nil
}

type authenticatedResponseWork struct {
	encoded        []byte
	log            logEvent
	started        time.Time
	measureLatency bool
	start          <-chan struct{}
	done           chan<- bool
}

const (
	// ponytail: fixed to v1's exact authenticated-session ceiling.
	maxInFlightSendsPerSession = 128
	// Each admitted logical send can own one original and one attached retry response.
	maxSequencedResponsesPerSession = maxInFlightSendsPerSession * 2
)

func (service *sessionAuthService) serveAuthenticated(
	connection *websocket.Conn,
	session *authenticatedSession,
	markUnavailable func(),
) {
	serveContext, cancelServe := context.WithCancel(context.Background())
	producerContext, cancelProducers := context.WithCancel(serveContext)
	responseQueue := make(chan authenticatedResponseWork, maxSequencedResponsesPerSession)
	responseSlots := make(chan struct{}, maxSequencedResponsesPerSession)
	responseDone := make(chan struct{})
	terminalQueue := make(chan authenticatedResponseWork, 1)
	terminalSignal := make(chan struct{})
	sendCapacity := make(chan struct{}, maxInFlightSendsPerSession)
	var sendWorkers sync.WaitGroup
	var responseAdmissionMu sync.Mutex
	terminalStarted := false

	var terminateOnce sync.Once
	terminate := func() {
		terminateOnce.Do(func() {
			markUnavailable()
			cancelProducers()
			cancelServe()
			_ = connection.CloseNow()
		})
	}
	defer func() {
		terminate()
		sendWorkers.Wait()
		<-responseDone
	}()

	prepareResponse := func(
		operation clientOperation,
		response operationResponse,
		operationStarted time.Time,
		start <-chan struct{},
	) (authenticatedResponseWork, error) {
		if service.beforeResponsePreparation != nil {
			service.beforeResponsePreparation(operation)
		}
		encodedResponse, err := encodeOperationResponse(operation, response)
		if err != nil {
			return authenticatedResponseWork{}, err
		}
		event := "operation_settled"
		level := "info"
		if operation.Type == "send" && response.Outcome == "settled" && operation.Dedupe == "" {
			event = "send_settled"
		}
		if response.Outcome == "denied" {
			event = "operation_denied"
			level = "warn"
		}
		log := logEvent{
			Level:          level,
			Event:          event,
			Result:         response.Outcome,
			Reason:         response.Code,
			Code:           response.Code,
			Type:           operation.Type,
			RequestID:      operation.RequestID,
			Count:          response.PeerCount,
			MessageID:      response.MessageID,
			DeliveryID:     response.DeliveryID,
			SenderRoute:    response.SenderRoute,
			RecipientRoute: response.RecipientRoute,
			Status:         response.Status,
			Dedupe:         operation.Dedupe,
		}
		if operation.Type == "send" {
			log.Body = redacted
		}
		return authenticatedResponseWork{
			encoded:        encodedResponse,
			log:            log,
			started:        operationStarted,
			measureLatency: true,
			start:          start,
		}, nil
	}

	releaseResponseSlots := func(count int) {
		for range count {
			<-responseSlots
		}
	}
	reserveResponseBatch := func(operation clientOperation, count int) bool {
		if service.beforeResponseBatchReservation != nil {
			service.beforeResponseBatchReservation(operation, count)
		}
		reserved := 0
		for reserved < count {
			select {
			case responseSlots <- struct{}{}:
				reserved++
				if service.afterResponseSlotReservation != nil {
					service.afterResponseSlotReservation(count, reserved)
				}
			case <-producerContext.Done():
				releaseResponseSlots(reserved)
				return false
			}
		}
		return true
	}
	publishReservedResponseBatch := func(works []authenticatedResponseWork) bool {
		// Publication and the terminal transition share this lock. Once the
		// transition wins, no completely reserved normal batch can enter the queue.
		responseAdmissionMu.Lock()
		defer responseAdmissionMu.Unlock()
		if terminalStarted {
			releaseResponseSlots(len(works))
			return false
		}
		select {
		case <-producerContext.Done():
			releaseResponseSlots(len(works))
			return false
		default:
		}
		for _, work := range works {
			// Response slots and queue capacity have the same ceiling. An active
			// writer owns a slot outside the queue, so a reserved batch always fits.
			responseQueue <- work
		}
		return true
	}

	finishResponse := func(work authenticatedResponseWork, settled bool) {
		if work.done == nil {
			return
		}
		select {
		case work.done <- settled:
		default:
		}
	}
	discardQueuedResponses := func() {
		for {
			select {
			case work := <-responseQueue:
				finishResponse(work, false)
				releaseResponseSlots(1)
			default:
				return
			}
		}
	}
	terminalIsStarted := func() bool {
		responseAdmissionMu.Lock()
		defer responseAdmissionMu.Unlock()
		return terminalStarted
	}
	claimNormalResponse := func() bool {
		responseAdmissionMu.Lock()
		defer responseAdmissionMu.Unlock()
		return !terminalStarted
	}

	go func() {
		defer close(responseDone)
		for {
			if terminalIsStarted() {
				discardQueuedResponses()
				select {
				case terminalWork := <-terminalQueue:
					writeContext, cancelWrite := context.WithTimeout(
						context.Background(), protocolResponseWriteTimeout,
					)
					writeErr := service.connections.writeToConnection(writeContext, connection, terminalWork.encoded)
					cancelWrite()
					if service.beforeResponseAudit != nil {
						service.beforeResponseAudit(terminalWork.log)
					}
					audited := service.writeAudit(terminalWork.log)
					finishResponse(terminalWork, writeErr == nil && audited)
				case <-serveContext.Done():
				}
				return
			}

			select {
			case work := <-responseQueue:
				// Claiming under the admission lock defines the one normal work
				// item allowed to finish after a terminal transition begins.
				if !claimNormalResponse() {
					finishResponse(work, false)
					releaseResponseSlots(1)
					continue
				}
				if service.afterNormalResponseClaim != nil {
					service.afterNormalResponseClaim(work.log)
				}
				select {
				case <-work.start:
				case <-serveContext.Done():
					finishResponse(work, false)
					releaseResponseSlots(1)
					discardQueuedResponses()
					return
				}
				// A claimed response whose producer had not opened its start gate is
				// not the active write permitted to cross a terminal transition.
				if terminalIsStarted() {
					finishResponse(work, false)
					releaseResponseSlots(1)
					continue
				}
				writeContext, cancelWrite := context.WithTimeout(serveContext, protocolResponseWriteTimeout)
				err := service.connections.writeToSession(writeContext, session, work.encoded)
				cancelWrite()
				if err != nil {
					finishResponse(work, false)
					releaseResponseSlots(1)
					if terminalIsStarted() {
						continue
					}
					terminate()
					discardQueuedResponses()
					return
				}
				if work.measureLatency {
					work.log.LatencyMS = latencySince(work.started)
				}
				if service.beforeResponseAudit != nil {
					service.beforeResponseAudit(work.log)
				}
				if !service.writeAudit(work.log) {
					finishResponse(work, false)
					releaseResponseSlots(1)
					if terminalIsStarted() {
						continue
					}
					terminate()
					discardQueuedResponses()
					return
				}
				finishResponse(work, true)
				releaseResponseSlots(1)
			case <-terminalSignal:
				// The next loop discards queued normal work before terminal I/O.
			case <-serveContext.Done():
				discardQueuedResponses()
				return
			}
		}
	}()

	immediateStart := make(chan struct{})
	close(immediateStart)
	enqueuePreparedResponse := func(
		operation clientOperation,
		response operationResponse,
		operationStarted time.Time,
	) bool {
		if !reserveResponseBatch(operation, 1) {
			return false
		}
		work, err := prepareResponse(operation, response, operationStarted, immediateStart)
		if err != nil {
			releaseResponseSlots(1)
			service.reportFatal(fmt.Errorf("prepare %s operation response: %w", operation.Type, err))
			terminate()
			return false
		}
		return publishReservedResponseBatch([]authenticatedResponseWork{work})
	}
	dispatchSynchronous := func(operation clientOperation, operationStarted time.Time) bool {
		response, respond, err := service.dispatchOperation(producerContext, session, operation)
		if err != nil {
			service.reportFatal(fmt.Errorf("dispatch %s operation: %w", operation.Type, err))
			terminate()
			return false
		}
		if !respond {
			return true
		}
		return enqueuePreparedResponse(operation, response, operationStarted)
	}

	startSend := func(operation clientOperation, operationStarted time.Time) {
		sendWorkers.Add(1)
		go func() {
			defer sendWorkers.Done()
			capacityOwned := true
			releaseCapacity := func() {
				if !capacityOwned {
					return
				}
				<-sendCapacity
				capacityOwned = false
			}
			defer releaseCapacity()

			response, respond, err := service.dispatchOperation(producerContext, session, operation)
			attached := service.connections.dedupe.complete(operation.Record, response, respond)
			if err != nil {
				service.reportFatal(fmt.Errorf("dispatch send operation: %w", err))
				terminate()
				return
			}
			if !respond {
				return
			}

			batchSize := 1
			if attached != nil {
				batchSize = 2
			}
			if !reserveResponseBatch(operation, batchSize) {
				return
			}

			start := make(chan struct{})
			works := make([]authenticatedResponseWork, 0, batchSize)
			work, prepareErr := prepareResponse(operation, response, operationStarted, start)
			if prepareErr != nil {
				releaseResponseSlots(batchSize)
				service.reportFatal(fmt.Errorf(
					"prepare send operation response for request %s: %w",
					operation.RequestID,
					prepareErr,
				))
				terminate()
				return
			}
			works = append(works, work)
			if attached != nil {
				attachedStarted := operationStarted
				if !attached.ObservedAt.IsZero() {
					attachedStarted = attached.ObservedAt
				}
				attachedWork, attachedErr := prepareResponse(*attached, response, attachedStarted, start)
				if attachedErr != nil {
					releaseResponseSlots(batchSize)
					service.reportFatal(fmt.Errorf("prepare attached send response: %w", attachedErr))
					terminate()
					return
				}
				works = append(works, attachedWork)
			}
			if !publishReservedResponseBatch(works) {
				return
			}
			if attached != nil {
				service.connections.dedupe.releaseCurrent(operation.Record)
			}
			if service.afterOperationResponseReservation != nil {
				service.afterOperationResponseReservation(operation)
			}
			// Capacity becomes reusable only after every response for this logical
			// send owns bounded sequencer space. Opening start afterward prevents a
			// peer-visible response from racing ahead of that release point.
			releaseCapacity()
			close(start)
		}()
	}

	for {
		operation, failure, err := readClientOperation(serveContext, connection)
		if err != nil {
			return
		}
		operationStarted := time.Now()
		operation.ObservedAt = operationStarted

		if failure != nil {
			encoded, encodeErr := encodeProtocolError(*failure)
			if encodeErr != nil {
				return
			}
			done := make(chan bool, 1)
			terminalWork := authenticatedResponseWork{
				encoded: encoded,
				log: logEvent{
					Level:     "warn",
					Event:     "protocol_rejected",
					Result:    "rejected",
					Reason:    failure.Reason,
					Code:      failure.Code,
					Type:      failure.Type,
					RequestID: failure.RequestID,
				},
				started: time.Now(),
				start:   immediateStart,
				done:    done,
			}

			// Terminal input wins atomically over normal response publication.
			// Unpublication then cancels all exact-session producers before the
			// dedicated terminal work is handed to the sole writer.
			responseAdmissionMu.Lock()
			if !terminalStarted {
				terminalStarted = true
				cancelProducers()
				close(terminalSignal)
			}
			responseAdmissionMu.Unlock()
			markUnavailable()
			if service.afterProtocolTerminalTransition != nil {
				service.afterProtocolTerminalTransition()
			}
			select {
			case terminalQueue <- terminalWork:
			case <-serveContext.Done():
				return
			}
			select {
			case <-done:
			case <-serveContext.Done():
			}
			return
		}

		// ACK candidates have no response and remain synchronous reader work, so
		// they can settle any of this exact session's concurrently held sends.
		if operation.Type == "received" {
			if !dispatchSynchronous(operation, operationStarted) {
				return
			}
			continue
		}

		// Body size is classified before dedupe and sender capacity by contract.
		if operation.Type == "send" && operation.Send.BodyTooLarge {
			if !dispatchSynchronous(operation, operationStarted) {
				return
			}
			continue
		}

		if operation.Type == "send" {
			if service.beforeRepeatedSendObservation != nil {
				service.beforeRepeatedSendObservation(operation)
			}
			observation, observeErr := service.connections.dedupe.observe(session, operation)
			if observeErr != nil {
				service.reportFatal(fmt.Errorf("classify repeated send: %w", observeErr))
				terminate()
				return
			}
			switch observation.kind {
			case dedupePendingAttached:
				continue
			case dedupeImmediate:
				operation.Dedupe = observation.dedupe
				if !enqueuePreparedResponse(operation, observation.response, operationStarted) {
					return
				}
				service.connections.dedupe.releaseCurrent(observation.record)
				continue
			case dedupeOverflow:
				return
			}

			admitted := false
			select {
			case sendCapacity <- struct{}{}:
				admitted = true
			default:
			}
			if !admitted {
				if !enqueuePreparedResponse(operation, senderCapacityResponse(session, operation.Send.MessageID), operationStarted) {
					return
				}
				continue
			}
			if beginErr := service.connections.dedupe.begin(session, &operation); beginErr != nil {
				<-sendCapacity
				service.reportFatal(fmt.Errorf("begin send dedupe record: %w", beginErr))
				terminate()
				return
			}
			startSend(operation, operationStarted)
			continue
		}

		// Lists run one at a time in the sole reader. They may overlap admitted
		// sends but cannot create a queue or consume sender SEND capacity.
		service.connections.dedupe.advanceSender(session)
		if !dispatchSynchronous(operation, operationStarted) {
			return
		}
	}
}

func senderCapacityResponse(sender *authenticatedSession, messageID string) operationResponse {
	return operationResponse{
		Type: "send_result",
		Payload: sendResultPayload{
			MessageID: messageID,
			Status:    "denied",
			Reason:    "sender_capacity",
		},
		Outcome:     "denied",
		Code:        "sender_capacity",
		MessageID:   messageID,
		SenderRoute: sender.Address,
		Status:      "denied",
	}
}

func readClientOperation(
	ctx context.Context,
	connection *websocket.Conn,
) (clientOperation, *protocolFailure, error) {
	messageType, reader, err := connection.Reader(ctx)
	if err != nil {
		if errors.Is(err, websocket.ErrMessageTooBig) {
			return clientOperation{}, &protocolFailure{
				Code:   "invalid_frame",
				Reason: "frame_too_large",
			}, nil
		}
		return clientOperation{}, nil, err
	}
	if messageType != websocket.MessageText {
		return clientOperation{}, &protocolFailure{
			Code:   "invalid_frame",
			Reason: "text_frame_required",
		}, nil
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxFrameBytes+1))
	if err != nil {
		if errors.Is(err, websocket.ErrMessageTooBig) {
			return clientOperation{}, &protocolFailure{
				Code:   "invalid_frame",
				Reason: "frame_too_large",
			}, nil
		}
		return clientOperation{}, nil, err
	}
	if len(data) > maxFrameBytes {
		return clientOperation{}, &protocolFailure{
			Code:   "invalid_frame",
			Reason: "frame_too_large",
		}, nil
	}
	if !utf8.Valid(data) {
		return clientOperation{}, &protocolFailure{
			Code:   "invalid_frame",
			Reason: "invalid_utf8",
		}, nil
	}
	return decodeClientOperation(data)
}

func decodeClientOperation(data []byte) (clientOperation, *protocolFailure, error) {
	inspection, err := inspectJSON(data)
	if err != nil {
		return clientOperation{}, &protocolFailure{Code: "invalid_frame", Reason: "malformed_json"}, nil
	}
	if !inspection.object {
		return clientOperation{}, &protocolFailure{Code: "invalid_envelope", Reason: "object_required"}, nil
	}
	requestID := recoverRequestID(data, inspection.duplicateRequestID)
	if inspection.duplicate {
		return clientOperation{}, &protocolFailure{
			Code:      "invalid_envelope",
			Reason:    "duplicate_field",
			RequestID: requestID,
		}, nil
	}

	fields, err := decodeObject(data)
	if err != nil {
		return clientOperation{}, &protocolFailure{Code: "invalid_envelope", Reason: "invalid_shape"}, nil
	}
	failure := func(code, reason, operationType string) (clientOperation, *protocolFailure, error) {
		return clientOperation{}, &protocolFailure{
			Code:      code,
			Reason:    reason,
			RequestID: requestID,
			Type:      safeClientOperationType(operationType),
		}, nil
	}
	if len(fields) != 4 || !hasOnlyFields(fields, "v", "type", "request_id", "payload") {
		return failure("invalid_envelope", "invalid_envelope_fields", "")
	}
	var version int
	if err := json.Unmarshal(fields["v"], &version); err != nil {
		return failure("invalid_envelope", "invalid_protocol_version", "")
	}
	var operationType string
	if err := json.Unmarshal(fields["type"], &operationType); err != nil || operationType == "" {
		return failure("invalid_envelope", "invalid_operation_type", "")
	}
	var submittedRequestID string
	if err := json.Unmarshal(fields["request_id"], &submittedRequestID); err != nil || !isUUIDv7(submittedRequestID) {
		return failure("invalid_envelope", "invalid_request_id", operationType)
	}
	requestID = submittedRequestID
	if !rawJSONObject(fields["payload"]) {
		return failure("invalid_envelope", "payload_object_required", operationType)
	}
	if version != 1 {
		return failure("unsupported_protocol", "unsupported_protocol", operationType)
	}

	operation := clientOperation{Type: operationType, RequestID: requestID}
	switch operationType {
	case "list":
		payload, valid := decodeListPayload(fields["payload"])
		if !valid {
			return failure("invalid_envelope", "invalid_list_payload", operationType)
		}
		operation.List = &payload
	case "send":
		payload, valid := decodeSendPayload(fields["payload"])
		if !valid {
			return failure("invalid_envelope", "invalid_send_payload", operationType)
		}
		operation.Send = &payload
	case "received":
		payload, valid := decodeReceivedPayload(fields["payload"])
		if !valid {
			return failure("invalid_envelope", "invalid_received_payload", operationType)
		}
		operation.Received = &payload
	default:
		return failure("invalid_envelope", "unsupported_operation_type", operationType)
	}
	return operation, nil, nil
}

func safeClientOperationType(operationType string) string {
	switch operationType {
	case "list", "send", "received":
		return operationType
	default:
		return ""
	}
}

func decodeListPayload(data []byte) (listOperationPayload, bool) {
	fields, err := decodeObject(data)
	if err != nil || len(fields) > 1 || !hasOnlyFields(fields, "cursor") {
		return listOperationPayload{}, false
	}
	encoded, exists := fields["cursor"]
	if !exists {
		return listOperationPayload{}, true
	}
	var cursor string
	if err := json.Unmarshal(encoded, &cursor); err != nil ||
		len(cursor) <= len(cursorPrefix) || len(cursor) > maxCursorBytes ||
		!strings.HasPrefix(cursor, cursorPrefix) {
		return listOperationPayload{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(cursor, cursorPrefix))
	if err != nil || len(raw) == 0 || len(raw) > maxAddressBytes || !utf8.Valid(raw) {
		return listOperationPayload{}, false
	}
	if cursorPrefix+base64.RawURLEncoding.EncodeToString(raw) != cursor {
		return listOperationPayload{}, false
	}
	return listOperationPayload{AfterAddress: string(raw)}, true
}

func decodeSendPayload(data []byte) (sendOperationPayload, bool) {
	fields, err := decodeObject(data)
	if err != nil || (len(fields) != 3 && len(fields) != 4) ||
		!hasOnlyFields(fields, "message_id", "to", "body", "re") {
		return sendOperationPayload{}, false
	}
	var payload sendOperationPayload
	if err := json.Unmarshal(fields["message_id"], &payload.MessageID); err != nil || !isUUIDv7(payload.MessageID) {
		return sendOperationPayload{}, false
	}
	if err := json.Unmarshal(fields["to"], &payload.To); err != nil ||
		payload.To == "" || len(payload.To) > maxAddressBytes || !utf8.ValidString(payload.To) {
		return sendOperationPayload{}, false
	}
	body := bytes.TrimSpace(fields["body"])
	if len(body) == 0 {
		return sendOperationPayload{}, false
	}
	switch body[0] {
	case '"':
		var text string
		if err := json.Unmarshal(body, &text); err != nil {
			return sendOperationPayload{}, false
		}
	case '{':
		if !rawJSONObject(body) {
			return sendOperationPayload{}, false
		}
	default:
		return sendOperationPayload{}, false
	}
	if len(body) > maxBodyBytes {
		payload.BodyTooLarge = true
	} else {
		payload.Body = append(json.RawMessage(nil), body...)
	}
	if re, exists := fields["re"]; exists {
		if err := json.Unmarshal(re, &payload.Re); err != nil || !isUUIDv7(payload.Re) {
			return sendOperationPayload{}, false
		}
		payload.RePresent = true
	}
	return payload, true
}

func decodeReceivedPayload(data []byte) (receivedOperationPayload, bool) {
	fields, err := decodeObject(data)
	if err != nil || len(fields) != 2 || !hasOnlyFields(fields, "delivery_id", "message_id") {
		return receivedOperationPayload{}, false
	}
	var payload receivedOperationPayload
	if err := json.Unmarshal(fields["delivery_id"], &payload.DeliveryID); err != nil || !isUUIDv7(payload.DeliveryID) {
		return receivedOperationPayload{}, false
	}
	if err := json.Unmarshal(fields["message_id"], &payload.MessageID); err != nil || !isUUIDv7(payload.MessageID) {
		return receivedOperationPayload{}, false
	}
	return payload, true
}

func decodeObject(data []byte) (map[string]json.RawMessage, error) {
	if !rawJSONObject(data) {
		return nil, errors.New("JSON value is not an object")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	return fields, nil
}

func rawJSONObject(data []byte) bool {
	trimmed := bytes.TrimSpace(data)
	return len(trimmed) >= 2 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}'
}

func hasOnlyFields(fields map[string]json.RawMessage, allowed ...string) bool {
	for name := range fields {
		found := false
		for _, candidate := range allowed {
			if name == candidate {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

type jsonInspection struct {
	object             bool
	duplicate          bool
	duplicateRequestID bool
}

func inspectJSON(data []byte) (jsonInspection, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	inspection := jsonInspection{}
	token, err := decoder.Token()
	if err != nil {
		return inspection, err
	}
	opening, isDelimiter := token.(json.Delim)
	inspection.object = isDelimiter && opening == '{'
	if err := inspectJSONToken(decoder, token, 0, true, &inspection); err != nil {
		return jsonInspection{}, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return jsonInspection{}, errors.New("trailing JSON")
		}
		return jsonInspection{}, err
	}
	return inspection, nil
}

func inspectJSONToken(
	decoder *json.Decoder,
	token json.Token,
	parentDepth int,
	root bool,
	inspection *jsonInspection,
) error {
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if parentDepth >= maxJSONNestingDepth {
		return errors.New("JSON nesting exceeds limit")
	}
	depth := parentDepth + 1
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := nameToken.(string)
			if !ok {
				return errors.New("object name is not a string")
			}
			if _, exists := seen[name]; exists {
				inspection.duplicate = true
				if root && name == "request_id" {
					inspection.duplicateRequestID = true
				}
			}
			seen[name] = struct{}{}
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := inspectJSONToken(decoder, value, depth, false, inspection); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("object is not closed")
		}
	case '[':
		for decoder.More() {
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := inspectJSONToken(decoder, value, depth, false, inspection); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("array is not closed")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func recoverRequestID(data []byte, duplicateRequestID bool) string {
	if duplicateRequestID {
		return ""
	}
	fields, err := decodeObject(data)
	if err != nil {
		return ""
	}
	var requestID string
	if err := json.Unmarshal(fields["request_id"], &requestID); err != nil || !isUUIDv7(requestID) {
		return ""
	}
	return requestID
}

func encodeProtocolError(failure protocolFailure) ([]byte, error) {
	return json.Marshal(websocketErrorEnvelope{
		Version:   1,
		Type:      "error",
		RequestID: failure.RequestID,
		Payload: websocketErrorPayload{
			Code:    failure.Code,
			Message: protocolErrorMessage(failure.Code),
			Close:   true,
		},
	})
}

func protocolErrorMessage(code string) string {
	switch code {
	case "unsupported_protocol":
		return "Unsupported protocol version"
	case "invalid_envelope":
		return "Invalid protocol envelope"
	default:
		return "Invalid WebSocket frame"
	}
}

func encodeOperationResponse(
	operation clientOperation,
	response operationResponse,
) ([]byte, error) {
	if response.Type == "" || response.Payload == nil ||
		(response.Outcome != "denied" && response.Outcome != "settled") || response.Code == "" {
		return nil, errors.New("operation dispatcher returned an invalid response")
	}
	payload, err := json.Marshal(response.Payload)
	if err != nil {
		// Dispatcher payload errors can contain application data. Keep fatal telemetry actionable but redacted.
		return nil, errors.New("operation dispatcher returned a response payload that cannot be encoded")
	}
	if !rawJSONObject(payload) {
		return nil, errors.New("operation dispatcher returned a response payload that is not an object")
	}
	encoded, err := json.Marshal(operationResponseEnvelope{
		Version:   1,
		Type:      response.Type,
		RequestID: operation.RequestID,
		Payload:   json.RawMessage(payload),
	})
	if err != nil {
		return nil, errors.New("operation dispatcher returned a response that cannot be encoded")
	}
	if response.Type == "roster" && len(encoded) > maxRosterFrameBytes {
		return nil, errors.New("operation dispatcher returned a roster response above the frame ceiling")
	}
	return encoded, nil
}

func writeOperationResponse(connection *websocket.Conn, encodedResponse []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), protocolResponseWriteTimeout)
	defer cancel()
	return connection.Write(ctx, websocket.MessageText, encodedResponse)
}
