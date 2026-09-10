package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

const (
	maxAddressBytes              = maxCWDBytes + 1 + maxHostnameBytes + 1 + 36
	maxJSONNestingDepth          = 64
	protocolResponseWriteTimeout = time.Second
)

type listOperationPayload struct{}

type sendOperationPayload struct {
	MessageID string
	To        string
	Body      json.RawMessage
	Re        string
}

type receivedOperationPayload struct {
	DeliveryID string
	MessageID  string
}

type clientOperation struct {
	Type      string
	RequestID string
	List      *listOperationPayload
	Send      *sendOperationPayload
	Received  *receivedOperationPayload
}

type operationResponse struct {
	Type    string
	Payload any
	Outcome string
	Code    string
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

func (service *sessionAuthService) serveAuthenticated(
	connection *websocket.Conn,
	session *authenticatedSession,
) {
	for {
		operation, failure, err := readClientOperation(context.Background(), connection)
		if err != nil {
			return
		}
		if failure != nil {
			if !service.writeAudit(logEvent{
				Level:     "warn",
				Event:     "protocol_rejected",
				Result:    "rejected",
				Reason:    failure.Reason,
				Code:      failure.Code,
				Type:      failure.Type,
				RequestID: failure.RequestID,
			}) {
				_ = connection.CloseNow()
				return
			}
			_ = writeProtocolError(connection, *failure)
			_ = connection.CloseNow()
			return
		}

		response, respond, err := service.dispatchOperation(context.Background(), session, operation)
		if err != nil {
			service.reportFatal(fmt.Errorf("dispatch %s operation: %w", operation.Type, err))
			_ = connection.CloseNow()
			return
		}
		if !respond {
			continue
		}
		encodedResponse, err := encodeOperationResponse(operation, response)
		if err != nil {
			service.reportFatal(fmt.Errorf(
				"prepare %s operation response for request %s: %w",
				operation.Type,
				operation.RequestID,
				err,
			))
			_ = connection.CloseNow()
			return
		}
		if err := writeOperationResponse(connection, encodedResponse); err != nil {
			return
		}
		event := "operation_settled"
		level := "info"
		if response.Outcome == "denied" {
			event = "operation_denied"
			level = "warn"
		}
		if !service.writeAudit(logEvent{
			Level:     level,
			Event:     event,
			Result:    response.Outcome,
			Reason:    response.Code,
			Code:      response.Code,
			Type:      operation.Type,
			RequestID: operation.RequestID,
		}) {
			_ = connection.CloseNow()
			return
		}
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
		payloadFields, err := decodeObject(fields["payload"])
		if err != nil || len(payloadFields) != 0 {
			return failure("invalid_envelope", "invalid_list_payload", operationType)
		}
		operation.List = &listOperationPayload{}
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
	payload.Body = append(json.RawMessage(nil), body...)
	if re, exists := fields["re"]; exists {
		if err := json.Unmarshal(re, &payload.Re); err != nil || !isUUIDv7(payload.Re) {
			return sendOperationPayload{}, false
		}
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

func writeProtocolError(connection *websocket.Conn, failure protocolFailure) error {
	ctx, cancel := context.WithTimeout(context.Background(), protocolResponseWriteTimeout)
	defer cancel()
	return wsjson.Write(ctx, connection, websocketErrorEnvelope{
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
	return encoded, nil
}

func writeOperationResponse(connection *websocket.Conn, encodedResponse []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), protocolResponseWriteTimeout)
	defer cancel()
	return connection.Write(ctx, websocket.MessageText, encodedResponse)
}
