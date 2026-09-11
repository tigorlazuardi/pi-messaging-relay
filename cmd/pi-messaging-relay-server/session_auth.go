package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

const (
	authDeadline          = 5 * time.Second
	maxFrameBytes         = 512 * 1024
	maxHelloFrameBytes    = 16 * 1024
	maxCWDBytes           = 4096
	maxHostnameBytes      = 255
	heartbeatMilliseconds = 30_000
	// ponytail: fixed to v1's 256 KiB serialized body; make configurable when another profile exists.
	maxBodyBytes          = 262_144
	maxSessionConnections = 1024
	authTranscriptDomain  = "pi-messaging-relay-auth-v1\n"
)

type challengeEnvelope struct {
	Version int              `json:"v"`
	Type    string           `json:"type"`
	Payload challengePayload `json:"payload"`
}

type challengePayload struct {
	Nonce string `json:"nonce"`
}

type helloEnvelope struct {
	Version   int
	Type      string
	RequestID string
	Payload   helloPayload
}

type helloPayload struct {
	ClientPublicKey string
	RouteID         string
	Hostname        string
	CWD             string
	Signature       string
}

type welcomeEnvelope struct {
	Version   int            `json:"v"`
	Type      string         `json:"type"`
	RequestID string         `json:"request_id"`
	Payload   welcomePayload `json:"payload"`
}

type welcomePayload struct {
	SelfAddress  string `json:"self_address"`
	HeartbeatMS  int    `json:"heartbeat_ms"`
	MaxBodyBytes int    `json:"max_body_bytes"`
}

type websocketErrorEnvelope struct {
	Version   int                   `json:"v"`
	Type      string                `json:"type"`
	RequestID string                `json:"request_id,omitempty"`
	Payload   websocketErrorPayload `json:"payload"`
}

type websocketErrorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Close   bool   `json:"close"`
}

type authenticatedSession struct {
	ClientID        string
	ClientPublicKey string
	RouteID         string
	Hostname        string
	CWD             string
	Address         string
}

type trackedSessionConnection struct {
	connection *websocket.Conn
	session    *authenticatedSession
	visible    bool
	writeMu    sync.Mutex
}

type sessionAuthenticationResult int

const (
	sessionAuthenticated sessionAuthenticationResult = iota
	sessionRegistryClosing
	sessionRouteConflict
)

type sessionConnectionRegistry struct {
	mu                   sync.Mutex
	lifecycleMu          sync.Mutex
	closing              bool
	limit                int
	entries              map[*trackedSessionConnection]struct{}
	changed              chan struct{}
	closed               chan struct{}
	shutdownOnce         sync.Once
	onSessionUnavailable func(*authenticatedSession)
	onShutdown           func()
	dedupe               *dedupeLedger
}

func newSessionConnectionRegistry() *sessionConnectionRegistry {
	return newSessionConnectionRegistryWithLimit(maxSessionConnections)
}

func newSessionConnectionRegistryWithLimit(limit int) *sessionConnectionRegistry {
	return &sessionConnectionRegistry{
		limit:   limit,
		entries: make(map[*trackedSessionConnection]struct{}),
		changed: make(chan struct{}, 1),
		closed:  make(chan struct{}),
		dedupe:  newDedupeLedger(),
	}
}

func (registry *sessionConnectionRegistry) reserve() (*trackedSessionConnection, bool) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.closing || len(registry.entries) >= registry.limit {
		return nil, false
	}
	entry := &trackedSessionConnection{}
	registry.entries[entry] = struct{}{}
	return entry, true
}

func (registry *sessionConnectionRegistry) attach(
	entry *trackedSessionConnection,
	connection *websocket.Conn,
) bool {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, exists := registry.entries[entry]; !exists {
		return false
	}
	entry.connection = connection
	return !registry.closing
}

func (registry *sessionConnectionRegistry) reserveAuthentication(
	entry *trackedSessionConnection,
	session *authenticatedSession,
) sessionAuthenticationResult {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.closing {
		return sessionRegistryClosing
	}
	if _, exists := registry.entries[entry]; !exists || entry.connection == nil {
		return sessionRegistryClosing
	}
	for active := range registry.entries {
		if active == entry || active.session == nil {
			continue
		}
		if active.session.RouteID == session.RouteID || active.session.Address == session.Address {
			return sessionRouteConflict
		}
	}
	entry.session = session
	entry.visible = false
	return sessionAuthenticated
}

func (registry *sessionConnectionRegistry) publishAuthentication(
	entry *trackedSessionConnection,
	session *authenticatedSession,
) bool {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.closing {
		return false
	}
	if _, exists := registry.entries[entry]; !exists || entry.connection == nil || entry.session != session {
		return false
	}
	entry.visible = true
	return true
}

func (registry *sessionConnectionRegistry) clearAuthentication(entry *trackedSessionConnection) {
	registry.mu.Lock()
	var unavailable *authenticatedSession
	if _, exists := registry.entries[entry]; exists {
		unavailable = entry.session
		entry.visible = false
		entry.session = nil
	}
	onUnavailable := registry.onSessionUnavailable
	registry.mu.Unlock()
	registry.notifySessionUnavailable(unavailable, onUnavailable)
}

func (registry *sessionConnectionRegistry) remove(entry *trackedSessionConnection) {
	registry.mu.Lock()
	unavailable := entry.session
	delete(registry.entries, entry)
	empty := len(registry.entries) == 0
	onUnavailable := registry.onSessionUnavailable
	registry.mu.Unlock()
	registry.notifySessionUnavailable(unavailable, onUnavailable)
	if empty {
		select {
		case registry.changed <- struct{}{}:
		default:
		}
	}
}

func (registry *sessionConnectionRegistry) notifySessionUnavailable(
	session *authenticatedSession,
	notify func(*authenticatedSession),
) {
	if session == nil || notify == nil {
		return
	}
	registry.lifecycleMu.Lock()
	defer registry.lifecycleMu.Unlock()
	notify(session)
}

func (registry *sessionConnectionRegistry) beginShutdown() {
	registry.shutdownOnce.Do(func() {
		registry.lifecycleMu.Lock()
		defer registry.lifecycleMu.Unlock()

		registry.mu.Lock()
		registry.closing = true
		onShutdown := registry.onShutdown
		registry.mu.Unlock()
		if onShutdown != nil {
			onShutdown()
		}
		close(registry.closed)
	})
}

func (registry *sessionConnectionRegistry) closeAndWait(ctx context.Context) error {
	registry.beginShutdown()
	registry.mu.Lock()
	connections := make([]*websocket.Conn, 0, len(registry.entries))
	for entry := range registry.entries {
		if entry.connection != nil {
			connections = append(connections, entry.connection)
		}
	}
	registry.mu.Unlock()

	for _, connection := range connections {
		_ = connection.CloseNow()
	}
	for {
		registry.mu.Lock()
		empty := len(registry.entries) == 0
		registry.mu.Unlock()
		if empty {
			return nil
		}
		select {
		case <-registry.changed:
		case <-ctx.Done():
			return fmt.Errorf("settle WebSocket connections: %w", ctx.Err())
		}
	}
}

func (registry *sessionConnectionRegistry) closingSignal() <-chan struct{} {
	return registry.closed
}

func (registry *sessionConnectionRegistry) publishedSession(address string) (*authenticatedSession, bool) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	for entry := range registry.entries {
		if entry.visible && entry.session != nil && entry.session.Address == address {
			return entry.session, true
		}
	}
	return nil, false
}

func (registry *sessionConnectionRegistry) isPublishedSession(session *authenticatedSession) bool {
	if session == nil {
		return false
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	for entry := range registry.entries {
		if entry.visible && entry.session == session {
			return true
		}
	}
	return false
}

func (registry *sessionConnectionRegistry) writeToSession(
	ctx context.Context,
	session *authenticatedSession,
	frame []byte,
) error {
	registry.mu.Lock()
	var destination *trackedSessionConnection
	for entry := range registry.entries {
		if entry.visible && entry.session == session && entry.connection != nil {
			destination = entry
			break
		}
	}
	registry.mu.Unlock()
	return writeTrackedConnection(ctx, destination, frame)
}

func writeTrackedConnection(ctx context.Context, destination *trackedSessionConnection, frame []byte) error {
	if destination == nil || destination.connection == nil {
		return errors.New("tracked destination is unavailable")
	}
	destination.writeMu.Lock()
	defer destination.writeMu.Unlock()
	return destination.connection.Write(ctx, websocket.MessageText, frame)
}

type sessionAuthService struct {
	pairing                            *pairingService
	connections                        *sessionConnectionRegistry
	logger                             *eventLogger
	reportFatal                        func(error)
	dispatchOperation                  operationDispatcher
	writeWelcome                       func(context.Context, *websocket.Conn, welcomeEnvelope) error
	beforeOperationAdmissionDecision   func(clientOperation)
	afterOperationAdmissionDecision    func(clientOperation, bool)
	afterOperationAdmissionPublication func(clientOperation)
	beforeRepeatedSendObservation      func(clientOperation)
	afterOperationResponseReservation  func(clientOperation)
	beforeResponseAudit                func(logEvent)
	authTimeout                        time.Duration
}

func newSessionAuthService(
	pairing *pairingService,
	connections *sessionConnectionRegistry,
	logger *eventLogger,
	reportFatal func(error),
) *sessionAuthService {
	delivery := newDeliveryDispatcher(connections)
	return &sessionAuthService{
		pairing:           pairing,
		connections:       connections,
		logger:            logger,
		reportFatal:       reportFatal,
		dispatchOperation: delivery.dispatch,
		writeWelcome: func(ctx context.Context, connection *websocket.Conn, welcome welcomeEnvelope) error {
			return wsjson.Write(ctx, connection, welcome)
		},
		authTimeout: authDeadline,
	}
}

func (service *sessionAuthService) handleConnect(response http.ResponseWriter, request *http.Request) {
	started := time.Now()
	entry, reserved := service.connections.reserve()
	if !reserved {
		http.Error(response, "relay session capacity reached", http.StatusServiceUnavailable)
		service.writeAudit(logEvent{
			Level:     "warn",
			Event:     "session_capacity_rejected",
			Result:    "rejected",
			Reason:    "connection_capacity_reached",
			LatencyMS: latencySince(started),
		})
		return
	}
	defer service.connections.remove(entry)

	connection, err := websocket.Accept(response, request, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	defer connection.CloseNow()
	if !service.connections.attach(entry, connection) {
		return
	}
	connection.SetReadLimit(maxFrameBytes)
	authContext, cancelAuth := context.WithTimeout(context.Background(), service.authTimeout)
	defer cancelAuth()
	nonce, err := randomToken(32)
	if err != nil {
		service.reportFatal(fmt.Errorf("generate authentication nonce: %w", err))
		return
	}
	if err := wsjson.Write(authContext, connection, challengeEnvelope{
		Version: 1,
		Type:    "challenge",
		Payload: challengePayload{Nonce: nonce},
	}); err != nil {
		service.logRejected("challenge_failed", started, "", "")
		return
	}

	hello, err := readHello(authContext, connection)
	if err != nil {
		service.logRejected("invalid_hello", started, "", "")
		_ = connection.CloseNow()
		return
	}
	clientID, publicKey, authorized := service.pairing.authorizedKey(hello.Payload.ClientPublicKey)
	if !authorized || !verifyHelloSignature(publicKey, nonce, hello) {
		if !service.logRejected("not_authorized", started, hello.Payload.ClientPublicKey, hello.Payload.RouteID) {
			_ = connection.CloseNow()
			return
		}
		_ = writeNotAuthorized(authContext, connection, hello.RequestID)
		_ = connection.Close(websocket.StatusPolicyViolation, "not authorized")
		return
	}

	address := hello.Payload.CWD + "@" + hello.Payload.Hostname + "#" + hello.Payload.RouteID
	session := &authenticatedSession{
		ClientID:        clientID,
		ClientPublicKey: hello.Payload.ClientPublicKey,
		RouteID:         hello.Payload.RouteID,
		Hostname:        hello.Payload.Hostname,
		CWD:             hello.Payload.CWD,
		Address:         address,
	}
	switch service.connections.reserveAuthentication(entry, session) {
	case sessionRegistryClosing:
		_ = connection.CloseNow()
		return
	case sessionRouteConflict:
		service.logRejected("route_conflict", started, hello.Payload.ClientPublicKey, hello.Payload.RouteID)
		_ = connection.CloseNow()
		return
	case sessionAuthenticated:
	}
	if err := service.writeWelcome(authContext, connection, welcomeEnvelope{
		Version:   1,
		Type:      "welcome",
		RequestID: hello.RequestID,
		Payload: welcomePayload{
			SelfAddress:  address,
			HeartbeatMS:  heartbeatMilliseconds,
			MaxBodyBytes: maxBodyBytes,
		},
	}); err != nil {
		service.logRejected("welcome_failed", started, hello.Payload.ClientPublicKey, hello.Payload.RouteID)
		return
	}
	if !service.connections.publishAuthentication(entry, session) {
		_ = connection.CloseNow()
		return
	}
	service.writeAudit(logEvent{
		Level:           "info",
		Event:           "auth_accepted",
		Result:          "accepted",
		Address:         address,
		ClientPublicKey: hello.Payload.ClientPublicKey,
		ClientID:        clientID,
		RouteID:         hello.Payload.RouteID,
		Hostname:        hello.Payload.Hostname,
		CWD:             hello.Payload.CWD,
		Nonce:           redacted,
		Signature:       redacted,
		PrivateKey:      redacted,
		LatencyMS:       latencySince(started),
	})
	cancelAuth()

	var unavailableOnce sync.Once
	markUnavailable := func() {
		unavailableOnce.Do(func() { service.connections.clearAuthentication(entry) })
	}
	service.serveAuthenticated(connection, session, markUnavailable)
	markUnavailable()
	service.writeAudit(logEvent{
		Level:           "info",
		Event:           "session_disconnected",
		Result:          "disconnected",
		Address:         address,
		ClientPublicKey: hello.Payload.ClientPublicKey,
		ClientID:        clientID,
		RouteID:         hello.Payload.RouteID,
	})
}

func (service *sessionAuthService) logRejected(
	reason string,
	started time.Time,
	publicKey string,
	routeID string,
) bool {
	return service.writeAudit(logEvent{
		Level:           "warn",
		Event:           "auth_rejected",
		Result:          "rejected",
		Reason:          reason,
		ClientPublicKey: publicKey,
		RouteID:         routeID,
		Nonce:           redacted,
		Signature:       redacted,
		PrivateKey:      redacted,
		LatencyMS:       latencySince(started),
	})
}

func (service *sessionAuthService) writeAudit(event logEvent) bool {
	if err := service.logger.write(event); err != nil {
		service.reportFatal(fmt.Errorf("write %s session audit event: %w", event.Event, err))
		return false
	}
	return true
}

func writeNotAuthorized(ctx context.Context, connection *websocket.Conn, requestID string) error {
	return wsjson.Write(ctx, connection, websocketErrorEnvelope{
		Version:   1,
		Type:      "error",
		RequestID: requestID,
		Payload: websocketErrorPayload{
			Code:    "not_authorized",
			Message: "Client key is not authorized",
			Close:   true,
		},
	})
}

func readHello(ctx context.Context, connection *websocket.Conn) (helloEnvelope, error) {
	messageType, reader, err := connection.Reader(ctx)
	if err != nil {
		return helloEnvelope{}, err
	}
	if messageType != websocket.MessageText {
		return helloEnvelope{}, errors.New("hello must be a text frame")
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxHelloFrameBytes+1))
	if err != nil {
		return helloEnvelope{}, err
	}
	if len(data) > maxHelloFrameBytes {
		return helloEnvelope{}, errors.New("hello exceeds authentication frame limit")
	}
	if !utf8.Valid(data) {
		return helloEnvelope{}, errors.New("hello must be valid UTF-8")
	}
	return decodeHello(data)
}

func decodeHello(data []byte) (helloEnvelope, error) {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return helloEnvelope{}, errors.New("hello must be an object")
	}
	var hello helloEnvelope
	seen := make(map[string]struct{}, 4)
	for decoder.More() {
		name, err := nextObjectField(decoder, seen)
		if err != nil {
			return helloEnvelope{}, err
		}
		switch name {
		case "v":
			err = decoder.Decode(&hello.Version)
		case "type":
			err = decoder.Decode(&hello.Type)
		case "request_id":
			err = decoder.Decode(&hello.RequestID)
		case "payload":
			hello.Payload, err = decodeHelloPayload(decoder)
		default:
			return helloEnvelope{}, fmt.Errorf("unknown hello field %q", name)
		}
		if err != nil {
			return helloEnvelope{}, fmt.Errorf("decode hello field %q: %w", name, err)
		}
	}
	if err := closeJSONObject(decoder); err != nil {
		return helloEnvelope{}, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return helloEnvelope{}, errors.New("hello contains trailing JSON")
		}
		return helloEnvelope{}, err
	}
	if len(seen) != 4 || hello.Version != 1 || hello.Type != "hello" || !isUUIDv7(hello.RequestID) {
		return helloEnvelope{}, errors.New("hello envelope is invalid")
	}
	if err := validateHelloPayload(hello.Payload); err != nil {
		return helloEnvelope{}, err
	}
	return hello, nil
}

func decodeHelloPayload(decoder *json.Decoder) (helloPayload, error) {
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return helloPayload{}, errors.New("hello payload must be an object")
	}
	var payload helloPayload
	seen := make(map[string]struct{}, 5)
	for decoder.More() {
		name, err := nextObjectField(decoder, seen)
		if err != nil {
			return helloPayload{}, err
		}
		var target *string
		switch name {
		case "client_public_key":
			target = &payload.ClientPublicKey
		case "route_id":
			target = &payload.RouteID
		case "hostname":
			target = &payload.Hostname
		case "cwd":
			target = &payload.CWD
		case "signature":
			target = &payload.Signature
		default:
			return helloPayload{}, fmt.Errorf("unknown hello payload field %q", name)
		}
		if err := decoder.Decode(target); err != nil {
			return helloPayload{}, fmt.Errorf("decode hello payload field %q: %w", name, err)
		}
	}
	if err := closeJSONObject(decoder); err != nil {
		return helloPayload{}, err
	}
	if len(seen) != 5 {
		return helloPayload{}, errors.New("hello payload fields are missing")
	}
	return payload, nil
}

func nextObjectField(decoder *json.Decoder, seen map[string]struct{}) (string, error) {
	token, err := decoder.Token()
	if err != nil {
		return "", err
	}
	name, ok := token.(string)
	if !ok {
		return "", errors.New("object field name must be a string")
	}
	if _, duplicate := seen[name]; duplicate {
		return "", fmt.Errorf("duplicate field %q", name)
	}
	seen[name] = struct{}{}
	return name, nil
}

func closeJSONObject(decoder *json.Decoder) error {
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return errors.New("object is not closed")
	}
	return nil
}

func validateHelloPayload(payload helloPayload) error {
	if err := validateEd25519PublicKey(payload.ClientPublicKey); err != nil {
		return errors.New("hello public key is invalid")
	}
	if !isUUIDv7(payload.RouteID) {
		return errors.New("route_id must be UUIDv7")
	}
	if !validDisplayMetadata(payload.Hostname, maxHostnameBytes) ||
		!validDisplayMetadata(payload.CWD, maxCWDBytes) {
		return errors.New("route display metadata is invalid")
	}
	signature, err := base64.StdEncoding.DecodeString(payload.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.StdEncoding.EncodeToString(signature) != payload.Signature {
		return errors.New("hello signature is invalid")
	}
	return nil
}

func validDisplayMetadata(value string, maximumBytes int) bool {
	return value != "" && len(value) <= maximumBytes && utf8.ValidString(value)
}

func isUUIDv7(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' || value[14] != '7' {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return strings.ContainsRune("89ab", rune(value[19]))
}

func verifyHelloSignature(publicKey ed25519.PublicKey, nonce string, hello helloEnvelope) bool {
	signature, err := base64.StdEncoding.DecodeString(hello.Payload.Signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(publicKey, helloTranscript(nonce, hello), signature)
}

func helloTranscript(nonce string, hello helloEnvelope) []byte {
	var transcript strings.Builder
	transcript.WriteString(authTranscriptDomain)
	appendTranscriptField(&transcript, "nonce", nonce)
	appendTranscriptField(&transcript, "request_id", hello.RequestID)
	appendTranscriptField(&transcript, "client_public_key", hello.Payload.ClientPublicKey)
	appendTranscriptField(&transcript, "route_id", hello.Payload.RouteID)
	appendTranscriptField(&transcript, "hostname", hello.Payload.Hostname)
	appendTranscriptField(&transcript, "cwd", hello.Payload.CWD)
	return []byte(transcript.String())
}

func appendTranscriptField(transcript *strings.Builder, name, value string) {
	transcript.WriteString(name)
	transcript.WriteByte(':')
	transcript.WriteString(strconv.Itoa(len([]byte(value))))
	transcript.WriteByte(':')
	transcript.WriteString(value)
	transcript.WriteByte('\n')
}

func decodeEd25519PublicKey(encoded string) (ed25519.PublicKey, error) {
	if err := validateEd25519PublicKey(encoded); err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(encoded, "ed25519:"))
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(decoded), nil
}
