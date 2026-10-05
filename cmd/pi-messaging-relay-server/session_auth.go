package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

const (
	establishmentDeadline = 5 * time.Second
	maxFrameBytes         = 512 * 1024
	maxHelloFrameBytes    = 16 * 1024
	maxCWDBytes           = 4096
	maxHostnameBytes      = 255
	heartbeatMilliseconds = 30_000
	// ponytail: fixed to the advertised 30 s liveness cadence; the ping write
	// gets one full interval before the watchdog declares the transport dead.
	// Make configurable when another deployment profile exists.
	heartbeatInterval = time.Duration(heartbeatMilliseconds) * time.Millisecond
	// ponytail: fixed to v1's 256 KiB serialized body; make configurable when another profile exists.
	maxBodyBytes          = 262_144
	maxSessionConnections = 1024
)

type helloEnvelope struct {
	Version   int
	Type      string
	RequestID string
	Payload   helloPayload
}

type helloPayload struct {
	RouteID  string
	Hostname string
	CWD      string
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
	RouteID  string
	Hostname string
	CWD      string
	Address  string
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
	mu                      sync.Mutex
	lifecycleMu             sync.Mutex
	closing                 bool
	limit                   int
	entries                 map[*trackedSessionConnection]struct{}
	changed                 chan struct{}
	closed                  chan struct{}
	shutdownOnce            sync.Once
	onSessionUnavailable    func(*authenticatedSession)
	onShutdown              func()
	beforeSessionWriteLease func(*authenticatedSession)
	dedupe                  *dedupeLedger
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
		// Revocation blocks new selection immediately. Synchronizing on writeMu
		// below then fences every preselected write before cleanup is published.
		entry.visible = false
	}
	onUnavailable := registry.onSessionUnavailable
	registry.mu.Unlock()

	if unavailable != nil {
		entry.writeMu.Lock()
		registry.mu.Lock()
		if _, exists := registry.entries[entry]; exists && entry.session == unavailable {
			entry.session = nil
		}
		registry.mu.Unlock()
		entry.writeMu.Unlock()
	}
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
	beforeLease := registry.beforeSessionWriteLease
	registry.mu.Unlock()
	if destination == nil {
		return errors.New("tracked destination is unavailable")
	}
	if beforeLease != nil {
		beforeLease(session)
	}

	destination.writeMu.Lock()
	defer destination.writeMu.Unlock()
	registry.mu.Lock()
	_, tracked := registry.entries[destination]
	available := tracked && destination.visible && destination.session == session && destination.connection != nil
	registry.mu.Unlock()
	if !available {
		return errors.New("tracked destination is unavailable")
	}
	return destination.connection.Write(ctx, websocket.MessageText, frame)
}

func (registry *sessionConnectionRegistry) writeToConnection(
	ctx context.Context,
	connection *websocket.Conn,
	frame []byte,
) error {
	registry.mu.Lock()
	var destination *trackedSessionConnection
	for entry := range registry.entries {
		if entry.connection == connection {
			destination = entry
			break
		}
	}
	registry.mu.Unlock()
	if destination == nil || destination.connection == nil {
		return errors.New("tracked destination is unavailable")
	}
	destination.writeMu.Lock()
	defer destination.writeMu.Unlock()
	return destination.connection.Write(ctx, websocket.MessageText, frame)
}

type sessionAuthService struct {
	// secret is the retained v2 shared secret. Empty means authentication off:
	// every upgrade is accepted without inspecting headers. The secret itself is
	// never logged and never leaves process memory after startup.
	secret                            string
	connections                       *sessionConnectionRegistry
	logger                            *eventLogger
	reportFatal                       func(error)
	dispatchOperation                 operationDispatcher
	writeWelcome                      func(context.Context, *websocket.Conn, welcomeEnvelope) error
	beforeRepeatedSendObservation     func(clientOperation)
	beforeResponseBatchReservation    func(clientOperation, int)
	afterResponseSlotReservation      func(batchSize int, reserved int)
	beforeResponsePreparation         func(clientOperation)
	afterOperationResponseReservation func(clientOperation)
	afterNormalResponseClaim          func(logEvent)
	afterProtocolTerminalTransition   func()
	beforeResponseAudit               func(logEvent)
	establishmentTimeout              time.Duration
	heartbeatInterval                 time.Duration
}

func newSessionAuthService(
	secret string,
	connections *sessionConnectionRegistry,
	logger *eventLogger,
	reportFatal func(error),
) *sessionAuthService {
	delivery := newDeliveryDispatcher(connections)
	return &sessionAuthService{
		secret:            secret,
		connections:       connections,
		logger:            logger,
		reportFatal:       reportFatal,
		dispatchOperation: delivery.dispatch,
		writeWelcome: func(ctx context.Context, connection *websocket.Conn, welcome welcomeEnvelope) error {
			return wsjson.Write(ctx, connection, welcome)
		},
		establishmentTimeout: establishmentDeadline,
		heartbeatInterval:    heartbeatInterval,
	}
}

func (service *sessionAuthService) handleConnect(response http.ResponseWriter, request *http.Request) {
	started := time.Now()
	if service.secret != "" && !service.authorizeUpgrade(request.Header.Get("Authorization")) {
		// One closed rejection spelling covers missing, malformed, over-limit, and
		// wrong credentials; a rejected request consumes no tracked capacity slot.
		// The wire rejection is unconditional; an audit failure reaches the fatal owner.
		service.writeAudit(logEvent{
			Level:     "warn",
			Event:     "auth_rejected",
			Result:    "rejected",
			Reason:    "not_authorized",
			LatencyMS: latencySince(started),
		})
		writeUpgradeUnauthorized(response)
		return
	}
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
	// Hello read, validation, and welcome write share one bounded establishment
	// deadline; the hello is unsigned display metadata, not a credential.
	establishContext, cancelEstablish := context.WithTimeout(context.Background(), service.establishmentTimeout)
	defer cancelEstablish()

	hello, err := readHello(establishContext, connection)
	if err != nil {
		service.logRejected("invalid_hello", started, "", "")
		_ = connection.CloseNow()
		return
	}
	address := hello.Payload.CWD + "@" + hello.Payload.Hostname + "#" + hello.Payload.RouteID
	session := &authenticatedSession{
		RouteID:  hello.Payload.RouteID,
		Hostname: hello.Payload.Hostname,
		CWD:      hello.Payload.CWD,
		Address:  address,
	}
	switch service.connections.reserveAuthentication(entry, session) {
	case sessionRegistryClosing:
		_ = connection.CloseNow()
		return
	case sessionRouteConflict:
		service.logRejected(
			"route_conflict",
			started,
			hello.Payload.RouteID,
			hello.RequestID,
		)
		_ = connection.CloseNow()
		return
	case sessionAuthenticated:
	}
	if err := service.writeWelcome(establishContext, connection, welcomeEnvelope{
		Version:   1,
		Type:      "welcome",
		RequestID: hello.RequestID,
		Payload: welcomePayload{
			SelfAddress:  address,
			HeartbeatMS:  heartbeatMilliseconds,
			MaxBodyBytes: maxBodyBytes,
		},
	}); err != nil {
		service.logRejected(
			"welcome_failed",
			started,
			hello.Payload.RouteID,
			hello.RequestID,
		)
		return
	}
	if !service.connections.publishAuthentication(entry, session) {
		_ = connection.CloseNow()
		return
	}
	service.writeAudit(logEvent{
		Level:     "info",
		Event:     "auth_accepted",
		Result:    "accepted",
		RequestID: hello.RequestID,
		Address:   address,
		RouteID:   hello.Payload.RouteID,
		Hostname:  hello.Payload.Hostname,
		CWD:       hello.Payload.CWD,
		LatencyMS: latencySince(started),
	})
	cancelEstablish()

	var unavailableOnce sync.Once
	markUnavailable := func() {
		unavailableOnce.Do(func() { service.connections.clearAuthentication(entry) })
	}
	stopHeartbeat := service.startHeartbeatWatchdog(connection)
	service.serveAuthenticated(connection, session, markUnavailable)
	stopHeartbeat()
	markUnavailable()
	service.writeAudit(logEvent{
		Level:   "info",
		Event:   "session_disconnected",
		Result:  "disconnected",
		Address: address,
		RouteID: hello.Payload.RouteID,
	})
}

// startHeartbeatWatchdog enforces the advertised liveness cadence on one
// authenticated connection: one WebSocket ping per interval, each allowed a
// full interval before the next check. A failed or late-answered ping means
// the transport is dead even though no TCP FIN arrived (sleep, NAT drop);
// CloseNow tears it down so the ordinary disconnected path owns cleanup.
// The concurrent Reader consumes pong frames per the coder/websocket
// contract, so the watchdog only writes pings and never races reads.
func (service *sessionAuthService) startHeartbeatWatchdog(connection *websocket.Conn) (stop func()) {
	interval := service.heartbeatInterval
	if interval <= 0 {
		interval = heartbeatInterval
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				pingContext, cancelPing := context.WithTimeout(context.Background(), interval)
				err := connection.Ping(pingContext)
				cancelPing()
				if err != nil {
					_ = connection.CloseNow()
					return
				}
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

// authorizeUpgrade validates one Authorization header value against the retained
// secret. The scheme token compares case-insensitively; the submitted secret bytes
// compare exactly and in constant time, so only the submitted length is observable.
func (service *sessionAuthService) authorizeUpgrade(header string) bool {
	if len(header) > maxAuthorizationHeaderValue {
		return false
	}
	scheme, submitted, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "bearer") {
		return false
	}
	return equalSecret(service.secret, submitted)
}

func (service *sessionAuthService) logRejected(
	reason string,
	started time.Time,
	routeID string,
	requestID string,
) bool {
	return service.writeAudit(logEvent{
		Level:     "warn",
		Event:     "auth_rejected",
		Result:    "rejected",
		Reason:    reason,
		RequestID: requestID,
		RouteID:   routeID,
		LatencyMS: latencySince(started),
	})
}

func (service *sessionAuthService) writeAudit(event logEvent) bool {
	if err := service.logger.write(event); err != nil {
		service.reportFatal(fmt.Errorf("write %s session audit event: %w", event.Event, err))
		return false
	}
	return true
}

func writeUpgradeUnauthorized(response http.ResponseWriter) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("WWW-Authenticate", "Bearer")
	response.WriteHeader(http.StatusUnauthorized)
	_, _ = io.WriteString(response, `{"error":"not_authorized","message":"Authentication is required"}`)
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
	seen := make(map[string]struct{}, 3)
	for decoder.More() {
		name, err := nextObjectField(decoder, seen)
		if err != nil {
			return helloPayload{}, err
		}
		var target *string
		switch name {
		case "route_id":
			target = &payload.RouteID
		case "hostname":
			target = &payload.Hostname
		case "cwd":
			target = &payload.CWD
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
	if len(seen) != 3 {
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
	if !isUUIDv7(payload.RouteID) {
		return errors.New("route_id must be UUIDv7")
	}
	if !validDisplayMetadata(payload.Hostname, maxHostnameBytes) ||
		!validDisplayMetadata(payload.CWD, maxCWDBytes) {
		return errors.New("route display metadata is invalid")
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

func latencySince(started time.Time) *int64 {
	latency := time.Since(started).Milliseconds()
	return &latency
}
