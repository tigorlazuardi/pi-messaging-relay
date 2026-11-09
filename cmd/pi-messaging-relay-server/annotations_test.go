package main

import (
	"context"
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

const (
	annotationHelloRequestID = "01993c79-8ad7-79fa-83e3-9789dcaca168"
	annotationRouteA         = "01993ca1-1111-7aaa-8aaa-111111111111"
	annotationRouteB         = "01993ca1-2222-7aaa-8aaa-222222222222"
	annotationRouteC         = "01993ca1-3333-7aaa-8aaa-333333333333"
)

type annotationRosterResponse struct {
	Type      string        `json:"type"`
	RequestID string        `json:"request_id"`
	Payload   rosterPayload `json:"payload"`
}

// openAnnotationSession dials the relay upgrade with an optional capability
// header and returns the raw welcome payload keys plus the connection.
func openAnnotationSession(
	t *testing.T,
	endpoint string,
	routeID string,
	hostname string,
	cwd string,
	capable bool,
) (*websocket.Conn, map[string]json.RawMessage) {
	t.Helper()
	return openAnnotationSessionWith(t, endpoint, annotationSessionOptions{
		routeID:   routeID,
		hostname:  hostname,
		cwd:       cwd,
		capable:   capable,
		annotated: nil,
	})
}

// annotationSessionOptions describes one test session handshake.
type annotationSessionOptions struct {
	routeID   string
	hostname  string
	cwd       string
	capable   bool
	annotated map[string]string
}

// openAnnotationSessionWith dials the relay upgrade and returns the raw
// welcome payload keys plus the connection.
func openAnnotationSessionWith(
	t *testing.T,
	endpoint string,
	options annotationSessionOptions,
) (*websocket.Conn, map[string]json.RawMessage) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dialOptions := &websocket.DialOptions{}
	if options.capable {
		dialOptions.HTTPHeader = http.Header{capabilityHeaderName: []string{annotationsCapability}}
	}
	connection, _, err := websocket.Dial(ctx, endpoint, dialOptions)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	payload := map[string]any{
		"route_id": options.routeID,
		"hostname": options.hostname,
		"cwd":      options.cwd,
	}
	if options.annotated != nil {
		payload["annotations"] = options.annotated
	}
	if err := wsjson.Write(ctx, connection, map[string]any{
		"v":          1,
		"type":       "hello",
		"request_id": annotationHelloRequestID,
		"payload":    payload,
	}); err != nil {
		_ = connection.CloseNow()
		t.Fatalf("write hello: %v", err)
	}
	_, reader, err := connection.Reader(ctx)
	if err != nil {
		_ = connection.CloseNow()
		t.Fatalf("read welcome: %v", err)
	}
	buffer := make([]byte, 8192)
	read, err := reader.Read(buffer)
	if err != nil {
		_ = connection.CloseNow()
		t.Fatalf("read welcome frame: %v", err)
	}
	var envelope struct {
		Type    string                     `json:"type"`
		Payload map[string]json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(buffer[:read], &envelope); err != nil {
		_ = connection.CloseNow()
		t.Fatalf("decode welcome: %v", err)
	}
	if envelope.Type != "welcome" {
		_ = connection.CloseNow()
		t.Fatalf("welcome type = %q", envelope.Type)
	}
	return connection, envelope.Payload
}

// annotateFrame builds one annotate operation frame.
func annotateFrame(requestID string, annotations string) string {
	return fmt.Sprintf(
		`{"v":1,"type":"annotate","request_id":%q,"payload":{"annotations":%s}}`,
		requestID,
		annotations,
	)
}

// annotatePayloadFrame builds one annotate operation frame with a raw payload.
func annotatePayloadFrame(requestID string, payload string) string {
	return fmt.Sprintf(`{"v":1,"type":"annotate","request_id":%q,"payload":%s}`, requestID, payload)
}

// listFrame builds one roster request frame.
func listFrame(requestID string) string {
	return fmt.Sprintf(`{"v":1,"type":"list","request_id":%q,"payload":{}}`, requestID)
}

// readRoster reads one correlated roster response.
func readRoster(t *testing.T, connection *websocket.Conn, requestID string) rosterPayload {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var response annotationRosterResponse
	if err := wsjson.Read(ctx, connection, &response); err != nil {
		t.Fatalf("read roster response: %v", err)
	}
	if response.Type != "roster" || response.RequestID != requestID {
		t.Fatalf("roster response = %+v, want correlated roster", response)
	}
	return response.Payload
}

// syncAnnotations sends one annotate frame and waits until the relay applied
// it: the same connection's next roster response is ordered after it.
func syncAnnotations(t *testing.T, connection *websocket.Conn, annotations string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := connection.Write(ctx, websocket.MessageText, []byte(annotateFrame(
		"01993c85-1111-7aaa-8aaa-111111111111",
		annotations,
	))); err != nil {
		t.Fatalf("write annotate frame: %v", err)
	}
	requestID := "01993c86-2222-7aaa-8aaa-222222222222"
	if err := connection.Write(ctx, websocket.MessageText, []byte(listFrame(requestID))); err != nil {
		t.Fatalf("write list frame: %v", err)
	}
	readRoster(t, connection, requestID)
}

func TestWelcomeShapeDependsOnNegotiatedCapability(t *testing.T) {
	registry := newSessionConnectionRegistryWithLimit(4)
	logger := newEventLogger(writerFunc(func(data []byte) (int, error) { return len(data), nil }))
	t.Cleanup(func() { _ = logger.close() })
	service := newSessionAuthService("", registry, logger, newFatalRuntimeReporter().report)
	server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
	t.Cleanup(server.Close)
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")

	capable, capablePayload := openAnnotationSession(t, endpoint, annotationRouteA, "host", "/srv/project", true)
	defer capable.CloseNow()
	if _, exists := capablePayload["capabilities"]; !exists {
		t.Fatal("capable session did not receive a capabilities field")
	}
	var capabilities []string
	if err := json.Unmarshal(capablePayload["capabilities"], &capabilities); err != nil {
		t.Fatalf("decode capabilities: %v", err)
	}
	if len(capabilities) != 1 || capabilities[0] != annotationsCapability {
		t.Fatalf("capabilities = %#v, want annotations only", capabilities)
	}
	if len(capablePayload) != 4 {
		t.Fatalf("capable welcome payload keys = %d, want 4", len(capablePayload))
	}

	legacy, legacyPayload := openAnnotationSession(t, endpoint, annotationRouteB, "host", "/srv/legacy", false)
	defer legacy.CloseNow()
	if len(legacyPayload) != 3 {
		t.Fatalf("legacy welcome payload keys = %d, want the exact legacy three", len(legacyPayload))
	}
	for _, key := range []string{"self_address", "heartbeat_ms", "max_body_bytes"} {
		if _, exists := legacyPayload[key]; !exists {
			t.Fatalf("legacy welcome payload is missing %q", key)
		}
	}
	if _, exists := legacyPayload["capabilities"]; exists {
		t.Fatal("legacy welcome payload advertised capabilities")
	}
}

func TestHelloWithAnnotationsFieldStaysRejectedForLegacySessions(t *testing.T) {
	registry := newSessionConnectionRegistryWithLimit(4)
	logger := newEventLogger(writerFunc(func(data []byte) (int, error) { return len(data), nil }))
	t.Cleanup(func() { _ = logger.close() })
	service := newSessionAuthService("", registry, logger, newFatalRuntimeReporter().report)
	server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
	t.Cleanup(server.Close)
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, _, err := websocket.Dial(ctx, endpoint, nil)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer connection.CloseNow()
	if err := wsjson.Write(ctx, connection, map[string]any{
		"v":          1,
		"type":       "hello",
		"request_id": annotationHelloRequestID,
		"payload": map[string]any{
			"route_id":    annotationRouteA,
			"hostname":    "host",
			"cwd":         "/srv/project",
			"annotations": map[string]string{"name": "alice"},
		},
	}); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	if _, _, err := connection.Reader(ctx); err == nil {
		t.Fatal("hello with an annotations field was accepted without the capability header")
	}
}

func TestHelloAnnotationsApplyForCapableSessions(t *testing.T) {
	logs := &lockedBuffer{changed: make(chan struct{}, 1)}
	logger := newEventLogger(writerFunc(func(data []byte) (int, error) { return logs.Write(data) }))
	t.Cleanup(func() { _ = logger.close() })
	registry := newSessionConnectionRegistryWithLimit(8)
	service := newSessionAuthService("", registry, logger, newFatalRuntimeReporter().report)
	server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
	t.Cleanup(server.Close)
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")

	announcer, _ := openAnnotationSessionWith(t, endpoint, annotationSessionOptions{
		routeID:   annotationRouteA,
		hostname:  "host",
		cwd:       "/srv/project",
		capable:   true,
		annotated: map[string]string{"name": "alice"},
	})
	defer announcer.CloseNow()
	observer, _ := openAnnotationSession(t, endpoint, annotationRouteB, "host", "/srv/other", true)
	defer observer.CloseNow()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// The observer's roster is ordered after the announcer's hello on its own
	// connection only once the announcer's session is published; poll for the
	// annotation to appear.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		requestID := "01993c93-eeee-7aaa-8aaa-eeeeeeeeeeee"
		if err := observer.Write(ctx, websocket.MessageText, []byte(listFrame(requestID))); err != nil {
			t.Fatalf("write observer list: %v", err)
		}
		page := readRoster(t, observer, requestID)
		for _, peer := range page.Peers {
			if strings.HasPrefix(peer.Address, "/srv/project@") {
				if peer.Annotations["name"] == "alice" {
					if strings.Contains(logs.String(), "alice") {
						t.Fatalf("annotation value reached the log: %s", logs.String())
					}
					return
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the hello annotation never reached the roster: %s", logs.String())
}

func TestAnnotateAcceptedVisibleOnlyToCapableRequesters(t *testing.T) {
	logs := &lockedBuffer{changed: make(chan struct{}, 1)}
	logger := newEventLogger(writerFunc(func(data []byte) (int, error) { return logs.Write(data) }))
	t.Cleanup(func() { _ = logger.close() })
	registry := newSessionConnectionRegistryWithLimit(8)
	service := newSessionAuthService("", registry, logger, newFatalRuntimeReporter().report)
	server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
	t.Cleanup(server.Close)
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")

	announcer, _ := openAnnotationSession(t, endpoint, annotationRouteA, "host", "/srv/project", true)
	defer announcer.CloseNow()
	observer, _ := openAnnotationSession(t, endpoint, annotationRouteB, "host", "/srv/other", true)
	defer observer.CloseNow()
	legacy, _ := openAnnotationSession(t, endpoint, annotationRouteC, "host", "/srv/legacy", false)
	defer legacy.CloseNow()

	syncAnnotations(t, announcer, `{"name":"alice","state":"idle"}`)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	observerRequest := "01993c87-3333-7aaa-8aaa-333333333333"
	if err := observer.Write(ctx, websocket.MessageText, []byte(listFrame(observerRequest))); err != nil {
		t.Fatalf("write observer list: %v", err)
	}
	capablePage := readRoster(t, observer, observerRequest)
	if len(capablePage.Peers) != 2 {
		t.Fatalf("capable roster peers = %#v, want two peers", capablePage.Peers)
	}
	var announcerPeer *rosterPeer
	for index := range capablePage.Peers {
		if strings.HasPrefix(capablePage.Peers[index].Address, "/srv/project@") {
			announcerPeer = &capablePage.Peers[index]
		}
	}
	if announcerPeer == nil {
		t.Fatalf("capable roster = %#v, want the announcer", capablePage.Peers)
	}
	if len(announcerPeer.Annotations) != 2 ||
		announcerPeer.Annotations["name"] != "alice" ||
		announcerPeer.Annotations["state"] != "idle" {
		t.Fatalf("capable roster annotations = %#v", announcerPeer.Annotations)
	}

	legacyRequest := "01993c88-4444-7aaa-8aaa-444444444444"
	if err := legacy.Write(ctx, websocket.MessageText, []byte(listFrame(legacyRequest))); err != nil {
		t.Fatalf("write legacy list: %v", err)
	}
	legacyPage := readRoster(t, legacy, legacyRequest)
	for _, peer := range legacyPage.Peers {
		if strings.HasPrefix(peer.Address, "/srv/project@") && peer.Annotations != nil {
			t.Fatalf("legacy requester received annotations: %#v", peer.Annotations)
		}
	}
	encoded, err := json.Marshal(legacyPage.Peers)
	if err != nil {
		t.Fatalf("encode legacy page: %v", err)
	}
	if strings.Contains(string(encoded), "annotations") {
		t.Fatalf("legacy roster shape changed: %s", encoded)
	}
}

func TestAnnotateReplaceAllDroppedSetKeepsPreviousSetAndSocketHealthy(t *testing.T) {
	logs := &lockedBuffer{changed: make(chan struct{}, 1)}
	logger := newEventLogger(writerFunc(func(data []byte) (int, error) { return logs.Write(data) }))
	t.Cleanup(func() { _ = logger.close() })
	registry := newSessionConnectionRegistryWithLimit(8)
	service := newSessionAuthService("", registry, logger, newFatalRuntimeReporter().report)
	server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
	t.Cleanup(server.Close)
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")

	announcer, _ := openAnnotationSession(t, endpoint, annotationRouteA, "host", "/srv/project", true)
	defer announcer.CloseNow()
	observer, _ := openAnnotationSession(t, endpoint, annotationRouteB, "host", "/srv/other", true)
	defer observer.CloseNow()

	syncAnnotations(t, announcer, `{"name":"alice"}`)

	for _, annotations := range []string{
		`{"invalid key":"value"}`,
		`{"name":"bad\nvalue"}`,
		fmt.Sprintf(`{"name":%q}`, strings.Repeat("x", maxAnnotationValueBytes+1)),
		`{"a1":"v","a2":"v","a3":"v","a4":"v","a5":"v","a6":"v","a7":"v","a8":"v","a9":"v"}`,
		`{"name":42}`,
		`{"name":"first","name":"second"}`,
	} {
		syncAnnotations(t, announcer, annotations)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	requestID := "01993c89-5555-7aaa-8aaa-555555555555"
	if err := observer.Write(ctx, websocket.MessageText, []byte(listFrame(requestID))); err != nil {
		t.Fatalf("write observer list: %v", err)
	}
	page := readRoster(t, observer, requestID)
	for _, peer := range page.Peers {
		if strings.HasPrefix(peer.Address, "/srv/project@") {
			if len(peer.Annotations) != 1 || peer.Annotations["name"] != "alice" {
				t.Fatalf("dropped sets changed the live set: %#v", peer.Annotations)
			}
		}
	}

	// Replace-all: the previous keys disappear with the new set.
	syncAnnotations(t, announcer, `{"state":"busy"}`)
	requestID = "01993c8a-6666-7aaa-8aaa-666666666666"
	if err := observer.Write(ctx, websocket.MessageText, []byte(listFrame(requestID))); err != nil {
		t.Fatalf("write observer list: %v", err)
	}
	page = readRoster(t, observer, requestID)
	for _, peer := range page.Peers {
		if strings.HasPrefix(peer.Address, "/srv/project@") {
			if len(peer.Annotations) != 1 || peer.Annotations["state"] != "busy" {
				t.Fatalf("replace-all kept stale keys: %#v", peer.Annotations)
			}
		}
	}

	// An empty map clears the set.
	syncAnnotations(t, announcer, `{}`)
	requestID = "01993c8b-7777-7aaa-8aaa-777777777777"
	if err := observer.Write(ctx, websocket.MessageText, []byte(listFrame(requestID))); err != nil {
		t.Fatalf("write observer list: %v", err)
	}
	page = readRoster(t, observer, requestID)
	for _, peer := range page.Peers {
		if strings.HasPrefix(peer.Address, "/srv/project@") && len(peer.Annotations) != 0 {
			t.Fatalf("empty map did not clear the set: %#v", peer.Annotations)
		}
	}

	settleContext, cancelSettle := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelSettle()
	if err := registry.closeAndWait(settleContext); err != nil {
		t.Fatalf("settle sessions: %v", err)
	}
}

func TestAnnotationsAreClearedOnDisconnect(t *testing.T) {
	registry := newSessionConnectionRegistryWithLimit(8)
	logger := newEventLogger(writerFunc(func(data []byte) (int, error) { return len(data), nil }))
	t.Cleanup(func() { _ = logger.close() })
	service := newSessionAuthService("", registry, logger, newFatalRuntimeReporter().report)
	server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
	t.Cleanup(server.Close)
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")

	announcer, _ := openAnnotationSession(t, endpoint, annotationRouteA, "host", "/srv/project", true)
	observer, _ := openAnnotationSession(t, endpoint, annotationRouteB, "host", "/srv/other", true)
	defer observer.CloseNow()

	syncAnnotations(t, announcer, `{"name":"alice"}`)
	_ = announcer.CloseNow()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	requestID := "01993c8c-8888-7aaa-8aaa-888888888888"
	if err := observer.Write(ctx, websocket.MessageText, []byte(listFrame(requestID))); err != nil {
		t.Fatalf("write observer list: %v", err)
	}
	page := readRoster(t, observer, requestID)
	for _, peer := range page.Peers {
		if strings.HasPrefix(peer.Address, "/srv/project@") {
			t.Fatalf("disconnected peer stayed in the roster: %#v", peer)
		}
	}
}

func TestLegacySessionAnnotateOperationStaysTerminal(t *testing.T) {
	logs := &lockedBuffer{changed: make(chan struct{}, 1)}
	logger := newEventLogger(writerFunc(func(data []byte) (int, error) { return logs.Write(data) }))
	t.Cleanup(func() { _ = logger.close() })
	registry := newSessionConnectionRegistryWithLimit(8)
	service := newSessionAuthService("", registry, logger, newFatalRuntimeReporter().report)
	server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
	t.Cleanup(server.Close)
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")

	legacy, _ := openAnnotationSession(t, endpoint, annotationRouteA, "host", "/srv/project", false)
	defer legacy.CloseNow()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := legacy.Write(ctx, websocket.MessageText, []byte(annotateFrame(
		"01993c8d-9999-7aaa-8aaa-999999999999",
		`{"name":"alice"}`,
	))); err != nil {
		t.Fatalf("write annotate frame: %v", err)
	}
	var failure struct {
		Type    string `json:"type"`
		Payload struct {
			Code  string `json:"code"`
			Close bool   `json:"close"`
		} `json:"payload"`
	}
	if err := wsjson.Read(ctx, legacy, &failure); err != nil {
		t.Fatalf("read protocol failure: %v", err)
	}
	if failure.Type != "error" || failure.Payload.Code != "invalid_envelope" || !failure.Payload.Close {
		t.Fatalf("legacy annotate failure = %+v", failure)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(logs.String(), `"reason":"unsupported_operation_type"`) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no unsupported_operation_type rejection was logged: %s", logs.String())
}

func TestAnnotationTelemetryCarriesNoValues(t *testing.T) {
	logs := &lockedBuffer{changed: make(chan struct{}, 1)}
	logger := newEventLogger(writerFunc(func(data []byte) (int, error) { return logs.Write(data) }))
	t.Cleanup(func() { _ = logger.close() })
	registry := newSessionConnectionRegistryWithLimit(8)
	service := newSessionAuthService("", registry, logger, newFatalRuntimeReporter().report)
	server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
	t.Cleanup(server.Close)
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")

	announcer, _ := openAnnotationSession(t, endpoint, annotationRouteA, "host", "/srv/project", true)
	defer announcer.CloseNow()

	syncAnnotations(t, announcer, `{"name":"alice","secret_value":"do-not-log"}`)
	syncAnnotations(t, announcer, `{"bad key":"do-not-log"}`)
	syncAnnotations(t, announcer, `{"name":"first","name":"do-not-log"}`)

	// A malformed annotate payload is dropped, never terminal.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := announcer.Write(ctx, websocket.MessageText, []byte(annotatePayloadFrame(
		"01993c91-cccc-7aaa-8aaa-cccccccccccc",
		`{"names":"do-not-log"}`,
	))); err != nil {
		t.Fatalf("write malformed annotate frame: %v", err)
	}
	// The next roster response on the same connection orders after the
	// dropped annotate frame.
	barrierRequest := "01993c92-dddd-7aaa-8aaa-dddddddddddd"
	if err := announcer.Write(ctx, websocket.MessageText, []byte(listFrame(barrierRequest))); err != nil {
		t.Fatalf("write barrier list frame: %v", err)
	}
	readRoster(t, announcer, barrierRequest)

	settled := false
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(logs.String(), `"event":"annotations_dropped"`) {
			settled = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !settled {
		t.Fatalf("no annotations_dropped event was logged: %s", logs.String())
	}
	output := logs.String()
	if !strings.Contains(output, `"event":"annotations_accepted"`) {
		t.Fatalf("no annotations_accepted event was logged: %s", output)
	}
	for _, secret := range []string{"alice", "do-not-log"} {
		if strings.Contains(output, secret) {
			t.Fatalf("annotation value %q reached the log: %s", secret, output)
		}
	}
	if !strings.Contains(output, `"reason":"invalid_key"`) {
		t.Fatalf("no stable drop reason was logged: %s", output)
	}
	if !strings.Contains(output, `"reason":"duplicate_key"`) {
		t.Fatalf("no duplicate drop reason was logged: %s", output)
	}
	if !strings.Contains(output, `"reason":"invalid_payload"`) {
		t.Fatalf("no invalid payload drop reason was logged: %s", output)
	}
}

func TestAnnotationValidationAcceptsLegalSetsAndRejectsIllegalOnes(t *testing.T) {
	valid := map[string]string{"name": "alice", "state": "idle", "empty": ""}
	set, reason := decodeAnnotationMap([]byte(`{"name":"alice","state":"idle","empty":""}`))
	if reason != "" || len(set) != 3 {
		t.Fatalf("valid set = %#v reason %q", set, reason)
	}
	if annotationSerializedBytes(valid) == 0 {
		t.Fatal("serialized size is zero")
	}
	for name, payload := range map[string]string{
		"invalid key":   `{"Name":"alice"}`,
		"spaced key":    `{"na me":"alice"}`,
		"numeric key":   `{"1name":"alice"}`,
		"too many keys": `{"a1":"v","a2":"v","a3":"v","a4":"v","a5":"v","a6":"v","a7":"v","a8":"v","a9":"v"}`,
		"control value": `{"name":"a\nb"}`,
		"delete value":  `{"name":"a\u007fb"}`,
		"long value":    fmt.Sprintf(`{"name":%q}`, strings.Repeat("x", maxAnnotationValueBytes+1)),
		"number value":  `{"name":42}`,
		"null value":    `{"name":null}`,
		"object value":  `{"name":{"a":"b"}}`,
		"array value":   `{"name":["a"]}`,
		"not an object": `["name"]`,
	} {
		if _, reason := decodeAnnotationMap([]byte(payload)); reason == "" {
			t.Fatalf("%s was accepted", name)
		}
	}
	oversized := fmt.Sprintf(
		`{"a1":%q,"a2":%q,"a3":%q,"a4":%q,"a5":%q}`,
		strings.Repeat("x", 250),
		strings.Repeat("x", 250),
		strings.Repeat("x", 250),
		strings.Repeat("x", 250),
		strings.Repeat("x", 250),
	)
	if _, reason := decodeAnnotationMap([]byte(oversized)); reason != "too_large" {
		t.Fatalf("oversized set reason = %q, want too_large", reason)
	}
}

func TestRosterPageFitsWorstCaseAddressAndAnnotationSet(t *testing.T) {
	operation := clientOperation{
		Type:      "list",
		RequestID: "01993c8e-aaaa-7aaa-8aaa-aaaaaaaaaaaa",
		List:      &listOperationPayload{},
	}
	maximumAddress := strings.Repeat("\u0001", maxCWDBytes) + "@" +
		strings.Repeat("h", maxHostnameBytes) + "#" + strings.Repeat("0", 36)
	// The worst accepted annotation set fills the serialized ceiling with
	// characters that the roster frame escapes to six bytes each.
	annotations := map[string]string{}
	for index := 0; index < maxAnnotationKeys; index++ {
		annotations[fmt.Sprintf("k%d", index)] = strings.Repeat("<", 119)
	}
	if size := annotationSerializedBytes(annotations); size > maxAnnotationSerializedBytes {
		t.Fatalf("worst annotation set is %d bytes, above the ceiling", size)
	}
	peer := rosterPeer{Address: maximumAddress, Annotations: annotations}
	page, err := buildRosterPage(operation, []rosterPeer{peer})
	if err != nil {
		t.Fatalf("worst-case peer did not fit: %v", err)
	}
	encoded, err := encodeOperationResponse(operation, operationResponse{
		Type: "roster", Payload: page, Outcome: "settled", Code: "roster",
	})
	if err != nil {
		t.Fatalf("worst-case roster frame did not fit: %v", err)
	}
	if len(encoded) > maxRosterFrameBytes {
		t.Fatalf("worst-case roster frame = %d bytes, cap %d", len(encoded), maxRosterFrameBytes)
	}

	// Two worst-case peers must page instead of exceeding the ceiling.
	two, err := buildRosterPage(operation, []rosterPeer{peer, peer})
	if err != nil {
		t.Fatalf("two worst-case peers did not page: %v", err)
	}
	if len(two.Peers) != 1 || two.NextCursor == "" {
		t.Fatalf("two worst-case peers = %#v, want one paged peer", two)
	}
	encoded, err = encodeOperationResponse(operation, operationResponse{
		Type: "roster", Payload: two, Outcome: "settled", Code: "roster",
	})
	if err != nil {
		t.Fatalf("paged worst-case roster frame did not fit: %v", err)
	}
	if len(encoded) > maxRosterFrameBytes {
		t.Fatalf("paged roster frame = %d bytes, cap %d", len(encoded), maxRosterFrameBytes)
	}
}

func TestConcurrentAnnotationUpdatesKeepTheSocketHealthy(t *testing.T) {
	logger := newEventLogger(writerFunc(func(data []byte) (int, error) { return len(data), nil }))
	t.Cleanup(func() { _ = logger.close() })
	registry := newSessionConnectionRegistryWithLimit(8)
	service := newSessionAuthService("", registry, logger, newFatalRuntimeReporter().report)
	server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
	t.Cleanup(server.Close)
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")

	announcer, _ := openAnnotationSession(t, endpoint, annotationRouteA, "host", "/srv/project", true)
	defer announcer.CloseNow()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var writers sync.WaitGroup
	for index := 0; index < 8; index++ {
		writers.Add(1)
		go func(iteration int) {
			defer writers.Done()
			frame := annotateFrame(
				fmt.Sprintf("01993c8f-%04x-7aaa-8aaa-bbbbbbbbbbbb", iteration),
				fmt.Sprintf(`{"name":"agent-%d"}`, iteration),
			)
			for attempt := 0; attempt < 4; attempt++ {
				if err := announcer.Write(ctx, websocket.MessageText, []byte(frame)); err != nil {
					return
				}
			}
		}(index)
	}
	writers.Wait()
	requestID := "01993c90-bbbb-7aaa-8aaa-bbbbbbbbbbbb"
	if err := announcer.Write(ctx, websocket.MessageText, []byte(listFrame(requestID))); err != nil {
		t.Fatalf("write list frame: %v", err)
	}
	readRoster(t, announcer, requestID)
}
