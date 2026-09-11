package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

func TestAuthenticatedAddressSnapshotIsLiveAddressOnlyAndOmitsCaller(t *testing.T) {
	registry := newSessionConnectionRegistryWithLimit(4)
	caller, ok := registry.reserve()
	if !ok {
		t.Fatal("reserve caller")
	}
	peer, ok := registry.reserve()
	if !ok {
		t.Fatal("reserve peer")
	}
	unauthed, ok := registry.reserve()
	if !ok {
		t.Fatal("reserve unauthenticated entry")
	}
	caller.connection = nil
	peer.connection = nil
	caller.session = &authenticatedSession{Address: "caller", ClientID: "secret-caller", CWD: "/private"}
	caller.visible = true
	peer.session = &authenticatedSession{Address: "peer", ClientID: "secret-peer", Hostname: "private-host"}
	peer.visible = true

	got := registry.authenticatedAddressSnapshot(caller.session)
	if len(got) != 1 || got[0] != "peer" {
		t.Fatalf("snapshot = %#v, want peer only", got)
	}
	registry.remove(peer)
	if got := registry.authenticatedAddressSnapshot(caller.session); len(got) != 0 {
		t.Fatalf("snapshot after removal = %#v, want empty", got)
	}
	registry.remove(caller)
	registry.remove(unauthed)
}

func TestRosterDispatcherSortsStrictlyAfterCursorAndReadsLiveRegistry(t *testing.T) {
	registry := newSessionConnectionRegistryWithLimit(5)
	callerSession := &authenticatedSession{Address: "bravo"}
	add := func(address string) *trackedSessionConnection {
		entry, ok := registry.reserve()
		if !ok {
			t.Fatalf("reserve %q", address)
		}
		entry.session = &authenticatedSession{Address: address}
		entry.visible = true
		return entry
	}
	caller := add("bravo")
	alpha := add("alpha")
	charlie := add("charlie")
	delta := add("delta")
	dispatch := rosterOperationDispatcher(registry)
	operation := clientOperation{Type: "list", RequestID: "01993c84-5d38-7d75-8bc1-f945bfa42cdf", List: &listOperationPayload{AfterAddress: "bravo"}}

	response, respond, err := dispatch(context.Background(), callerSession, operation)
	if err != nil || !respond {
		t.Fatalf("dispatch = response %#v, respond %v, error %v", response, respond, err)
	}
	payload, ok := response.Payload.(rosterPayload)
	if !ok {
		t.Fatalf("payload type = %T", response.Payload)
	}
	if len(payload.Peers) != 2 || payload.Peers[0].Address != "charlie" || payload.Peers[1].Address != "delta" {
		t.Fatalf("ordered page = %#v", payload)
	}

	registry.remove(charlie)
	response, _, err = dispatch(context.Background(), callerSession, operation)
	if err != nil {
		t.Fatalf("dispatch after churn: %v", err)
	}
	payload = response.Payload.(rosterPayload)
	if len(payload.Peers) != 1 || payload.Peers[0].Address != "delta" {
		t.Fatalf("live page after churn = %#v", payload)
	}
	registry.remove(caller)
	registry.remove(alpha)
	registry.remove(delta)
}

func TestRosterPublishesOnlyAfterSuccessfulWelcome(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		welcomeFail bool
	}{
		{name: "successful welcome publishes"},
		{name: "failed welcome remains absent", welcomeFail: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			const (
				helloRequestID   = "01993c79-8ad7-79fa-83e3-9789dcaca168"
				callerRouteID    = "01993ca1-1111-7aaa-8aaa-111111111111"
				candidateRouteID = "01993ca1-2222-7aaa-8aaa-222222222222"
				callerAddress    = "/caller@host#" + callerRouteID
				candidateAddress = "/candidate@host#" + candidateRouteID
			)

			callerAccepted := make(chan struct{})
			candidateAccepted := make(chan struct{})
			candidateRejected := make(chan struct{})
			var callerAcceptedOnce sync.Once
			var candidateAcceptedOnce sync.Once
			var candidateRejectedOnce sync.Once
			logger := newEventLogger(writerFunc(func(data []byte) (int, error) {
				line := string(data)
				if strings.Contains(line, `"event":"auth_accepted"`) &&
					strings.Contains(line, `"request_id":"`+helloRequestID+`"`) &&
					strings.Contains(line, `"address":"`+callerAddress+`"`) {
					callerAcceptedOnce.Do(func() { close(callerAccepted) })
				}
				if strings.Contains(line, `"event":"auth_accepted"`) &&
					strings.Contains(line, `"request_id":"`+helloRequestID+`"`) &&
					strings.Contains(line, `"address":"`+candidateAddress+`"`) {
					candidateAcceptedOnce.Do(func() { close(candidateAccepted) })
				}
				if strings.Contains(line, `"reason":"welcome_failed"`) &&
					strings.Contains(line, `"request_id":"`+helloRequestID+`"`) &&
					strings.Contains(line, `"route_id":"`+candidateRouteID+`"`) {
					candidateRejectedOnce.Do(func() { close(candidateRejected) })
				}
				return len(data), nil
			}))
			t.Cleanup(func() { _ = logger.close() })

			reporter := newFatalRuntimeReporter()
			pairing, err := newTestPairingService(t, t.TempDir(), "", logger, reporter.report)
			if err != nil {
				t.Fatalf("create pairing service: %v", err)
			}
			publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("generate installation key: %v", err)
			}
			encodedKey := "ed25519:" + base64.StdEncoding.EncodeToString(publicKey)
			pairing.mu.Lock()
			pairing.allowlist.Clients = []allowlistClient{{ClientID: "cli_roster_visibility", PublicKey: encodedKey}}
			pairing.mu.Unlock()

			registry := newSessionConnectionRegistryWithLimit(4)
			service := newSessionAuthService(pairing, registry, logger, reporter.report)
			welcomeStarted := make(chan struct{})
			releaseWelcome := make(chan struct{})
			service.writeWelcome = func(ctx context.Context, connection *websocket.Conn, welcome welcomeEnvelope) error {
				if welcome.Payload.SelfAddress != candidateAddress {
					return wsjson.Write(ctx, connection, welcome)
				}
				close(welcomeStarted)
				select {
				case <-releaseWelcome:
				case <-ctx.Done():
					return ctx.Err()
				}
				if testCase.welcomeFail {
					return errors.New("injected welcome write failure")
				}
				return wsjson.Write(ctx, connection, welcome)
			}
			server := httptest.NewServer(http.HandlerFunc(service.handleConnect))
			t.Cleanup(server.Close)
			endpoint := "ws" + strings.TrimPrefix(server.URL, "http")

			caller, err := openAuthenticatedTestSession(endpoint, privateKey, encodedKey, callerRouteID, "host", "/caller")
			if err != nil {
				t.Fatalf("authenticate roster caller: %v", err)
			}
			defer caller.CloseNow()

			await := func(name string, signal <-chan struct{}) {
				t.Helper()
				select {
				case <-signal:
				case <-time.After(2 * time.Second):
					t.Fatalf("timed out waiting for %s", name)
				}
			}
			await("caller publication", callerAccepted)

			type authenticationResult struct {
				connection *websocket.Conn
				err        error
			}
			candidateResult := make(chan authenticationResult, 1)
			go func() {
				connection, err := openAuthenticatedTestSession(
					endpoint,
					privateKey,
					encodedKey,
					candidateRouteID,
					"host",
					"/candidate",
				)
				candidateResult <- authenticationResult{connection: connection, err: err}
			}()
			await("held candidate welcome", welcomeStarted)

			collision, err := openAuthenticatedTestSession(
				endpoint,
				privateKey,
				encodedKey,
				candidateRouteID,
				"other-host",
				"/other-candidate",
			)
			if collision != nil {
				_ = collision.CloseNow()
				t.Fatal("reserved pre-publication route accepted a collision")
			}
			if err == nil {
				t.Fatal("reserved pre-publication route did not reject a collision")
			}

			listAddresses := func() []string {
				t.Helper()
				operation := clientOperation{
					Type:      "list",
					RequestID: "01993c84-5d38-7d75-8bc1-f945bfa42cdf",
					List:      &listOperationPayload{},
				}
				response, respond, err := rosterOperationDispatcher(registry)(
					context.Background(),
					&authenticatedSession{Address: callerAddress},
					operation,
				)
				if err != nil || !respond {
					t.Fatalf("list while welcome settles = response %#v, respond %v, error %v", response, respond, err)
				}
				payload := response.Payload.(rosterPayload)
				addresses := make([]string, len(payload.Peers))
				for index, peer := range payload.Peers {
					addresses[index] = peer.Address
				}
				return addresses
			}
			if got := listAddresses(); len(got) != 0 {
				t.Fatalf("roster before welcome publication = %#v, want empty", got)
			}

			close(releaseWelcome)
			if testCase.welcomeFail {
				await("welcome failure audit", candidateRejected)
				result := <-candidateResult
				if result.connection != nil {
					_ = result.connection.CloseNow()
					t.Fatal("failed welcome returned an authenticated connection")
				}
				if result.err == nil {
					t.Fatal("failed welcome returned no authentication error")
				}
				if got := listAddresses(); len(got) != 0 {
					t.Fatalf("roster after welcome failure = %#v, want empty", got)
				}
			} else {
				result := <-candidateResult
				if result.err != nil {
					t.Fatalf("authenticate candidate after welcome release: %v", result.err)
				}
				defer result.connection.CloseNow()
				await("candidate publication", candidateAccepted)
				got := listAddresses()
				if len(got) != 1 || got[0] != candidateAddress {
					t.Fatalf("roster after welcome publication = %#v, want candidate", got)
				}
			}

			_ = caller.CloseNow()
			settleContext, cancelSettle := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancelSettle()
			if err := registry.closeAndWait(settleContext); err != nil {
				t.Fatalf("settle roster visibility connections: %v", err)
			}
		})
	}
}

func TestRosterPageUsesLongestExactBoundedPrefix(t *testing.T) {
	operation := clientOperation{Type: "list", RequestID: "01993c84-5d38-7d75-8bc1-f945bfa42cdf", List: &listOperationPayload{}}
	addresses := make([]string, 13)
	for index := range addresses {
		addresses[index] = string(rune('a'+index)) + strings.Repeat("x", 3_999)
	}
	payload, err := buildRosterPage(operation, addresses)
	if err != nil {
		t.Fatalf("build page: %v", err)
	}
	if len(payload.Peers) != 10 {
		t.Fatalf("peer count = %d, want longest fitting prefix of 10", len(payload.Peers))
	}
	wantCursor := cursorPrefix + base64.RawURLEncoding.EncodeToString([]byte(addresses[9]))
	if payload.NextCursor != wantCursor {
		t.Fatalf("next cursor does not encode last returned address")
	}
	encoded, err := encodeOperationResponse(operation, operationResponse{
		Type: "roster", Payload: payload, Outcome: "settled", Code: "roster",
	})
	if err != nil {
		t.Fatalf("encode page: %v", err)
	}
	if len(encoded) > maxRosterFrameBytes {
		t.Fatalf("encoded page = %d bytes, cap %d", len(encoded), maxRosterFrameBytes)
	}
	if strings.Contains(string(encoded), addresses[10]) {
		t.Fatal("page silently included address after cursor")
	}
}

func TestRosterPageBoundaryAndMaximumLegalAddress(t *testing.T) {
	operation := clientOperation{Type: "list", RequestID: "01993c84-5d38-7d75-8bc1-f945bfa42cdf", List: &listOperationPayload{}}
	maximumEscaped := strings.Repeat("\u0001", maxCWDBytes) + "@" + strings.Repeat("h", maxHostnameBytes) + "#" + strings.Repeat("0", 36)
	payload, err := buildRosterPage(operation, []string{maximumEscaped})
	if err != nil {
		t.Fatalf("maximum legal address did not fit: %v", err)
	}
	if len(payload.Peers) != 1 || payload.NextCursor != "" {
		t.Fatalf("maximum-address page = %#v", payload)
	}
	secondMaximum := maximumEscaped[:len(maximumEscaped)-1] + "1"
	payload, err = buildRosterPage(operation, []string{maximumEscaped, secondMaximum})
	if err != nil {
		t.Fatalf("maximum legal address with required cursor did not fit: %v", err)
	}
	if len(payload.Peers) != 1 || payload.Peers[0].Address != maximumEscaped || payload.NextCursor == "" {
		t.Fatalf("maximum-address continued page = %#v", payload)
	}

	base := rosterPayload{Peers: []rosterPeer{{Address: "peer"}}}
	response := operationResponse{Type: "roster", Payload: base, Outcome: "settled", Code: "roster"}
	encoded, err := encodeOperationResponse(operation, response)
	if err != nil {
		t.Fatalf("encode ordinary roster: %v", err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatalf("decode encoded roster: %v", err)
	}
	if len(encoded) >= maxRosterFrameBytes {
		t.Fatalf("small roster unexpectedly reached cap: %d", len(encoded))
	}

	over := rosterPayload{Peers: []rosterPeer{{Address: strings.Repeat("x", maxRosterFrameBytes)}}}
	if _, err := encodeOperationResponse(operation, operationResponse{
		Type: "roster", Payload: over, Outcome: "settled", Code: "roster",
	}); err == nil {
		t.Fatal("encode boundary accepted oversized roster")
	}
}
