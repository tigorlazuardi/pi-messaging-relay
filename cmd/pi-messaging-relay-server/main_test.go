package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

type writerFunc func([]byte) (int, error)

func (write writerFunc) Write(data []byte) (int, error) {
	return write(data)
}

type blockingAfterWriter struct {
	mu            sync.Mutex
	writes        int
	passWrites    int
	events        chan []byte
	blocked       chan struct{}
	release       chan struct{}
	writeReturned chan struct{}
	onBlock       func()
	blockedOnce   sync.Once
	releaseOnce   sync.Once
	returnedOnce  sync.Once
}

func newBlockingAfterWriter(passWrites int, onBlock func()) *blockingAfterWriter {
	return &blockingAfterWriter{
		passWrites:    passWrites,
		events:        make(chan []byte, passWrites),
		blocked:       make(chan struct{}),
		release:       make(chan struct{}),
		writeReturned: make(chan struct{}),
		onBlock:       onBlock,
	}
}

func (writer *blockingAfterWriter) Write(data []byte) (int, error) {
	writer.mu.Lock()
	writer.writes++
	writeNumber := writer.writes
	writer.mu.Unlock()
	if writeNumber <= writer.passWrites {
		writer.events <- append([]byte(nil), data...)
		return len(data), nil
	}
	writer.blockedOnce.Do(func() {
		close(writer.blocked)
		if writer.onBlock != nil {
			writer.onBlock()
		}
	})
	<-writer.release
	writer.returnedOnce.Do(func() { close(writer.writeReturned) })
	return len(data), nil
}

func (writer *blockingAfterWriter) unblock() {
	writer.releaseOnce.Do(func() { close(writer.release) })
}

type failOnceAfterWriter struct {
	mu        sync.Mutex
	writes    int
	failWrite int
	failure   error
	onFailure func()
	events    chan []byte
}

func (writer *failOnceAfterWriter) Write(data []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	writer.writes++
	if writer.writes == writer.failWrite {
		if writer.onFailure != nil {
			writer.onFailure()
		}
		return 0, writer.failure
	}
	writer.events <- append([]byte(nil), data...)
	return len(data), nil
}

type closeTrackingConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (connection *closeTrackingConn) Close() error {
	connection.once.Do(func() { close(connection.closed) })
	return connection.Conn.Close()
}

type singleConnListener struct {
	connection net.Conn
	closed     chan struct{}
	closeOnce  sync.Once
	accepted   chan net.Conn
}

func newSingleConnListener(connection net.Conn) *singleConnListener {
	accepted := make(chan net.Conn, 1)
	accepted <- connection
	return &singleConnListener{
		connection: connection,
		closed:     make(chan struct{}),
		accepted:   accepted,
	}
}

func (listener *singleConnListener) Accept() (net.Conn, error) {
	select {
	case connection := <-listener.accepted:
		return connection, nil
	case <-listener.closed:
		return nil, net.ErrClosed
	}
}

func (listener *singleConnListener) Close() error {
	listener.closeOnce.Do(func() { close(listener.closed) })
	return nil
}

func (listener *singleConnListener) Addr() net.Addr {
	return listener.connection.LocalAddr()
}

func TestSessionAuthAuditFailureReportsFatalRelayRuntimeClassification(t *testing.T) {
	auditFailure := errors.New("injected auth audit failure")
	terminationContext, cancelTermination := context.WithCancel(context.Background())
	defer cancelTermination()
	output := &failOnceAfterWriter{
		failWrite: 3,
		failure:   auditFailure,
		onFailure: cancelTermination,
		events:    make(chan []byte, 4),
	}
	var fallback bytes.Buffer
	runDone := make(chan error, 1)
	go func() {
		runErr := runWithContext(nil, output, syncDirectory, terminationContext)
		runDone <- reportServerFailure(runErr, &fallback)
	}()

	readEvent := func() logEvent {
		t.Helper()
		select {
		case data := <-output.events:
			var event logEvent
			if err := json.Unmarshal(data, &event); err != nil {
				t.Fatalf("decode startup event: %v", err)
			}
			return event
		case <-time.After(eventWriteTimeout):
			t.Fatal("timed out waiting for startup event")
			return logEvent{}
		}
	}
	ready := readEvent()
	if ready.Event != "server_ready" {
		t.Fatalf("first event = %q, want server_ready", ready.Event)
	}
	if created := readEvent(); created.Event != "pairing_code_created" {
		t.Fatalf("second event = %q, want pairing_code_created", created.Event)
	}

	dialContext, cancelDial := context.WithTimeout(context.Background(), time.Second)
	defer cancelDial()
	connection, _, err := websocket.Dial(dialContext, "ws://"+ready.Address+"/v1/connect", nil)
	if err != nil {
		t.Fatalf("dial auth audit fixture: %v", err)
	}
	t.Cleanup(func() { _ = connection.CloseNow() })
	var challenge challengeEnvelope
	if err := wsjson.Read(dialContext, connection, &challenge); err != nil {
		t.Fatalf("read auth challenge: %v", err)
	}
	if err := wsjson.Write(dialContext, connection, map[string]any{}); err != nil {
		t.Fatalf("write invalid hello: %v", err)
	}

	select {
	case runErr := <-runDone:
		if !errors.Is(runErr, auditFailure) {
			t.Fatalf("run error = %v, want auth audit failure", runErr)
		}
	case <-time.After(shutdownTimeout + eventWriteTimeout):
		t.Fatal("server did not settle fatal auth audit failure")
	}
	failureOutput := fallback.String()
	if !strings.Contains(failureOutput, `"event":"server_failed"`) ||
		!strings.Contains(failureOutput, "fatal relay runtime failure") ||
		!strings.Contains(failureOutput, "write auth_rejected session audit event") ||
		strings.Contains(failureOutput, "fatal pairing runtime failure") {
		t.Fatalf("server failure classification is inaccurate: %s", failureOutput)
	}
}

func TestNewDurableStateDirectoryMustSyncBeforeServerReadiness(t *testing.T) {
	stateParent := t.TempDir()
	stateDir := filepath.Join(stateParent, "durable-state")
	syncFailure := errors.New("injected parent sync failure")
	var syncedPath string
	var output bytes.Buffer

	runErr := runWithContext(
		[]string{"--state-dir", stateDir},
		&output,
		func(path string) error {
			syncedPath = path
			return syncFailure
		},
		context.Background(),
	)

	if !errors.Is(runErr, syncFailure) {
		t.Fatalf("run error = %v, want injected parent sync failure", runErr)
	}
	if syncedPath != stateParent {
		t.Fatalf("synced path = %q, want state parent %q", syncedPath, stateParent)
	}
	if output.Len() != 0 {
		t.Fatalf("server emitted readiness before durable state parent sync: %s", output.String())
	}
	if info, err := os.Stat(stateDir); err != nil {
		t.Fatalf("inspect newly created state directory: %v", err)
	} else if info.Mode().Perm() != 0o700 {
		t.Fatalf("new state directory permissions = %o, want 700", info.Mode().Perm())
	}
}

func TestBlockedStartupEventAndFailureFallbackRemainBounded(t *testing.T) {
	t.Run("startup stdout", func(t *testing.T) {
		output := newBlockingAfterWriter(0, nil)
		t.Cleanup(output.unblock)
		runDone := make(chan error, 1)
		go func() {
			runDone <- runWithContext(nil, output, syncDirectory, context.Background())
		}()
		select {
		case <-output.blocked:
		case <-time.After(eventWriteTimeout):
			t.Fatal("startup writer did not block")
		}
		select {
		case runErr := <-runDone:
			if !errors.Is(runErr, context.DeadlineExceeded) ||
				!strings.Contains(runErr.Error(), "report readiness") {
				t.Fatalf("blocked startup error = %v", runErr)
			}
		case <-time.After(2*eventWriteTimeout + eventWriteTimeout/2):
			t.Fatal("blocked startup did not return through write and close deadlines")
		}
		output.unblock()
		select {
		case <-output.writeReturned:
		case <-time.After(eventWriteTimeout):
			t.Fatal("released startup writer did not return")
		}
	})

	t.Run("stderr fallback", func(t *testing.T) {
		output := newBlockingAfterWriter(0, nil)
		t.Cleanup(output.unblock)
		primary := errors.New("primary server failure")
		reportDone := make(chan error, 1)
		go func() { reportDone <- reportServerFailure(primary, output) }()
		select {
		case <-output.blocked:
		case <-time.After(eventWriteTimeout):
			t.Fatal("stderr fallback writer did not block")
		}
		select {
		case reportErr := <-reportDone:
			if !errors.Is(reportErr, primary) || !errors.Is(reportErr, context.DeadlineExceeded) {
				t.Fatalf("blocked stderr fallback error = %v", reportErr)
			}
		case <-time.After(2*eventWriteTimeout + eventWriteTimeout/2):
			t.Fatal("blocked stderr fallback did not return through write and close deadlines")
		}
		output.unblock()
		select {
		case <-output.writeReturned:
		case <-time.After(eventWriteTimeout):
			t.Fatal("released stderr fallback writer did not return")
		}
	})
}

func TestRelayHTTPServerReleasesNonReadingClientAtWriteDeadline(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	tracked := &closeTrackingConn{Conn: serverSide, closed: make(chan struct{})}
	listener := newSingleConnListener(tracked)
	server := newRelayHTTPServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"ok":true}`))
	}))
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	t.Cleanup(func() {
		_ = clientSide.Close()
		_ = server.Close()
		_ = listener.Close()
		select {
		case <-serveDone:
		case <-time.After(time.Second):
			t.Error("HTTP server was not reaped during cleanup")
		}
	})

	writeDone := make(chan error, 1)
	go func() {
		_, err := clientSide.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"))
		writeDone <- err
	}()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("write HTTP request: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not read request within one second")
	}

	deadline := time.NewTimer(pairingWriteTimeout + time.Second)
	defer deadline.Stop()
	select {
	case <-tracked.closed:
	case <-deadline.C:
		t.Fatalf("server retained a non-reading connection beyond write timeout %s", pairingWriteTimeout)
	}
}

func TestBlockedRejectionAuditDoesNotRetainRequestHandlersOrLoggerWorker(t *testing.T) {
	output := newBlockingAfterWriter(0, nil)
	t.Cleanup(output.unblock)
	logger := newEventLogger(output)
	reporter := newFatalRuntimeReporter()
	service, err := newPairingService(t.TempDir(), "", logger, reporter.report)
	if err != nil {
		t.Fatalf("create pairing service: %v", err)
	}

	const callers = 4
	responses := make([]*httptest.ResponseRecorder, callers)
	var handlers sync.WaitGroup
	handlers.Add(callers)
	for index := range callers {
		responses[index] = httptest.NewRecorder()
		go func(response *httptest.ResponseRecorder) {
			defer handlers.Done()
			request := httptest.NewRequest(http.MethodPost, "/v1/pair", strings.NewReader(`{}`))
			request.Header.Set("Content-Type", "application/json")
			service.handlePair(response, request)
		}(responses[index])
	}

	select {
	case <-output.blocked:
	case <-time.After(eventWriteTimeout):
		t.Fatal("audit writer did not enter deterministic blocked state")
	}
	handlersDone := make(chan struct{})
	go func() {
		handlers.Wait()
		close(handlersDone)
	}()
	select {
	case <-handlersDone:
	case <-time.After(eventWriteTimeout + eventWriteTimeout/2):
		t.Fatalf("malformed request handlers remained blocked beyond audit deadline %s", eventWriteTimeout)
	}
	for index, response := range responses {
		if response.Code != http.StatusBadRequest {
			t.Fatalf("response %d status = %d, want 400", index, response.Code)
		}
	}
	select {
	case <-reporter.reported:
		if !errors.Is(reporter.err(), context.DeadlineExceeded) {
			t.Fatalf("fatal audit error = %v, want deadline", reporter.err())
		}
	default:
		t.Fatal("blocked audit deadline did not reach fatal runtime latch")
	}

	if err := logger.close(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("close blocked logger error = %v, want bounded deadline", err)
	}
	output.unblock()
	select {
	case <-output.writeReturned:
	case <-time.After(eventWriteTimeout):
		t.Fatal("released writer did not return")
	}
	select {
	case <-logger.done:
	case <-time.After(eventWriteTimeout):
		t.Fatal("released logger worker was not reaped")
	}
}

func TestAcceptedPairBlockedAuditWinsCancellationAndPreservesIdentity(t *testing.T) {
	stateParent := t.TempDir()
	stateDir := filepath.Join(stateParent, "durable-state")
	codeFile := filepath.Join(stateParent, "pairing-code")
	terminationContext, cancelTermination := context.WithCancel(context.Background())
	defer cancelTermination()
	output := newBlockingAfterWriter(2, cancelTermination)
	t.Cleanup(output.unblock)
	var fallback bytes.Buffer
	runDone := make(chan error, 1)
	go func() {
		runErr := runWithContext(
			[]string{
				"--listen", "127.0.0.1:0",
				"--state-dir", stateDir,
				"--pairing-code-file", codeFile,
			},
			output,
			syncDirectory,
			terminationContext,
		)
		runDone <- reportServerFailure(runErr, &fallback)
	}()

	readEvent := func() logEvent {
		t.Helper()
		select {
		case data := <-output.events:
			var event logEvent
			if err := json.Unmarshal(data, &event); err != nil {
				t.Fatalf("decode server event %q: %v", data, err)
			}
			return event
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for server startup event")
			return logEvent{}
		}
	}
	ready := readEvent()
	if ready.Event != "server_ready" {
		t.Fatalf("first event = %q, want server_ready", ready.Event)
	}
	created := readEvent()
	if created.Event != "pairing_code_created" {
		t.Fatalf("second event = %q, want pairing_code_created", created.Event)
	}
	codeData, err := os.ReadFile(codeFile)
	if err != nil {
		t.Fatalf("read pairing code fixture: %v", err)
	}
	code := strings.TrimSpace(string(codeData))
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate public key fixture: %v", err)
	}
	requestBody, err := json.Marshal(map[string]string{
		"pairing_code":      code,
		"client_public_key": "ed25519:" + base64.StdEncoding.EncodeToString(publicKey),
	})
	if err != nil {
		t.Fatalf("encode pairing request: %v", err)
	}
	type pairResult struct {
		status int
		body   []byte
		err    error
	}
	pairDone := make(chan pairResult, 1)
	go func() {
		response, err := http.Post(
			"http://"+ready.Address+"/v1/pair",
			"application/json",
			bytes.NewReader(requestBody),
		)
		if err != nil {
			pairDone <- pairResult{err: err}
			return
		}
		responseBody, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		pairDone <- pairResult{
			status: response.StatusCode,
			body:   responseBody,
			err:    errors.Join(readErr, closeErr),
		}
	}()
	select {
	case <-output.blocked:
	case <-time.After(eventWriteTimeout):
		t.Fatal("accepted audit writer did not enter deterministic blocked state")
	}
	var paired pairResult
	select {
	case paired = <-pairDone:
	case <-time.After(eventWriteTimeout + pairingWriteTimeout):
		t.Fatal("accepted handler did not settle after audit deadline")
	}
	if paired.err != nil {
		t.Fatalf("submit/read accepted response: %v", paired.err)
	}
	if paired.status != http.StatusCreated {
		t.Fatalf("pair status = %d, want 201; body: %s", paired.status, paired.body)
	}
	var accepted pairResponse
	if err := json.Unmarshal(paired.body, &accepted); err != nil {
		t.Fatalf("decode accepted identity: %v", err)
	}

	select {
	case runErr := <-runDone:
		if !errors.Is(runErr, context.DeadlineExceeded) {
			t.Fatalf("run error = %v, want blocked audit deadline", runErr)
		}
	case <-time.After(shutdownTimeout + 2*eventWriteTimeout):
		t.Fatal("server did not complete bounded fatal runtime shutdown")
	}
	output.unblock()
	select {
	case <-output.writeReturned:
	case <-time.After(eventWriteTimeout):
		t.Fatal("released accepted-audit writer did not return")
	}

	allowlistData, err := os.ReadFile(filepath.Join(stateDir, allowlistFilename))
	if err != nil {
		t.Fatalf("read durable allowlist after audit failure: %v", err)
	}
	var stored allowlist
	if err := json.Unmarshal(allowlistData, &stored); err != nil {
		t.Fatalf("decode durable allowlist: %v", err)
	}
	if len(stored.Clients) != 1 || stored.Clients[0].ClientID != accepted.ClientID {
		t.Fatalf("durable identity = %+v, accepted identity = %q", stored.Clients, accepted.ClientID)
	}
	if !strings.Contains(fallback.String(), `"event":"server_failed"`) ||
		!strings.Contains(fallback.String(), "write pair_accepted pairing audit event") {
		t.Fatalf("stderr fallback lacks fatal audit context: %s", fallback.String())
	}
	if _, err := os.Stat(codeFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pairing code channel remains after durable acceptance: %v", err)
	}
	connection, err := net.DialTimeout("tcp", ready.Address, 100*time.Millisecond)
	if err == nil {
		_ = connection.Close()
		t.Fatal("server still accepts connections after fatal audit failure")
	}
}

func TestOneShotAcceptedAuditFailureCannotBeMaskedByCancellation(t *testing.T) {
	stateParent := t.TempDir()
	stateDir := filepath.Join(stateParent, "durable-state")
	codeFile := filepath.Join(stateParent, "pairing-code")
	auditFailure := errors.New("one-shot pair_accepted audit failure")
	terminationContext, cancelTermination := context.WithCancel(context.Background())
	defer cancelTermination()
	output := &failOnceAfterWriter{
		failWrite: 3,
		failure:   auditFailure,
		onFailure: cancelTermination,
		events:    make(chan []byte, 4),
	}
	var fallback bytes.Buffer
	runDone := make(chan error, 1)
	go func() {
		runErr := runWithContext(
			[]string{
				"--listen", "127.0.0.1:0",
				"--state-dir", stateDir,
				"--pairing-code-file", codeFile,
			},
			output,
			syncDirectory,
			terminationContext,
		)
		runDone <- reportServerFailure(runErr, &fallback)
	}()

	readEvent := func() logEvent {
		t.Helper()
		select {
		case data := <-output.events:
			var event logEvent
			if err := json.Unmarshal(data, &event); err != nil {
				t.Fatalf("decode server event %q: %v", data, err)
			}
			return event
		case <-time.After(eventWriteTimeout):
			t.Fatal("timed out waiting for server startup event")
			return logEvent{}
		}
	}
	ready := readEvent()
	if ready.Event != "server_ready" {
		t.Fatalf("first event = %q, want server_ready", ready.Event)
	}
	if created := readEvent(); created.Event != "pairing_code_created" {
		t.Fatalf("second event = %q, want pairing_code_created", created.Event)
	}
	codeData, err := os.ReadFile(codeFile)
	if err != nil {
		t.Fatalf("read pairing code fixture: %v", err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate public key fixture: %v", err)
	}
	requestBody, err := json.Marshal(map[string]string{
		"pairing_code":      strings.TrimSpace(string(codeData)),
		"client_public_key": "ed25519:" + base64.StdEncoding.EncodeToString(publicKey),
	})
	if err != nil {
		t.Fatalf("encode pairing request: %v", err)
	}
	response, err := http.Post(
		"http://"+ready.Address+"/v1/pair",
		"application/json",
		bytes.NewReader(requestBody),
	)
	if err != nil {
		t.Fatalf("submit pairing request: %v", err)
	}
	responseBody, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		t.Fatalf("read accepted response: %v", err)
	}
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("pair status = %d, want 201; body: %s", response.StatusCode, responseBody)
	}
	var accepted pairResponse
	if err := json.Unmarshal(responseBody, &accepted); err != nil {
		t.Fatalf("decode accepted identity: %v", err)
	}

	select {
	case runErr := <-runDone:
		if !errors.Is(runErr, auditFailure) {
			t.Fatalf("cancellation-masked run error = %v, want one-shot audit failure", runErr)
		}
	case <-time.After(shutdownTimeout + eventWriteTimeout):
		t.Fatal("server did not settle one-shot audit/cancellation race")
	}
	if !strings.Contains(fallback.String(), `"event":"server_failed"`) ||
		!strings.Contains(fallback.String(), auditFailure.Error()) {
		t.Fatalf("stderr fallback lacks one-shot audit failure: %s", fallback.String())
	}
	allowlistData, err := os.ReadFile(filepath.Join(stateDir, allowlistFilename))
	if err != nil {
		t.Fatalf("read durable allowlist: %v", err)
	}
	var stored allowlist
	if err := json.Unmarshal(allowlistData, &stored); err != nil {
		t.Fatalf("decode durable allowlist: %v", err)
	}
	if len(stored.Clients) != 1 || stored.Clients[0].ClientID != accepted.ClientID {
		t.Fatalf("durable identity = %+v, accepted identity = %q", stored.Clients, accepted.ClientID)
	}
	select {
	case data := <-output.events:
		var event logEvent
		if err := json.Unmarshal(data, &event); err != nil {
			t.Fatalf("decode unexpected terminal event: %v", err)
		}
		if event.Event == "server_stopped" {
			t.Fatal("one-shot audit failure was masked by successful server_stopped")
		}
	default:
	}
}

func TestRunPreservesPrimaryAndFallbackCleanupFailures(t *testing.T) {
	stateParent := t.TempDir()
	movedStateParent := filepath.Join(t.TempDir(), "state-parent")
	t.Setenv("TMPDIR", stateParent)
	t.Setenv("TMP", stateParent)
	t.Setenv("TEMP", stateParent)

	primaryErr := errors.New("readiness output failed")
	var sabotageErr error
	sabotaged := false
	restoreStateParent := func() error {
		if !sabotaged {
			return nil
		}
		if err := os.Remove(stateParent); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Rename(movedStateParent, stateParent); err != nil {
			return err
		}
		sabotaged = false
		return nil
	}
	t.Cleanup(func() {
		if err := restoreStateParent(); err != nil {
			t.Errorf("restore test state parent: %v", err)
		}
	})

	output := writerFunc(func([]byte) (int, error) {
		if err := os.Rename(stateParent, movedStateParent); err != nil {
			sabotageErr = err
			return 0, err
		}
		sabotaged = true
		if err := os.WriteFile(stateParent, []byte("blocks child removal"), 0o600); err != nil {
			sabotageErr = err
			return 0, err
		}
		return 0, primaryErr
	})

	runErr := run(nil, output)
	if err := restoreStateParent(); err != nil {
		t.Fatalf("restore test state parent: %v", err)
	}
	if sabotageErr != nil {
		t.Fatalf("arrange cleanup failure: %v", sabotageErr)
	}
	if !errors.Is(runErr, primaryErr) {
		t.Fatalf("run error does not preserve primary failure: %v", runErr)
	}
	if !strings.Contains(runErr.Error(), "report readiness: readiness output failed") {
		t.Fatalf("run error lacks actionable primary context: %v", runErr)
	}
	if !strings.Contains(runErr.Error(), "remove temporary state directory:") {
		t.Fatalf("run error lacks fallback cleanup failure: %v", runErr)
	}
}
