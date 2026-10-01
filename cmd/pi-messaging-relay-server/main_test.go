package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
		failWrite: 2,
		failure:   auditFailure,
		onFailure: cancelTermination,
		events:    make(chan []byte, 4),
	}
	var fallback bytes.Buffer
	runDone := make(chan error, 1)
	go func() {
		runErr := runWithContext(nil, output, syncOpenedDirectory, terminationContext)
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
	if ready.Auth != authModeOff {
		t.Fatalf("server_ready auth = %q, want off", ready.Auth)
	}

	dialContext, cancelDial := context.WithTimeout(context.Background(), time.Second)
	defer cancelDial()
	connection, _, err := websocket.Dial(dialContext, "ws://"+ready.Address+"/v1/connect", nil)
	if err != nil {
		t.Fatalf("dial auth audit fixture: %v", err)
	}
	t.Cleanup(func() { _ = connection.CloseNow() })
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
		!strings.Contains(failureOutput, "write auth_rejected session audit event") {
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
		func(directory *os.File) error {
			syncedPath = directory.Name()
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
	if _, err := os.Stat(stateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state directory remains after parent-sync startup failure: %v", err)
	}
}

func TestDurableStateDirectoryRejectsUnsafeExistingPaths(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		setup func(t *testing.T, parent string) string
	}{
		{
			name: "permissive directory",
			setup: func(t *testing.T, parent string) string {
				t.Helper()
				path := filepath.Join(parent, "permissive")
				if err := os.Mkdir(path, 0o755); err != nil {
					t.Fatalf("create permissive directory: %v", err)
				}
				return path
			},
		},
		{
			name: "regular file",
			setup: func(t *testing.T, parent string) string {
				t.Helper()
				path := filepath.Join(parent, "regular-file")
				if err := os.WriteFile(path, nil, 0o700); err != nil {
					t.Fatalf("create regular file: %v", err)
				}
				return path
			},
		},
		{
			name: "symbolic link",
			setup: func(t *testing.T, parent string) string {
				t.Helper()
				target := filepath.Join(parent, "target")
				if err := os.Mkdir(target, 0o700); err != nil {
					t.Fatalf("create symlink target: %v", err)
				}
				path := filepath.Join(parent, "state-link")
				if err := os.Symlink(target, path); err != nil {
					t.Fatalf("create state symlink: %v", err)
				}
				return path
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			path := testCase.setup(t, t.TempDir())
			if _, err := prepareStateDirectoryWithSync(path, syncOpenedDirectory); err == nil {
				t.Fatal("unsafe durable state path was accepted")
			}
		})
	}
}

func TestBlockedStartupEventAndFailureFallbackRemainBounded(t *testing.T) {
	t.Run("startup stdout", func(t *testing.T) {
		output := newBlockingAfterWriter(0, nil)
		t.Cleanup(output.unblock)
		runDone := make(chan error, 1)
		go func() {
			runDone <- runWithContext(nil, output, syncOpenedDirectory, context.Background())
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
		writeUpgradeUnauthorized(response)
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
		_, err := clientSide.Write([]byte("GET /v1/connect HTTP/1.1\r\nHost: localhost\r\n\r\n"))
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

	deadline := time.NewTimer(httpResponseWriteTimeout + time.Second)
	defer deadline.Stop()
	select {
	case <-tracked.closed:
	case <-deadline.C:
		t.Fatalf("server retained a non-reading client beyond the 401 write timeout %s", httpResponseWriteTimeout)
	}
}

func TestBlockedRejectionAuditDoesNotRetainRequestHandlersOrLoggerWorker(t *testing.T) {
	output := newBlockingAfterWriter(0, nil)
	t.Cleanup(output.unblock)
	logger := newEventLogger(output)
	reporter := newFatalRuntimeReporter()
	registry := newSessionConnectionRegistry()
	service := newSessionAuthService(testSecret, registry, logger, reporter.report)

	const callers = 4
	responses := make([]*httptest.ResponseRecorder, callers)
	var handlers sync.WaitGroup
	handlers.Add(callers)
	for index := range callers {
		responses[index] = httptest.NewRecorder()
		go func(response *httptest.ResponseRecorder) {
			defer handlers.Done()
			request := httptest.NewRequest(http.MethodGet, "/v1/connect", nil)
			service.handleConnect(response, request)
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
		t.Fatalf("unauthorized handlers remained blocked beyond audit deadline %s", eventWriteTimeout)
	}
	for index, response := range responses {
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("response %d status = %d, want 401", index, response.Code)
		}
		if got := response.Header().Get("WWW-Authenticate"); got != "Bearer" {
			t.Fatalf("response %d www-authenticate = %q", index, got)
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
	if len(registry.entries) != 0 {
		t.Fatalf("rejected authorizations consumed tracked capacity: %d entries", len(registry.entries))
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

func TestRunRetainedTemporaryParentDefeatsPathReplacementDuringCleanup(t *testing.T) {
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
	remaining, readErr := os.ReadDir(movedStateParent)
	if readErr != nil {
		t.Fatalf("inspect retained temporary parent: %v", readErr)
	}
	if len(remaining) != 0 {
		t.Fatalf("retained parent still contains temporary state: %v", remaining)
	}
	if err := restoreStateParent(); err != nil {
		t.Fatalf("restore test state parent: %v", err)
	}
	if sabotageErr != nil {
		t.Fatalf("arrange cleanup failure: %v", sabotageErr)
	}
	if !errors.Is(runErr, primaryErr) {
		t.Fatalf("run error does not preserve primary failure: %v", runErr)
	}
	if runErr.Error() != "report readiness: readiness output failed" {
		t.Fatalf("run error includes unexpected cleanup failure: %v", runErr)
	}
}
