// Command pi-messaging-relay-server runs the localhost Pi messaging relay.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const (
	defaultListenAddress = "127.0.0.1:0"
	shutdownTimeout      = 5 * time.Second
	pairingWriteTimeout  = 2 * time.Second
	eventWriteTimeout    = 1 * time.Second
	redacted             = "<redacted>"
)

type logEvent struct {
	Level           string `json:"level"`
	Event           string `json:"event"`
	Address         string `json:"address,omitempty"`
	StateDir        string `json:"state_dir,omitempty"`
	Result          string `json:"result,omitempty"`
	Reason          string `json:"reason,omitempty"`
	Code            string `json:"code,omitempty"`
	Type            string `json:"type,omitempty"`
	RequestID       string `json:"request_id,omitempty"`
	PairingCode     string `json:"pairing_code,omitempty"`
	PrivateKey      string `json:"private_key,omitempty"`
	ClientPublicKey string `json:"client_public_key,omitempty"`
	ClientID        string `json:"client_id,omitempty"`
	RouteID         string `json:"route_id,omitempty"`
	Hostname        string `json:"hostname,omitempty"`
	CWD             string `json:"cwd,omitempty"`
	Nonce           string `json:"nonce,omitempty"`
	Signature       string `json:"signature,omitempty"`
	ExpiresAt       string `json:"expires_at,omitempty"`
	LatencyMS       *int64 `json:"latency_ms,omitempty"`
}

type eventWriteRequest struct {
	event  logEvent
	result chan error
}

type eventLogger struct {
	requests  chan eventWriteRequest
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func newEventLogger(output io.Writer) *eventLogger {
	logger := &eventLogger{
		requests: make(chan eventWriteRequest),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go logger.run(output)
	return logger
}

func (logger *eventLogger) run(output io.Writer) {
	defer close(logger.done)
	for {
		select {
		case <-logger.stop:
			return
		case request := <-logger.requests:
			request.result <- writeEvent(output, request.event)
		}
	}
}

func (logger *eventLogger) write(event logEvent) error {
	request := eventWriteRequest{event: event, result: make(chan error, 1)}
	timer := time.NewTimer(eventWriteTimeout)
	defer timer.Stop()
	select {
	case logger.requests <- request:
	case <-logger.stop:
		return errors.New("event logger is closed")
	case <-timer.C:
		return fmt.Errorf("handoff %s event within %s: %w", event.Event, eventWriteTimeout, context.DeadlineExceeded)
	}
	select {
	case err := <-request.result:
		return err
	case <-logger.stop:
		return errors.New("event logger closed before write acknowledgement")
	case <-timer.C:
		return fmt.Errorf("write %s event within %s: %w", event.Event, eventWriteTimeout, context.DeadlineExceeded)
	}
}

func (logger *eventLogger) close() error {
	logger.closeOnce.Do(func() { close(logger.stop) })
	timer := time.NewTimer(eventWriteTimeout)
	defer timer.Stop()
	select {
	case <-logger.done:
		return nil
	case <-timer.C:
		return fmt.Errorf("stop event logger worker within %s: %w", eventWriteTimeout, context.DeadlineExceeded)
	}
}

func main() {
	if err := runAndReport(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		os.Exit(1)
	}
}

func runAndReport(args []string, output, errorOutput io.Writer) error {
	return reportServerFailure(run(args, output), errorOutput)
}

func reportServerFailure(runErr error, errorOutput io.Writer) error {
	if runErr == nil {
		return nil
	}
	fallback := newEventLogger(errorOutput)
	writeErr := fallback.write(logEvent{
		Level:  "error",
		Event:  "server_failed",
		Reason: runErr.Error(),
	})
	closeErr := fallback.close()
	if writeErr != nil {
		writeErr = fmt.Errorf("report server failure on stderr: %w", writeErr)
	}
	if closeErr != nil {
		closeErr = fmt.Errorf("close stderr event logger: %w", closeErr)
	}
	return errors.Join(runErr, writeErr, closeErr)
}

type fatalRuntimeReporter struct {
	once     sync.Once
	mu       sync.RWMutex
	failure  error
	reported chan struct{}
}

func newFatalRuntimeReporter() *fatalRuntimeReporter {
	return &fatalRuntimeReporter{reported: make(chan struct{})}
}

func (reporter *fatalRuntimeReporter) report(err error) {
	if err == nil {
		return
	}
	reporter.once.Do(func() {
		reporter.mu.Lock()
		reporter.failure = err
		reporter.mu.Unlock()
		close(reporter.reported)
	})
}

func (reporter *fatalRuntimeReporter) err() error {
	reporter.mu.RLock()
	defer reporter.mu.RUnlock()
	return reporter.failure
}

func run(args []string, output io.Writer) error {
	signalContext, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	return runWithContext(args, output, syncDirectory, signalContext)
}

func runWithContext(
	args []string,
	output io.Writer,
	syncStateDirectoryParent func(string) error,
	terminationContext context.Context,
) (runErr error) {
	flags := flag.NewFlagSet("pi-messaging-relay-server", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	listenAddress := flags.String("listen", defaultListenAddress, "loopback IP and port to listen on")
	configuredStateDir := flags.String("state-dir", "", "durable state directory; empty uses temporary process state")
	pairingCodeFile := flags.String("pairing-code-file", "", "operator-only file to create with the startup pairing code")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if err := validateListenAddress(*listenAddress); err != nil {
		return err
	}

	stateDir, temporaryState, err := prepareStateDirectoryWithSync(*configuredStateDir, syncStateDirectoryParent)
	if err != nil {
		return err
	}
	stateCleanupAttempted := false
	defer func() {
		if !temporaryState || stateCleanupAttempted {
			return
		}
		if err := os.RemoveAll(stateDir); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("remove temporary state directory: %w", err))
		}
	}()

	logger := newEventLogger(output)
	defer func() {
		if err := logger.close(); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("close stdout event logger: %w", err))
		}
	}()
	runtimeFailures := newFatalRuntimeReporter()
	pairing, err := newPairingService(stateDir, *pairingCodeFile, logger, runtimeFailures.report)
	if err != nil {
		return err
	}
	defer func() {
		if err := pairing.closeCodeChannel(); err != nil {
			runErr = errors.Join(runErr, err)
		}
	}()
	connections := newSessionConnectionRegistry()
	connectionsClosed := false
	defer func() {
		if connectionsClosed {
			return
		}
		closeContext, cancelClose := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancelClose()
		if err := connections.closeAndWait(closeContext); err != nil {
			runErr = errors.Join(runErr, err)
		}
	}()
	authentication := newSessionAuthService(pairing, connections, logger, runtimeFailures.report)

	listener, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pair", pairing.handlePair)
	mux.HandleFunc("/v1/connect", authentication.handleConnect)
	server := newRelayHTTPServer(mux)
	serveResult := make(chan error, 1)
	go func() {
		err := server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveResult <- err
	}()

	selectedAddress := listener.Addr().String()
	if err := logger.write(logEvent{
		Level:    "info",
		Event:    "server_ready",
		Address:  selectedAddress,
		StateDir: stateDir,
	}); err != nil {
		_ = server.Close()
		<-serveResult
		return fmt.Errorf("report readiness: %w", err)
	}
	if err := logger.write(logEvent{
		Level:       "info",
		Event:       "pairing_code_created",
		PairingCode: redacted,
		PrivateKey:  redacted,
		ExpiresAt:   pairing.expiresAt.UTC().Format(time.RFC3339Nano),
	}); err != nil {
		_ = server.Close()
		<-serveResult
		return fmt.Errorf("report pairing code creation: %w", err)
	}

	var terminalErr error
	select {
	case err := <-serveResult:
		if err != nil {
			return fmt.Errorf("serve: %w", err)
		}
		return errors.New("server stopped before a termination signal")
	case <-runtimeFailures.reported:
		terminalErr = fmt.Errorf("fatal relay runtime failure: %w", runtimeFailures.err())
	case <-terminationContext.Done():
	}

	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancelShutdown()
	if err := server.Shutdown(shutdownContext); err != nil {
		_ = server.Close()
		<-serveResult
		return errors.Join(terminalErr, fmt.Errorf("shut down server: %w", err))
	}
	if err := <-serveResult; err != nil {
		return errors.Join(terminalErr, fmt.Errorf("serve during shutdown: %w", err))
	}
	if err := connections.closeAndWait(shutdownContext); err != nil {
		return errors.Join(terminalErr, err)
	}
	connectionsClosed = true
	if temporaryState {
		stateCleanupAttempted = true
		if err := os.RemoveAll(stateDir); err != nil {
			return errors.Join(terminalErr, fmt.Errorf("remove temporary state directory: %w", err))
		}
	}
	if fatalErr := runtimeFailures.err(); fatalErr != nil {
		terminalErr = fmt.Errorf("fatal relay runtime failure: %w", fatalErr)
	}
	if terminalErr != nil {
		return terminalErr
	}

	if err := logger.write(logEvent{
		Level:   "info",
		Event:   "server_stopped",
		Address: selectedAddress,
		Result:  "graceful",
	}); err != nil {
		return fmt.Errorf("report shutdown: %w", err)
	}
	return nil
}

func newRelayHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      pairingWriteTimeout,
		IdleTimeout:       30 * time.Second,
	}
}

func prepareStateDirectoryWithSync(
	configured string,
	syncStateDirectoryParent func(string) error,
) (path string, temporary bool, err error) {
	if configured == "" {
		path, err := os.MkdirTemp("", "pi-messaging-relay-")
		if err != nil {
			return "", false, fmt.Errorf("create temporary state directory: %w", err)
		}
		return path, true, nil
	}
	created := false
	if err := os.Mkdir(configured, 0o700); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return "", false, fmt.Errorf("create durable state directory: %w", err)
		}
	} else {
		created = true
	}
	info, err := os.Lstat(configured)
	if err != nil {
		return "", false, fmt.Errorf("inspect durable state directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		return "", false, errors.New("durable state directory must be a directory with permissions 0700")
	}
	if created {
		if err := syncStateDirectoryParent(filepath.Dir(configured)); err != nil {
			return "", false, fmt.Errorf("sync durable state directory parent: %w", err)
		}
	}
	return configured, false, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return err
	}
	return nil
}

func validateListenAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("listen address must be a loopback IP literal and numeric port")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("listen address must use a loopback IP literal")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 0 || portNumber > 65535 {
		return errors.New("listen address must use a numeric port from 0 through 65535")
	}
	return nil
}

func writeEvent(output io.Writer, event logEvent) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(event)
}
