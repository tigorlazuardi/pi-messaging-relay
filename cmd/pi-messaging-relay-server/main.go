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
	"strconv"
	"syscall"
	"time"
)

const (
	defaultListenAddress = "127.0.0.1:0"
	shutdownTimeout      = 5 * time.Second
)

type logEvent struct {
	Level    string `json:"level"`
	Event    string `json:"event"`
	Address  string `json:"address,omitempty"`
	StateDir string `json:"state_dir,omitempty"`
	Result   string `json:"result,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		writeEvent(os.Stderr, logEvent{
			Level:  "error",
			Event:  "server_failed",
			Reason: err.Error(),
		})
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) (runErr error) {
	flags := flag.NewFlagSet("pi-messaging-relay-server", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	listenAddress := flags.String("listen", defaultListenAddress, "loopback IP and port to listen on")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if err := validateListenAddress(*listenAddress); err != nil {
		return err
	}

	signalContext, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	stateDir, err := os.MkdirTemp("", "pi-messaging-relay-")
	if err != nil {
		return fmt.Errorf("create temporary state directory: %w", err)
	}
	stateCleanupAttempted := false
	defer func() {
		if stateCleanupAttempted {
			return
		}
		if err := os.RemoveAll(stateDir); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("remove temporary state directory: %w", err))
		}
	}()

	listener, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()

	server := &http.Server{
		Handler:           http.NotFoundHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	serveResult := make(chan error, 1)
	go func() {
		err := server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveResult <- err
	}()

	selectedAddress := listener.Addr().String()
	if err := writeEvent(output, logEvent{
		Level:    "info",
		Event:    "server_ready",
		Address:  selectedAddress,
		StateDir: stateDir,
	}); err != nil {
		_ = server.Close()
		<-serveResult
		return fmt.Errorf("report readiness: %w", err)
	}

	select {
	case err := <-serveResult:
		if err != nil {
			return fmt.Errorf("serve: %w", err)
		}
		return errors.New("server stopped before a termination signal")
	case <-signalContext.Done():
	}

	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancelShutdown()
	if err := server.Shutdown(shutdownContext); err != nil {
		_ = server.Close()
		<-serveResult
		return fmt.Errorf("shut down server: %w", err)
	}
	if err := <-serveResult; err != nil {
		return fmt.Errorf("serve during shutdown: %w", err)
	}
	stateCleanupAttempted = true
	if err := os.RemoveAll(stateDir); err != nil {
		return fmt.Errorf("remove temporary state directory: %w", err)
	}

	if err := writeEvent(output, logEvent{
		Level:   "info",
		Event:   "server_stopped",
		Address: selectedAddress,
		Result:  "graceful",
	}); err != nil {
		return fmt.Errorf("report shutdown: %w", err)
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
	return json.NewEncoder(output).Encode(event)
}
