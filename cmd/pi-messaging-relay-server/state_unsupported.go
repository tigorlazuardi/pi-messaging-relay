//go:build !linux

package main

import (
	"errors"
	"os"
)

var errUnsupportedServerPlatform = errors.New("pi-messaging-relay-server supports Linux only")

func requireSupportedPlatform() error {
	return errUnsupportedServerPlatform
}

func terminationSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}

func syncOpenedDirectory(*os.File) error {
	return errUnsupportedServerPlatform
}

func prepareStateDirectoryWithSync(string, directorySync) (*stateDirectory, error) {
	return nil, errUnsupportedServerPlatform
}

func (state *stateDirectory) openAllowlist() (*os.File, int64, error) {
	return nil, 0, errUnsupportedServerPlatform
}

func (state *stateDirectory) persistAllowlistData([]byte) error {
	return errUnsupportedServerPlatform
}

func (state *stateDirectory) writePairingCodeFile(string, string) (func() error, error) {
	return nil, errUnsupportedServerPlatform
}

func (state *stateDirectory) removeTemporaryState() error {
	return errUnsupportedServerPlatform
}
