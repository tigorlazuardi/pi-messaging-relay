package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const (
	// ponytail: fixed ceilings per the accepted online relay auth v2 page; make them
	// configurable only when a second deployment profile exists.
	maxSecretBytes              = 512
	maxSecretFileReadBytes      = 4096
	maxAuthorizationHeaderValue = 4096
	authModeOff                 = "off"
	authModeSecret              = "secret"
	asciiWhitespace             = " \t\n\r\v\f"
)

// loadServerSecret reads the v2 shared secret from one configured direct state-directory
// child. An empty configured path selects authentication off. A configured path that is
// missing, unsafe, unreadable, or out of bounds fails startup before readiness; a broken
// secret never degrades to authentication off. Rotation is one restart.
func loadServerSecret(state *stateDirectory, configured string) (string, error) {
	if configured == "" {
		return "", nil
	}
	name, err := directSecretFilename(state, configured)
	if err != nil {
		return "", err
	}
	file, size, err := state.openStateChild(name)
	if err != nil {
		return "", fmt.Errorf("open server secret file: %w", err)
	}
	if size > maxSecretFileReadBytes {
		_ = file.Close()
		return "", errors.New("server secret file exceeds 4096 bytes")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxSecretFileReadBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return "", errors.Join(
			wrapError("read server secret file", readErr),
			wrapError("close server secret file", closeErr),
		)
	}
	if len(data) > maxSecretFileReadBytes {
		return "", errors.New("server secret file exceeds 4096 bytes")
	}
	if !utf8.Valid(data) {
		return "", errors.New("server secret file must be valid UTF-8")
	}
	if strings.IndexByte(string(data), 0) >= 0 {
		return "", errors.New("server secret file must not contain a NUL byte")
	}
	secret := strings.Trim(string(data), asciiWhitespace)
	if len(secret) < 1 || len(secret) > maxSecretBytes {
		return "", fmt.Errorf("server secret must be 1 through %d UTF-8 bytes after trimming", maxSecretBytes)
	}
	return secret, nil
}

// directSecretFilename validates that the configured path names exactly one direct child
// of the retained state directory: the state root itself, external parents, traversal,
// and empty components fail before any descriptor-relative open.
func directSecretFilename(state *stateDirectory, configured string) (string, error) {
	if state == nil || state.directory == nil {
		return "", errors.New("server secret requires an opened state directory")
	}
	for _, component := range strings.Split(filepath.ToSlash(configured), "/") {
		if component == ".." {
			return "", errors.New("secret file must be a direct child of the state directory")
		}
	}
	absolute, err := filepath.Abs(configured)
	if err != nil {
		return "", fmt.Errorf("resolve secret file: %w", err)
	}
	cleaned := filepath.Clean(absolute)
	name := filepath.Base(cleaned)
	if filepath.Clean(filepath.Dir(cleaned)) != state.path ||
		filepath.Base(name) != name || name == "." || name == ".." || name == "" ||
		strings.IndexByte(name, 0) >= 0 {
		return "", errors.New("secret file must be a direct child of the state directory")
	}
	return name, nil
}

// equalSecret compares two secret-bearing values in constant time; only the value
// lengths are observable.
func equalSecret(expected, received string) bool {
	if len(expected) != len(received) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(received)) == 1
}

func wrapError(context string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", context, err)
}

func randomToken(size int) (string, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}
