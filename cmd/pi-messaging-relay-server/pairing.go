package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	pairingCodeLifetime = 10 * time.Minute
	maxPairRequestBytes = 4096
	// ponytail: fixed to 1 MiB; make configurable when a second deployment profile needs more paired installations.
	maxAllowlistBytes = 1 << 20
	allowlistFilename = "allowlist.json"
)

var (
	errPairingCodeInvalid = errors.New("pairing code is invalid or expired")
	errAllowlistTooLarge  = errors.New("allowlist exceeds 1 MiB")
)

type pairingService struct {
	mu             sync.Mutex
	code           string
	expiresAt      time.Time
	now            func() time.Time
	state          *stateDirectory
	allowlist      allowlist
	logger         *eventLogger
	reportFatal    func(error)
	removeCodeFile func() error
}

type pairRequest struct {
	PairingCode     string
	ClientPublicKey string
}

type pairResponse struct {
	ClientID string `json:"client_id"`
}

type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

type allowlist struct {
	Version int               `json:"version"`
	Clients []allowlistClient `json:"clients"`
}

type allowlistClient struct {
	ClientID  string `json:"client_id"`
	PublicKey string `json:"client_public_key"`
	PairedAt  string `json:"paired_at"`
}

func newPairingService(
	state *stateDirectory,
	codeFilePath string,
	logger *eventLogger,
	reportFatal func(error),
) (*pairingService, error) {
	return newPairingServiceWithClock(state, codeFilePath, logger, reportFatal, time.Now)
}

func newPairingServiceWithClock(
	state *stateDirectory,
	codeFilePath string,
	logger *eventLogger,
	reportFatal func(error),
	now func() time.Time,
) (*pairingService, error) {
	return newPairingServiceWithClockAndToken(state, codeFilePath, logger, reportFatal, now, randomToken)
}

func newPairingServiceWithClockAndToken(
	state *stateDirectory,
	codeFilePath string,
	logger *eventLogger,
	reportFatal func(error),
	now func() time.Time,
	generateToken func(int) (string, error),
) (*pairingService, error) {
	if state == nil || state.directory == nil {
		return nil, errors.New("pairing service requires an opened state directory")
	}
	if reportFatal == nil {
		return nil, errors.New("pairing service requires a fatal runtime reporter")
	}
	if now == nil {
		return nil, errors.New("pairing service requires a clock")
	}
	if generateToken == nil {
		return nil, errors.New("pairing service requires a token generator")
	}
	codeFilename, err := directPairingCodeFilename(state, codeFilePath)
	if err != nil {
		return nil, err
	}
	stored, err := loadAllowlist(state)
	if err != nil {
		return nil, err
	}
	code, err := generateToken(24)
	if err != nil {
		return nil, fmt.Errorf("generate pairing code: %w", err)
	}

	service := &pairingService{
		code:        code,
		expiresAt:   now().Add(pairingCodeLifetime),
		now:         now,
		state:       state,
		allowlist:   stored,
		logger:      logger,
		reportFatal: reportFatal,
	}
	if codeFilename != "" {
		cleanup, err := state.writePairingCodeFile(codeFilename, code)
		if err != nil {
			return nil, err
		}
		service.removeCodeFile = cleanup
	}
	return service, nil
}

func directPairingCodeFilename(state *stateDirectory, configured string) (string, error) {
	if configured == "" {
		return "", nil
	}
	for _, component := range strings.Split(filepath.ToSlash(configured), "/") {
		if component == ".." {
			return "", errors.New("pairing code file must be a direct child of the state directory")
		}
	}
	absolute, err := filepath.Abs(configured)
	if err != nil {
		return "", fmt.Errorf("resolve pairing code file: %w", err)
	}
	cleaned := filepath.Clean(absolute)
	name := filepath.Base(cleaned)
	if filepath.Clean(filepath.Dir(cleaned)) != state.path ||
		filepath.Base(name) != name || name == "." || name == ".." || name == "" || strings.IndexByte(name, 0) >= 0 {
		return "", errors.New("pairing code file must be a direct child of the state directory")
	}
	if name == allowlistFilename {
		return "", errors.New("pairing code file must not be the allowlist file")
	}
	return name, nil
}

func (service *pairingService) closeCodeChannel() error {
	service.mu.Lock()
	defer service.mu.Unlock()
	return service.closeCodeChannelLocked()
}

func (service *pairingService) closeCodeChannelLocked() error {
	if service.removeCodeFile == nil {
		return nil
	}
	cleanup := service.removeCodeFile
	if err := cleanup(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove pairing code file: %w", err)
	}
	service.removeCodeFile = nil
	return nil
}

func (service *pairingService) handlePair(response http.ResponseWriter, request *http.Request) {
	started := time.Now()
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		writeJSON(response, http.StatusMethodNotAllowed, errorResponse{
			Error:   "method_not_allowed",
			Message: "Use POST /v1/pair",
		})
		return
	}

	input, err := decodePairRequest(response, request)
	if err != nil {
		service.logPairFailure("invalid_request", started, "")
		writeJSON(response, http.StatusBadRequest, errorResponse{
			Error:   "invalid_request",
			Message: "Pairing request must be a closed JSON object with pairing_code and client_public_key",
		})
		return
	}
	if err := validateEd25519PublicKey(input.ClientPublicKey); err != nil {
		service.logPairFailure("invalid_client_public_key", started, "")
		writeJSON(response, http.StatusBadRequest, errorResponse{
			Error:   "invalid_client_public_key",
			Message: "client_public_key must be an Ed25519 public key encoded as ed25519:<base64>",
		})
		return
	}

	clientID, err := service.accept(input, service.now())
	if errors.Is(err, errPairingCodeInvalid) {
		service.logPairFailure("pairing_code_invalid", started, input.ClientPublicKey)
		writeJSON(response, http.StatusUnauthorized, errorResponse{
			Error:   "pairing_code_invalid",
			Message: "Pairing code is invalid or expired",
		})
		return
	}
	if err != nil {
		service.logPairFailure("persistence_failed", started, input.ClientPublicKey)
		writeJSON(response, http.StatusInternalServerError, errorResponse{
			Error:   "pairing_unavailable",
			Message: "Pairing could not be persisted; check relay state permissions and retry",
		})
		return
	}

	service.writeAudit(logEvent{
		Level:           "info",
		Event:           "pair_accepted",
		Result:          "accepted",
		PairingCode:     redacted,
		PrivateKey:      redacted,
		ClientPublicKey: input.ClientPublicKey,
		ClientID:        clientID,
		LatencyMS:       latencySince(started),
	})
	writeJSON(response, http.StatusCreated, pairResponse{ClientID: clientID})
}

func (service *pairingService) accept(input pairRequest, now time.Time) (string, error) {
	service.mu.Lock()
	defer service.mu.Unlock()

	if service.code == "" || !now.Before(service.expiresAt) || !equalSecret(service.code, input.PairingCode) {
		return "", errPairingCodeInvalid
	}
	clientIDToken, err := randomToken(12)
	if err != nil {
		return "", fmt.Errorf("generate client id: %w", err)
	}
	clientID := "cli_" + clientIDToken
	for _, client := range service.allowlist.Clients {
		if client.PublicKey == input.ClientPublicKey {
			return "", errors.New("client public key is already allowlisted")
		}
		if client.ClientID == clientID {
			return "", errors.New("generated client id collides with existing identity")
		}
	}
	next := allowlist{
		Version: service.allowlist.Version,
		Clients: append(append([]allowlistClient(nil), service.allowlist.Clients...), allowlistClient{
			ClientID:  clientID,
			PublicKey: input.ClientPublicKey,
			PairedAt:  now.UTC().Format(time.RFC3339Nano),
		}),
	}
	if err := persistAllowlist(service.state, next); err != nil {
		return "", err
	}
	service.allowlist = next
	service.code = ""
	if err := service.closeCodeChannelLocked(); err != nil {
		service.writeAudit(logEvent{
			Level:       "warn",
			Event:       "pairing_code_channel_cleanup_failed",
			Reason:      "remove_failed",
			PairingCode: redacted,
			PrivateKey:  redacted,
		})
	}
	return clientID, nil
}

func (service *pairingService) authorizedKey(encoded string) (string, ed25519.PublicKey, bool) {
	publicKey, err := decodeEd25519PublicKey(encoded)
	if err != nil {
		return "", nil, false
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	for _, client := range service.allowlist.Clients {
		if client.PublicKey == encoded {
			return client.ClientID, publicKey, true
		}
	}
	return "", nil, false
}

func (service *pairingService) logPairFailure(reason string, started time.Time, publicKey string) {
	service.writeAudit(logEvent{
		Level:           "warn",
		Event:           "pair_rejected",
		Result:          "rejected",
		Reason:          reason,
		PairingCode:     redacted,
		PrivateKey:      redacted,
		ClientPublicKey: publicKey,
		LatencyMS:       latencySince(started),
	})
}

func (service *pairingService) writeAudit(event logEvent) {
	if err := service.logger.write(event); err != nil {
		service.reportFatal(fmt.Errorf("write %s pairing audit event: %w", event.Event, err))
	}
}

func latencySince(started time.Time) *int64 {
	latency := time.Since(started).Milliseconds()
	return &latency
}

func decodePairRequest(response http.ResponseWriter, request *http.Request) (pairRequest, error) {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return pairRequest{}, errors.New("content type must be application/json")
	}
	request.Body = http.MaxBytesReader(response, request.Body, maxPairRequestBytes)
	decoder := json.NewDecoder(request.Body)

	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return pairRequest{}, errors.New("request must be a JSON object")
	}
	var result pairRequest
	seen := make(map[string]struct{}, 2)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return pairRequest{}, err
		}
		name, ok := token.(string)
		if !ok {
			return pairRequest{}, errors.New("request field name must be a string")
		}
		if _, duplicate := seen[name]; duplicate {
			return pairRequest{}, fmt.Errorf("duplicate field %q", name)
		}
		seen[name] = struct{}{}
		var value string
		if err := decoder.Decode(&value); err != nil {
			return pairRequest{}, fmt.Errorf("decode field %q: %w", name, err)
		}
		switch name {
		case "pairing_code":
			result.PairingCode = value
		case "client_public_key":
			result.ClientPublicKey = value
		default:
			return pairRequest{}, fmt.Errorf("unknown field %q", name)
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return pairRequest{}, errors.New("request object is not closed")
	}
	if result.PairingCode == "" || result.ClientPublicKey == "" || len(seen) != 2 {
		return pairRequest{}, errors.New("required pairing fields are missing")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return pairRequest{}, errors.New("request contains trailing JSON")
		}
		return pairRequest{}, err
	}
	return result, nil
}

func validateEd25519PublicKey(encoded string) error {
	const prefix = "ed25519:"
	if !strings.HasPrefix(encoded, prefix) {
		return errors.New("missing ed25519 prefix")
	}
	value := strings.TrimPrefix(encoded, prefix)
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key")
	}
	if base64.StdEncoding.EncodeToString(decoded) != value {
		return errors.New("non-canonical Ed25519 public key")
	}
	return nil
}

func equalSecret(expected, received string) bool {
	if len(expected) != len(received) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(received)) == 1
}

func randomToken(size int) (string, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func loadAllowlist(state *stateDirectory) (allowlist, error) {
	file, size, err := state.openAllowlist()
	if errors.Is(err, os.ErrNotExist) {
		return allowlist{Version: 1, Clients: []allowlistClient{}}, nil
	}
	if err != nil {
		return allowlist{}, fmt.Errorf("open allowlist: %w", err)
	}
	if size > maxAllowlistBytes {
		return allowlist{}, errors.Join(errAllowlistTooLarge, file.Close())
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxAllowlistBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return allowlist{}, errors.Join(
			wrapError("read allowlist", readErr),
			wrapError("close allowlist after read", closeErr),
		)
	}
	if len(data) > maxAllowlistBytes {
		return allowlist{}, errAllowlistTooLarge
	}
	inspection, err := inspectJSON(data)
	if err != nil {
		return allowlist{}, fmt.Errorf("inspect allowlist JSON: %w", err)
	}
	if !inspection.object || inspection.duplicate {
		return allowlist{}, errors.New("allowlist must be an unambiguous JSON object")
	}

	var stored allowlist
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&stored); err != nil {
		return allowlist{}, fmt.Errorf("decode allowlist: %w", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return allowlist{}, errors.New("allowlist contains trailing JSON")
	}
	if stored.Version != 1 || stored.Clients == nil {
		return allowlist{}, errors.New("allowlist has unsupported or missing version")
	}
	seenClientIDs := make(map[string]struct{}, len(stored.Clients))
	seenPublicKeys := make(map[string]struct{}, len(stored.Clients))
	for _, client := range stored.Clients {
		clientToken := strings.TrimPrefix(client.ClientID, "cli_")
		decodedID, err := base64.RawURLEncoding.DecodeString(clientToken)
		if err != nil || len(decodedID) != 12 || "cli_"+base64.RawURLEncoding.EncodeToString(decodedID) != client.ClientID {
			return allowlist{}, errors.New("allowlist contains an invalid client_id")
		}
		if _, duplicate := seenClientIDs[client.ClientID]; duplicate {
			return allowlist{}, errors.New("allowlist contains a duplicate client_id")
		}
		seenClientIDs[client.ClientID] = struct{}{}
		if err := validateEd25519PublicKey(client.PublicKey); err != nil {
			return allowlist{}, errors.New("allowlist contains an invalid client_public_key")
		}
		if _, duplicate := seenPublicKeys[client.PublicKey]; duplicate {
			return allowlist{}, errors.New("allowlist contains a duplicate client_public_key")
		}
		seenPublicKeys[client.PublicKey] = struct{}{}
		pairedAt, err := time.Parse(time.RFC3339Nano, client.PairedAt)
		if err != nil || pairedAt.UTC().Format(time.RFC3339Nano) != client.PairedAt {
			return allowlist{}, errors.New("allowlist contains an invalid or non-canonical paired_at")
		}
	}
	return stored, nil
}

func persistAllowlist(state *stateDirectory, value allowlist) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode allowlist: %w", err)
	}
	data = append(data, '\n')
	if len(data) > maxAllowlistBytes {
		return errAllowlistTooLarge
	}
	return state.persistAllowlistData(data)
}

func wrapError(context string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", context, err)
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	encoder := json.NewEncoder(response)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
}
