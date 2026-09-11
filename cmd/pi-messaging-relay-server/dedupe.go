package main

import (
	"bytes"
	"container/list"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const maxSettledMessageIDsPerRecipient = 1024

type dedupeKey struct {
	sender    *authenticatedSession
	messageID string
}

type dedupeRecord struct {
	key             dedupeKey
	fingerprint     [sha256.Size]byte
	recipient       *authenticatedSession
	recipientGone   bool
	settled         bool
	response        operationResponse
	repeatUsed      bool
	attached        *clientOperation
	current         bool
	recipientOwned  bool
	settledPosition *list.Element
}

type recipientDedupeRecords struct {
	records map[*dedupeRecord]struct{}
	settled *list.List
}

type dedupeObservationKind int

const (
	dedupeNew dedupeObservationKind = iota
	dedupePendingAttached
	dedupeImmediate
	dedupeOverflow
)

type dedupeObservation struct {
	kind     dedupeObservationKind
	response operationResponse
	dedupe   string
	record   *dedupeRecord
}

type dedupeLedger struct {
	mu              sync.Mutex
	records         map[dedupeKey]*dedupeRecord
	bySender        map[*authenticatedSession]map[*dedupeRecord]struct{}
	byRecipient     map[*authenticatedSession]*recipientDedupeRecords
	currentBySender map[*authenticatedSession]*dedupeRecord
}

func newDedupeLedger() *dedupeLedger {
	return &dedupeLedger{
		records:         make(map[dedupeKey]*dedupeRecord),
		bySender:        make(map[*authenticatedSession]map[*dedupeRecord]struct{}),
		byRecipient:     make(map[*authenticatedSession]*recipientDedupeRecords),
		currentBySender: make(map[*authenticatedSession]*dedupeRecord),
	}
}

func (ledger *dedupeLedger) observe(
	sender *authenticatedSession,
	operation clientOperation,
) (dedupeObservation, error) {
	fingerprint, err := sendFingerprint(operation.Send)
	if err != nil {
		return dedupeObservation{}, err
	}
	key := dedupeKey{sender: sender, messageID: operation.Send.MessageID}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	record := ledger.records[key]
	if record == nil {
		return dedupeObservation{kind: dedupeNew}, nil
	}
	if record.settled {
		if record.fingerprint != fingerprint {
			return dedupeObservation{
				kind:     dedupeImmediate,
				response: messageIDConflictResponse(sender, operation.Send.MessageID, operation.Send.To),
				dedupe:   "conflict",
				record:   record,
			}, nil
		}
		return dedupeObservation{
			kind:     dedupeImmediate,
			response: record.response,
			dedupe:   "replayed",
			record:   record,
		}, nil
	}
	if record.repeatUsed {
		return dedupeObservation{kind: dedupeOverflow, record: record}, nil
	}
	record.repeatUsed = true
	if record.fingerprint != fingerprint {
		return dedupeObservation{
			kind:     dedupeImmediate,
			response: messageIDConflictResponse(sender, operation.Send.MessageID, operation.Send.To),
			dedupe:   "conflict",
			record:   record,
		}, nil
	}
	attached := operation
	attached.Record = record
	attached.Dedupe = "replayed"
	record.attached = &attached
	return dedupeObservation{kind: dedupePendingAttached, record: record}, nil
}

func (ledger *dedupeLedger) begin(
	sender *authenticatedSession,
	operation *clientOperation,
) error {
	fingerprint, err := sendFingerprint(operation.Send)
	if err != nil {
		return err
	}
	key := dedupeKey{sender: sender, messageID: operation.Send.MessageID}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if ledger.records[key] != nil {
		return errors.New("message ID record appeared after admission")
	}
	ledger.retireCurrentLocked(sender)
	record := &dedupeRecord{key: key, fingerprint: fingerprint, current: true}
	ledger.records[key] = record
	ledger.currentBySender[sender] = record
	ledger.addSenderRecordLocked(record)
	operation.Record = record
	return nil
}

func (ledger *dedupeLedger) bindRecipient(record *dedupeRecord, recipient *authenticatedSession) {
	if record == nil || recipient == nil {
		return
	}
	ledger.mu.Lock()
	if ledger.records[record.key] == record && !record.settled && record.recipient == nil {
		record.recipient = recipient
		ledger.addRecipientRecordLocked(record)
	}
	ledger.mu.Unlock()
}

func (ledger *dedupeLedger) complete(
	record *dedupeRecord,
	response operationResponse,
	respond bool,
) *clientOperation {
	if record == nil {
		return nil
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if ledger.records[record.key] != record || record.settled {
		return nil
	}
	attached := record.attached
	record.attached = nil
	if !respond {
		ledger.removeRecordLocked(record)
		return attached
	}
	record.response = response
	record.settled = true
	retainForRecipient := record.recipientOwned && !record.recipientGone &&
		(response.Code == "received" || response.Code == "ack_timeout")
	if !retainForRecipient {
		ledger.detachRecipientLocked(record)
		if !record.current {
			ledger.removeRecordLocked(record)
		}
		return attached
	}

	owner := ledger.byRecipient[record.recipient]
	record.settledPosition = owner.settled.PushBack(record)
	if owner.settled.Len() > maxSettledMessageIDsPerRecipient {
		oldest := owner.settled.Front().Value.(*dedupeRecord)
		ledger.detachRecipientLocked(oldest)
		if !oldest.current {
			ledger.removeRecordLocked(oldest)
		}
	}
	return attached
}

// releaseCurrent drops sender-current tombstone ownership only after the
// permitted retry/conflict response has reserved bounded sequencer ownership.
func (ledger *dedupeLedger) releaseCurrent(record *dedupeRecord) {
	if record == nil {
		return
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if ledger.currentBySender[record.key.sender] != record {
		return
	}
	delete(ledger.currentBySender, record.key.sender)
	record.current = false
	if record.settled && !record.recipientOwned {
		ledger.removeRecordLocked(record)
	}
}

func (ledger *dedupeLedger) advanceSender(sender *authenticatedSession) {
	if sender == nil {
		return
	}
	ledger.mu.Lock()
	ledger.retireCurrentLocked(sender)
	ledger.mu.Unlock()
}

func (ledger *dedupeLedger) forgetSender(sender *authenticatedSession) {
	if sender == nil {
		return
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	for record := range ledger.bySender[sender] {
		ledger.removeRecordLocked(record)
	}
}

func (ledger *dedupeLedger) forgetRecipient(recipient *authenticatedSession) {
	if recipient == nil {
		return
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	owner := ledger.byRecipient[recipient]
	if owner == nil {
		return
	}
	for record := range owner.records {
		record.recipientGone = true
		ledger.detachRecipientLocked(record)
		if record.settled && !record.current {
			ledger.removeRecordLocked(record)
		}
	}
	delete(ledger.byRecipient, recipient)
}

func (ledger *dedupeLedger) shutdown() {
	ledger.mu.Lock()
	ledger.records = make(map[dedupeKey]*dedupeRecord)
	ledger.bySender = make(map[*authenticatedSession]map[*dedupeRecord]struct{})
	ledger.byRecipient = make(map[*authenticatedSession]*recipientDedupeRecords)
	ledger.currentBySender = make(map[*authenticatedSession]*dedupeRecord)
	ledger.mu.Unlock()
}

func (ledger *dedupeLedger) retireCurrentLocked(sender *authenticatedSession) {
	current := ledger.currentBySender[sender]
	if current == nil {
		return
	}
	delete(ledger.currentBySender, sender)
	current.current = false
	if current.settled && !current.recipientOwned {
		ledger.removeRecordLocked(current)
	}
}

func (ledger *dedupeLedger) addSenderRecordLocked(record *dedupeRecord) {
	owned := ledger.bySender[record.key.sender]
	if owned == nil {
		owned = make(map[*dedupeRecord]struct{})
		ledger.bySender[record.key.sender] = owned
	}
	owned[record] = struct{}{}
}

func (ledger *dedupeLedger) addRecipientRecordLocked(record *dedupeRecord) {
	owner := ledger.byRecipient[record.recipient]
	if owner == nil {
		owner = &recipientDedupeRecords{
			records: make(map[*dedupeRecord]struct{}),
			settled: list.New(),
		}
		ledger.byRecipient[record.recipient] = owner
	}
	owner.records[record] = struct{}{}
	record.recipientOwned = true
}

func (ledger *dedupeLedger) detachRecipientLocked(record *dedupeRecord) {
	if !record.recipientOwned {
		return
	}
	owner := ledger.byRecipient[record.recipient]
	if owner != nil {
		delete(owner.records, record)
		if record.settledPosition != nil {
			owner.settled.Remove(record.settledPosition)
		}
		if len(owner.records) == 0 {
			delete(ledger.byRecipient, record.recipient)
		}
	}
	record.recipientOwned = false
	record.settledPosition = nil
}

func (ledger *dedupeLedger) removeRecordLocked(record *dedupeRecord) {
	if ledger.records[record.key] != record {
		return
	}
	delete(ledger.records, record.key)
	if ledger.currentBySender[record.key.sender] == record {
		delete(ledger.currentBySender, record.key.sender)
	}
	record.current = false
	if owned := ledger.bySender[record.key.sender]; owned != nil {
		delete(owned, record)
		if len(owned) == 0 {
			delete(ledger.bySender, record.key.sender)
		}
	}
	ledger.detachRecipientLocked(record)
}

func messageIDConflictResponse(
	sender *authenticatedSession,
	messageID string,
	recipientRoute string,
) operationResponse {
	return operationResponse{
		Type: "send_result",
		Payload: sendResultPayload{
			MessageID: messageID,
			Status:    "denied",
			Reason:    "message_id_conflict",
		},
		Outcome:        "denied",
		Code:           "message_id_conflict",
		MessageID:      messageID,
		SenderRoute:    sender.Address,
		RecipientRoute: recipientRoute,
		Status:         "denied",
	}
}

func sendFingerprint(payload *sendOperationPayload) ([sha256.Size]byte, error) {
	if payload == nil {
		return [sha256.Size]byte{}, errors.New("missing send payload")
	}
	hash := sha256.New()
	writeFingerprintPart(hash, "to", payload.To)
	if payload.RePresent {
		writeFingerprintPart(hash, "re", payload.Re)
	} else {
		writeFingerprintPart(hash, "re-absent", "")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload.Body))
	decoder.UseNumber()
	var body any
	if err := decoder.Decode(&body); err != nil {
		return [sha256.Size]byte{}, err
	}
	if err := writeCanonicalJSONValue(hash, body); err != nil {
		return [sha256.Size]byte{}, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return [sha256.Size]byte{}, errors.New("trailing body JSON")
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result, nil
}

type fingerprintWriter interface {
	Write([]byte) (int, error)
}

func writeFingerprintPart(writer fingerprintWriter, kind, value string) {
	_, _ = writer.Write([]byte(kind))
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = writer.Write(size[:])
	_, _ = writer.Write([]byte(value))
}

func writeCanonicalJSONValue(writer fingerprintWriter, value any) error {
	switch typed := value.(type) {
	case nil:
		writeFingerprintPart(writer, "null", "")
	case bool:
		if typed {
			writeFingerprintPart(writer, "bool", "true")
		} else {
			writeFingerprintPart(writer, "bool", "false")
		}
	case string:
		writeFingerprintPart(writer, "string", typed)
	case json.Number:
		normalized, err := normalizeJSONNumber(string(typed))
		if err != nil {
			return err
		}
		writeFingerprintPart(writer, "number", normalized)
	case []any:
		writeFingerprintPart(writer, "array", strconv.Itoa(len(typed)))
		for _, item := range typed {
			if err := writeCanonicalJSONValue(writer, item); err != nil {
				return err
			}
		}
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		writeFingerprintPart(writer, "object", strconv.Itoa(len(keys)))
		for _, key := range keys {
			writeFingerprintPart(writer, "key", key)
			if err := writeCanonicalJSONValue(writer, typed[key]); err != nil {
				return err
			}
		}
	default:
		return errors.New("unsupported JSON fingerprint value")
	}
	return nil
}

func normalizeJSONNumber(value string) (string, error) {
	negative := strings.HasPrefix(value, "-")
	if negative {
		value = value[1:]
	}
	exponent := new(big.Int)
	if index := strings.IndexAny(value, "eE"); index >= 0 {
		if _, ok := exponent.SetString(strings.TrimPrefix(value[index+1:], "+"), 10); !ok {
			return "", errors.New("invalid JSON number exponent")
		}
		value = value[:index]
	}
	fractionDigits := 0
	if index := strings.IndexByte(value, '.'); index >= 0 {
		fractionDigits = len(value) - index - 1
		value = value[:index] + value[index+1:]
	}
	value = strings.TrimLeft(value, "0")
	if value == "" {
		return "0", nil
	}
	exponent.Sub(exponent, big.NewInt(int64(fractionDigits)))
	trailing := len(value) - len(strings.TrimRight(value, "0"))
	if trailing > 0 {
		value = value[:len(value)-trailing]
		exponent.Add(exponent, big.NewInt(int64(trailing)))
	}
	prefix := ""
	if negative {
		prefix = "-"
	}
	return prefix + value + "e" + exponent.String(), nil
}
