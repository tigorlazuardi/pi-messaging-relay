package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode/utf8"
)

const (
	// maxAnnotationKeys bounds one session's live annotation set.
	maxAnnotationKeys = 8
	// maxAnnotationValueBytes bounds one annotation value.
	maxAnnotationValueBytes = 256
	// maxAnnotationSerializedBytes bounds the compact JSON encoding of one
	// annotation set. The limit is measured on the JSON-escaped encoding
	// without HTML escaping, which is exactly what the extension measures with
	// JSON.stringify. The roster frame re-encodes the set with HTML escaping,
	// so the wire size of one set stays below six times this limit.
	maxAnnotationSerializedBytes = 1024
)

// annotationSet is the live, ephemeral, replace-all metadata one session
// publishes about itself. It is never persisted, never replayed, and never
// logged with values: only the accepted key count and a stable drop reason
// reach telemetry.
type annotationSet map[string]string

// decodeAnnotatePayload decodes one annotate operation payload. It never
// rejects the connection: an invalid annotation set is reported with a stable
// drop reason so the caller keeps the previous set and the socket stays
// healthy. A duplicated annotations key is a dropped set, not a terminal
// frame, because the annotation map is best-effort metadata.
func decodeAnnotatePayload(data []byte, duplicate bool) (annotationSet, string) {
	if duplicate {
		return nil, "duplicate_key"
	}
	fields, err := decodeObject(data)
	if err != nil || len(fields) != 1 {
		return nil, "invalid_payload"
	}
	raw, exists := fields["annotations"]
	if !exists {
		return nil, "invalid_payload"
	}
	return decodeAnnotationMap(raw)
}

// decodeAnnotationMap validates one annotation map. Every failure is a
// best-effort drop with a stable reason; no failure is fatal.
func decodeAnnotationMap(data []byte) (annotationSet, string) {
	if !rawJSONObject(data) {
		return nil, "invalid_payload"
	}
	var entries map[string]json.RawMessage
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, "invalid_payload"
	}
	if len(entries) > maxAnnotationKeys {
		return nil, "too_many_keys"
	}
	set := make(annotationSet, len(entries))
	for key, raw := range entries {
		if !validAnnotationKey(key) {
			return nil, "invalid_key"
		}
		value, ok := decodeAnnotationValue(raw)
		if !ok {
			return nil, "invalid_value"
		}
		set[key] = value
	}
	if annotationSerializedBytes(set) > maxAnnotationSerializedBytes {
		return nil, "too_large"
	}
	return set, ""
}

// decodeAnnotationValue accepts one JSON string value. Numbers, booleans,
// null, objects, and arrays are not annotation values.
func decodeAnnotationValue(raw json.RawMessage) (string, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return "", false
	}
	var value string
	if err := json.Unmarshal(trimmed, &value); err != nil {
		return "", false
	}
	if !validAnnotationValue(value) {
		return "", false
	}
	return value, true
}

// validAnnotationKey accepts the documented key shape: a lowercase letter
// followed by at most 31 lowercase letters, digits, or underscores.
func validAnnotationKey(key string) bool {
	if len(key) == 0 || len(key) > 32 {
		return false
	}
	if key[0] < 'a' || key[0] > 'z' {
		return false
	}
	for index := 1; index < len(key); index++ {
		character := key[index]
		switch {
		case character >= 'a' && character <= 'z':
		case character >= '0' && character <= '9':
		case character == '_':
		default:
			return false
		}
	}
	return true
}

// validAnnotationValue accepts one bounded UTF-8 value without control
// characters or line separators. The empty value is legal: an annotation key
// may carry no text. U+2028 and U+2029 are rejected because Go's JSON encoder
// escapes them while JSON.stringify does not, and both sides must measure the
// same serialized size.
func validAnnotationValue(value string) bool {
	if len(value) > maxAnnotationValueBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		switch {
		case character < 0x20:
			return false
		case character == 0x7f:
			return false
		case character >= 0x80 && character <= 0x9f:
			return false
		case character == '\u2028' || character == '\u2029':
			return false
		}
	}
	return true
}

// annotationSerializedBytes measures the compact JSON encoding of one
// annotation set without HTML escaping, matching the extension's
// JSON.stringify measurement.
func annotationSerializedBytes(set annotationSet) int {
	if len(set) == 0 {
		return len("{}")
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(set); err != nil {
		return maxAnnotationSerializedBytes + 1
	}
	return len(bytes.TrimRight(buffer.Bytes(), "\n"))
}

// annotationPath reports whether one JSON field path belongs to the
// annotations map of an operation payload. Duplicates inside that map are a
// dropped annotation set; every other duplicate stays a terminal frame.
func annotationPath(path string) bool {
	return path == "payload.annotations" || strings.HasPrefix(path, "payload.annotations.")
}
