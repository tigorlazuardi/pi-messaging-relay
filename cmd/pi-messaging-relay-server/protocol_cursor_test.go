package main

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestDecodeListCursor(t *testing.T) {
	const requestID = "01993c84-5d38-7d75-8bc1-f945bfa42cdf"
	frame := func(payload string) []byte {
		return []byte(fmt.Sprintf(`{"v":1,"type":"list","request_id":%q,"payload":%s}`, requestID, payload))
	}

	t.Run("absence selects first page", func(t *testing.T) {
		operation, failure, err := decodeClientOperation(frame(`{}`))
		if err != nil || failure != nil {
			t.Fatalf("decode first-page list = failure %+v, error %v", failure, err)
		}
		if operation.List == nil || operation.List.AfterAddress != "" {
			t.Fatalf("first-page list payload = %+v", operation.List)
		}
	})

	t.Run("canonical maximum retains decoded opaque navigation value", func(t *testing.T) {
		address := strings.Repeat("a", maxAddressBytes)
		cursor := "cur_" + base64.RawURLEncoding.EncodeToString([]byte(address))
		if len(cursor) != 5856 {
			t.Fatalf("maximum cursor length = %d, want 5856", len(cursor))
		}
		operation, failure, err := decodeClientOperation(frame(fmt.Sprintf(`{"cursor":%q}`, cursor)))
		if err != nil || failure != nil {
			t.Fatalf("decode maximum cursor = failure %+v, error %v", failure, err)
		}
		if operation.List == nil || operation.List.AfterAddress != address {
			t.Fatal("maximum cursor did not retain exact decoded address")
		}
	})

	invalid := map[string]string{
		"empty":              `{"cursor":""}`,
		"empty decoded":      `{"cursor":"cur_"}`,
		"bad prefix":         `{"cursor":"peer"}`,
		"bad alphabet":       `{"cursor":"cur_cGVl+g"}`,
		"padding":            `{"cursor":"cur_cGVlcg=="}`,
		"noncanonical":       `{"cursor":"cur_cGVlcj"}`,
		"invalid UTF-8":      `{"cursor":"cur__w"}`,
		"decoded over limit": fmt.Sprintf(`{"cursor":%q}`, "cur_"+base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("a", maxAddressBytes+1)))),
		"wrong scalar":       `{"cursor":12}`,
		"unknown field":      `{"cursor":"cur_cGVlcg","extra":true}`,
		"duplicate field":    `{"cursor":"cur_cGVlcg","cursor":"cur_cGVlcg"}`,
	}
	for name, payload := range invalid {
		t.Run(name, func(t *testing.T) {
			operation, failure, err := decodeClientOperation(frame(payload))
			if err != nil {
				t.Fatalf("decode invalid cursor returned internal error: %v", err)
			}
			if failure == nil || failure.Code != "invalid_envelope" || operation.List != nil {
				t.Fatalf("decode invalid cursor = operation %+v, failure %+v", operation, failure)
			}
		})
	}
}
