package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"unicode/utf8"
)

const maxRosterFrameBytes = 48 * 1024

type rosterPeer struct {
	Address string `json:"address"`
}

type rosterPayload struct {
	Peers      []rosterPeer `json:"peers"`
	NextCursor string       `json:"next_cursor,omitempty"`
}

func (registry *sessionConnectionRegistry) authenticatedAddressSnapshot(caller *authenticatedSession) []string {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	addresses := make([]string, 0, len(registry.entries))
	for entry := range registry.entries {
		if !entry.visible || entry.session == nil || entry.session == caller || entry.session.Address == caller.Address {
			continue
		}
		addresses = append(addresses, entry.session.Address)
	}
	return addresses
}

func rosterOperationDispatcher(registry *sessionConnectionRegistry) operationDispatcher {
	return func(
		_ context.Context,
		session *authenticatedSession,
		operation clientOperation,
	) (operationResponse, bool, error) {
		if operation.Type != "list" || operation.List == nil {
			return operationResponse{}, false, nil
		}
		addresses := registry.authenticatedAddressSnapshot(session)
		sort.Strings(addresses)
		first := sort.SearchStrings(addresses, operation.List.AfterAddress)
		for first < len(addresses) && addresses[first] <= operation.List.AfterAddress {
			first++
		}
		page, err := buildRosterPage(operation, addresses[first:])
		if err != nil {
			return operationResponse{}, false, err
		}
		count := len(page.Peers)
		return operationResponse{
			Type:      "roster",
			Payload:   page,
			Outcome:   "settled",
			Code:      "roster",
			PeerCount: &count,
		}, true, nil
	}
}

func buildRosterPage(operation clientOperation, addresses []string) (rosterPayload, error) {
	peers := make([]rosterPeer, len(addresses))
	peerSizes := make([]int, len(addresses))
	for index, address := range addresses {
		if address == "" || len(address) > maxAddressBytes || !utf8.ValidString(address) {
			return rosterPayload{}, errors.New("registry supplied an invalid authenticated address")
		}
		peers[index] = rosterPeer{Address: address}
		encoded, err := json.Marshal(peers[index])
		if err != nil {
			return rosterPayload{}, errors.New("authenticated address cannot be encoded")
		}
		peerSizes[index] = len(encoded)
	}

	prefix, noCursorSuffix, err := rosterFrameSizeParts(operation.RequestID)
	if err != nil {
		return rosterPayload{}, err
	}
	allPeerBytes := 0
	for index, size := range peerSizes {
		allPeerBytes += size
		if index > 0 {
			allPeerBytes++
		}
	}
	if prefix+allPeerBytes+noCursorSuffix <= maxRosterFrameBytes {
		return rosterPayload{Peers: peers}, nil
	}

	longest := 0
	prefixPeerBytes := 0
	for index := 0; index < len(peers)-1; index++ {
		if index > 0 {
			prefixPeerBytes++
		}
		prefixPeerBytes += peerSizes[index]
		cursor := cursorPrefix + base64.RawURLEncoding.EncodeToString([]byte(peers[index].Address))
		encodedCursor, err := json.Marshal(cursor)
		if err != nil {
			return rosterPayload{}, errors.New("roster cursor cannot be encoded")
		}
		cursorSuffix := len(`],"next_cursor":`) + len(encodedCursor) + len(`}}`)
		if prefix+prefixPeerBytes+cursorSuffix <= maxRosterFrameBytes {
			longest = index + 1
		}
	}
	if longest == 0 {
		return rosterPayload{}, errors.New("no authenticated address fits the roster frame ceiling")
	}
	lastAddress := peers[longest-1].Address
	return rosterPayload{
		Peers:      peers[:longest],
		NextCursor: cursorPrefix + base64.RawURLEncoding.EncodeToString([]byte(lastAddress)),
	}, nil
}

func rosterFrameSizeParts(requestID string) (prefix int, noCursorSuffix int, err error) {
	encodedRequestID, err := json.Marshal(requestID)
	if err != nil {
		return 0, 0, errors.New("roster request ID cannot be encoded")
	}
	prefix = len(`{"v":1,"type":"roster","request_id":`) + len(encodedRequestID) + len(`,"payload":{"peers":[`)
	return prefix, len(`]}}`), nil
}
