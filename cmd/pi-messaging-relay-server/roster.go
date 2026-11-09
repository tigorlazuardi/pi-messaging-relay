package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"sort"
	"unicode/utf8"
)

const maxRosterFrameBytes = 48 * 1024

type rosterPeer struct {
	Address string `json:"address"`
	// Annotations is present only for a capable requester and only for a peer
	// that published a non-empty set. A legacy requester receives the exact
	// legacy address-only peer shape.
	Annotations map[string]string `json:"annotations,omitempty"`
}

type rosterPayload struct {
	Peers      []rosterPeer `json:"peers"`
	NextCursor string       `json:"next_cursor,omitempty"`
}

// authenticatedPeerSnapshot returns the live peers of one caller in address
// order. Annotations are attached only when the caller negotiated the
// annotations capability.
func (registry *sessionConnectionRegistry) authenticatedPeerSnapshot(caller *authenticatedSession) []rosterPeer {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	peers := make([]rosterPeer, 0, len(registry.entries))
	includeAnnotations := caller != nil && caller.AnnotationsCapable
	for entry := range registry.entries {
		if !entry.visible || entry.session == nil || entry.session == caller ||
			entry.session.Address == caller.Address {
			continue
		}
		peer := rosterPeer{Address: entry.session.Address}
		if includeAnnotations && len(entry.session.Annotations) > 0 {
			peer.Annotations = maps.Clone(entry.session.Annotations)
		}
		peers = append(peers, peer)
	}
	sort.Slice(peers, func(left, right int) bool {
		return peers[left].Address < peers[right].Address
	})
	return peers
}

// replaceAnnotations stores one session's live annotation set. The set is
// replace-all, lives only in the session entry, and is never persisted.
func (registry *sessionConnectionRegistry) replaceAnnotations(
	session *authenticatedSession,
	annotations map[string]string,
) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	for entry := range registry.entries {
		if entry.session != session {
			continue
		}
		if len(annotations) == 0 {
			entry.session.Annotations = nil
			return
		}
		entry.session.Annotations = maps.Clone(annotations)
		return
	}
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
		peers := registry.authenticatedPeerSnapshot(session)
		addresses := make([]string, len(peers))
		for index, peer := range peers {
			addresses[index] = peer.Address
		}
		first := sort.SearchStrings(addresses, operation.List.AfterAddress)
		for first < len(addresses) && addresses[first] <= operation.List.AfterAddress {
			first++
		}
		page, err := buildRosterPage(operation, peers[first:])
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

func buildRosterPage(operation clientOperation, peers []rosterPeer) (rosterPayload, error) {
	peerSizes := make([]int, len(peers))
	for index, peer := range peers {
		if peer.Address == "" || len(peer.Address) > maxAddressBytes || !utf8.ValidString(peer.Address) {
			return rosterPayload{}, errors.New("registry supplied an invalid authenticated address")
		}
		encoded, err := json.Marshal(peer)
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
