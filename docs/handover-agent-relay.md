# Agent Relay handover

Status: input for wayfinder and grilling; not an approved specification.

Source: handover from the `Agent-Relay` project after narrowing this repository to Pi coding agent support only.

## Product boundary

Build online-only messaging between active Pi coding-agent sessions.

The repository contains two services:

1. **Pi extension client** — connects and registers an active Pi session, lists peers, sends and receives envelopes, injects incoming messages through Pi's native turn/wake mechanism, and acknowledges only after the harness accepts or queues the injection.
2. **Standalone Go server** — authenticates clients, maintains live presence and routes, forwards unicast envelopes, correlates delivery acknowledgements, and returns a bounded send result.

MCP is outside the product boundary.

## MVP delivery semantics

- Start with unicast only.
- Sender result is `received`, `denied`, or `timeout`.
- `received` means the recipient extension or Pi harness accepted the envelope for the current or a future turn. It does not mean the model read it, completed work, or replied.
- Busy Pi sessions queue delivery for a later turn; the sender does not retry merely because the recipient is busy.
- After reconnect or an ambiguous transport failure, allow at most one bounded retry using the same message ID. The recipient deduplicates retries in memory.
- A reply is an ordinary later message carrying `re=<original-message-id>`. Sending never blocks a model turn while waiting for reply content.

## MVP non-goals

- Offline inbox, storage, or replay
- Message durability across client or server restart
- Delivery windows, tombstones, or SQLite message lifecycle
- Agent-level MCP acknowledgements or prompt-enforced acknowledgements
- Guaranteed task execution or reply
- Federated relays or multi-server high availability
- Broadcast or multicast
- Support for harnesses other than Pi
- Large normalized-trace or exhaustive oracle conformance systems

## First vertical slice

1. Build a throwaway Pi extension proving a server-pushed WebSocket message can create or queue a Pi turn while the session is idle and while it is busy.
2. Treat reliable native Pi wake/injection as the first go/no-go gate. Stop deeper broker design if this primitive cannot be made reliable.
3. Build a Go echo/router exercised by two authenticated fake clients.
4. Add Pi extension tools for peer listing and message sending, then delivery acknowledgement.
5. Add cross-machine TLS/pairing and packaging only after the local vertical slice works.

## Protocol handover

Use JSON messages over a persistent WebSocket. TLS is required when traffic leaves localhost or a trusted private tunnel.

Core envelope fields:

- protocol version
- message ID
- opaque sender address
- opaque recipient address
- optional `re` correlation ID
- free-form JSON or string body

Addresses are opaque routing keys. Clients copy addresses verbatim. Authorization uses authenticated internal identity, never address parsing.

Suggested client-to-server operations:

- `hello {v, type, client_public_key, session_nonce, connection_name, cwd_label?, signature/challenge}`
- `list {id}`
- `send {id, to, re?, body}`
- `received {id}` after Pi injection is accepted
- heartbeat response

Suggested server-to-client operations:

- `welcome {v, self_address, heartbeat_ms, max_body_bytes}`
- `roster {id, peers:[{address, display_name?}]}`
- `message {id, from, to, re?, body}`
- `send_result {id, status, reason?}`
- heartbeat request

Server boundary rules:

- Validate a closed set of message types, frame/body sizes, identifiers, and state transitions.
- The server creates and returns opaque addresses. A display address may contain session metadata, but routing uses an internal authenticated route ID.
- Sender-generated UUID or ULID message IDs are unique within the connection horizon.
- Reuse of the same ID and identical envelope is idempotent. Conflicting reuse is denied.
- ACK deadline and pending-send count are bounded.
- Disconnect before ACK settles as `timeout` or `offline`.
- Secrets and private identity objects never enter logs.

Initial constants such as body size and ACK timeout may be hardcoded. Ponytail: make them configurable when a second operational use case exists.

## Identity and authentication

Recommended MVP:

- Generate one Ed25519 keypair per client installation.
- Pair through a short-lived, one-time server code.
- Store the allowed public key on the server.
- Authenticate WebSocket registration by signing a server nonce.
- Treat connection name and cwd as display metadata only.

Simpler development mode:

- A pre-shared bearer token is acceptable on localhost only.
- Label this mode non-production; it must not silently become cross-machine security.

Cross-machine topology:

- Use one central server reachable through TLS or VPN.
- Do not federate servers in MVP.

## Connection lifecycle

- Reconnect with exponential backoff, jitter, and a cap.
- A new socket registers the current Pi session; its previous route becomes offline.
- Server restart provides no replay. Ambiguous pending sends settle as timeout; callers may explicitly resend the same message ID.
- Keep a small recipient-side in-memory LRU for same-session deduplication.
- Keep a bounded server pending-send map keyed by message ID; clean entries on ACK, timeout, and disconnect.

## Presence and ordering

- The live roster contains connected, authenticated sessions.
- Keep stable device/client identity separate from ephemeral Pi session and route identity.
- Arrival or collector order is not causal protocol order. MVP must not claim global total ordering.

## Observability

Server structured logs should record connection/session aliases, message ID, transition, latency, and result without message body or secrets.

Pi extension logs should record connect, reconnect, injection, and ACK failures.

Optional minimal counters:

- connected sessions
- send results by status
- delivery latency
- protocol rejects

OpenTelemetry is unnecessary initially.

## Packaging handover

Go server:

- Produce static binaries for supported operating systems and architectures.
- Support configuration for listen address, TLS, and allowlist/data location through flags or a config file.

Pi extension:

- Ship from source inside this repository first.
- Document the exact supported Pi version.
- Delay package publication until the vertical slice works.

README should cover value, topology, installation, pairing, server startup, extension configuration, list/send usage, operational limits, security, and troubleshooting.

## Suggested repository shape

```text
cmd/pi-messaging-relay-server/main.go
internal/server/ws.go
internal/server/registry.go
internal/server/router.go
internal/server/auth.go
internal/server/protocol.go
protocol/schema-or-types.md
extension/index.ts
extension/client.ts
extension/protocol.ts
test/integration/two-pi-clients.test.ts
scripts/dev-two-clients
README.md
CONTEXT.md
docs/adr/0001-online-only-pi-relay.md
```

Exact structure remains a wayfinder decision.

## Lessons learned

1. **Prove Pi wake first.** Native Pi wake/steer/incoming-turn behavior is the fundamental product primitive. Validate it with a throwaway extension before investing in broker durability.
2. **Separate ACK from reply.** Transport delivery acknowledgement and content reply represent different facts and occur at different times.
3. **Keep routing identity opaque.** Human labels, cwd, hostname, PC alias, and formatted address are not authorization evidence.
4. **Prefer an explicit state machine.** Test public delivery transitions plus a few real two-client integrations rather than constructing exhaustive causal graphs.
5. **Bound every transient resource.** ACK wait, pending sends, retries, frame/body size, and dedupe memory all need fixed ceilings.
6. **Reconnect is not durability.** Re-establish live presence after failure; do not imply persisted messages or restart replay.
7. **Avoid invisible proof expansion.** After three failed review/fix passes, split or stop instead of growing conformance infrastructure without a product decision.
8. **Keep MVP online-only.** Durable message, delivery-attempt, tombstone, offline FIFO, storage fault, and restart-recovery domains from Agent Relay should not transfer into this repository.

## Decisions for wayfinder and grilling

- Which exact Pi extension API can reliably wake or queue a turn?
- Is the ACK boundary definitively “Pi harness accepted/queued injection”?
- Does MVP use Ed25519 one-time-code pairing or a localhost-only shared token?
- What display form should presence and addresses use while preserving opaque routing?
- Is deployment limited to localhost/VPN, or must the server support a public TLS endpoint?
- What are the initial body limit, ACK timeout, maximum pending sends, and dedupe LRU size?
- Should the server persist allowlisted public keys only while never persisting messages?
- Does any proven first use case require broadcast? Current recommendation: no.
