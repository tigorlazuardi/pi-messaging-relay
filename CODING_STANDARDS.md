# Coding Standards

This repository is greenfield application code. The accepted [online relay API v1](docs/src/content/docs/developer/protocol/online-relay-api-v1.mdx) and its originating issue define behavior; these standards define implementation conventions without expanding that contract.

## Formatting

Go formatting is enforced by configuration-free `gofmt`; no TypeScript/Astro formatter is configured, so this document prescribes none.

## Naming

- Use short, lowercase Go package names; PascalCase for exported identifiers; camelCase for unexported identifiers; and standard initialisms such as `ID`, `HTTP`, `URL`, and `UUID`.
- Name Go tests `TestXxx` in `*_test.go`. Name TypeScript tests `*.test.ts` and describe observable behavior rather than an implementation method.
- Use camelCase for TypeScript values and functions, PascalCase for types and Astro components, and lowercase descriptive filenames for non-component modules.
- Preserve contract spellings at boundaries: JSON fields and stable reasons use the documented snake_case; model tool names remain `list_peers` and `agent_send`. Do not translate wire names into a second public vocabulary.

## Modules and seams

- Validate and decode HTTP/WebSocket input before domain logic sees it. Keep address strings opaque; routing and authorization use authenticated internal identity, never parsed cwd, hostname, or route formatting.
- Keep the Go server and TypeScript extension compatible through the documented HTTP, WebSocket, model-tool, and log contracts. Internal types or package layout are not public contracts.

## Errors and logging

- Reject invalid input at the first trust boundary. Protocol, framing, and authentication failures fail closed as documented; operation denials use the documented stable status and reason instead of ad hoc strings.
- In Go, return errors, add actionable context with `%w`, and inspect causes with `errors.Is` or `errors.As`. In TypeScript, treat caught values as `unknown`, narrow them, and convert them to a typed result only at the owning boundary.
- Log each lifecycle transition or settled operation once, at the layer that owns the outcome. Emit one structured JSON object per line with a stable event name, severity, result or reason, latency when relevant, and available correlation IDs.
- Use `debug` for protocol detail, `info` for normal transitions, `warn` for recoverable anomalies, and `error` for failures requiring operator attention. Do not log heartbeat ticks or repeat an error at every call layer.
- Preserve telemetry field names but replace pairing codes, nonces, signatures, private keys, and message bodies with `<redacted>`. Never log or commit private keys or other credentials. Public keys and correlation/route IDs may remain visible as the accepted contract permits.

## Testing

- The primary compatibility test is the highest-level black-box harness: start the real Go server on an ephemeral localhost port, drive two real extension instances through fake Pi adapters, and assert public HTTP/WebSocket frames, model-tool results, Pi injection calls, reconnect behavior, allowlist persistence, and process logs.
- Assert observable outcomes, not maps, goroutines, locks, package layout, or persistence encoding. Use deterministic clocks and bounded waits; routine tests must not make live model calls.
- Every contract behavior change must cover its happy path and stable failure paths. In particular, test malformed and oversized input, authentication rejection, limit exhaustion, offline and disconnect handling, ACK timeout, idempotent duplicate IDs, conflicting IDs, reconnect without replay, and sensitive-log redaction.
- Add focused unit tests only for behavior that the black-box seam cannot exercise deterministically, including cryptographic verification, duplicate-key JSON rejection, canonical JSON encoding, UUID handling, and timing edge cases.
- Test cleanup must terminate child processes and remove temporary state even after assertion failure. Tests must not depend on execution order, fixed ports, ambient credentials, or retained messages.

## Comments and documentation

- Go exported declarations require idiomatic doc comments. TypeScript exported protocol and tool types require documentation when their constraints are not evident from the type.
- Inline comments explain a constraint, safety boundary, or non-obvious reason; do not narrate code that is already clear.
- Complete each feature or fix by updating affected documentation. Put implementation and protocol material under `docs/src/content/docs/developer/<domain>/`; put operator setup, use, security, limits, and troubleshooting under `docs/src/content/docs/user/`.
- Treat accepted MDX decisions and I/O examples as binding. Update the accepted spec before intentionally changing a public request, response, failure reason, delivery meaning, or model-tool surface.

## Repository prohibitions

- Do not add MCP, offline inboxes, message persistence or replay, broadcast, sender-selected steering, public TLS termination, or extra model tools without an accepted spec change.
- On the relay server, persist only allowlisted public keys and minimal pairing metadata required by the accepted v1 contract; never persist message bodies, pending sends, dedupe entries, or offline inbox/replay state.
- Extension persistence may retain the installation private key and same-session route ID as required by the accepted contract; this standard does not select a storage format. Treat the installation private key as sensitive: permission to persist it does not permit logging or committing it.
- Do not derive authorization from client-supplied cwd, hostname, address text, message IDs, or role-like fields.
- Do not introduce unbounded frames, bodies, pending sends, ACK waits, retries, dedupe storage, goroutines, queues, or reconnect loops. Use the fixed v1 ceilings until an accepted contract changes them.
- Do not commit generated documentation output, dependency directories, environment files, logs, credentials, or private key material.
- Do not expose internal Go packages or TypeScript symbols speculatively, and do not couple compatibility tests to internal structure.

The Fowler smell baseline from the `code-review` skill still applies below these standards. Where this document and the baseline disagree, this document wins.

The first ticket touching an area is its pathfinder: it establishes the living code pattern for that area. Later reviews check both this document and that implementation; disagreement signals that the standard may need updating, not that the code is wrong by default.
