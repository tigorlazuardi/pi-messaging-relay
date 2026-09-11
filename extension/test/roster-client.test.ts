import assert from "node:assert/strict";
import test from "node:test";

import WebSocket, { WebSocketServer } from "ws";

import { createRecipientDelivery } from "../internal/delivery-policy.ts";
import { RosterClient, RosterRequestError } from "../internal/roster-client.ts";

const REQUEST_ID = "01993c84-5d38-7d75-8bc1-f945bfa42cdf";
const MAX_ROSTER_FRAME_BYTES = 48 * 1024;

async function socketPair(): Promise<{ client: WebSocket; server: WebSocket; close(): Promise<void> }> {
  const listener = new WebSocketServer({ host: "127.0.0.1", port: 0, perMessageDeflate: false });
  await new Promise<void>((resolve, reject) => {
    listener.once("listening", resolve);
    listener.once("error", reject);
  });
  const address = listener.address();
  assert.ok(address && typeof address === "object");
  const accepted = new Promise<WebSocket>((resolve) => listener.once("connection", resolve));
  const client = new WebSocket(`ws://127.0.0.1:${address.port}`, { perMessageDeflate: false });
  await new Promise<void>((resolve, reject) => {
    client.once("open", resolve);
    client.once("error", reject);
  });
  const server = await accepted;
  return {
    client,
    server,
    close: async () => {
      client.terminate();
      server.terminate();
      await new Promise<void>((resolve) => listener.close(() => resolve()));
    },
  };
}

function nextClientFrame(socket: WebSocket): Promise<string> {
  return new Promise((resolve, reject) => socket.once("message", (data, isBinary) => {
    try {
      assert.equal(isBinary, false);
      resolve(data.toString("utf8"));
    } catch (error) {
      reject(error);
    }
  }));
}

async function nextClientRequest(socket: WebSocket): Promise<Record<string, unknown>> {
  return JSON.parse(await nextClientFrame(socket)) as Record<string, unknown>;
}

function roster(requestID: string, payload: unknown): string {
  return JSON.stringify({ v: 1, type: "roster", request_id: requestID, payload });
}

async function closes(socket: WebSocket): Promise<void> {
  if (socket.readyState === WebSocket.CLOSED) return;
  await new Promise<void>((resolve) => socket.once("close", () => resolve()));
}

function exactBoundaryRoster(requestID: string): string {
  const peers: Array<{ address: string }> = [];
  while (true) {
    const current = roster(requestID, { peers });
    const remaining = MAX_ROSTER_FRAME_BYTES - Buffer.byteLength(current, "utf8");
    if (remaining <= 15) break;
    const addressLength = Math.min(4_389, remaining - 15);
    peers.push({ address: "x".repeat(Math.max(1, addressLength)) });
    if (Buffer.byteLength(roster(requestID, { peers }), "utf8") >= MAX_ROSTER_FRAME_BYTES) break;
  }
  let encoded = roster(requestID, { peers });
  const difference = MAX_ROSTER_FRAME_BYTES - Buffer.byteLength(encoded, "utf8");
  assert.ok(difference >= 0);
  peers[peers.length - 1].address += "y".repeat(difference);
  encoded = roster(requestID, { peers });
  assert.equal(Buffer.byteLength(encoded, "utf8"), MAX_ROSTER_FRAME_BYTES);
  assert.ok(Buffer.byteLength(peers[peers.length - 1].address, "utf8") <= 4_389);
  return encoded;
}

test("roster client sends one UUIDv7 list and returns deterministic address-only tool data", async (context) => {
  const pair = await socketPair();
  context.after(pair.close);
  const client = new RosterClient(pair.client, { responseTimeoutMS: 1_000 });
  const requestPromise = nextClientRequest(pair.server);
  const resultPromise = client.list("cur_YWxwaGE", new AbortController().signal);
  const request = await requestPromise;
  assert.equal(request.v, 1);
  assert.equal(request.type, "list");
  assert.match(String(request.request_id), /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.deepEqual(request.payload, { cursor: "cur_YWxwaGE" });

  pair.server.send(roster(String(request.request_id), {
    peers: [{ address: "alpha" }, { address: "beta" }],
    next_cursor: "cur_YmV0YQ",
  }));
  const result = await resultPromise;
  assert.deepEqual(result, {
    peers: [{ address: "alpha" }, { address: "beta" }],
    next_cursor: "cur_YmV0YQ",
  });
  assert.equal(JSON.stringify(result), '{"peers":[{"address":"alpha"},{"address":"beta"}],"next_cursor":"cur_YmV0YQ"}');
});

test("roster client rejects concurrent list locally without sending or queueing", async (context) => {
  const pair = await socketPair();
  context.after(pair.close);
  const client = new RosterClient(pair.client, { responseTimeoutMS: 1_000 });
  const firstRequest = nextClientRequest(pair.server);
  const first = client.list(undefined, new AbortController().signal);
  const request = await firstRequest;
  await assert.rejects(client.list(undefined, new AbortController().signal), {
    message: "Relay list_peers already has one request in flight.",
  });
  pair.server.send(roster(String(request.request_id), { peers: [] }));
  await first;
});

test("malformed, wrong-correlation, and unsolicited roster frames fail closed", async (context) => {
  const cases = [
    (id: string) => `{"v":1,"type":"roster","request_id":"${id}","payload":{"peers":[],"peers":[]}}`,
    (_id: string) => roster(REQUEST_ID, { peers: [] }),
  ];
  for (const makeFrame of cases) {
    const pair = await socketPair();
    const client = new RosterClient(pair.client, { responseTimeoutMS: 1_000 });
    const requestPromise = nextClientRequest(pair.server);
    const result = client.list(undefined, new AbortController().signal);
    const request = await requestPromise;
    const peerClosed = closes(pair.server);
    pair.server.send(makeFrame(String(request.request_id)));
    await assert.rejects(result, { message: "Relay returned an invalid list_peers response." });
    await peerClosed;
    await pair.close();
  }

  const pair = await socketPair();
  const _client = new RosterClient(pair.client, { responseTimeoutMS: 1_000 });
  const peerClosed = closes(pair.server);
  pair.server.send(roster(REQUEST_ID, { peers: [] }));
  await peerClosed;
  await pair.close();
});

test("roster client rejects every non-closed roster value and canonical cursor violation", async () => {
  const invalidFrames: Array<(id: string) => string | Buffer> = [
    (id) => JSON.stringify({ v: 1, type: "roster", request_id: id, payload: { peers: [] }, extra: true }),
    (id) => JSON.stringify({ v: 2, type: "roster", request_id: id, payload: { peers: [] } }),
    (id) => JSON.stringify({ v: 1, type: "welcome", request_id: id, payload: { peers: [] } }),
    (id) => JSON.stringify({ v: 1, type: "roster", request_id: id, payload: { peers: [], extra: true } }),
    (id) => JSON.stringify({ v: 1, type: "roster", request_id: id, payload: { peers: {} } }),
    (id) => JSON.stringify({ v: 1, type: "roster", request_id: id, payload: { peers: [{ address: "peer", extra: true }] } }),
    (id) => JSON.stringify({ v: 1, type: "roster", request_id: id, payload: { peers: [{ address: 1 }] } }),
    (id) => JSON.stringify({ v: 1, type: "roster", request_id: id, payload: { peers: [{ address: "" }] } }),
    (id) => JSON.stringify({ v: 1, type: "roster", request_id: id, payload: { peers: [{ address: "x".repeat(4_390) }] } }),
    (id) => `{"v":1,"type":"roster","request_id":"${id}","payload":{"peers":[{"address":"\\ud800"}]}}`,
    (id) => JSON.stringify({ v: 1, type: "roster", request_id: id, payload: { peers: [], next_cursor: "cur_cGVlcg==" } }),
    (id) => JSON.stringify({ v: 1, type: "roster", request_id: id, payload: { peers: [], next_cursor: "cur_cGVlcj" } }),
    (id) => JSON.stringify({ v: 1, type: "roster", request_id: id, payload: { peers: [], next_cursor: "cur__w" } }),
    (id) => Buffer.from(`{"v":1,"type":"roster","request_id":"${id}","payload":{"peers":[{"address":"\xff"}]}}`, "latin1"),
  ];

  for (const [index, makeFrame] of invalidFrames.entries()) {
    const pair = await socketPair();
    let rejected = false;
    try {
      const client = new RosterClient(pair.client, { responseTimeoutMS: 1_000 });
      const requestPromise = nextClientRequest(pair.server);
      const result = client.list(undefined, new AbortController().signal);
      const request = await requestPromise;
      const peerClosed = closes(pair.server);
      const frame = makeFrame(String(request.request_id));
      pair.server.send(frame, Buffer.isBuffer(frame) ? { binary: false } : undefined);
      try {
        await result;
      } catch (error) {
        assert.equal((error as Error).message, "Relay returned an invalid list_peers response.");
        rejected = true;
        await peerClosed;
      }
      assert.equal(rejected, true, `invalid frame case ${index} was accepted`);
    } finally {
      await pair.close();
    }
  }
});

test("roster client accepts exact 48 KiB frame and rejects one byte over", async (context) => {
  const exactPair = await socketPair();
  context.after(exactPair.close);
  const exactClient = new RosterClient(exactPair.client, { responseTimeoutMS: 1_000 });
  const exactRequestPromise = nextClientRequest(exactPair.server);
  const exactResult = exactClient.list(undefined, new AbortController().signal);
  const exactRequest = await exactRequestPromise;
  const exact = exactBoundaryRoster(String(exactRequest.request_id));
  exactPair.server.send(exact);
  assert.ok((await exactResult).peers.length > 1);

  const overPair = await socketPair();
  context.after(overPair.close);
  const overClient = new RosterClient(overPair.client, { responseTimeoutMS: 1_000 });
  const overRequestPromise = nextClientRequest(overPair.server);
  const overResult = overClient.list(undefined, new AbortController().signal);
  const overRequest = await overRequestPromise;
  const over = exactBoundaryRoster(String(overRequest.request_id)) + " ";
  const peerClosed = closes(overPair.server);
  overPair.server.send(over);
  await assert.rejects(overResult, { message: "Relay returned an invalid list_peers response." });
  await peerClosed;
});

test("abort, timeout, and socket close reject in-flight list and settle resources", async () => {
  for (const mode of ["abort", "timeout", "close"] as const) {
    const pair = await socketPair();
    const controller = new AbortController();
    const client = new RosterClient(pair.client, { responseTimeoutMS: 30 });
    const requestPromise = nextClientRequest(pair.server);
    const result = client.list(undefined, controller.signal);
    await requestPromise;
    if (mode === "abort") controller.abort();
    if (mode === "close") pair.server.close();
    await assert.rejects(result, {
      message: mode === "abort"
        ? "Relay list_peers request was aborted."
        : mode === "timeout"
          ? "Relay list_peers response timed out."
          : "Relay disconnected during list_peers.",
    });
    await closes(pair.client);
    await pair.close();
  }
});

test("send generates internal IDs and accepts only exact correlated send_result", async (context) => {
  const pair = await socketPair();
  context.after(pair.close);
  const client = new RosterClient(pair.client, { responseTimeoutMS: 1_000 });
  const requestPromise = nextClientRequest(pair.server);
  const resultPromise = client.send("opaque-destination", "hello", undefined, new AbortController().signal);
  const request = await requestPromise;
  const payload = request.payload as Record<string, unknown>;
  assert.match(String(request.request_id), /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.match(String(payload.message_id), /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.notEqual(request.request_id, payload.message_id);
  assert.deepEqual(Object.keys(payload), ["message_id", "to", "body"]);
  pair.server.send(JSON.stringify({
    v: 1,
    type: "send_result",
    request_id: request.request_id,
    payload: { message_id: payload.message_id, status: "received" },
  }));
  assert.deepEqual(await resultPromise, { message_id: payload.message_id, status: "received" });
});

test("send rejects unsupported, unsafe, or over-transport-limit input without consuming the connection", async (context) => {
  const pair = await socketPair();
  context.after(pair.close);
  const client = new RosterClient(pair.client, { responseTimeoutMS: 1_000 });
  const frames: string[] = [];
  pair.server.on("message", (data) => frames.push(data.toString("utf8")));
  const objectMarker = "unsupported-object-body-must-not-cross-wire";
  await assert.rejects(
    client.send("destination", { private: objectMarker }, undefined, new AbortController().signal),
    (error: unknown) => error instanceof RosterRequestError &&
      error.reason === "object_body_unsupported" &&
      error.message === "Relay agent_send object bodies are not supported by this release." &&
      !error.message.includes(objectMarker),
  );
  await assert.rejects(client.send("destination", "\ud800", undefined, new AbortController().signal), {
    message: "Relay agent_send arguments are invalid.",
  });
  await assert.rejects(client.send("destination", "x".repeat(512 * 1024), undefined, new AbortController().signal), {
    message: "Relay agent_send frame exceeds 512 KiB.",
  });
  const requestPromise = nextClientRequest(pair.server);
  const resultPromise = client.list(undefined, new AbortController().signal);
  const request = await requestPromise;
  assert.equal(request.type, "list");
  pair.server.send(roster(String(request.request_id), { peers: [] }));
  assert.deepEqual(await resultPromise, { peers: [] });
  assert.equal(frames.length, 1);
  assert.equal(frames[0].includes(objectMarker), false);
});

test("message is injected without steering before a fresh exact received ACK", async (context) => {
  const pair = await socketPair();
  context.after(pair.close);
  const attempts: unknown[][] = [];
  const client = new RosterClient(pair.client, {
    responseTimeoutMS: 1_000,
    selfAddress: "recipient",
    deliverUserMessage: (...args: unknown[]) => { attempts.push(args); },
  });
  void client;
  const ackPromise = nextClientRequest(pair.server);
  pair.server.send(JSON.stringify({
    v: 1,
    type: "message",
    payload: {
      delivery_id: "01993c85-d827-7cd9-966c-07aa3ee42e47",
      message_id: "01993c84-fc2b-7e1c-af99-61b8118ac6df",
      from: "sender",
      to: "recipient",
      body: "exact body",
    },
  }));
  const ack = await ackPromise;
  assert.deepEqual(attempts, [["exact body"]]);
  assert.equal(ack.type, "received");
  assert.match(String(ack.request_id), /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.deepEqual(ack.payload, {
    delivery_id: "01993c85-d827-7cd9-966c-07aa3ee42e47",
    message_id: "01993c84-fc2b-7e1c-af99-61b8118ac6df",
  });
});

test("retained socket fails safe after its recipient session identity is replaced", { timeout: 2_000 }, async (context) => {
  const pair = await socketPair();
  context.after(pair.close);
  const oldSessionIdle = () => true;
  let activeSessionIdle: (() => boolean) | undefined = oldSessionIdle;
  let callAttempted = false;
  const attempts: unknown[][] = [];
  const deliverUserMessage = createRecipientDelivery(
    (...args: unknown[]) => {
      callAttempted = true;
      attempts.push(args);
    },
    oldSessionIdle,
    () => activeSessionIdle === oldSessionIdle,
  );
  const client = new RosterClient(pair.client, {
    responseTimeoutMS: 1_000,
    selfAddress: "recipient",
    deliverUserMessage,
  });
  void client;

  activeSessionIdle = () => true;
  const ackFramePromise = nextClientFrame(pair.server).then((frame) => {
    assert.equal(callAttempted, true);
    return frame;
  });
  pair.server.send(JSON.stringify({
    v: 1,
    type: "message",
    payload: {
      delivery_id: "01993c85-d827-7cd9-966c-07aa3ee42e47",
      message_id: "01993c84-fc2b-7e1c-af99-61b8118ac6df",
      from: "sender",
      to: "recipient",
      body: "retained socket body",
    },
  }));

  const ackFrame = await ackFramePromise;
  const ack = JSON.parse(ackFrame) as Record<string, unknown>;
  assert.deepEqual(attempts, [["retained socket body", { deliverAs: "followUp" }]]);
  assert.equal(JSON.stringify(attempts).includes("steer"), false);
  assert.match(String(ack.request_id), /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.equal(ackFrame, JSON.stringify({
    v: 1,
    type: "received",
    request_id: ack.request_id,
    payload: {
      delivery_id: "01993c85-d827-7cd9-966c-07aa3ee42e47",
      message_id: "01993c84-fc2b-7e1c-af99-61b8118ac6df",
    },
  }));
});

test("object message push closes without Pi injection or received ACK", { timeout: 2_000 }, async () => {
  const pair = await socketPair();
  const attempts: unknown[][] = [];
  const outbound: string[] = [];
  pair.server.on("message", (data) => outbound.push(data.toString("utf8")));
  const _client = new RosterClient(pair.client, {
    responseTimeoutMS: 1_000,
    selfAddress: "recipient",
    deliverUserMessage: (...args: unknown[]) => { attempts.push(args); },
  });
  const peerClosed = closes(pair.server);
  pair.server.send(JSON.stringify({
    v: 1,
    type: "message",
    payload: {
      delivery_id: "01993c85-d827-7cd9-966c-07aa3ee42e47",
      message_id: "01993c84-fc2b-7e1c-af99-61b8118ac6df",
      from: "hostile-sender",
      to: "recipient",
      body: { private: "hostile-object-body-must-not-be-injected" },
    },
  }));
  await peerClosed;
  assert.deepEqual(attempts, []);
  assert.deepEqual(outbound, []);
  await pair.close();
});

test("wrong destination, duplicate message fields, and send-result desync fail closed", async () => {
  const cases: Array<(requestID: string, messageID: string) => string> = [
    () => `{"v":1,"type":"message","payload":{"delivery_id":"01993c85-d827-7cd9-966c-07aa3ee42e47","message_id":"01993c84-fc2b-7e1c-af99-61b8118ac6df","from":"sender","to":"other","body":"x"}}`,
    () => `{"v":1,"type":"message","payload":{"delivery_id":"01993c85-d827-7cd9-966c-07aa3ee42e47","message_id":"01993c84-fc2b-7e1c-af99-61b8118ac6df","from":"sender","to":"recipient","body":"x","body":"y"}}`,
    () => `{"v":1,"type":"message","payload":{"delivery_id":"01993c85-d827-7cd9-966c-07aa3ee42e47","message_id":"01993c84-fc2b-7e1c-af99-61b8118ac6df","from":"sender","to":"recipient","body":"\\ud800"}}`,
    () => JSON.stringify({ v: 1, type: "message", payload: { delivery_id: "01993c85-d827-7cd9-966c-07aa3ee42e47", message_id: "01993c84-fc2b-7e1c-af99-61b8118ac6df", from: "sender", to: "recipient", body: "x".repeat(512 * 1024) } }),
    (requestID) => JSON.stringify({ v: 1, type: "send_result", request_id: requestID, payload: { message_id: REQUEST_ID, status: "received" } }),
  ];
  for (const makeFrame of cases) {
    const pair = await socketPair();
    const attempts: unknown[][] = [];
    const client = new RosterClient(pair.client, {
      responseTimeoutMS: 1_000,
      selfAddress: "recipient",
      deliverUserMessage: (...args: unknown[]) => { attempts.push(args); },
    });
    const requestPromise = nextClientRequest(pair.server);
    const result = client.send("destination", "body", undefined, new AbortController().signal);
    const request = await requestPromise;
    const messageID = String((request.payload as Record<string, unknown>).message_id);
    const peerClosed = closes(pair.server);
    pair.server.send(makeFrame(String(request.request_id), messageID));
    await assert.rejects(result, { message: "Relay returned an invalid agent_send response." });
    await peerClosed;
    assert.deepEqual(attempts, []);
    await pair.close();
  }
});
