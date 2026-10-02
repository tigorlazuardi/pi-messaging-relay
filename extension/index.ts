import { hostname as operatingSystemHostname, homedir } from "node:os";

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

import { senderLabel } from "./internal/message-renderer.ts";
import {
  appendDiagnosticLine,
  readSessionLogTail,
  resolveSessionLogPath,
} from "./internal/session-log.ts";
import {
  Text,
  truncateToWidth,
  truncateStyledToWidth,
  visibleWidth,
  type CardTheme,
} from "./internal/relay-box.ts";

import {
  ClientConfigurationError,
  loadClientConfiguration,
  type ClientConfiguration,
} from "./internal/client-config.ts";
import {
  relayStatusText,
  RELAY_STATUS_KEY,
  resolveThemeForeground,
  type RelayConnectionStatus,
} from "./internal/connection-status.ts";
import { createRecipientDelivery } from "./internal/delivery-policy.ts";
import {
  reconnectDelayMS,
  reconnectDependencies,
  RECONNECT_MAX_RETRIES,
  type ReconnectDeadline,
} from "./internal/reconnect.ts";
import { RelayCardComponent } from "./internal/relay-box.ts";
import { RelayLogsOverlay } from "./internal/logs-overlay.ts";
import type { RelayCardDetails } from "./internal/message-renderer.ts";
import { RosterRequestError, type SendResult } from "./internal/roster-client.ts";
import { generateUUIDv7, SessionSocketAttempt } from "./internal/session-auth.ts";

const DISCONNECTED_ERROR =
  "Relay is disconnected. Write ~/.config/pi/pi-messaging-relay.json with mode 0600 (url required, secret optional) or set PI_MESSAGING_RELAY_URL, then restart the session.";
const MAX_CURSOR_CHARACTERS = 5_856;
const UUID_V7_PATTERN = "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$";
const ROUTE_ENTRY_TYPE = "pi-messaging-relay-route-v1";
const ROUTE_ENTRY_VERSION = 1;
const RELAY_MESSAGE_TYPE = "pi-messaging-relay-message-v1";
const RELAY_RESULT_LIST_TYPE = "pi-messaging-relay-roster-v1";
const RELAY_RESULT_SEND_TYPE = "pi-messaging-relay-send-v1";
const REDACTED = "<redacted>";
// ponytail: fixed 200-line /relay-logs tail; make configurable when an
// operator needs more scrollback.
const RELAY_LOG_TAIL_LINES = 200;

const listPeersParameters = Type.Object(
  {
    cursor: Type.Optional(Type.String({
      maxLength: MAX_CURSOR_CHARACTERS,
      pattern: "^cur_[A-Za-z0-9_-]+$",
      description: "Opaque next_cursor from the preceding list_peers page; omit for the first page",
    })),
  },
  { additionalProperties: false },
);
const agentSendParameters = Type.Object(
  {
    to: Type.String({
      minLength: 1,
      description: "Opaque address returned by list_peers",
    }),
    body: Type.Union([
      Type.String({ description: "Message text" }),
      Type.Record(Type.String(), Type.Unknown(), {
        description: "JSON object message body",
      }),
    ]),
    re: Type.Optional(
      Type.String({
        pattern: UUID_V7_PATTERN,
        description: "Original UUIDv7 message ID when sending a reply",
      }),
    ),
  },
  { additionalProperties: false },
);

// Set per extension instance in session_start: the interactive TUI gets no
// stderr diagnostic stream (the footer indicator owns state display there);
// RPC, print, and json hosts keep it, the nix oracle included. Factory-local
// stale closures cannot re-enable output after the instance is discarded.
let diagnosticsMuted = false;

// Persisted-session capture: when the host reports one persisted session file
// (interactive TUI), every diagnostic event is appended to that session's own
// JSONL log under the relay state dir. Headless hosts and in-memory sessions
// capture nothing; they keep the stderr stream, which is their display.
let sessionLogPath: string | undefined;

function emitDiagnostic(event: Record<string, unknown>): void {
  const line = JSON.stringify(event);
  // Capture first: the per-session file works in every host, muted or not.
  try {
    if (sessionLogPath) appendDiagnosticLine(sessionLogPath, line);
  } catch {
    // Capture must never replace lifecycle, transport, or model-tool ownership.
  }
  // When the interactive TUI is active the footer indicator already owns
  // relay state display; console output would only pollute the transcript.
  try {
    if (!diagnosticsMuted) console.error(line);
  } catch {
    // Diagnostics must never replace lifecycle, transport, or model-tool ownership.
  }
}

function logFailure(
  operation: string,
  reason: string,
  fields: { recipientRoute?: string; body?: boolean; latencyMS?: number } = {},
): void {
  emitDiagnostic({
    level: "warn",
    event: "relay_operation_failed",
    operation,
    result: "failed",
    reason,
    ...(fields.recipientRoute ? { recipient_route: fields.recipientRoute } : {}),
    ...(fields.body ? { body: REDACTED } : {}),
    ...(fields.latencyMS === undefined ? {} : { latency_ms: fields.latencyMS }),
  });
}

function logSendSettlement(
  result: SendResult,
  senderRoute: string,
  recipientRoute: string,
  latencyMS: number,
): void {
  emitDiagnostic({
    level: result.status === "received" ? "info" : "warn",
    event: "relay_send_settled",
    operation: "agent_send",
    result: "settled",
    reason: "reason" in result ? result.reason : result.status,
    message_id: result.message_id,
    sender_route: senderRoute,
    recipient_route: recipientRoute,
    status: result.status,
    body: REDACTED,
    latency_ms: latencyMS,
  });
}

function disconnected(operation: "list_peers" | "agent_send", body = false): never {
  logFailure(operation, "disconnected", { body });
  throw new Error(DISCONNECTED_ERROR);
}

function connectEndpoint(origin: URL): URL {
  const endpoint = new URL("/v1/connect", origin);
  endpoint.protocol = origin.protocol === "https:" ? "wss:" : "ws:";
  return endpoint;
}

function retainedSessionRouteID(context: {
  sessionManager: { getEntries(): unknown[] };
}): string | undefined {
  const entries = context.sessionManager.getEntries();
  for (let index = entries.length - 1; index >= 0; index -= 1) {
    const candidate = entries[index];
    if (candidate === null || typeof candidate !== "object" ||
        (candidate as { type?: unknown }).type !== "custom" ||
        (candidate as { customType?: unknown }).customType !== ROUTE_ENTRY_TYPE) {
      continue;
    }
    const data = (candidate as { data?: unknown }).data;
    if (data === null || typeof data !== "object" || Array.isArray(data)) return undefined;
    const record = data as Record<string, unknown>;
    if (Object.keys(record).sort().join(",") !== "route_id,version" ||
        record.version !== ROUTE_ENTRY_VERSION || typeof record.route_id !== "string" ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(record.route_id)) {
      return undefined;
    }
    return record.route_id;
  }
  return undefined;
}

export default function relayExtension(pi: ExtensionAPI): void {
  type ConnectionIdentity = {
    endpoint: URL;
    secret: string | undefined;
    routeID: string;
    cwd: string;
    hostname: string;
    sessionIdle(): boolean;
  };

  // Module-level emitDiagnostic mirrors diagnosticsMuted via session_start;
  // see the module-scope comment there.

  const reconnect = reconnectDependencies();
  let sessionStarted = false;
  let sessionRouteID: string | undefined;
  let sessionCWD: string | undefined;
  let startupAttempted = false;
  let lifecycleGeneration = 0;
  let retryIndex = 0;
  let reconnectExhausted = false;
  let retryDeadline: { deadline: ReconnectDeadline } | undefined;
  let activeSessionIdle: (() => boolean) | undefined;
  let activeAttempt: SessionSocketAttempt | undefined;
  let activeTask: Promise<void> | undefined;
  let activeConnection: Awaited<SessionSocketAttempt["result"]> | undefined;
  let sessionAddress: string | undefined;
  let activeUI: unknown;
  let connectionStatus: RelayConnectionStatus | undefined;

  // Footer indicator: one setStatus line pushed on every state transition; a
  // host without setStatus (or a forbidding fake) only loses the cosmetic line.
  const applyStatus = (): void => {
    const ui = activeUI;
    if (ui === undefined) return;
    try {
      (ui as { setStatus?: (key: string, text?: string) => void }).setStatus?.(
        RELAY_STATUS_KEY,
        connectionStatus === undefined
          ? undefined
          : relayStatusText(connectionStatus, resolveThemeForeground(ui)),
      );
    } catch {
      // The statusline is cosmetic; it must never block lifecycle or transport ownership.
    }
  };

  const logAuthentication = (
    level: "info" | "warn",
    result: "accepted" | "rejected" | "disconnected",
    fields: { reason?: string; address?: string; routeID?: string; latencyMS?: number },
  ) => {
    emitDiagnostic({
      level,
      event: result === "accepted"
        ? "relay_auth_accepted"
        : result === "rejected"
          ? "relay_auth_rejected"
          : "relay_session_disconnected",
      result,
      ...(fields.reason ? { reason: fields.reason } : {}),
      ...(fields.address ? { address: fields.address } : {}),
      ...(fields.routeID ? { route_id: fields.routeID } : {}),
      ...(fields.latencyMS === undefined ? {} : { latency_ms: fields.latencyMS }),
    });
  };

  const logReconnect = (
    event: "relay_reconnect_scheduled" | "relay_reconnect_attempted" |
      "relay_reconnect_succeeded" | "relay_reconnect_exhausted",
    level: "info" | "warn",
    result: "scheduled" | "attempted" | "connected" | "exhausted",
    fields: {
      reason?: string;
      retryIndex: number;
      delayMS?: number;
      address?: string;
      routeID: string;
      latencyMS?: number;
    },
  ): void => {
    emitDiagnostic({
      level,
      event,
      result,
      ...(fields.reason ? { reason: fields.reason } : {}),
      retry_index: fields.retryIndex,
      ...(fields.delayMS === undefined ? {} : { delay_ms: fields.delayMS }),
      ...(fields.address ? { address: fields.address } : {}),
      route_id: fields.routeID,
      ...(fields.latencyMS === undefined ? {} : { latency_ms: fields.latencyMS }),
    });
  };

  const now = (): number => {
    const value = reconnect.now();
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error("Reconnect clock returned an invalid timestamp.");
    }
    return value;
  };

  const isCurrent = (generation: number, routeID?: string): boolean =>
    sessionStarted && lifecycleGeneration === generation &&
    (routeID === undefined || sessionRouteID === routeID);

  const cancelRetry = (): void => {
    const scheduled = retryDeadline;
    retryDeadline = undefined;
    if (!scheduled) return;
    try {
      scheduled.deadline.cancel();
    } catch {
      // Cancellation must not block session teardown or replace socket settlement.
    }
  };

  const launchConnection = async (
    identity: ConnectionIdentity,
    generation: number,
    cause: { kind: "startup" } | { kind: "reconnect"; retryIndex: number },
  ): Promise<void> => {
    if (!isCurrent(generation, identity.routeID) || activeConnection) return;
    if (activeTask) {
      const previousTask = activeTask;
      await previousTask;
      if (!isCurrent(generation, identity.routeID) || activeConnection || activeTask) return;
    }

    if (cause.kind === "reconnect") {
      logReconnect("relay_reconnect_attempted", "info", "attempted", {
        retryIndex: cause.retryIndex,
        routeID: identity.routeID,
      });
    }
    const operation = (async () => {
      let started: number;
      try {
        started = now();
      } catch {
        return;
      }
      let connection: Awaited<SessionSocketAttempt["result"]> | undefined;
      let retained = false;
      let attempt: SessionSocketAttempt;
      try {
        attempt = new SessionSocketAttempt({
          endpoint: identity.endpoint,
          secret: identity.secret,
          routeID: identity.routeID,
          cwd: identity.cwd,
          hostname: identity.hostname,
          deliverUserMessage: createRecipientDelivery(
            pi.sendUserMessage,
            identity.sessionIdle,
            () => activeSessionIdle === identity.sessionIdle,
            (body, details, deliverWhileIdle) =>
              injectInbound(body, details, deliverWhileIdle) ||
              (deliverWhileIdle ? pi.sendUserMessage(body) : pi.sendUserMessage(body, { deliverAs: "steer" })),
          ),
          onDisconnected: () => {
            if (!retained || !connection) return;
            const wasCurrent = activeConnection?.socket === connection.socket;
            if (wasCurrent) activeConnection = undefined;
            logAuthentication("info", "disconnected", {
              address: connection.address,
              routeID: identity.routeID,
            });
            if (wasCurrent && isCurrent(generation, identity.routeID)) {
              scheduleRetry(identity, generation, "session_disconnected");
            }
          },
        });
      } catch {
        // A failed construction is one ordinary failed attempt; the Pi session
        // must never crash over transport creation.
        logAuthentication("warn", "rejected", {
          reason: "connection_failed",
          routeID: identity.routeID,
        });
        scheduleRetry(identity, generation, "connection_failed");
        return;
      }
      activeAttempt = attempt;
      try {
        connection = await attempt.result;
        if (!isCurrent(generation, identity.routeID)) {
          await connection.closeAndWait();
          return;
        }
        if (connection.socket.readyState !== connection.socket.OPEN) {
          // A close that beats retention is a failed attempt; retained closes run after tracked ownership clears.
          await connection.closeAndWait();
          throw new Error("established socket closed before retention");
        }
        const latencyMS = now() - started;
        activeConnection = connection;
        retained = true;
        sessionAddress = connection.address;
        retryIndex = 0;
        reconnectExhausted = false;
        if (cause.kind === "reconnect") {
          logReconnect("relay_reconnect_succeeded", "info", "connected", {
            retryIndex: cause.retryIndex,
            address: connection.address,
            routeID: identity.routeID,
            latencyMS,
          });
        } else {
          logAuthentication("info", "accepted", {
            address: connection.address,
            routeID: identity.routeID,
            latencyMS,
          });
        }
        connectionStatus = "connected";
        applyStatus();
      } catch (error) {
        if (!isCurrent(generation, identity.routeID)) return;
        const reason = error !== null && typeof error === "object" && "reason" in error &&
            typeof (error as { reason?: unknown }).reason === "string"
          ? (error as { reason: string }).reason
          : "connection_failed";
        let latencyMS: number | undefined;
        try {
          latencyMS = now() - started;
        } catch {
          latencyMS = undefined;
        }
        logAuthentication("warn", "rejected", {
          reason,
          routeID: identity.routeID,
          latencyMS,
        });
        scheduleRetry(identity, generation, reason);
      } finally {
        if (activeAttempt === attempt) activeAttempt = undefined;
      }
    })();
    let trackedTask: Promise<void>;
    trackedTask = operation.finally(() => {
      if (activeTask === trackedTask) activeTask = undefined;
    });

    activeTask = trackedTask;
    await trackedTask;
  };

  function scheduleRetry(identity: ConnectionIdentity, generation: number, reason: string): void {
    if (!isCurrent(generation, identity.routeID) || activeConnection || retryDeadline) return;
    if (retryIndex >= RECONNECT_MAX_RETRIES) {
      if (!reconnectExhausted) {
        reconnectExhausted = true;
        connectionStatus = "disconnected";
        applyStatus();
        logReconnect("relay_reconnect_exhausted", "warn", "exhausted", {
          reason,
          retryIndex,
          routeID: identity.routeID,
        });
      }
      return;
    }
    let delayMS: number;
    try {
      delayMS = reconnectDelayMS(retryIndex, reconnect.randomUnit);
    } catch {
      return;
    }
    const scheduledRetryIndex = retryIndex + 1;
    retryIndex += 1;

    let deadline: ReconnectDeadline | undefined;
    let firedSynchronously = false;
    const fire = () => {
      if (!deadline) {
        firedSynchronously = true;
        return;
      }
      if (retryDeadline?.deadline !== deadline) return;
      retryDeadline = undefined;
      void launchConnection(identity, generation, {
        kind: "reconnect",
        retryIndex: scheduledRetryIndex,
      }).catch(() => undefined);
    };
    try {
      deadline = reconnect.schedule(fire, delayMS);
      if (!deadline || typeof deadline.cancel !== "function") return;
    } catch {
      return;
    }
    logReconnect("relay_reconnect_scheduled", "info", "scheduled", {
      reason,
      retryIndex: scheduledRetryIndex,
      delayMS,
      routeID: identity.routeID,
    });
    connectionStatus = "connecting";
    applyStatus();
    if (firedSynchronously) {
      void launchConnection(identity, generation, {
        kind: "reconnect",
        retryIndex: scheduledRetryIndex,
      }).catch(() => undefined);
      return;
    }
    retryDeadline = { deadline };
  }

  const connectOnce = async (): Promise<void> => {
    const generation = lifecycleGeneration;
    if (!sessionStarted || activeConnection) return;
    if (startupAttempted) return;
    if (activeTask) {
      await activeTask;
      if (!sessionStarted || activeConnection) return;
    }

    let configuration: ClientConfiguration | undefined;
    try {
      configuration = await loadClientConfiguration();
    } catch (error) {
      // An invalid file never degrades to an unauthenticated fallback origin and
      // never crashes the session; it surfaces one closed diagnostic instead.
      startupAttempted = true;
      connectionStatus = "config_rejected";
      applyStatus();
      emitDiagnostic({
        level: "warn",
        event: "relay_config_rejected",
        result: "rejected",
        reason: error instanceof ClientConfigurationError ? error.reason : "config_unreadable",
        secret: REDACTED,
      });
      return;
    }
    startupAttempted = true;
    if (!configuration) {
      // No endpoint configured: render nothing, never a placeholder indicator.
      connectionStatus = undefined;
      applyStatus();
      return;
    }

    let hostname: string;
    try {
      now();
      hostname = operatingSystemHostname();
    } catch {
      return;
    }
    const routeID = sessionRouteID;
    const cwd = sessionCWD;
    const sessionIdle = activeSessionIdle;
    if (!routeID || !cwd || !sessionIdle) return;
    // Fire-and-forget entry: a session_start→shutdown race or a reload must
    // not connect a stale generation over the fresh session's socket.
    if (generation !== lifecycleGeneration) return;

    cancelRetry();
    connectionStatus = "connecting";
    applyStatus();
    const identity: ConnectionIdentity = {
      endpoint: connectEndpoint(configuration.endpoint),
      secret: configuration.secret,
      routeID,
      cwd,
      hostname,
      sessionIdle,
    };
    await launchConnection(identity, lifecycleGeneration, { kind: "startup" });
  };

  const stopSession = async (reportGraceful = false): Promise<void> => {
    const wasStarted = sessionStarted;
    const stoppedRouteID = sessionRouteID;
    const stoppedAddress = sessionAddress;
    sessionStarted = false;
    lifecycleGeneration += 1;
    activeSessionIdle = undefined;
    cancelRetry();
    const task = activeTask;
    activeAttempt?.close();
    if (task) await task;
    const connection = activeConnection;
    activeConnection = undefined;
    if (connection) await connection.closeAndWait();
    retryIndex = 0;
    reconnectExhausted = false;
    sessionRouteID = undefined;
    sessionCWD = undefined;
    sessionAddress = undefined;
    connectionStatus = undefined;
    applyStatus();
    if (reportGraceful && wasStarted) {
      emitDiagnostic({
        level: "info",
        event: "relay_session_stopped",
        result: "graceful",
        ...(stoppedAddress ? { address: stoppedAddress } : {}),
        ...(stoppedRouteID ? { route_id: stoppedRouteID } : {}),
      });
    }
  };

  pi.on("session_start", async (event, ctx) => {
    await stopSession();
    sessionStarted = true;
    const submittedReason = (event as { reason?: unknown }).reason;
    const reason = typeof submittedReason === "string" &&
        ["startup", "reload", "resume", "new", "fork"].includes(submittedReason)
      ? submittedReason
      : "unknown";
    const mayRetainRoute = reason === "startup" || reason === "reload" || reason === "resume";
    const retainedRouteID = mayRetainRoute
      ? retainedSessionRouteID(ctx as unknown as { sessionManager: { getEntries(): unknown[] } })
      : undefined;
    sessionRouteID = retainedRouteID ?? generateUUIDv7(now());
    if (!retainedRouteID) {
      pi.appendEntry(ROUTE_ENTRY_TYPE, {
        version: ROUTE_ENTRY_VERSION,
        route_id: sessionRouteID,
      });
    }
    sessionCWD = ctx.cwd;
    activeSessionIdle = () => ctx.isIdle();
    activeUI = (ctx as { ui?: unknown }).ui;
    // Mute and capture state must be set before the first diagnostic of the
    // session; the previous ordering leaked one relay_session_started line
    // to every TUI transcript on boot.
    diagnosticsMuted = (ctx as { mode?: unknown }).mode === "tui";
    const reportedSessionFile = (ctx as { sessionManager?: { getSessionFile?: () => unknown } })
      .sessionManager?.getSessionFile?.();
    sessionLogPath = diagnosticsMuted && typeof reportedSessionFile === "string"
      ? resolveSessionLogPath(process.env, homedir(), reportedSessionFile)
      : undefined;
    startupAttempted = false;
    emitDiagnostic({
      level: "info",
      event: "relay_session_started",
      result: "started",
      reason,
      route_id: sessionRouteID,
    });
    // Fire-and-forget: a slow or unreachable relay must never delay session
    // start; tools report the disconnected state until the connect lands.
    void connectOnce().catch(() => undefined);
  });

  pi.on("session_shutdown", () => stopSession(true));

  // Inbound relay messages are session messages so the host renders them as a
  // card via the custom renderer below; the plain-text content (protocol v1
  // provenance line) stays the LLM-visible body exactly as before. UI-less or
  // forbidding hosts keep the raw sendUserMessage path.
  const injectInbound = (
    renderedBody: string,
    details: RelayCardDetails | undefined,
    deliverWhileIdle: boolean,
  ): boolean => {
    if (details === undefined || typeof pi.sendMessage !== "function") return false;
    try {
      void pi.sendMessage({
        customType: RELAY_MESSAGE_TYPE,
        content: renderedBody,
        display: true,
        details,
      }, deliverWhileIdle ? { triggerTurn: true } : { deliverAs: "steer" });
      return true;
    } catch {
      return false;
    }
  };

  pi.registerMessageRenderer(RELAY_MESSAGE_TYPE, (message, options, theme) => {
    const details = message.details as RelayCardDetails | undefined;
    if (details === null || typeof details !== "object") return undefined;
    const candidate = theme && typeof theme === "object" ? theme as Partial<CardTheme> : undefined;
    const cardTheme = candidate && typeof candidate.fg === "function"
      ? {
        fg: candidate.fg,
        bold: candidate.bold,
        // Hosts exposing theme.bg paint the intercom-style card background.
        ...(typeof candidate.bg === "function" ? { bg: candidate.bg } : {}),
      }
      : undefined;
    return new RelayCardComponent(details, cardTheme, options.expanded === true);
  });

  // /relay-logs: on-demand diagnostic snapshot. Persisted TUI sessions read
  // their own JSONL log tail; the overlay keeps stderr noise out of the
  // transcript. Headless hosts and in-memory sessions have no file — the
  // command says so, because their stderr stream is already the record.
  pi.registerCommand("relay-logs", {
    description: "Show a snapshot of captured relay diagnostic events",
    handler: async (_args, ctx) => {
      const tailLines = () =>
        sessionLogPath ? readSessionLogTail(sessionLogPath, RELAY_LOG_TAIL_LINES) : Promise.resolve([] as string[]);
      const snapshotText = async () => {
        const lines = await tailLines();
        const header = sessionLogPath
          ? `relay diagnostics — ${lines.length} line(s), max ${RELAY_LOG_TAIL_LINES} — ${sessionLogPath}`
          : "relay diagnostics — no session log (headless host or in-memory session; stderr carries the stream)";
        return [header, ...lines].join("\n");
      };
      const ui = (ctx as { ui?: unknown }).ui as { custom?: unknown } | undefined;
      let overlayFactory: ((
        factory: (tui: unknown, theme: unknown, keybindings: unknown, done: (value: boolean) => void) => unknown,
        options?: { overlay?: boolean },
      ) => Promise<unknown>) | undefined;
      try {
        if (ui && typeof ui.custom === "function") {
          overlayFactory = ui.custom as typeof overlayFactory;
        }
      } catch {
        // Hosts forbidding live UI access fall through to the stderr snapshot.
      }
      if (overlayFactory) {
        try {
          // Load before opening: first paint is never blank, and the async
          // load can never race the host's render pass.
          const initial = await snapshotText();
          await overlayFactory(
            (tui, theme, _keybindings, done) => {
              const cardTheme = theme && typeof theme === "object" &&
                  typeof (theme as CardTheme).fg === "function"
                ? theme as CardTheme
                : undefined;
              return new RelayLogsOverlay(
                snapshotText,
                done,
                cardTheme,
                () => {
                  try {
                    (tui as { requestRender?: () => void } | undefined)?.requestRender?.();
                  } catch {
                    // The refresh render is cosmetic; never surface it.
                  }
                },
                initial,
              );
            },
            {
              overlay: true,
              overlayOptions: { anchor: "center", width: "90%", maxHeight: "80%" },
            },
          );
          return;
        } catch {
          // Overlay unavailable (host without overlay support, UI teardown);
          // fall through to the stderr snapshot.
        }
      }
      const snapshot = await snapshotText();
      for (const line of snapshot.split("\n")) {
        try {
          console.error(line);
        } catch {
          return;
        }
      }
    },
  });

  // Header slot: title, short body preview, destination. renderResult owns
  // the outcome; repeating the title there produced doubled labels.
  const renderSendHeader = (args: Record<string, unknown>, theme: CardTheme): Text => {
    let left = theme.fg("toolTitle", theme.bold("agent_send"));
    const body = args.body;
    if (typeof body === "string") left += theme.fg("muted", ` "${truncateToWidth(body.replace(/\s+/g, " ").trim(), 32)}"`);
    const destination = args.to;
    if (typeof destination === "string") {
      left += theme.fg("muted", " → ") + theme.fg("accent", senderLabel(destination));
    }
    return new Text(left);
  };


  pi.registerTool({
    name: "list_peers",
    label: "List Relay Peers",
    description: "List one address-only page of online Pi relay sessions; the result contains peers and optional next_cursor",
    parameters: listPeersParameters,
    async execute(_toolCallID, params, signal) {
      const connection = activeConnection;
      if (!connection) return disconnected("list_peers");
      try {
        const cursor = (params as { cursor?: string }).cursor;
        const page = await connection.list(cursor, signal as AbortSignal);
        return {
          content: [{ type: "text", text: JSON.stringify(page) }],
          details: page,
        };
      } catch (error) {
        logFailure(
          "list_peers",
          error instanceof RosterRequestError ? error.reason : "unexpected_failure",
        );
        throw error;
      }
    },
    renderCall(_args, theme) {
      return new Text(theme.fg("toolTitle", theme.bold("list_peers")));
    },
    renderResult(result, _options, theme) {
      // Outcome only: the call header already shows the title.
      const details = result.details as { peers?: unknown[] } | undefined;
      const count = Array.isArray(details?.peers) ? details!.peers.length : 0;
      return new Text(theme.fg("muted", "└ ") +
        theme.fg(count > 0 ? "success" : "muted", `${count} online`));
    },
  });

  pi.registerTool({
    name: "agent_send",
    label: "Send to Relay Peer",
    description: "Send a string or JSON object to one online Pi relay session",
    parameters: agentSendParameters,
    async execute(_toolCallID, params, signal) {
      const started = Date.now();
      const input = params as {
        to?: unknown;
        body?: unknown;
        re?: unknown;
      };
      const destination = input.to;
      const body = input.body;
      const replyTo = input.re;
      const connection = activeConnection;
      if (!connection) return disconnected("agent_send", true);
      try {
        const result = await connection.send(
          destination as string,
          body as string | Record<string, unknown>,
          replyTo as string | undefined,
          signal as AbortSignal,
        );
        logSendSettlement(result, connection.address, destination as string, Date.now() - started);
        return {
          content: [{ type: "text", text: JSON.stringify(result) }],
          details: result,
        };
      } catch (error) {
        logFailure(
          "agent_send",
          error instanceof RosterRequestError ? error.reason : "unexpected_failure",
          {
            recipientRoute: typeof destination === "string" ? destination : undefined,
            body: true,
            latencyMS: Date.now() - started,
          },
        );
        throw error;
      }
    },
    renderCall(args, theme) {
      return renderSendHeader(args as Record<string, unknown>, theme as CardTheme);
    },
    renderResult(result, _options, theme) {
      // Outcome only: the call header already shows title, body, destination.
      const details = result.details as Record<string, unknown> | undefined;
      const status = typeof details?.status === "string" ? details.status : undefined;
      const reason = typeof details?.reason === "string" ? details.reason : undefined;
      const text = status === undefined
        ? theme.fg("error", "failed")
        : theme.fg(status === "received" ? "success" : "error", `${status}${reason ? ` (${reason})` : ""}`);
      return new Text(theme.fg("muted", "└ ") + text);
    },
  });
}
