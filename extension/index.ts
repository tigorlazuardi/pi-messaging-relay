import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

const DISCONNECTED_ERROR =
  "Relay is disconnected. /relay-pair is unavailable in this shell; install a relay-enabled release before retrying.";
const PAIRING_UNAVAILABLE =
  "Pairing unavailable: no pairing occurred and the relay remains disconnected. Install a relay-enabled release before retrying.";

const listPeersParameters = Type.Object({}, { additionalProperties: false });
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
        minLength: 1,
        description: "Original message ID when sending a reply",
      }),
    ),
  },
  { additionalProperties: false },
);

function logFailure(operation: string, reason: "disconnected" | "not_implemented"): void {
  console.error(
    JSON.stringify({
      level: "warn",
      event: "relay_operation_failed",
      operation,
      reason,
    }),
  );
}

function disconnected(operation: "list_peers" | "agent_send"): never {
  logFailure(operation, "disconnected");
  throw new Error(DISCONNECTED_ERROR);
}

export default function relayExtension(pi: ExtensionAPI): void {
  pi.registerCommand("relay-pair", {
    description: "Pair this Pi installation with a relay server",
    handler: async (_args, ctx) => {
      logFailure("relay-pair", "not_implemented");
      ctx.ui.notify(PAIRING_UNAVAILABLE, "error");
    },
  });

  pi.registerTool({
    name: "list_peers",
    label: "List Relay Peers",
    description: "List other authenticated Pi relay sessions that are currently online",
    parameters: listPeersParameters,
    async execute() {
      return disconnected("list_peers");
    },
  });

  pi.registerTool({
    name: "agent_send",
    label: "Send to Relay Peer",
    description: "Send a string or JSON object body to one online Pi relay session",
    parameters: agentSendParameters,
    async execute() {
      return disconnected("agent_send");
    },
  });
}
