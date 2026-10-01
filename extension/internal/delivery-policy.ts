type SendUserMessage = (
  body: string,
  options?: { deliverAs: "followUp" },
) => void;

type InjectInbound = (
  body: string,
  details: RelayCardDetails,
  deliverWhileIdle: boolean,
) => boolean;

/** Structural subset of the inbound card metadata produced by the transport. */
type RelayCardDetails = {
  from: string;
  messageID: string;
  re?: string;
  bodyText: string;
};

/**
 * Captures one recipient session and fails safe when its identity or idle
 * observation is stale. Card injection is tried first so the host renders the
 * inbound message through the relay renderer; any refusal falls back to the
 * original user-message injection with unchanged semantics.
 */
export function createRecipientDelivery(
  sendUserMessage: SendUserMessage,
  isIdle: () => boolean,
  isActive: () => boolean,
  injectInbound?: InjectInbound,
): (body: string, details?: RelayCardDetails) => void {
  return (body, details) => {
    let deliverWhileIdle = false;
    try {
      if (isActive()) {
        const observedIdle = isIdle();
        deliverWhileIdle = observedIdle && isActive();
      }
    } catch {
      // Missing or unusable recipient lifecycle state must never steer active work.
    }

    if (injectInbound && details !== undefined && injectInbound(body, details, deliverWhileIdle)) {
      return;
    }
    if (deliverWhileIdle) sendUserMessage(body);
    else sendUserMessage(body, { deliverAs: "followUp" });
  };
}
