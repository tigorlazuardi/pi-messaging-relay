type SendUserMessage = (
  body: string,
  options?: { deliverAs: "followUp" },
) => void;

/** Captures one recipient session and fails safe when its identity or idle observation is stale. */
export function createRecipientDelivery(
  sendUserMessage: SendUserMessage,
  isIdle: () => boolean,
  isActive: () => boolean,
): (body: string) => void {
  return (body) => {
    let deliverWhileIdle = false;
    try {
      if (isActive()) {
        const observedIdle = isIdle();
        deliverWhileIdle = observedIdle && isActive();
      }
    } catch {
      // Missing or unusable recipient lifecycle state must never steer active work.
    }

    if (deliverWhileIdle) sendUserMessage(body);
    else sendUserMessage(body, { deliverAs: "followUp" });
  };
}
