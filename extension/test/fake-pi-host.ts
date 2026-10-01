type CommandRegistration = {
  description?: string;
  handler: (args: string, context: unknown) => Promise<void> | void;
};

type MessageRendererRegistration = {
  customType: string;
  renderer: unknown;
};

type ToolRegistration = {
  name: string;
  label: string;
  description: string;
  parameters: object;
  execute: (...args: unknown[]) => Promise<unknown> | unknown;
};

type Notification = {
  message: string;
  level: string | undefined;
};

type EventHandler = (event: unknown, context: unknown) => Promise<unknown> | unknown;

export class FakePiHost {
  readonly commands = new Map<string, CommandRegistration>();
  readonly tools = new Map<string, ToolRegistration>();
  readonly messageRenderers = new Map<string, MessageRendererRegistration>();
  readonly registrations: Array<{ kind: "command" | "tool"; name: string }> = [];
  readonly notifications: Notification[] = [];
  readonly sendMessageAttempts: unknown[] = [];
  readonly sendUserMessageAttempts: unknown[] = [];
  readonly appendEntryAttempts: Array<{ customType: string; data: unknown }> = [];
  readonly sessionEntries: Array<{ type: "custom"; customType: string; data: unknown }> = [];
  readonly liveAccessAttempts: string[] = [];
  readonly statusMessages: Array<{ key: string; text: string | undefined }> = [];
  readonly events = new Map<string, EventHandler[]>();
  cwd = "/tmp/fake-pi-session";
  /** Persisted session file reported through ctx.sessionManager; undefined
   * mirrors in-memory sessions, which capture no per-session log. */
  sessionFile: string | undefined = undefined;
  /** Host mode reported on ctx; default mirrors no-UI hosts for diagnostic streaming. */
  mode = "print";
  private idle = true;
  private nextIdleCheckError: Error | undefined;
  private nextSendUserMessageError: Error | undefined;

  readonly api = new Proxy(
    {
      on: (name: string, handler: EventHandler) => {
        const handlers = this.events.get(name) ?? [];
        handlers.push(handler);
        this.events.set(name, handlers);
      },
      registerCommand: (name: string, registration: CommandRegistration) => {
        this.registrations.push({ kind: "command", name });
        this.commands.set(name, registration);
      },
      registerTool: (registration: ToolRegistration) => {
        this.registrations.push({ kind: "tool", name: registration.name });
        this.tools.set(registration.name, registration);
      },
      registerMessageRenderer: (customType: string, renderer: unknown) => {
        this.messageRenderers.set(customType, { customType, renderer });
      },
      sendMessage: (...args: unknown[]) => {
        this.sendMessageAttempts.push(args);
      },
      sendUserMessage: (...args: unknown[]) => {
        this.sendUserMessageAttempts.push(args);
        const error = this.nextSendUserMessageError;
        this.nextSendUserMessageError = undefined;
        if (error) throw error;
      },
      appendEntry: (customType: string, data: unknown) => {
        const entry = { type: "custom" as const, customType, data };
        this.appendEntryAttempts.push({ customType, data });
        this.sessionEntries.push(entry);
      },
    },
    {
      get: (target, property, receiver) => {
        if (Reflect.has(target, property)) {
          return Reflect.get(target, property, receiver);
        }
        const name = String(property);
        this.liveAccessAttempts.push(`pi.${name}`);
        throw new Error(`Fake Pi host forbids live access through pi.${name}`);
      },
    },
  );

  statusFor(key: string): string | undefined {
    for (let index = this.statusMessages.length - 1; index >= 0; index -= 1) {
      if (this.statusMessages[index].key === key) return this.statusMessages[index].text;
    }
    return undefined;
  }

  setIdle(idle: boolean): void {
    this.idle = idle;
  }

  failNextIdleCheck(error: Error): void {
    this.nextIdleCheckError = error;
  }

  failNextSendUserMessage(error: Error): void {
    this.nextSendUserMessageError = error;
  }

  async executeCommand(name: string, args = ""): Promise<void> {
    const command = this.commands.get(name);
    if (!command) throw new Error(`Command not registered: ${name}`);
    await command.handler(args, this.createContext());
  }

  async emit(name: string, event: unknown = {}): Promise<void> {
    for (const handler of this.events.get(name) ?? []) {
      await handler(event, this.createContext());
    }
  }

  async executeTool(name: string, params: unknown): Promise<unknown> {
    const tool = this.tools.get(name);
    if (!tool) throw new Error(`Tool not registered: ${name}`);
    return tool.execute(
      "fake-tool-call-id",
      params,
      new AbortController().signal,
      undefined,
      this.createContext(),
    );
  }

  private createContext(): unknown {
    const ui = new Proxy(
      {
        notify: (message: string, level?: string) => {
          this.notifications.push({ message, level });
        },
        setStatus: (key: string, text?: string) => {
          this.statusMessages.push({ key, text });
        },
        theme: {
          fg: (color: string, text: string) => `${color}:${text}`,
        },
      },
      {
        get: (target, property, receiver) => {
          if (Reflect.has(target, property)) {
            return Reflect.get(target, property, receiver);
          }
          const name = String(property);
          this.liveAccessAttempts.push(`ctx.ui.${name}`);
          throw new Error(`Fake Pi host forbids live UI access through ctx.ui.${name}`);
        },
      },
    );

    return new Proxy(
      {
        ui,
        cwd: this.cwd,
        mode: this.mode,
        sessionManager: {
          getEntries: () => [...this.sessionEntries],
          getSessionFile: () => this.sessionFile,
        },
        isIdle: () => {
          const error = this.nextIdleCheckError;
          this.nextIdleCheckError = undefined;
          if (error) throw error;
          return this.idle;
        },
      },
      {
        get: (target, property, receiver) => {
          if (Reflect.has(target, property)) {
            return Reflect.get(target, property, receiver);
          }
          const name = String(property);
          this.liveAccessAttempts.push(`ctx.${name}`);
          throw new Error(`Fake Pi host forbids live access through ctx.${name}`);
        },
      },
    );
  }
}
