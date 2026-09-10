type CommandRegistration = {
  description?: string;
  handler: (args: string, context: unknown) => Promise<void> | void;
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
  readonly registrations: Array<{ kind: "command" | "tool"; name: string }> = [];
  readonly notifications: Notification[] = [];
  readonly sendMessageAttempts: unknown[] = [];
  readonly sendUserMessageAttempts: unknown[] = [];
  readonly liveAccessAttempts: string[] = [];
  readonly events = new Map<string, EventHandler[]>();
  cwd = "/tmp/fake-pi-session";

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
      sendMessage: (...args: unknown[]) => {
        this.sendMessageAttempts.push(args);
      },
      sendUserMessage: (...args: unknown[]) => {
        this.sendUserMessageAttempts.push(args);
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
      { ui, cwd: this.cwd },
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
