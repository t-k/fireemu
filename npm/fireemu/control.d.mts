/** Environment values may be absent, including when spreading process.env. */
export type Environment = Readonly<Record<string, string | undefined>>;

export type ControlClientOptions = {
  readonly env?: Environment;
  readonly requestTimeoutMs?: number;
} & (
  | { readonly origin: string; readonly apiBaseUrl?: never; readonly token: string }
  | { readonly apiBaseUrl: string; readonly origin?: never; readonly token: string }
  | { readonly origin?: never; readonly apiBaseUrl?: never; readonly token?: string }
);

export interface ControlClient {
  readonly origin: string;
  readonly apiBaseUrl: string;
  /** Responses are unvalidated JSON; narrow them before accessing fields. */
  readonly request: (
    method: string,
    path: string,
    body?: unknown,
    options?: { readonly signal?: AbortSignal },
  ) => Promise<unknown>;
}

/** Explicit endpoints require their own token; environment mode reads FIREEMU_CONTROL_*.
 * URLs, tokens, paths and positive integer timeouts are validated at runtime.
 */
export function createControlClient(options?: ControlClientOptions): ControlClient;
