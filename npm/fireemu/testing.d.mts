import type { Environment } from './control.mjs';
export type { Environment } from './control.mjs';

/** Codebase suffixes must match [A-Za-z0-9_-]+; this is checked at runtime. */
export type TestWorldService = 'auth' | 'firestore' | 'storage' | 'functions' | `functions:${string}` | 'pubsub' | 'database' | 'appcheck';

export interface TestWorldOptions {
  readonly binaryPath?: string;
  readonly tempRoot?: string;
  readonly cwd?: string;
  readonly firebaseJson?: string;
  readonly functionsSource?: string;
  readonly import?: string;
  readonly projectId?: string;
  readonly clockStart?: string;
  /** A path or extensible configuration object; backend validation remains authoritative. */
  readonly config?: string | Readonly<Record<string, unknown>>;
  readonly services?: readonly [TestWorldService, ...TestWorldService[]];
  readonly hub?: boolean;
  readonly ui?: boolean;
  readonly seed?: number;
  readonly startupTimeoutMs?: number;
  readonly shutdownTimeoutMs?: number;
  readonly requestTimeoutMs?: number;
  readonly signal?: AbortSignal;
  readonly nodePathExcludes?: readonly string[];
  readonly env?: Environment;
  readonly clock?: {
    readonly date?: 'real' | 'virtual';
    readonly timers?: 'real' | 'virtual';
    readonly tasks?: 'real' | 'virtual';
  };
}

export interface Endpoint {
  readonly host: string;
  readonly port: number;
  readonly url: string;
}

export interface TestWorldEndpoints {
  readonly control: Endpoint & { readonly origin: string; readonly apiBaseUrl: string };
  readonly firestore?: Endpoint;
  readonly auth?: Endpoint;
  readonly storage?: Endpoint;
  readonly functions?: Endpoint;
  readonly eventarc?: Endpoint;
  readonly tasks?: Endpoint;
  readonly pubsub?: Endpoint;
  readonly database?: Endpoint;
  readonly hub?: Endpoint;
  readonly logging?: Endpoint;
}

export interface ClockState {
  clock: string;
  backwardsSets: number;
}

export interface ClockSession {
  session: string;
  edition: string;
  requireDemoPrefix: boolean;
  clock: ClockState;
}

/** Timer reports follow the bundled Node runner protocol, not arbitrary custom runners. */
export interface RunDueResult {
  codebases: Array<{
    codebase: string;
    timers: {
      executed: number;
      pending: number;
      due: number;
      instantNanos: string;
      elapsedNanos: string;
    };
  }>;
}

export interface TestWorldClock {
  readonly get: () => Promise<ClockSession>;
  readonly set: (instant: string, options?: { readonly allowBackwards?: boolean }) => Promise<ClockState>;
  readonly advance: (duration: number | { readonly seconds: number; readonly millis?: number } | { readonly millis: number; readonly seconds?: number }) => Promise<ClockState>;
  readonly advanceTo: (instant: string) => Promise<ClockState>;
  /** The runtime requires an integer budget from 1 through 10000. */
  readonly runDue: (budget?: number) => Promise<RunDueResult>;
}

export interface RunOptions {
  readonly cwd?: string;
  readonly env?: Environment;
  readonly stdio?: 'pipe' | 'inherit';
  readonly signal?: AbortSignal;
}

export interface RunResult {
  code: number | null;
  signal: string | null;
  stdout: string;
  stderr: string;
}

/** Frozen world; generation-scoped getters and operations may reject or throw after disposal. */
export interface TestWorld {
  readonly id: string;
  readonly projectId: string;
  readonly generation: number;
  readonly directory: string;
  readonly uiUrl: string | undefined;
  readonly endpoints: TestWorldEndpoints;
  readonly environment: Environment;
  readonly clock: TestWorldClock;
  readonly control: (method: string, path: string, body?: unknown) => Promise<unknown>;
  readonly run: (command: string, args?: readonly string[], options?: RunOptions) => Promise<RunResult>;
  readonly reset: () => Promise<TestWorld>;
  readonly dispose: () => Promise<void>;
}

export function createTestWorld(options?: TestWorldOptions): Promise<TestWorld>;
export function withTestWorld<T>(options: TestWorldOptions, callback: (world: TestWorld) => T): Promise<Awaited<T>>;
