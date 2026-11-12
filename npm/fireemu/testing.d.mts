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
  /** Time budget for the initial input snapshot and each generation copy. */
  readonly snapshotTimeoutMs?: number;
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
  /**
   * Advance the clock, run due virtual timers and wait for idle, in that order. The wait never
   * delays a later clock call. Rejects when the move fails or the wait times out.
   */
  readonly advanceAndSettle: (
    duration: number | { readonly seconds: number; readonly millis?: number } | { readonly millis: number; readonly seconds?: number },
    options?: AwaitIdleOptions,
  ) => Promise<AdvanceAndSettleResult>;
}

/** Cost of one input snapshot or generation copy. */
export interface CopyStats {
  /** Regular files owned by the copy, including generated configuration. */
  readonly files: number;
  readonly directories: number;
  readonly symlinks: number;
  readonly bytes: number;
  /** `clone` when copy-on-write was used for every file, `mixed` for some, `copy` for none. */
  readonly method: 'copy' | 'clone' | 'mixed';
  readonly elapsedMs: number;
}

export interface TestWorldSnapshotStats {
  /** The one-time snapshot of caller inputs. `functions` is `skipped` when no selected service loads Functions. */
  readonly initial: CopyStats & { readonly functions: 'included' | 'skipped' };
  /** One entry per started generation, in order. */
  readonly generations: readonly (CopyStats & { readonly generation: number })[];
}

export interface AwaitIdleOptions {
  /** `runnable` (the default) excludes future task schedules and retry backoff; `all` waits for every outstanding task. */
  readonly scope?: 'all' | 'runnable';
  /** Daemon-side wait budget, 0 through 600 (default 20). */
  readonly timeoutSeconds?: number;
  /** Run due virtual timers after the move. Defaults to true only when Functions runs with `timers: 'virtual'`; the daemon refuses `runDue` otherwise. */
  readonly runTimers?: boolean;
}

export interface AdvanceAndSettleResult {
  readonly clock: ClockState;
  /** The last `runDue` report, or `undefined` when `runTimers` is false. */
  readonly timers: RunDueResult | undefined;
  /** The `awaitIdle` response; the shape follows the daemon's control API. */
  readonly idle: { readonly idle: boolean; readonly scope?: 'all' | 'runnable'; readonly [key: string]: unknown };
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
  readonly snapshotStats: TestWorldSnapshotStats;
  readonly control: (method: string, path: string, body?: unknown) => Promise<unknown>;
  readonly run: (command: string, args?: readonly string[], options?: RunOptions) => Promise<RunResult>;
  readonly reset: () => Promise<TestWorld>;
  readonly dispose: () => Promise<void>;
}

export function createTestWorld(options?: TestWorldOptions): Promise<TestWorld>;
export function withTestWorld<T>(options: TestWorldOptions, callback: (world: TestWorld) => T): Promise<Awaited<T>>;
