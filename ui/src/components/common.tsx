import { createSignal, Show, type Component, type JSX } from "solid-js";
import { t } from "../i18n";
import { createSubmitGuard } from "../lib/submitGuard";

/** An error line (hidden while empty). */
export const ErrorBanner: Component<{ message: string | null | undefined }> = (props) => (
  <Show when={props.message}>
    <div
      role="alert"
      class="mb-3 rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-800 dark:border-red-800 dark:bg-red-950 dark:text-red-200"
    >
      {props.message}
    </div>
  </Show>
);

/** A short success line. */
export const Notice: Component<{ message: string | null | undefined }> = (props) => (
  <Show when={props.message}>
    <div
      role="status"
      class="mb-3 rounded-md border border-emerald-300 bg-emerald-50 px-3 py-2 text-sm text-emerald-800 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-200"
    >
      {props.message}
    </div>
  </Show>
);

export const Section: Component<{ title: string; actions?: JSX.Element; children: JSX.Element }> = (
  props,
) => (
  <section class="card mb-4">
    <div class="mb-3 flex items-center justify-between gap-2">
      <h2 class="text-base font-semibold">{props.title}</h2>
      <div class="flex items-center gap-2">{props.actions}</div>
    </div>
    {props.children}
  </section>
);

/**
 * A button running an asynchronous action once at a time (synchronous re-entry guard plus
 * `disabled` while pending).
 */
export const AsyncButton: Component<{
  onClick: () => Promise<unknown>;
  class?: string | undefined;
  disabled?: boolean | undefined;
  children: JSX.Element;
  testId?: string | undefined;
}> = (props) => {
  const guard = createSubmitGuard();
  return (
    <button
      type="button"
      class={props.class ?? "btn"}
      disabled={props.disabled || guard.pending()}
      aria-busy={guard.pending()}
      data-testid={props.testId}
      onClick={() => void guard.run(props.onClick)}
    >
      {props.children}
    </button>
  );
};

/**
 * A destructive action in two clicks: the first shows the question with confirm / cancel
 * buttons inline (no browser dialog), the second runs it.
 */
export const ConfirmButton: Component<{
  label: string;
  question: string;
  /** What the action reaches (project, session, path, recursion, undo), for heavy actions. */
  details?: string | undefined;
  onConfirm: () => Promise<unknown>;
  class?: string | undefined;
  testId?: string | undefined;
}> = (props) => {
  const [asking, setAsking] = createSignal(false);
  return (
    <Show
      when={asking()}
      fallback={
        <button
          type="button"
          class={props.class ?? "btn btn-danger"}
          data-testid={props.testId}
          onClick={() => setAsking(true)}
        >
          {props.label}
        </button>
      }
    >
      <span
        class="inline-flex flex-wrap items-center gap-2 rounded-md border border-red-300 bg-red-50 px-2 py-1 text-sm dark:border-red-800 dark:bg-red-950"
        role="alertdialog"
      >
        <span>
          <span class="font-semibold">{props.question}</span>
          <Show when={props.details}>
            <span class="block text-xs text-zinc-600 dark:text-zinc-300">{props.details}</span>
          </Show>
        </span>
        <AsyncButton
          class="btn btn-danger"
          testId={props.testId ? `${props.testId}-confirm` : undefined}
          onClick={async () => {
            await props.onConfirm();
            setAsking(false);
          }}
        >
          {t("app.confirm")}
        </AsyncButton>
        <button type="button" class="btn" onClick={() => setAsking(false)}>
          {t("app.cancel")}
        </button>
      </span>
    </Show>
  );
};

/** A key / value row for detail views. */
export const Field: Component<{ label: string; children: JSX.Element; mono?: boolean }> = (
  props,
) => (
  <div class="mb-2">
    <div class="label">{props.label}</div>
    <div class={props.mono ? "mono break-all" : "text-sm break-all"}>{props.children}</div>
  </div>
);

/**
 * A read-only value with a copy button. The value is rendered from the signal it is given
 * and is never written anywhere else: the caller owns its lifetime.
 */
export const CopyField: Component<{
  label: string;
  value: string;
  testId?: string | undefined;
}> = (props) => {
  const [copied, setCopied] = createSignal(false);
  const [field, setField] = createSignal<HTMLInputElement | undefined>();
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(props.value);
    } catch {
      // No clipboard permission (or no clipboard at all): select the text so the reader can
      // copy it by hand rather than losing a value that is shown exactly once.
      field()?.select();
    }
    setCopied(true);
  };
  return (
    <div class="mb-2">
      <label class="label" for={props.testId}>
        {props.label}
      </label>
      <div class="flex items-center gap-2">
        <input
          id={props.testId}
          ref={setField}
          class="input mono"
          readOnly
          value={props.value}
          data-testid={props.testId}
          onFocus={(e) => e.currentTarget.select()}
        />
        <AsyncButton onClick={copy} testId={props.testId ? `${props.testId}-copy` : undefined}>
          {copied() ? t("app.copied") : t("app.copy")}
        </AsyncButton>
      </div>
    </div>
  );
};

/**
 * The state of a fetched list or record, told apart so a failure never reads as "empty":
 * loading (nothing shown yet), failed (with retry), stale (an older successful read is shown
 * because the latest refresh failed), empty, or the content.
 */
export const FetchState: Component<{
  loading: boolean;
  error?: string | null | undefined;
  stale?: string | null | undefined;
  onRetry?: (() => Promise<unknown>) | undefined;
  empty?: boolean | undefined;
  emptyMessage?: string | undefined;
  children: JSX.Element;
}> = (props) => (
  <Show
    when={!props.error}
    fallback={
      <div
        role="alert"
        data-testid="fetch-error"
        class="mb-3 flex flex-wrap items-center gap-2 rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-800 dark:border-red-800 dark:bg-red-950 dark:text-red-200"
      >
        <span class="font-semibold">{t("app.fetchFailed")}</span>
        <span class="break-all">{props.error}</span>
        <Show when={props.onRetry}>
          {(retry) => (
            <AsyncButton class="btn" onClick={retry()} testId="fetch-retry">
              {t("app.retry")}
            </AsyncButton>
          )}
        </Show>
      </div>
    }
  >
    <Show when={!props.loading} fallback={<Spinner />}>
      <Show when={props.stale}>
        <div
          role="status"
          data-testid="fetch-stale"
          class="mb-3 flex flex-wrap items-center gap-2 rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-100"
        >
          <span class="font-semibold">{t("app.fetchStale")}</span>
          <span class="break-all">{props.stale}</span>
          <Show when={props.onRetry}>
            {(retry) => (
              <AsyncButton class="btn" onClick={retry()}>
                {t("app.retry")}
              </AsyncButton>
            )}
          </Show>
        </div>
      </Show>
      <Show
        when={!props.empty}
        fallback={<p class="text-sm text-zinc-500">{props.emptyMessage ?? t("app.none")}</p>}
      >
        {props.children}
      </Show>
    </Show>
  </Show>
);

export const Spinner: Component = () => (
  <span class="text-sm text-zinc-500" role="status">
    {t("app.loading")}
  </span>
);
