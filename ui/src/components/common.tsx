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
      <span class="inline-flex items-center gap-2 text-sm">
        <span>{props.question}</span>
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

export const Spinner: Component = () => (
  <span class="text-sm text-zinc-500" role="status">
    {t("app.loading")}
  </span>
);
