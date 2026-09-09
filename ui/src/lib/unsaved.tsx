import { useBeforeLeave } from "@solidjs/router";
import { createSignal, onCleanup, onMount, Show, type Accessor, type Component } from "solid-js";
import { t } from "../i18n";

/**
 * Protects unsaved edits. Route changes and page unloads are held while `dirty()`; in-page
 * target changes (another user, another document) go through `request`, which runs the
 * action at once when there is nothing to lose and otherwise parks it until the reader
 * chooses to discard the draft or keep editing. Rendered by `LeavePrompt`.
 */
export type LeaveGuard = {
  /** The parked action, when a prompt is due. */
  pending: Accessor<(() => void) | null>;
  /** Runs `action` now, or parks it behind the prompt while there are unsaved edits. */
  request: (action: () => void) => void;
  /** Discards the draft: runs the parked action. */
  discard: () => void;
  /** Keeps editing: forgets the parked action. */
  keep: () => void;
};

// Scope changes do not pass through the router. Ask each mounted editor before changing
// the header target, using the same prompt as route navigation.
const scopeGuards = new Set<LeaveGuard>();
export const requestScopeChange = (action: () => void): void => {
  const guards = [...scopeGuards];
  const next = (index: number): void => {
    const guard = guards[index];
    if (guard) guard.request(() => next(index + 1));
    else action();
  };
  next(0);
};

export const createLeaveGuard = (dirty: Accessor<boolean>): LeaveGuard => {
  const [pending, setPending] = createSignal<(() => void) | null>(null);
  useBeforeLeave((e) => {
    if (dirty() && !e.defaultPrevented) {
      e.preventDefault();
      setPending(() => () => e.retry(true));
    }
  });
  let draftInput: HTMLInputElement | HTMLTextAreaElement | null = null;
  onMount(() => {
    const rememberInput = (event: FocusEvent) => {
      if (event.target instanceof HTMLInputElement || event.target instanceof HTMLTextAreaElement) {
        draftInput = event.target;
      }
    };
    document.addEventListener("focusin", rememberInput);
    onCleanup(() => document.removeEventListener("focusin", rememberInput));
    const onUnload = (event: BeforeUnloadEvent) => {
      if (dirty()) {
        event.preventDefault();
      }
    };
    window.addEventListener("beforeunload", onUnload);
    onCleanup(() => window.removeEventListener("beforeunload", onUnload));
  });
  const guard: LeaveGuard = {
    pending,
    request: (action) => {
      if (dirty()) {
        setPending(() => action);
      } else {
        action();
      }
    },
    discard: () => {
      const action = pending();
      setPending(null);
      action?.();
    },
    keep: () => {
      setPending(null);
      if (draftInput?.isConnected) draftInput.focus();
    },
  };
  scopeGuards.add(guard);
  onCleanup(() => scopeGuards.delete(guard));
  return guard;
};

/** The inline question a guard asks: what is unsaved, discard it, or keep editing. */
export const LeavePrompt: Component<{ guard: LeaveGuard; subject: string }> = (props) => (
  <Show when={props.guard.pending()}>
    <div
      role="alertdialog"
      aria-live="assertive"
      data-testid="unsaved-prompt"
      class="mb-3 flex flex-wrap items-center gap-2 rounded-md border border-amber-400 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-100"
    >
      <span>{t("app.unsaved", { subject: props.subject })}</span>
      <button
        type="button"
        class="btn btn-danger"
        data-testid="unsaved-discard"
        onClick={props.guard.discard}
      >
        {t("app.discard")}
      </button>
      <button type="button" class="btn" data-testid="unsaved-keep" onClick={props.guard.keep}>
        {t("app.keepEditing")}
      </button>
    </div>
  </Show>
);
