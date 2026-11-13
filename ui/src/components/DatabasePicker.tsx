import { createEffect, createMemo, createSignal, For, Show, type Component } from "solid-js";
import { listDatabases } from "../api/firestore";
import { createScopedFetch } from "../lib/rules-state";
import { t } from "../i18n";

const DatabasePicker: Component<{
  project: string;
  session: string;
  database: string;
  onSelect: (name: string) => void;
}> = (props) => {
  const scope = createMemo(() => JSON.stringify([props.session, props.project]));
  const catalog = createScopedFetch(
    () => JSON.stringify([scope(), props.database]),
    () => listDatabases(props.project),
  );
  const [input, setInput] = createSignal(props.database);
  const [recent, setRecent] = createSignal<string[]>([]);
  createEffect(() => {
    setInput(props.database);
    const key = `fireemu.databases.${scope()}`;
    let previous: unknown = [];
    try {
      previous = JSON.parse(sessionStorage.getItem(key) ?? "[]");
    } catch {
      /* Storage is optional. */
    }
    const names = Array.isArray(previous)
      ? previous.filter((value): value is string => typeof value === "string")
      : [];
    const next = [props.database, ...names.filter((name) => name !== props.database)].slice(0, 8);
    setRecent(next);
    try {
      sessionStorage.setItem(key, JSON.stringify(next));
    } catch {
      /* Storage is optional. */
    }
  });
  const options = () => [...new Set([...(catalog.data() ?? []), ...recent()])];
  return (
    <div>
      <form
        class="flex flex-wrap items-end gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          if (input().trim()) props.onSelect(input().trim());
        }}
      >
        <label class="grid gap-1 text-sm">
          <span>{t("firestore.database")}</span>
          <input
            class="input mono w-40"
            list="firestore-databases"
            data-testid="database-input"
            value={input()}
            required
            onInput={(event) => setInput(event.currentTarget.value)}
          />
        </label>
        <datalist id="firestore-databases" data-testid="database-options">
          <For each={options()}>{(name) => <option value={name}>{name}</option>}</For>
        </datalist>
        <button class="btn" type="submit">
          {t("firestore.databaseOpen")}
        </button>
        <button class="btn" type="button" onClick={() => void catalog.refetch()}>
          {t("app.refresh")}
        </button>
      </form>
      <Show when={recent().length > 1}>
        <p class="mt-1 text-xs text-zinc-500">
          {t("firestore.databaseRecent")}: {recent().join(", ")}
        </p>
      </Show>
      <Show when={catalog.error()}>
        {(message) => (
          <p role="alert">
            {t("firestore.databaseListError", { message: message() })}{" "}
            <button type="button" class="btn" onClick={() => void catalog.refetch()}>
              {t("app.retry")}
            </button>
          </p>
        )}
      </Show>
      <Show
        when={
          catalog.data() &&
          !catalog.loading() &&
          !catalog.error() &&
          !catalog.data()!.includes(props.database)
        }
      >
        <p role="status">{t("firestore.databaseMissing", { name: props.database })}</p>
      </Show>
    </div>
  );
};
export default DatabasePicker;
