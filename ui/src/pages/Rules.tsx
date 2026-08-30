import { createResource, createSignal, Show, type Component } from "solid-js";
import { t } from "../i18n";
import { appState } from "../state";
import {
  AsyncButton,
  ConfirmButton,
  ErrorBanner,
  Notice,
  Section,
  Spinner,
} from "../components/common";
import { dropRules, getRules, putRules } from "../api/control";
import { settle } from "../api/client";

const RulesEditor: Component<{ which: "firestore" | "storage"; title: string }> = (props) => {
  const [info, { refetch }] = createResource(() => settle(getRules(props.which)));
  const [draft, setDraft] = createSignal<string | null>(null);
  const [error, setError] = createSignal<string | null>(null);
  const [notice, setNotice] = createSignal<string | null>(null);
  const source = () =>
    draft() ??
    info()
      ?.map((i) => i.source)
      .unwrapOr("") ??
    "";
  const loaded = () =>
    info()
      ?.map((i) => i.loaded)
      .unwrapOr(false) ?? false;
  const save = async () => {
    setError(null);
    setNotice(null);
    const result = await putRules(props.which, source());
    result.match(
      () => {
        setNotice(t("rules.saved"));
        setDraft(null);
        void refetch();
      },
      (e) => setError(e.message),
    );
  };
  const drop = async () => {
    setError(null);
    const result = await dropRules(props.which);
    result.match(
      () => {
        setDraft(null);
        void refetch();
      },
      (e) => setError(e.message),
    );
  };
  return (
    <Section
      title={props.title}
      actions={
        <>
          <span
            class={`badge ${loaded() ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-900 dark:text-emerald-100" : "bg-zinc-200 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"}`}
          >
            {loaded() ? t("rules.loaded") : t("rules.notLoaded")}
          </span>
          <AsyncButton class="btn btn-primary" onClick={save} testId={`rules-${props.which}-save`}>
            {t("rules.replace")}
          </AsyncButton>
          <ConfirmButton
            label={t("rules.drop")}
            question={t("rules.dropConfirm", { which: props.which })}
            onConfirm={drop}
            testId={`rules-${props.which}-drop`}
          />
        </>
      }
    >
      <ErrorBanner message={error()} />
      <Notice message={notice()} />
      <Show when={!info.loading} fallback={<Spinner />}>
        <label class="label" for={`rules-${props.which}`}>
          {t("rules.source")}
        </label>
        <textarea
          id={`rules-${props.which}`}
          class="input mono h-72"
          spellcheck={false}
          value={source()}
          onInput={(e) => setDraft(e.currentTarget.value)}
        />
      </Show>
    </Section>
  );
};

const Rules: Component = () => (
  <div>
    <h1 class="mb-4 text-xl font-bold">{t("rules.title")}</h1>
    <Show when={!appState.config().rulesEnforced}>
      <div class="mb-4 rounded-md border border-amber-400 bg-amber-50 p-3 text-sm dark:bg-amber-900/30">
        {t("rules.enforcedOff")}
      </div>
    </Show>
    <RulesEditor which="firestore" title={t("rules.firestore")} />
    <RulesEditor which="storage" title={t("rules.storage")} />
  </div>
);

export default Rules;
