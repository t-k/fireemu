import { createSignal, For, type Component } from "solid-js";
import { t } from "../i18n";
import { AsyncButton, ErrorBanner, Notice, Section } from "../components/common";
import { publishAlert } from "../api/control";
import { ALERT_TYPES, examplePayload } from "../lib/alertTypes";

/**
 * Synthesises a Firebase alert the way the official Emulator Suite UI does: it publishes a
 * CloudEvent onto the Eventarc `google` channel through `/google/publishEvents`, which fires
 * every registered `onAlertPublished` handler for the chosen alerttype. This is the official
 * delivery path, not a fireemu-only injection; the answer reports how many handlers received
 * the alert.
 */
const Alerts: Component = () => {
  const [alertType, setAlertType] = createSignal(ALERT_TYPES[0]?.alerttype ?? "");
  const [appId, setAppId] = createSignal("");
  const [payload, setPayload] = createSignal(JSON.stringify(examplePayload(alertType()), null, 2));
  const [error, setError] = createSignal<string | null>(null);
  const [notice, setNotice] = createSignal<string | null>(null);

  const onTypeChange = (value: string) => {
    setAlertType(value);
    setPayload(JSON.stringify(examplePayload(value), null, 2));
  };

  const publish = async () => {
    setError(null);
    setNotice(null);
    let parsed: unknown;
    try {
      parsed = JSON.parse(payload());
    } catch (e) {
      setError(t("alerts.badJson", { error: String(e) }));
      return;
    }
    const result = await publishAlert(alertType(), parsed, appId() || undefined);
    result.match(
      (r) => setNotice(t("alerts.delivered", { count: String(r.delivered) })),
      (e) => setError(e.message),
    );
  };

  return (
    <div>
      <h1 class="mb-4 text-xl font-bold">{t("alerts.title")}</h1>
      <p class="mb-4 text-sm text-zinc-600 dark:text-zinc-300">{t("alerts.intro")}</p>
      <Section title={t("alerts.publish")}>
        <ErrorBanner message={error()} />
        <Notice message={notice()} />
        <label class="label" for="alert-type">
          {t("alerts.type")}
        </label>
        <select
          id="alert-type"
          class="input"
          data-testid="alert-type"
          value={alertType()}
          onChange={(e) => onTypeChange(e.currentTarget.value)}
        >
          <For each={ALERT_TYPES}>
            {(a) => (
              <option value={a.alerttype}>
                {a.product} — {a.alerttype}
              </option>
            )}
          </For>
        </select>
        <label class="label mt-3" for="alert-appid">
          {t("alerts.appId")}
        </label>
        <input
          id="alert-appid"
          class="input"
          data-testid="alert-appid"
          placeholder="1:1234567890:web:abc"
          value={appId()}
          onInput={(e) => setAppId(e.currentTarget.value)}
        />
        <label class="label mt-3" for="alert-payload">
          {t("alerts.payload")}
        </label>
        <textarea
          id="alert-payload"
          class="input mono h-56"
          spellcheck={false}
          data-testid="alert-payload"
          value={payload()}
          onInput={(e) => setPayload(e.currentTarget.value)}
        />
        <div class="mt-3">
          <AsyncButton class="btn btn-primary" onClick={publish} testId="alert-publish">
            {t("alerts.publishButton")}
          </AsyncButton>
        </div>
      </Section>
    </div>
  );
};

export default Alerts;
