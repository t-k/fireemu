import { createResource, createSignal, For, Show, type Component } from "solid-js";
import { t } from "../i18n";
import { appState } from "../state";
import {
  AsyncButton,
  ConfirmButton,
  ErrorBanner,
  Field,
  Notice,
  Section,
  Spinner,
} from "../components/common";
import {
  createUser,
  deleteAllUsers,
  deleteUser,
  listOobCodes,
  listUsers,
  listVerificationCodes,
  lookupUser,
  updateUser,
  type UserInfo,
  type UserUpdate,
} from "../api/auth";
import { settle } from "../api/client";

const formatMillis = (value: string | undefined): string => {
  if (!value) return "";
  const n = Number(value);
  return Number.isFinite(n) ? new Date(n).toISOString() : value;
};

const NewUserForm: Component<{ project: string; onDone: () => void; onCancel: () => void }> = (
  props,
) => {
  const [email, setEmail] = createSignal("");
  const [password, setPassword] = createSignal("");
  const [phone, setPhone] = createSignal("");
  const [displayName, setDisplayName] = createSignal("");
  const [uid, setUid] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);
  const save = async () => {
    setError(null);
    const user = {
      ...(email() ? { email: email() } : {}),
      ...(password() ? { password: password() } : {}),
      ...(phone() ? { phoneNumber: phone() } : {}),
      ...(displayName() ? { displayName: displayName() } : {}),
      ...(uid() ? { localId: uid() } : {}),
    };
    const r = await createUser(props.project, user);
    r.match(
      () => props.onDone(),
      (e) => setError(e.message),
    );
  };
  return (
    <div class="card mb-4" data-testid="new-user">
      <h3 class="mb-2 font-semibold">{t("auth.addUser")}</h3>
      <ErrorBanner message={error()} />
      <div class="grid gap-2 md:grid-cols-2">
        <label class="text-sm">
          <span class="label">{t("auth.email")}</span>
          <input
            class="input"
            data-testid="new-user-email"
            value={email()}
            onInput={(e) => setEmail(e.currentTarget.value)}
          />
        </label>
        <label class="text-sm">
          <span class="label">{t("auth.password")}</span>
          <input
            class="input"
            type="password"
            data-testid="new-user-password"
            value={password()}
            onInput={(e) => setPassword(e.currentTarget.value)}
          />
        </label>
        <label class="text-sm">
          <span class="label">{t("auth.phone")}</span>
          <input
            class="input"
            placeholder="+15555550100"
            value={phone()}
            onInput={(e) => setPhone(e.currentTarget.value)}
          />
        </label>
        <label class="text-sm">
          <span class="label">{t("auth.displayName")}</span>
          <input
            class="input"
            data-testid="new-user-name"
            value={displayName()}
            onInput={(e) => setDisplayName(e.currentTarget.value)}
          />
        </label>
        <label class="text-sm">
          <span class="label">{t("auth.uid")}</span>
          <input
            class="input mono"
            placeholder={t("auth.uidOptional")}
            value={uid()}
            onInput={(e) => setUid(e.currentTarget.value)}
          />
        </label>
      </div>
      <div class="mt-3 flex gap-2">
        <AsyncButton class="btn btn-primary" onClick={save} testId="new-user-save">
          {t("app.save")}
        </AsyncButton>
        <button type="button" class="btn" onClick={props.onCancel}>
          {t("app.cancel")}
        </button>
      </div>
    </div>
  );
};

const UserEditor: Component<{
  project: string;
  user: UserInfo;
  onSaved: () => void;
  onClose: () => void;
}> = (props) => {
  const [email, setEmail] = createSignal(props.user.email ?? "");
  const [password, setPassword] = createSignal("");
  const [phone, setPhone] = createSignal(props.user.phoneNumber ?? "");
  const [displayName, setDisplayName] = createSignal(props.user.displayName ?? "");
  const [photoUrl, setPhotoUrl] = createSignal(props.user.photoUrl ?? "");
  const [verified, setVerified] = createSignal(props.user.emailVerified ?? false);
  const [claims, setClaims] = createSignal(props.user.customAttributes ?? "{}");
  const [error, setError] = createSignal<string | null>(null);
  const [notice, setNotice] = createSignal<string | null>(null);
  const apply = async (update: Omit<UserUpdate, "localId">) => {
    setError(null);
    setNotice(null);
    const r = await updateUser(props.project, { localId: props.user.localId, ...update });
    r.match(
      () => {
        setNotice(t("app.save"));
        props.onSaved();
      },
      (e) => setError(e.message),
    );
  };
  const save = async () => {
    let parsedClaims: unknown;
    try {
      parsedClaims = JSON.parse(claims() || "{}");
    } catch {
      setError(t("auth.customClaimsInvalid"));
      return;
    }
    if (!parsedClaims || typeof parsedClaims !== "object" || Array.isArray(parsedClaims)) {
      setError(t("auth.customClaimsInvalid"));
      return;
    }
    const deleteAttribute: string[] = [];
    if (!displayName() && props.user.displayName) deleteAttribute.push("DISPLAY_NAME");
    if (!photoUrl() && props.user.photoUrl) deleteAttribute.push("PHOTO_URL");
    await apply({
      ...(email() ? { email: email() } : {}),
      ...(password() ? { password: password() } : {}),
      ...(phone() ? { phoneNumber: phone() } : {}),
      ...(displayName() ? { displayName: displayName() } : {}),
      ...(photoUrl() ? { photoUrl: photoUrl() } : {}),
      emailVerified: verified(),
      customAttributes: JSON.stringify(parsedClaims),
      ...(deleteAttribute.length > 0 ? { deleteAttribute } : {}),
    });
  };
  const withdraw = (enrollmentId: string) =>
    apply({
      mfa: {
        enrollments: (props.user.mfaInfo ?? []).filter((m) => m.mfaEnrollmentId !== enrollmentId),
      },
    });
  return (
    <div class="card mb-4" data-testid="user-editor">
      <div class="mb-2 flex items-center justify-between">
        <h3 class="font-semibold">{t("auth.editUser")}</h3>
        <button type="button" class="btn" onClick={props.onClose}>
          {t("app.close")}
        </button>
      </div>
      <ErrorBanner message={error()} />
      <Notice message={notice()} />
      <Field label={t("auth.uid")} mono>
        {props.user.localId}
      </Field>
      <div class="grid gap-2 md:grid-cols-2">
        <label class="text-sm">
          <span class="label">{t("auth.email")}</span>
          <input
            class="input"
            data-testid="edit-email"
            value={email()}
            onInput={(e) => setEmail(e.currentTarget.value)}
          />
        </label>
        <label class="text-sm">
          <span class="label">{t("auth.password")}</span>
          <input
            class="input"
            type="password"
            placeholder={t("auth.passwordKeep")}
            value={password()}
            onInput={(e) => setPassword(e.currentTarget.value)}
          />
        </label>
        <label class="text-sm">
          <span class="label">{t("auth.phone")}</span>
          <input class="input" value={phone()} onInput={(e) => setPhone(e.currentTarget.value)} />
        </label>
        <label class="text-sm">
          <span class="label">{t("auth.displayName")}</span>
          <input
            class="input"
            data-testid="edit-name"
            value={displayName()}
            onInput={(e) => setDisplayName(e.currentTarget.value)}
          />
        </label>
        <label class="text-sm">
          <span class="label">{t("auth.photoUrl")}</span>
          <input
            class="input"
            value={photoUrl()}
            onInput={(e) => setPhotoUrl(e.currentTarget.value)}
          />
        </label>
        <label class="flex items-center gap-2 pt-4 text-sm">
          <input
            type="checkbox"
            checked={verified()}
            onChange={(e) => setVerified(e.currentTarget.checked)}
          />
          {t("auth.emailVerified")}
        </label>
      </div>
      <label class="mt-2 block text-sm">
        <span class="label">{t("auth.customClaims")}</span>
        <textarea
          class="input mono h-20"
          data-testid="edit-claims"
          value={claims()}
          onInput={(e) => setClaims(e.currentTarget.value)}
        />
      </label>
      <div class="mt-3">
        <div class="label">{t("auth.mfa")}</div>
        <Show
          when={(props.user.mfaInfo?.length ?? 0) > 0}
          fallback={<p class="text-sm text-zinc-500">{t("auth.mfaNone")}</p>}
        >
          <ul class="space-y-1 text-sm">
            <For each={props.user.mfaInfo ?? []}>
              {(m) => (
                <li class="flex items-center gap-2">
                  <span class="mono">{m.mfaEnrollmentId}</span>
                  <span>{m.phoneInfo ?? (m.totpInfo ? "TOTP" : "")}</span>
                  <span class="text-zinc-500">{m.displayName}</span>
                  <AsyncButton class="btn" onClick={() => withdraw(m.mfaEnrollmentId)}>
                    {t("auth.mfaWithdraw")}
                  </AsyncButton>
                </li>
              )}
            </For>
          </ul>
        </Show>
      </div>
      <div class="mt-3 flex flex-wrap gap-2">
        <AsyncButton class="btn btn-primary" onClick={save} testId="edit-save">
          {t("app.save")}
        </AsyncButton>
        <AsyncButton
          class="btn"
          onClick={() => apply({ disableUser: !props.user.disabled })}
          testId="edit-toggle-disabled"
        >
          {props.user.disabled ? t("auth.enable") : t("auth.disable")}
        </AsyncButton>
      </div>
    </div>
  );
};

const Auth: Component = () => {
  const project = appState.project;
  const [query, setQuery] = createSignal("");
  const [users, setUsers] = createSignal<UserInfo[]>([]);
  const [nextToken, setNextToken] = createSignal<string | undefined>(undefined);
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [notice, setNotice] = createSignal<string | null>(null);
  const [adding, setAdding] = createSignal(false);
  const [selected, setSelected] = createSignal<string | null>(null);
  const [codes, { refetch: refetchCodes }] = createResource(project, (p) =>
    settle(listOobCodes(p)),
  );
  const [phoneCodes, { refetch: refetchPhoneCodes }] = createResource(project, (p) =>
    settle(listVerificationCodes(p)),
  );

  const load = async (token?: string) => {
    setLoading(true);
    setError(null);
    const q = query().trim();
    const r = q && !token ? await lookupUser(project(), q) : await listUsers(project(), token);
    setLoading(false);
    r.match(
      (page) => {
        setUsers(token ? [...users(), ...(page.users ?? [])] : (page.users ?? []));
        setNextToken(q ? undefined : page.nextPageToken);
      },
      (e) => {
        if (e.status === 400 && e.message.startsWith("USER_NOT_FOUND")) {
          setUsers([]);
          setNextToken(undefined);
        } else {
          setError(e.message);
        }
      },
    );
  };
  const refreshAll = async () => {
    await load();
    void refetchCodes();
    void refetchPhoneCodes();
  };
  void load();
  const selectedUser = () => users().find((u) => u.localId === selected()) ?? null;
  return (
    <div>
      <h1 class="mb-4 text-xl font-bold">{t("auth.title")}</h1>
      <Section
        title={t("auth.users")}
        actions={
          <>
            <input
              class="input w-64"
              data-testid="user-search"
              placeholder={t("auth.search")}
              value={query()}
              onInput={(e) => setQuery(e.currentTarget.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void load();
              }}
            />
            <AsyncButton class="btn" onClick={() => refreshAll()} testId="user-refresh">
              {t("app.refresh")}
            </AsyncButton>
            <button
              type="button"
              class="btn btn-primary"
              data-testid="add-user"
              onClick={() => setAdding(true)}
            >
              {t("auth.addUser")}
            </button>
            <ConfirmButton
              label={t("auth.deleteAll")}
              question={t("auth.deleteAllConfirm", { project: project() })}
              testId="delete-all-users"
              onConfirm={async () => {
                const r = await deleteAllUsers(project());
                r.match(
                  () => {
                    setSelected(null);
                    void refreshAll();
                  },
                  (e) => setError(e.message),
                );
              }}
            />
          </>
        }
      >
        <ErrorBanner message={error()} />
        <Notice message={notice()} />
        <Show when={adding()}>
          <NewUserForm
            project={project()}
            onDone={() => {
              setAdding(false);
              setNotice(t("app.create"));
              void refreshAll();
            }}
            onCancel={() => setAdding(false)}
          />
        </Show>
        <Show when={selectedUser()}>
          {(u) => (
            <UserEditor
              project={project()}
              user={u()}
              onSaved={() => void refreshAll()}
              onClose={() => setSelected(null)}
            />
          )}
        </Show>
        <Show when={!loading() || users().length > 0} fallback={<Spinner />}>
          <Show
            when={users().length > 0}
            fallback={<p class="text-sm text-zinc-500">{t("auth.noUsers")}</p>}
          >
            <table class="table" data-testid="user-table">
              <thead>
                <tr>
                  <th>{t("auth.uid")}</th>
                  <th>{t("auth.email")}</th>
                  <th>{t("auth.phone")}</th>
                  <th>{t("auth.displayName")}</th>
                  <th>{t("auth.providers")}</th>
                  <th>{t("auth.created")}</th>
                  <th>{t("auth.lastSignIn")}</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                <For each={users()}>
                  {(u) => (
                    <tr
                      class={u.disabled ? "opacity-60" : ""}
                      data-testid={`user-row-${u.localId}`}
                    >
                      <td class="mono">
                        <button
                          type="button"
                          class="text-amber-700 hover:underline dark:text-amber-300"
                          onClick={() => setSelected(u.localId)}
                        >
                          {u.localId}
                        </button>
                      </td>
                      <td>
                        {u.email}
                        <Show when={u.emailVerified}>
                          <span class="ml-1 text-xs text-emerald-600">
                            ({t("auth.emailVerified")})
                          </span>
                        </Show>
                      </td>
                      <td class="mono">{u.phoneNumber}</td>
                      <td>{u.displayName}</td>
                      <td class="text-xs">
                        {(u.providerUserInfo ?? []).map((p) => p.providerId).join(", ")}
                      </td>
                      <td class="mono text-xs">{formatMillis(u.createdAt)}</td>
                      <td class="mono text-xs">{formatMillis(u.lastLoginAt)}</td>
                      <td class="text-right">
                        <Show when={u.disabled}>
                          <span class="badge bg-zinc-200 dark:bg-zinc-800">
                            {t("auth.disabled")}
                          </span>
                        </Show>
                        <ConfirmButton
                          label={t("app.delete")}
                          question={t("auth.deleteUserConfirm", { uid: u.localId })}
                          testId={`delete-user-${u.localId}`}
                          onConfirm={async () => {
                            const r = await deleteUser(project(), u.localId);
                            r.match(
                              () => {
                                if (selected() === u.localId) setSelected(null);
                                void refreshAll();
                              },
                              (e) => setError(e.message),
                            );
                          }}
                        />
                      </td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </Show>
          <Show when={nextToken()}>
            <AsyncButton class="btn mt-2" onClick={() => load(nextToken())}>
              {t("auth.more")}
            </AsyncButton>
          </Show>
        </Show>
      </Section>
      <div class="grid gap-4 md:grid-cols-2">
        <Section title={t("auth.oobCodes")}>
          <Show when={!codes.loading} fallback={<Spinner />}>
            <Show
              when={(codes()?.unwrapOr({ oobCodes: [] }).oobCodes.length ?? 0) > 0}
              fallback={<p class="text-sm text-zinc-500">{t("auth.noOobCodes")}</p>}
            >
              <table class="table" data-testid="oob-table">
                <thead>
                  <tr>
                    <th>{t("auth.email")}</th>
                    <th>{t("auth.oobType")}</th>
                    <th>{t("auth.oobCode")}</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={codes()?.unwrapOr({ oobCodes: [] }).oobCodes ?? []}>
                    {(c) => (
                      <tr>
                        <td>{c.email}</td>
                        <td class="text-xs">{c.requestType}</td>
                        <td class="mono break-all">
                          <a
                            href={c.oobLink}
                            class="text-amber-700 hover:underline dark:text-amber-300"
                            target="_blank"
                            rel="noreferrer"
                          >
                            {c.oobCode}
                          </a>
                        </td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </Show>
          </Show>
        </Section>
        <Section title={t("auth.verificationCodes")}>
          <Show when={!phoneCodes.loading} fallback={<Spinner />}>
            <Show
              when={
                (phoneCodes()?.unwrapOr({ verificationCodes: [] }).verificationCodes.length ?? 0) >
                0
              }
              fallback={<p class="text-sm text-zinc-500">{t("auth.noVerificationCodes")}</p>}
            >
              <table class="table">
                <thead>
                  <tr>
                    <th>{t("auth.phone")}</th>
                    <th>{t("auth.oobCode")}</th>
                    <th>{t("auth.sessionInfo")}</th>
                  </tr>
                </thead>
                <tbody>
                  <For
                    each={phoneCodes()?.unwrapOr({ verificationCodes: [] }).verificationCodes ?? []}
                  >
                    {(c) => (
                      <tr>
                        <td class="mono">{c.phoneNumber}</td>
                        <td class="mono">{c.code}</td>
                        <td class="mono break-all text-xs">{c.sessionInfo}</td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </Show>
          </Show>
        </Section>
      </div>
    </div>
  );
};

export default Auth;
