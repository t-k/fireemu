import { A, useNavigate, useParams, useSearchParams } from "@solidjs/router";
import {
  createEffect,
  createMemo,
  on,
  createResource,
  createSignal,
  For,
  onCleanup,
  Show,
  type Component,
} from "solid-js";
import { createStore, produce, type SetStoreFunction } from "solid-js/store";
import { t } from "../i18n";
import { appState } from "../state";
import { AsyncButton, ConfirmButton, ErrorBanner, FetchState, Notice } from "../components/common";
import { decodeSplat, firestoreHref } from "../lib/hrefs";
import { createPagedList } from "../lib/pagedList";
import { createLeaveGuard, LeavePrompt } from "../lib/unsaved";
import { settle, subscribe } from "../api/client";
import {
  createDocument,
  deleteCollection,
  deleteDocument,
  documentsRoot,
  getDocument,
  listCollectionIds,
  listDocuments,
  updateDocument,
} from "../api/firestore";
import {
  applyFieldDiff,
  defaultText,
  diffFields,
  FIELD_TYPES,
  isDocumentPath,
  lastSegment,
  parentPath,
  parseFields,
  relativePath,
  summarize,
  toEditable,
  type EditableField,
  type FieldType,
  type FsDocument,
  type FsValue,
} from "../lib/firestoreValue";

const typeLabel = (type: FieldType): string => {
  switch (type) {
    case "string":
      return t("firestore.typeString");
    case "number":
      return t("firestore.typeNumber");
    case "boolean":
      return t("firestore.typeBoolean");
    case "null":
      return t("firestore.typeNull");
    case "timestamp":
      return t("firestore.typeTimestamp");
    case "geopoint":
      return t("firestore.typeGeopoint");
    case "reference":
      return t("firestore.typeReference");
    case "array":
      return t("firestore.typeArray");
    case "map":
      return t("firestore.typeMap");
    case "bytes":
      return t("firestore.typeBytes");
  }
};

const hint = (type: FieldType): string => {
  switch (type) {
    case "number":
      return t("firestore.hintNumber");
    case "boolean":
      return t("firestore.hintBoolean");
    case "timestamp":
      return t("firestore.hintTimestamp");
    case "geopoint":
      return t("firestore.hintGeopoint");
    case "reference":
      return t("firestore.hintReference");
    case "array":
      return t("firestore.hintArray");
    case "map":
      return t("firestore.hintMap");
    case "bytes":
      return t("firestore.hintBytes");
    default:
      return "";
  }
};

/**
 * The rows of a field editor as a store. A store keeps every row's identity across edits, so
 * `<For>` updates the input in place instead of replacing the row (which would drop focus, the
 * caret and any IME composition on every keystroke).
 */
export const createFieldsStore = (
  initial: EditableField[],
): [EditableField[], SetStoreFunction<EditableField[]>] => createStore<EditableField[]>(initial);

/** The typed field editor: a name, a type and a value per row. */
export const FieldsEditor: Component<{
  fields: EditableField[];
  setFields: SetStoreFunction<EditableField[]>;
  disabled?: boolean;
}> = (props) => {
  const update = (index: number, patch: Partial<EditableField>) => props.setFields(index, patch);
  const remove = (index: number) => props.setFields(produce((rows) => void rows.splice(index, 1)));
  return (
    <div>
      <table class="table">
        <thead>
          <tr>
            <th>{t("firestore.fieldName")}</th>
            <th>{t("firestore.fieldType")}</th>
            <th>{t("firestore.fieldValue")}</th>
            <th />
          </tr>
        </thead>
        <tbody>
          <For each={props.fields}>
            {(f, i) => (
              <tr>
                <td>
                  <input
                    class="input mono"
                    aria-label={t("firestore.fieldName")}
                    disabled={props.disabled}
                    value={f.name}
                    onInput={(e) => update(i(), { name: e.currentTarget.value })}
                  />
                </td>
                <td>
                  <select
                    class="input"
                    aria-label={t("firestore.fieldType")}
                    disabled={props.disabled}
                    value={f.type}
                    onChange={(e) => {
                      const type = e.currentTarget.value as FieldType;
                      update(i(), {
                        type,
                        text: defaultText(type),
                        original: undefined,
                        dirty: true,
                        numberKind: undefined,
                      });
                    }}
                  >
                    <For each={FIELD_TYPES}>
                      {(ty) => <option value={ty}>{typeLabel(ty)}</option>}
                    </For>
                  </select>
                </td>
                <td>
                  <Show
                    when={f.type === "array" || f.type === "map"}
                    fallback={
                      <input
                        class="input mono"
                        aria-label={t("firestore.fieldValue")}
                        placeholder={hint(f.type)}
                        disabled={props.disabled || f.type === "null"}
                        value={f.text}
                        onInput={(e) => update(i(), { text: e.currentTarget.value, dirty: true })}
                      />
                    }
                  >
                    <textarea
                      class="input mono h-20"
                      aria-label={t("firestore.fieldValue")}
                      disabled={props.disabled}
                      placeholder={hint(f.type)}
                      value={f.text}
                      onInput={(e) => update(i(), { text: e.currentTarget.value, dirty: true })}
                    />
                  </Show>
                </td>
                <td>
                  <button
                    type="button"
                    class="btn"
                    disabled={props.disabled}
                    onClick={() => remove(i())}
                  >
                    {t("app.delete")}
                  </button>
                </td>
              </tr>
            )}
          </For>
        </tbody>
      </table>
      <button
        type="button"
        class="btn mt-2"
        data-testid="add-field"
        disabled={props.disabled}
        onClick={() =>
          props.setFields(produce((rows) => void rows.push({ name: "", type: "string", text: "" })))
        }
      >
        {t("firestore.addField")}
      </button>
    </div>
  );
};

const Breadcrumbs: Component<{ path: string; db: string }> = (props) => {
  const segments = () => props.path.split("/").filter(Boolean);
  const link = (index: number) =>
    firestoreHref(
      segments()
        .slice(0, index + 1)
        .join("/"),
      props.db,
    );
  return (
    <nav class="mono mb-3 flex flex-wrap items-center gap-1" aria-label={t("firestore.title")}>
      <A href={firestoreHref("", props.db)} class="link">
        {t("firestore.root")}
      </A>
      <For each={segments()}>
        {(s, i) => (
          <>
            <span class="text-zinc-400">/</span>
            <A href={link(i())} class="link">
              {s}
            </A>
          </>
        )}
      </For>
    </nav>
  );
};

/** The collection IDs under a parent, paged (the API answers 300 at a time). */
const CollectionList: Component<{
  root: string;
  parent: string;
  db: string;
  version: number;
  testId: string;
}> = (props) => {
  const list = createPagedList((token) =>
    listCollectionIds(props.root, props.parent, token).map((page) => ({
      items: page.collectionIds ?? [],
      nextToken: page.nextPageToken,
    })),
  );
  createEffect(
    on(
      () => [props.root, props.parent] as const,
      () => void list.load(),
    ),
  );
  createEffect(
    on(
      () => props.version,
      () => void list.refresh(),
      { defer: true },
    ),
  );
  return (
    <FetchState
      loading={list.loading()}
      error={list.error()}
      stale={list.stale()}
      onRetry={list.refresh}
      empty={list.items().length === 0}
      emptyMessage={t("firestore.noCollections")}
    >
      <ul class="mono space-y-1" data-testid={props.testId}>
        <For each={list.items()}>
          {(id) => (
            <li>
              <A
                href={firestoreHref(props.parent ? `${props.parent}/${id}` : id, props.db)}
                class="link"
              >
                {id}
              </A>
            </li>
          )}
        </For>
      </ul>
      <Show when={list.nextToken()}>
        <AsyncButton class="btn mt-2" onClick={list.more}>
          {t("firestore.more")}
        </AsyncButton>
      </Show>
    </FetchState>
  );
};

/** New document form (collection known; ID optional). */
const NewDocumentForm: Component<{
  root: string;
  collection: string;
  onDone: (path: string) => void;
  onCancel: () => void;
}> = (props) => {
  const [id, setId] = createSignal("");
  const [fields, setFields] = createFieldsStore([{ name: "", type: "string", text: "" }]);
  const [error, setError] = createSignal<string | null>(null);
  const save = async () => {
    setError(null);
    const parsed = parseFields(
      fields.filter((f) => f.name || f.text),
      props.root,
    );
    if (parsed.isErr()) {
      setError(
        t("firestore.invalidValue", { field: parsed.error.field, message: parsed.error.message }),
      );
      return;
    }
    const r = await createDocument(props.root, props.collection, id().trim(), parsed.value);
    r.match(
      (doc) => props.onDone(relativePath(doc.name)),
      (e) => setError(e.message),
    );
  };
  return (
    <div class="card mb-4" data-testid="new-document">
      <h3 class="mb-2 font-semibold">{t("firestore.addDocument")}</h3>
      <ErrorBanner message={error()} />
      <label class="mb-2 block text-sm">
        <span class="label">{t("firestore.documentId")}</span>
        <input
          class="input mono"
          data-testid="new-document-id"
          placeholder={t("firestore.documentIdAuto")}
          value={id()}
          onInput={(e) => setId(e.currentTarget.value)}
        />
      </label>
      <FieldsEditor fields={fields} setFields={setFields} />
      <div class="mt-3 flex gap-2">
        <AsyncButton class="btn btn-primary" onClick={save} testId="new-document-save">
          {t("app.save")}
        </AsyncButton>
        <button type="button" class="btn" onClick={props.onCancel}>
          {t("app.cancel")}
        </button>
      </div>
    </div>
  );
};

/** New collection under `parent` (root or a document): a collection ID and a first document. */
const NewCollectionForm: Component<{
  root: string;
  parent: string;
  onDone: (path: string) => void;
  onCancel: () => void;
}> = (props) => {
  const [collection, setCollection] = createSignal("");
  const [id, setId] = createSignal("");
  const [fields, setFields] = createFieldsStore([{ name: "", type: "string", text: "" }]);
  const [error, setError] = createSignal<string | null>(null);
  const save = async () => {
    setError(null);
    const cid = collection().trim();
    if (!cid || cid.includes("/")) {
      setError(
        t("firestore.invalidValue", {
          field: t("firestore.collectionId"),
          message: t("firestore.emptyFieldName"),
        }),
      );
      return;
    }
    const parsed = parseFields(
      fields.filter((f) => f.name || f.text),
      props.root,
    );
    if (parsed.isErr()) {
      setError(
        t("firestore.invalidValue", { field: parsed.error.field, message: parsed.error.message }),
      );
      return;
    }
    const path = props.parent ? `${props.parent}/${cid}` : cid;
    const r = await createDocument(props.root, path, id().trim(), parsed.value);
    r.match(
      (doc) => props.onDone(relativePath(doc.name)),
      (e) => setError(e.message),
    );
  };
  return (
    <div class="card mb-4" data-testid="new-collection">
      <h3 class="mb-2 font-semibold">{t("firestore.addCollection")}</h3>
      <ErrorBanner message={error()} />
      <label class="mb-2 block text-sm">
        <span class="label">{t("firestore.collectionId")}</span>
        <input
          class="input mono"
          data-testid="new-collection-id"
          value={collection()}
          onInput={(e) => setCollection(e.currentTarget.value)}
        />
      </label>
      <label class="mb-2 block text-sm">
        <span class="label">{t("firestore.documentId")}</span>
        <input
          class="input mono"
          data-testid="new-collection-doc-id"
          placeholder={t("firestore.documentIdAuto")}
          value={id()}
          onInput={(e) => setId(e.currentTarget.value)}
        />
      </label>
      <FieldsEditor fields={fields} setFields={setFields} />
      <div class="mt-3 flex gap-2">
        <AsyncButton class="btn btn-primary" onClick={save} testId="new-collection-save">
          {t("app.save")}
        </AsyncButton>
        <button type="button" class="btn" onClick={props.onCancel}>
          {t("app.cancel")}
        </button>
      </div>
    </div>
  );
};

/** A document: fields (view or edit), subcollections, delete. */
const DocumentView: Component<{
  root: string;
  path: string;
  db: string;
  version: number;
  onDeleted: () => void;
}> = (props) => {
  const navigate = useNavigate();
  const [doc, { refetch }] = createResource(
    () => [props.root, props.path, props.version] as const,
    ([root, path]) => settle(getDocument(root, path)),
  );
  const [editing, setEditing] = createSignal(false);
  const [fields, setFields] = createFieldsStore([]);
  const [editSession, setEditSession] = createSignal<{
    root: string;
    path: string;
    fields: Record<string, FsValue>;
    updateTime: string;
    generation: number;
  } | null>(null);
  const [conflict, setConflict] = createSignal(false);
  const [editBusy, setEditBusy] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [notice, setNotice] = createSignal<string | null>(null);
  const [showJson, setShowJson] = createSignal(false);
  const [newCollection, setNewCollection] = createSignal(false);
  const current = createMemo<FsDocument | null>(() => doc()?.unwrapOr(null) ?? null);
  const loadError = () =>
    doc()?.match(
      () => null,
      (e) => (e.status === 404 ? null : e.message),
    ) ?? null;
  const guard = createLeaveGuard(() => {
    const session = editSession();
    if (!editing() || !session) return false;
    const parsed = parseFields(fields, session.root);
    return parsed.isErr() || diffFields(session.fields, parsed.value).fieldPaths.length > 0;
  });
  const missing = () =>
    doc()?.match(
      () => false,
      (e) => e.status === 404,
    ) ?? false;
  let editGeneration = 0;
  let editOperation = 0;
  createEffect(() => {
    void props.root;
    void props.path;
    editGeneration += 1;
    editOperation += 1;
    setEditing(false);
    setEditSession(null);
    setConflict(false);
    setEditBusy(false);
  });
  const startEdit = () => {
    const selected = current();
    if (!selected?.updateTime) return;
    const original = selected.fields ?? {};
    editGeneration += 1;
    editOperation += 1;
    setFields(toEditable(original));
    setEditSession({
      root: props.root,
      path: props.path,
      fields: original,
      updateTime: selected.updateTime,
      generation: editGeneration,
    });
    setConflict(false);
    setEditing(true);
  };
  const save = async () => {
    if (editBusy()) return;
    setError(null);
    const session = editSession();
    if (!session) return;
    const parsed = parseFields(fields, session.root);
    if (parsed.isErr()) {
      setError(
        t("firestore.invalidValue", { field: parsed.error.field, message: parsed.error.message }),
      );
      return;
    }
    const changes = diffFields(session.fields, parsed.value);
    if (changes.fieldPaths.length === 0) {
      setEditing(false);
      setEditSession(null);
      return;
    }
    const operation = ++editOperation;
    setEditBusy(true);
    const r = await updateDocument(
      session.root,
      session.path,
      changes.fields,
      changes.fieldPaths,
      session.updateTime,
    );
    const staleSession =
      editSession()?.generation !== session.generation ||
      editOperation !== operation ||
      props.root !== session.root ||
      props.path !== session.path;
    if (staleSession) return;
    setEditBusy(false);
    r.match(
      () => {
        setEditing(false);
        setEditSession(null);
        if (props.root === session.root && props.path === session.path) void refetch();
      },
      (e) => {
        if (e.code === "FAILED_PRECONDITION") {
          setConflict(true);
          setError(t("firestore.editConflict"));
        } else {
          setError(e.message);
        }
      },
    );
  };
  const reloadForReapply = async () => {
    if (editBusy()) return;
    const session = editSession();
    if (!session || props.root !== session.root || props.path !== session.path) return;
    const draft = fields;
    const parsedDraft = parseFields(draft, session.root);
    if (parsedDraft.isErr()) return;
    const draftChanges = diffFields(session.fields, parsedDraft.value);
    const operation = ++editOperation;
    setEditBusy(true);
    await refetch();
    if (
      editSession()?.generation !== session.generation ||
      editOperation !== operation ||
      props.root !== session.root ||
      props.path !== session.path
    )
      return;
    setEditBusy(false);
    const latest = current();
    if (!latest?.updateTime) {
      setError(t("firestore.editConflictDeleted"));
      return;
    }
    setEditSession({
      ...session,
      fields: latest.fields ?? {},
      updateTime: latest.updateTime,
    });
    setFields(toEditable(applyFieldDiff(latest.fields ?? {}, draftChanges)));
    setConflict(false);
    setError(null);
    setNotice(t("firestore.draftReapplied"));
  };
  const remove = async () => {
    const r = await deleteDocument(props.root, props.path);
    r.match(
      () => props.onDeleted(),
      (e) => setError(e.message),
    );
  };
  const fieldRows = () => Object.entries(current()?.fields ?? {}) as [string, FsValue][];
  return (
    <div data-testid="document-view">
      <div class="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h2 class="mono text-base font-semibold">{lastSegment(props.path)}</h2>
        <div class="flex flex-wrap items-start gap-2">
          <Show when={!editing()}>
            <button type="button" class="btn" data-testid="document-edit" onClick={startEdit}>
              {t("firestore.edit")}
            </button>
          </Show>
          <button type="button" class="btn" onClick={() => setShowJson(!showJson())}>
            {t("firestore.jsonView")}
          </button>
          <ConfirmButton
            label={t("firestore.deleteDocument")}
            question={t("firestore.deleteDocumentConfirm", { path: props.path })}
            details={t("firestore.deleteDocumentDetails", {
              project: appState.project(),
              db: props.db,
            })}
            onConfirm={remove}
            testId="document-delete"
          />
        </div>
      </div>
      <LeavePrompt guard={guard} subject={t("firestore.editorSubject", { path: props.path })} />
      <ErrorBanner message={error()} />
      <Notice message={notice()} />
      <FetchState
        loading={doc.loading && !current()}
        error={loadError()}
        onRetry={async () => {
          await refetch();
        }}
      >
        <Show when={missing()}>
          <p class="mb-3 text-sm text-zinc-500">{t("firestore.missing")}</p>
        </Show>
        <Show when={current()}>
          {(d) => (
            <div class="mb-3 text-xs text-zinc-500">
              {t("firestore.createTime")}: <span class="mono">{d().createTime}</span>{" "}
              {t("firestore.updateTime")}: <span class="mono">{d().updateTime}</span>
            </div>
          )}
        </Show>
        <Show
          when={editing()}
          fallback={
            <Show
              when={fieldRows().length > 0}
              fallback={<p class="text-sm text-zinc-500">{t("firestore.noFields")}</p>}
            >
              <table class="table" data-testid="document-fields">
                <thead>
                  <tr>
                    <th>{t("firestore.fieldName")}</th>
                    <th>{t("firestore.fieldType")}</th>
                    <th>{t("firestore.fieldValue")}</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={fieldRows()}>
                    {([name, value]) => (
                      <tr>
                        <td class="mono">{name}</td>
                        <td class="text-xs text-zinc-500">
                          {typeLabel(toEditable({ [name]: value })[0]?.type ?? "string")}
                        </td>
                        <td class="mono break-all">{summarize(value)}</td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </Show>
          }
        >
          <FieldsEditor fields={fields} setFields={setFields} disabled={editBusy()} />
          <Show when={conflict()}>
            <button
              type="button"
              class="btn mt-2"
              data-testid="document-reload-draft"
              disabled={editBusy()}
              onClick={reloadForReapply}
            >
              {t("firestore.reloadDraft")}
            </button>
          </Show>
          <div class="mt-3 flex gap-2">
            <AsyncButton
              class="btn btn-primary"
              disabled={editBusy()}
              onClick={save}
              testId="document-save"
            >
              {t("app.save")}
            </AsyncButton>
            <button
              type="button"
              class="btn"
              onClick={() => {
                editGeneration += 1;
                editOperation += 1;
                setEditing(false);
                setEditSession(null);
                setConflict(false);
                setEditBusy(false);
              }}
            >
              {t("app.cancel")}
            </button>
          </div>
        </Show>
        <Show when={showJson()}>
          <pre class="mono mt-3 whitespace-pre-wrap rounded-md bg-zinc-100 p-3 dark:bg-zinc-800">
            {JSON.stringify(current()?.fields ?? {}, null, 2)}
          </pre>
        </Show>
      </FetchState>
      <div class="mt-4">
        <div class="mb-2 flex items-center justify-between">
          <h3 class="font-semibold">{t("firestore.subcollections")}</h3>
          <button
            type="button"
            class="btn"
            data-testid="start-subcollection"
            onClick={() => setNewCollection(true)}
          >
            {t("firestore.addCollection")}
          </button>
        </div>
        <Show when={newCollection()}>
          <NewCollectionForm
            root={props.root}
            parent={props.path}
            onDone={(path) => {
              setNewCollection(false);
              setNotice(null);
              navigate(firestoreHref(path, props.db));
            }}
            onCancel={() => setNewCollection(false)}
          />
        </Show>
        <CollectionList
          root={props.root}
          parent={props.path}
          db={props.db}
          version={props.version}
          testId="subcollection-list"
        />
      </div>
    </div>
  );
};

/** A collection: its documents (paged), add document, delete collection. */
const CollectionView: Component<{
  root: string;
  path: string;
  db: string;
  version: number;
  onDeleted: () => void;
}> = (props) => {
  const navigate = useNavigate();
  const list = createPagedList((token) =>
    listDocuments(props.root, props.path, token).map((page) => ({
      items: page.documents ?? [],
      nextToken: page.nextPageToken,
    })),
  );
  const [error, setError] = createSignal<string | null>(null);
  const [notice, setNotice] = createSignal<string | null>(null);
  const [adding, setAdding] = createSignal(false);
  const [deleting, setDeleting] = createSignal<number | null>(null);
  createEffect(
    on(
      () => [props.root, props.path] as const,
      () => void list.load(),
    ),
  );
  // A commit anywhere in the database re-reads what is shown, keeping the pages loaded so far.
  createEffect(
    on(
      () => props.version,
      () => void list.refresh(),
      { defer: true },
    ),
  );
  const remove = async () => {
    setError(null);
    setDeleting(0);
    const r = await deleteCollection(props.root, props.path, setDeleting);
    const done = deleting() ?? 0;
    setDeleting(null);
    r.match(
      (count) => {
        setNotice(t("firestore.deleted", { count }));
        props.onDeleted();
      },
      (e) => setError(t("firestore.deletePartial", { count: done, message: e.message })),
    );
  };
  return (
    <div data-testid="collection-view">
      <div class="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h2 class="mono text-base font-semibold">{lastSegment(props.path)}</h2>
        <div class="flex flex-wrap items-start gap-2">
          <button
            type="button"
            class="btn btn-primary"
            data-testid="add-document"
            onClick={() => setAdding(true)}
          >
            {t("firestore.addDocument")}
          </button>
          <ConfirmButton
            label={t("firestore.deleteCollection")}
            question={t("firestore.deleteCollectionConfirm", { path: props.path })}
            details={t("firestore.deleteCollectionDetails", {
              project: appState.project(),
              db: props.db,
            })}
            onConfirm={remove}
            testId="collection-delete"
          />
        </div>
      </div>
      <Show when={deleting() !== null}>
        <p class="mb-3 text-sm" role="status" data-testid="collection-delete-progress">
          {t("firestore.deleting", { count: deleting() ?? 0 })}
        </p>
      </Show>
      <ErrorBanner message={error()} />
      <Notice message={notice()} />
      <Show when={adding()}>
        <NewDocumentForm
          root={props.root}
          collection={props.path}
          onDone={(path) => {
            setAdding(false);
            navigate(firestoreHref(path, props.db));
          }}
          onCancel={() => setAdding(false)}
        />
      </Show>
      <FetchState
        loading={list.loading()}
        error={list.error()}
        stale={list.stale()}
        onRetry={list.refresh}
        empty={list.items().length === 0}
        emptyMessage={t("firestore.noDocuments")}
      >
        <table class="table" data-testid="document-list">
          <thead>
            <tr>
              <th>{t("firestore.documentId")}</th>
              <th>{t("firestore.fields")}</th>
            </tr>
          </thead>
          <tbody>
            <For each={list.items()}>
              {(d) => (
                <tr>
                  <td class="mono">
                    <A href={firestoreHref(relativePath(d.name), props.db)} class="link">
                      {lastSegment(d.name)}
                    </A>
                    <Show when={!d.createTime && !d.fields}>
                      <span class="ml-2 text-xs text-zinc-400">({t("firestore.missing")})</span>
                    </Show>
                  </td>
                  <td class="mono break-all text-zinc-600 dark:text-zinc-400">
                    {Object.entries(d.fields ?? {})
                      .slice(0, 4)
                      .map(([k, v]) => `${k}: ${summarize(v)}`)
                      .join(", ")}
                  </td>
                </tr>
              )}
            </For>
          </tbody>
        </table>
        <Show when={list.nextToken()}>
          <AsyncButton class="btn mt-2" onClick={list.more}>
            {t("firestore.more")}
          </AsyncButton>
        </Show>
      </FetchState>
    </div>
  );
};

/** The root: collections and "start collection". */
const RootView: Component<{ root: string; db: string; version: number }> = (props) => {
  const navigate = useNavigate();
  const [adding, setAdding] = createSignal(false);
  return (
    <div data-testid="root-view">
      <div class="mb-3 flex items-center justify-between">
        <h2 class="text-base font-semibold">{t("firestore.collections")}</h2>
        <button
          type="button"
          class="btn btn-primary"
          data-testid="start-collection"
          onClick={() => setAdding(true)}
        >
          {t("firestore.addCollection")}
        </button>
      </div>
      <Show when={adding()}>
        <NewCollectionForm
          root={props.root}
          parent=""
          onDone={(path) => {
            setAdding(false);
            navigate(firestoreHref(path, props.db));
          }}
          onCancel={() => setAdding(false)}
        />
      </Show>
      <CollectionList
        root={props.root}
        parent=""
        db={props.db}
        version={props.version}
        testId="collection-list"
      />
    </div>
  );
};

const Firestore: Component = () => {
  const params = useParams<{ path?: string }>();
  const [search, setSearch] = useSearchParams<{ db?: string }>();
  const navigate = useNavigate();
  const db = () => (typeof search.db === "string" && search.db ? search.db : "(default)");
  const path = () => decodeSplat(params.path).join("/");
  const root = () => documentsRoot(appState.project(), db());
  const [version, setVersion] = createSignal(0);
  const [live, setLive] = createSignal(false);
  const [dbInput, setDbInput] = createSignal(db());

  // Live updates: any commit of the selected project / database refreshes the view
  // (coalesced; the views re-read what they show).
  createEffect(() => {
    const project = appState.project();
    const database = db();
    let timer: number | undefined;
    const bump = () => {
      if (timer === undefined) {
        timer = window.setTimeout(() => {
          timer = undefined;
          setVersion((v) => v + 1);
        }, 150);
      }
    };
    const stop = subscribe(
      `firestore/watch?project=${encodeURIComponent(project)}&database=${encodeURIComponent(database)}`,
      (event) => {
        if (event.event === "ready") {
          setLive(true);
        } else {
          bump();
        }
      },
      () => setLive(false),
    );
    onCleanup(() => {
      stop();
      if (timer !== undefined) {
        window.clearTimeout(timer);
      }
    });
  });

  const up = () => navigate(firestoreHref(parentPath(path()), db()));
  const [jump, setJump] = createSignal("");
  const goTo = () => {
    const target = jump().split("/").filter(Boolean).join("/");
    navigate(firestoreHref(target, db()));
    setJump("");
  };
  return (
    <div>
      <div class="mb-3 flex flex-wrap items-center gap-3">
        <h1 class="text-xl font-bold">{t("firestore.title")}</h1>
        <label class="flex items-center gap-1 text-sm">
          <span class="label">{t("firestore.database")}</span>
          <input
            class="input mono w-40"
            data-testid="database-input"
            value={dbInput()}
            onInput={(e) => setDbInput(e.currentTarget.value)}
            onChange={() => setSearch({ db: dbInput() })}
          />
        </label>
        <span class="text-sm text-zinc-500">
          {t("firestore.project")}: <span class="mono">{appState.project()}</span>
        </span>
        <span
          class="badge bg-violet-100 text-violet-900 dark:bg-violet-900 dark:text-violet-100"
          title={t("app.adminHint")}
          data-testid="admin-badge"
        >
          {t("app.admin")}
        </span>
        <span
          class={`badge ${live() ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-900 dark:text-emerald-100" : "bg-zinc-200 text-zinc-600 dark:bg-zinc-800"}`}
          data-testid="live-badge"
        >
          {live() ? t("firestore.live") : t("firestore.liveOff")}
        </span>
      </div>
      <div class="mb-3 flex flex-wrap items-center gap-2">
        <Breadcrumbs path={path()} db={db()} />
        <form
          class="mb-3 flex items-center gap-1"
          onSubmit={(e) => {
            e.preventDefault();
            goTo();
          }}
        >
          <input
            class="input mono w-72"
            data-testid="path-jump"
            placeholder={t("firestore.goToPlaceholder")}
            aria-label={t("firestore.goTo")}
            value={jump()}
            onInput={(e) => setJump(e.currentTarget.value)}
          />
          <button type="submit" class="btn">
            {t("firestore.goTo")}
          </button>
        </form>
      </div>
      <div class="card">
        <Show
          when={path() !== ""}
          fallback={<RootView root={root()} db={db()} version={version()} />}
        >
          <Show
            when={isDocumentPath(path())}
            fallback={
              <CollectionView
                root={root()}
                path={path()}
                db={db()}
                version={version()}
                onDeleted={up}
              />
            }
          >
            <DocumentView
              root={root()}
              path={path()}
              db={db()}
              version={version()}
              onDeleted={up}
            />
          </Show>
        </Show>
      </div>
    </div>
  );
};

export default Firestore;
