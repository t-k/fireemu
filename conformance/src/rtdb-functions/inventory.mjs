// Before and after the run, the CV14 recorder lists what a deploy of event-triggered functions can leave
// behind besides the functions: Cloud Run services, Eventarc triggers, Pub/Sub topics and subscriptions.
// A 2nd gen RTDB trigger makes an Eventarc trigger and a Pub/Sub topic whose names the platform chooses
// (FE v4 records: `.../triggers/<function>-<n>` and `eventarc-<region>-<trigger>-<n>`); they are removed
// with the function. Only the exact names the function's own record names are ever deleted, and only when
// they are still there after the function was deleted. Anything else new is reported, never removed.

import { PROJECT, resolveTarget } from "../../functions-http/harness.mjs";
import { LOCATION } from "./frames.mjs";

export const CLASSES = ["functions", "services", "triggers", "topics", "subscriptions"];
export const INVENTORY_BOUNDS = Object.freeze({ pageSize: 100, maxPages: 3, polls: 5 });
export const INVENTORY_HOSTS = ["https://eventarc.googleapis.com", "https://pubsub.googleapis.com"];

const LISTS = {
  functions: [
    `https://cloudfunctions.googleapis.com/v2/projects/${PROJECT}/locations/${LOCATION}/functions`,
    "functions",
  ],
  services: [
    `https://run.googleapis.com/v2/projects/${PROJECT}/locations/${LOCATION}/services`,
    "services",
  ],
  triggers: [
    `https://eventarc.googleapis.com/v1/projects/${PROJECT}/locations/${LOCATION}/triggers`,
    "triggers",
  ],
  topics: [`https://pubsub.googleapis.com/v1/projects/${PROJECT}/topics`, "topics"],
  subscriptions: [
    `https://pubsub.googleapis.com/v1/projects/${PROJECT}/subscriptions`,
    "subscriptions",
  ],
};

const escapeRegExp = (text) => text.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
const sleepFor = (ms) => new Promise((resolveSleep) => setTimeout(resolveSleep, ms));

/** Reads the five lists page by page within a bound; `complete` is false when any list is missing or unreadable. */
export async function takeInventory(control, kind) {
  const items = {};
  let complete = true;
  for (const cls of CLASSES) {
    const [base, key] = LISTS[cls];
    const names = [];
    let token;
    let finished = false;
    for (let page = 0; page < INVENTORY_BOUNDS.maxPages && !finished; page += 1) {
      const query = `pageSize=${INVENTORY_BOUNDS.pageSize}${token === undefined ? "" : `&pageToken=${encodeURIComponent(token)}`}`;
      const reply = await control("GET", `${base}?${query}`, undefined, kind);
      const list = reply.value?.[key] ?? [];
      if (!Array.isArray(list) || list.some((item) => typeof item?.name !== "string")) {
        complete = false;
        finished = true;
        break;
      }
      names.push(...list.map((item) => item.name));
      token = reply.value?.nextPageToken;
      if (token === undefined) finished = true;
      else if (typeof token !== "string" || token === "") {
        complete = false;
        finished = true;
      }
    }
    if (!finished) complete = false;
    items[cls] = names.toSorted();
  }
  return { complete, items };
}

/** The names present after the run and not before, class by class. */
export function newItems(before, after) {
  if (!before?.complete || !after?.complete) throw new Error("inventory is incomplete");
  return Object.fromEntries(
    CLASSES.map((cls) => {
      const known = new Set(before.items[cls]);
      return [cls, after.items[cls].filter((name) => !known.has(name))];
    }),
  );
}

/**
 * The Eventarc trigger and Pub/Sub topic a 2nd gen function record names, each checked against the
 * function's own name; null when the record names none.
 */
export function ownedEventarcNames(record, target) {
  const { project, region, functionName } = resolveTarget(target);
  const eventTrigger = record?.eventTrigger;
  if (eventTrigger === undefined || eventTrigger === null) return null;
  const trigger = new RegExp(
    `^projects/${escapeRegExp(project)}/locations/${escapeRegExp(region)}/triggers/(${escapeRegExp(functionName.toLowerCase())}-[0-9a-z]{1,16})$`,
    "u",
  ).exec(eventTrigger.trigger);
  const topic =
    trigger &&
    new RegExp(
      `^projects/${escapeRegExp(project)}/topics/eventarc-${escapeRegExp(region)}-${escapeRegExp(trigger[1])}-[0-9]{1,8}$`,
      "u",
    ).test(eventTrigger.pubsubTopic);
  if (!trigger || !topic) throw new Error("unreviewed Eventarc trigger or Pub/Sub topic name");
  return { trigger: eventTrigger.trigger, topic: eventTrigger.pubsubTopic };
}

async function deleteTrigger(control, name, sleep) {
  const started = await control(
    "DELETE",
    `https://eventarc.googleapis.com/v1/${name}`,
    undefined,
    "inventory",
  );
  const operation = started.value?.name;
  if (
    typeof operation !== "string" ||
    !new RegExp(
      `^projects/${escapeRegExp(PROJECT)}/locations/${LOCATION}/operations/[A-Za-z0-9_.-]+$`,
      "u",
    ).test(operation)
  ) {
    throw new Error("Eventarc returned an unreviewed delete operation");
  }
  let current = started.value;
  for (let poll = 0; !current.done && poll < INVENTORY_BOUNDS.polls; poll += 1) {
    await sleep(5000);
    current = (
      await control(
        "GET",
        `https://eventarc.googleapis.com/v1/${operation}`,
        undefined,
        "inventory",
      )
    ).value;
  }
  if (current.error) throw new Error("Eventarc trigger delete operation failed");
  if (!current.done) throw new Error("Eventarc trigger delete operation did not complete");
}

/**
 * After the functions were deleted: lists again, deletes the owned trigger and topic if they are still
 * there (exact names, each sent once), lists again and reports what is new. `ok` only for complete lists
 * with nothing new in any class.
 */
export async function removeLeftovers(control, before, owned, { sleep = sleepFor } = {}) {
  const result = { ok: false, deleted: [], residual: {}, incomplete: false, error: null };
  try {
    let after = await takeInventory(control, "inventory");
    if (!after.complete) {
      result.incomplete = true;
      return result;
    }
    const fresh = newItems(before, after);
    const owes = [];
    // `owned` is one {trigger, topic}, a list of them, or null.
    for (const names of owned === null || owned === undefined ? [] : [owned].flat()) {
      if (fresh.triggers.includes(names.trigger)) owes.push([names.trigger, "trigger"]);
      if (fresh.topics.includes(names.topic)) owes.push([names.topic, "topic"]);
    }
    for (const [name, kind] of owes) {
      if (kind === "trigger") await deleteTrigger(control, name, sleep);
      else
        await control("DELETE", `https://pubsub.googleapis.com/v1/${name}`, undefined, "inventory");
      result.deleted.push(name);
    }
    if (owes.length > 0) {
      after = await takeInventory(control, "inventory");
      if (!after.complete) {
        result.incomplete = true;
        return result;
      }
    }
    result.residual = newItems(before, after);
    result.ok = CLASSES.every((cls) => result.residual[cls].length === 0);
  } catch (error) {
    result.error = error.message;
  }
  return result;
}
