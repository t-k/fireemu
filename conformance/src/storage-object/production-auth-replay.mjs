import { isDeepStrictEqual, types } from "node:util";
import { buildProductionStage3DraftPlan } from "./stage3-plan.mjs";
import { buildAuthCorpus } from "./auth-corpus.mjs";
import { replayAuthCore } from "./auth-replay.mjs";
import * as authModule from "./production-auth.mjs";
import { verifyProductionRulesBinding } from "./production-rules.mjs";
import { verifyProductionSenderBinding } from "./sender.mjs";

function record(value, allowed) {
  if (
    !value ||
    types.isProxy(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  )
    throw new Error();
  const entries = [];
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      typeof key !== "string" ||
      (allowed && !allowed.includes(key)) ||
      !descriptor.enumerable ||
      !Object.hasOwn(descriptor, "value")
    )
      throw new Error();
    entries.push([key, descriptor.value]);
  }
  return Object.fromEntries(entries);
}
function data(value, depth = 0) {
  if (depth > 16 || types.isProxy(value)) throw new Error();
  if (value === null || ["string", "number", "boolean"].includes(typeof value)) return value;
  if (Array.isArray(value)) {
    if (
      Object.getPrototypeOf(value) !== Array.prototype ||
      value.length > 64 ||
      Reflect.ownKeys(value).length !== value.length + 1
    )
      throw new Error();
    return Array.from({ length: value.length }, (_, index) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) throw new Error();
      return data(descriptor.value, depth + 1);
    });
  }
  return Object.fromEntries(
    Object.entries(record(value)).map(([key, item]) => [key, data(item, depth + 1)]),
  );
}

/** Replay the canonical production Auth recipe through finite controls and the shared ownership sender. */
export async function replayProductionAuth(input) {
  let options, recipe, index;
  try {
    options = record(input, [
      "sender",
      "auth",
      "rules",
      "recipe",
      "recipeToken",
      "plan",
      "recording",
      "onCapture",
    ]);
    if (
      Object.keys(options).length !== 8 ||
      ![1, 2].includes(options.recording) ||
      options.recipeToken === undefined ||
      typeof options.onCapture !== "function" ||
      types.isProxy(options.onCapture)
    )
      throw new Error();
    options.plan = data(options.plan);
    if (
      !isDeepStrictEqual(
        options.plan,
        buildProductionStage3DraftPlan({
          projectId: options.plan.projectId,
          bucket: options.plan.bucket,
          runIds: options.plan.recordings.map((r) => r.runId),
        }),
      )
    )
      throw new Error();
    options.recipe = data(options.recipe);
    const recipes = buildAuthCorpus({
      projectId: options.plan.projectId,
      bucket: options.plan.bucket,
      runId: options.plan.recordings[options.recording - 1].runId,
    }).recipes;
    index = recipes.findIndex((r) => r.id === options.recipe.id);
    recipe = recipes[index];
    if (!recipe || !isDeepStrictEqual(options.recipe, recipe)) throw new Error();
    const binding = { plan: options.plan, recording: options.recording };
    if (
      !authModule.verifyProductionAuthBinding(options.auth, binding) ||
      !verifyProductionRulesBinding(options.rules, binding) ||
      !verifyProductionSenderBinding(options.sender, {
        plan: options.plan,
        recipeToken: options.recipeToken,
      })
    )
      throw new Error();
    for (const [value, names] of [
      [options.sender, ["start", "sendStep", "admitNamespace", "close"]],
      [options.auth, ["setup", "refresh", "cleanup", "snapshot"]],
      [options.rules, ["checkpoint"]],
    ]) {
      const methods = record(value);
      if (names.some((name) => typeof methods[name] !== "function" || types.isProxy(methods[name])))
        throw new Error();
    }
  } catch {
    throw new Error("invalid production Auth replay configuration");
  }
  const { sender, auth, rules, recipeToken, plan, recording, onCapture } = options;
  return replayAuthCore(
    {
      sender,
      recipe,
      bucket: plan.bucket,
      prefix: plan.recordings[recording - 1].prefix,
      onCapture,
    },
    {
      before: () => rules.checkpoint(`rules-before-${index + 1}`, recipeToken),
      setup: () => auth.setup(recipe.id, recipeToken),
      refresh: () => auth.refresh(recipe.id, recipeToken),
      cleanup: () => auth.cleanup(recipe.id, recipeToken),
      after: () => rules.checkpoint(`rules-after-${index + 1}`, recipeToken),
      verifyTerminal: () =>
        authModule.verifyProductionAuthRecipeTerminal(auth, { recipeId: recipe.id, recipeToken }),
      unresolved: () =>
        auth
          .snapshot()
          .unresolved.filter((r) =>
            Object.values(recipe.accounts).some((account) => account.ref === r.accountRef),
          )
          .map((r) => r.accountRef),
    },
  );
}
