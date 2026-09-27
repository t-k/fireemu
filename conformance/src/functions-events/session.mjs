import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";

const priority = { LOCAL_OBSERVATION: 0, INCOMPLETE: 1, DIFF: 2 };
const worst = (statuses) =>
  statuses.reduce((a, b) => (priority[a] >= priority[b] ? a : b), "LOCAL_OBSERVATION");

function resourceMatches(frame, key) {
  const event = frame.event ?? {};
  const data = event.data ?? {};
  switch (key.kind) {
    case "firestore":
      return [
        data.path,
        data.before?.path,
        data.after?.path,
        event.subject?.replace(/^documents\//, ""),
        event.context?.resource?.name?.split("/documents/")[1],
      ].includes(key.value);
    case "storage":
      return data.name === key.value && (key.bucket == null || data.bucket === key.bucket);
    case "auth":
      return data.uid === key.value;
    case "pubsub":
      return [data.message?.messageId, data.messageId, event.context?.eventId].includes(key.value);
    default:
      return false;
  }
}

function matchingFrames(capture, cursor, handler, key) {
  return capture
    .since(cursor)
    .filter(({ frame }) => frame.handler === handler && resourceMatches(frame, key));
}

function retryObserved(frames) {
  const failed = frames.find(({ frame }) => frame.event?.data?.fixtureAttempt === "failed");
  const succeeded = frames.find(
    ({ frame, sequence }) =>
      sequence > (failed?.sequence ?? Number.POSITIVE_INFINITY) &&
      frame.event?.data?.fixtureAttempt === "succeeded" &&
      frame.event.id === failed?.frame.event.id &&
      frame.event.time === failed?.frame.event.time,
  );
  return Boolean(failed && succeeded && failed.frame.event.id && failed.frame.event.time);
}

async function executeOperation({ capture, driver, program, scenario, role, windowMs, delivery }) {
  const before = await capture.barrier();
  let operation;
  let error = null;
  try {
    operation = await driver.runScenario({ scenario, program, role, capture });
  } catch (cause) {
    error = String(cause?.message ?? cause);
  }
  if (!operation) {
    return { scenarioId: scenario.id, role, status: "INCOMPLETE", error, framesByGeneration: {} };
  }
  const cursor = operation.cursor;
  const validCursor = Number.isSafeInteger(cursor) && cursor >= before.cursor;
  const framesByGeneration = {};
  const collect = () => {
    for (const [generation, handler] of Object.entries(program.handlerExports)) {
      framesByGeneration[generation] = validCursor
        ? matchingFrames(capture, cursor, handler, operation.matchKey)
        : [];
    }
  };
  const deadline = Date.now() + windowMs;
  while (Date.now() <= deadline) {
    await capture.barrier();
    collect();
    const complete = Object.values(framesByGeneration).every((frames) =>
      delivery === "failed-then-succeeded-same-event" ? retryObserved(frames) : frames.length > 0,
    );
    if (delivery !== "none-in-window" && complete) break;
    if (Date.now() >= deadline) break;
    await delay(Math.min(25, Math.max(1, deadline - Date.now())));
  }
  const after = await capture.barrier();
  collect();
  let cleanup;
  try {
    cleanup = await operation.cleanup();
  } catch (cause) {
    error = String(cause?.message ?? cause);
  }
  const allFrames = Object.values(framesByGeneration).flat();
  const hasCaptureIssue =
    after.lossCount !== before.lossCount || after.issueCount !== before.issueCount;
  let status = "LOCAL_OBSERVATION";
  if (
    error ||
    !validCursor ||
    !operation.matchKey ||
    operation.sourceResult !== scenario.sourceResult ||
    !operation.readback ||
    !cleanup?.checked ||
    hasCaptureIssue
  ) {
    status = "INCOMPLETE";
  } else if (delivery === "none-in-window") {
    if (allFrames.length > 0) status = "DIFF";
  } else if (delivery === "failed-then-succeeded-same-event") {
    if (!Object.values(framesByGeneration).every(retryObserved)) status = "INCOMPLETE";
  } else if (!Object.values(framesByGeneration).every((frames) => frames.length > 0)) {
    status = "INCOMPLETE";
  }
  return {
    scenarioId: scenario.id,
    role,
    status,
    sourceResult: operation.sourceResult,
    readback: operation.readback,
    cleanup,
    matchKey: operation.matchKey,
    cursor,
    windowMs,
    capture: {
      before,
      after,
      sequences: allFrames.map(({ sequence }) => sequence),
    },
    framesByGeneration,
    error,
  };
}

/** Execute fixed local recipes; results are observations, never closure verification. */
export async function runPrograms({
  manifest,
  corpus,
  capture,
  driver,
  onlyRecipeIds = manifest.programs.map((program) => program.recipeId),
  windowMs = 5000,
}) {
  assert.ok(Number.isSafeInteger(windowMs) && windowMs > 0 && windowMs <= 600_000);
  assert.equal(new Set(onlyRecipeIds).size, onlyRecipeIds.length);
  const scenarioMap = new Map(corpus.scenarios.map((scenario) => [scenario.id, scenario]));
  const selected = onlyRecipeIds.map((recipeId) => {
    const program = manifest.programs.find((candidate) => candidate.recipeId === recipeId);
    assert.ok(program, `unknown program: ${recipeId}`);
    return program;
  });
  const results = [];
  for (const program of selected) {
    const operations = [];
    const cases = [];
    for (const scenarioId of program.sourceOrder) {
      const scenario = scenarioMap.get(scenarioId);
      assert.ok(scenario);
      const rows = corpus.cases.filter(
        (row) => row.recipeId === program.recipeId && row.scenario === scenarioId,
      );
      assert.ok(rows.length > 0);
      const delivery = rows[0].delivery;
      assert.ok(rows.every((row) => row.delivery === delivery));
      let beforeControl = null;
      let afterControl = null;
      if (delivery === "none-in-window") {
        const controlIds = new Set(rows.map((row) => row.positiveControlScenario));
        assert.equal(controlIds.size, 1);
        const controlScenario = scenarioMap.get([...controlIds][0]);
        beforeControl = await executeOperation({
          capture,
          driver,
          program,
          scenario: controlScenario,
          role: "positive-control-before",
          windowMs,
          delivery: "at-least-one",
        });
        operations.push(beforeControl);
      }
      const subject = await executeOperation({
        capture,
        driver,
        program,
        scenario,
        role: "subject",
        windowMs,
        delivery,
      });
      operations.push(subject);
      if (delivery === "none-in-window") {
        const controlScenario = scenarioMap.get(rows[0].positiveControlScenario);
        afterControl = await executeOperation({
          capture,
          driver,
          program,
          scenario: controlScenario,
          role: "positive-control-after",
          windowMs,
          delivery: "at-least-one",
        });
        operations.push(afterControl);
      }
      for (const row of rows) {
        const controlStatus =
          beforeControl && afterControl
            ? worst([beforeControl.status, afterControl.status])
            : "LOCAL_OBSERVATION";
        const status = worst([subject.status, controlStatus]);
        cases.push({
          caseId: row.id,
          generation: row.generation,
          scenarioId,
          delivery: row.delivery,
          status,
          aspectStatus: "PENDING_LOCAL_COMPARISON",
          subjectSequences:
            subject.framesByGeneration[`v${row.generation}`]?.map(({ sequence }) => sequence) ?? [],
          controlBeforeSequences:
            beforeControl?.framesByGeneration[`v${row.generation}`]?.map(
              ({ sequence }) => sequence,
            ) ?? [],
          controlAfterSequences:
            afterControl?.framesByGeneration[`v${row.generation}`]?.map(
              ({ sequence }) => sequence,
            ) ?? [],
        });
      }
    }
    results.push({
      recipeId: program.recipeId,
      status: worst(cases.map((row) => row.status)),
      operations,
      cases,
    });
  }
  return {
    schemaVersion: 1,
    parent: "FUNCTIONS-EVENTS",
    status: worst(results.map((program) => program.status)),
    authority: "LOCAL_ONLY",
    productionEvidence: null,
    programs: results,
  };
}
