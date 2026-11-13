// Follow-up cells use one measured read per name, so a hit cannot extend its own observation window.
import { CELLS } from "./program.mjs";

const cells = CELLS.slice(0, 2);

for (const [bucket, age] of [6000, 7500, 9000, 10500].entries())
  for (let repeat = 0; repeat < 2; repeat += 1)
    cells.push({
      id: `DA${bucket * 2 + repeat + 1}`,
      question: "DELETE 404 arming after a successful delete",
      conn: "dedicated",
      arm: 2,
      steps: [
        { op: "putSub", target: "X", topic: "T", at: 0 },
        { op: "deleteSub", target: "X", after: 50 },
        { op: "deleteSub", target: "X", after: 50 },
        { op: "putSub", target: "X", topic: "T", after: 50 },
        { op: "getSub", target: "X", since: [2, age] },
        { op: "deleteSub", target: "X", after: 50 },
      ],
    });

for (const [bucket, age] of [3200, 3500, 3800, 4100, 4400, 4700, 5000, 5500].entries())
  for (let repeat = 0; repeat < 2; repeat += 1)
    cells.push({
      id: `N1${String.fromCharCode(97 + bucket * 2 + repeat)}`,
      question: "Activation on a never-created subscription name",
      conn: "dedicated",
      arm: 0,
      steps: [
        { op: "getSub", target: "M2", at: 0 },
        { op: "getSub", target: "M2", since: [0, age] },
      ],
    });

for (const seconds of [4, 7, 13])
  for (const repeat of ["a", "b"])
    cells.push({
      id: `E200-${seconds}${repeat}`,
      question: "Recent successful subscription GET exemption",
      conn: "dedicated",
      arm: 3,
      steps: [
        { op: "putSub", target: "X", topic: "T", at: 0 },
        { op: "getSub", target: "X", after: 50 },
        { op: "deleteSub", target: "X", after: 50 },
        { op: "getSub", target: "X", since: [1, seconds * 1000] },
        { op: "putSub", target: "X", topic: "T", after: 50 },
        { op: "getSub", target: "X", after: 50 },
        { op: "deleteSub", target: "X", after: 50 },
      ],
    });

for (const edge of [25, 30, 35, 40, 45, 50])
  for (const repeat of ["a", "b"])
    cells.push({
      id: `W${edge}${repeat}`,
      question: "Single-read window edge",
      conn: "dedicated",
      arm: 0,
      steps: [
        { op: "getSub", target: "X", at: 0 },
        { op: "putSub", target: "X", topic: "T", after: 50 },
        { op: "getSub", target: "X", since: [0, 10000 + edge * 10] },
        { op: "deleteSub", target: "X", after: 50 },
      ],
    });

export const CELLS_V5 = Object.freeze(cells.map((cell) => Object.freeze(cell)));
export const requestCountV5 = () => CELLS_V5.reduce((sum, cell) => sum + cell.steps.length, 0);
