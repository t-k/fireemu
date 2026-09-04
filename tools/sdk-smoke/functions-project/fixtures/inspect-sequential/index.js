const { onSchedule } = require("firebase-functions/v2/scheduler");
const { onRequest } = require("firebase-functions/v2/https");

let active = 0;

async function hold(name) {
  active += 1;
  console.log(`${name} active=${active}`);
  await new Promise((resolve) => setTimeout(resolve, 150));
  active -= 1;
}

exports.alpha = onSchedule("every 5 minutes", () => hold("alpha"));
exports.beta = onSchedule("every 5 minutes", () => hold("beta"));
exports.http = onRequest(async (_request, response) => {
  await hold("http");
  response.status(200).send("ok");
});
