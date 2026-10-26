const { onRequest } = require("firebase-functions/v2/https");
const { initializeApp } = require("firebase-admin/app");
const { getAppCheck } = require("firebase-admin/app-check");

initializeApp();

// Verifies the header exactly as a production middleware would. `?consume=1` asks for
// limited-use consumption, which fireemu refuses locally.
exports.verify = onRequest(async (req, res) => {
  try {
    const result = await getAppCheck().verifyToken(req.get("X-Firebase-AppCheck"), {
      consume: req.query.consume === "1",
    });
    res.json({ ok: true, appId: result.appId, sub: result.token.sub });
  } catch (error) {
    res.json({ ok: false, code: error.code, message: error.message });
  }
});
