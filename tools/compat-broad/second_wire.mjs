// Thin stdin bridge to the existing current local-only bounded recorder.
import { receiveHttp } from "./record-http.mjs";
let input = "";
for await (const chunk of process.stdin) input += chunk;
const request = JSON.parse(input);
const result = await receiveHttp(request.url, { method: request.method, headers: request.headers, body: request.body === null ? undefined : JSON.stringify(request.body) }, { origin: request.origin, privateDirectory: request.privateDirectory, maxBytes: 65536 });
process.stdout.write(JSON.stringify(result));
