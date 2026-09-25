// Test-only tripwire. This is not an OS sandbox or a protection against arbitrary
// malicious modules. It observes calls made by the known pure fixture audit.
import net from "node:net";
import tls from "node:tls";
import http from "node:http";
import https from "node:https";
import dns from "node:dns";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
let networkAttempts = 0,
  processAttempts = 0;
const network = () => {
  networkAttempts++;
  throw new Error("unexpected-network");
};
const processCall = () => {
  processAttempts++;
  throw new Error("unexpected-subprocess");
};
globalThis.fetch = network;
net.connect = net.createConnection = net.Socket.prototype.connect = tls.connect = network;
http.get = http.request = https.get = https.request = network;
dns.lookup = dns.resolve = dns.promises.lookup = dns.promises.resolve = network;
for (const key of ["exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork"])
  childProcess[key] = processCall;
syncBuiltinESMExports();
const { fixtureSubject } = await import("./subject.mjs");
const { auditSubject } = await import("../suite.mjs");
const subject = await fixtureSubject();
const report = auditSubject(subject, subject.identity);
console.log(
  JSON.stringify({
    auditPassed: report.auditPassed,
    networkAttempts,
    processAttempts,
    completeRepositoryValidation: false,
    identity: "derived-test-fixture",
  }),
);
process.exitCode = report.auditPassed && networkAttempts === 0 && processAttempts === 0 ? 0 : 1;
