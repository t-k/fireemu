// Unix command group owner. The application runs in a separate process, so its code
// cannot block this native lifecycle loop or consume the parent's lifetime pipe.
import { spawn } from 'node:child_process';

const [command, ...args] = process.argv.slice(2);
let stopping = false;
function retire() {
  if (stopping) return;
  stopping = true;
  // This process remains the group's leader until escalation, preventing ID reuse.
  try { process.kill(-process.pid, 'SIGTERM'); } catch {}
  setTimeout(() => {
    try { process.kill(-process.pid, 'SIGKILL'); } catch { process.exit(1); }
  }, 100);
}
process.on('SIGTERM', retire);
process.on('SIGINT', retire);
process.stdin.on('end', retire);
process.stdin.on('error', retire);
process.stdin.resume();
const child = spawn(command, args, {stdio:['ignore','inherit','inherit']});
function finish(result) {
  if (process.connected) process.send(result, retire);
  else retire();
}
child.once('error', error => finish({type:'command-exit',error:error.message}));
child.once('exit', (code, signal) => finish({type:'command-exit',code,signal}));
