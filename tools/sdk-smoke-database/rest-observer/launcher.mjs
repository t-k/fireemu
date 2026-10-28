import {createHash,randomBytes} from 'node:crypto';
import {readFile,mkdir,realpath} from 'node:fs/promises';
import {readSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {join,resolve} from 'node:path';
import {verifyPacket} from './packet-gate.mjs';
import {createTransport,makeWire} from './transport.mjs';
import {runPacket} from './orchestrator.mjs';
import {recoverApi,recoverInstance} from './recovery.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
const TOKENINFO='https://oauth2.googleapis.com/tokeninfo';
const scopes=['https://www.googleapis.com/auth/firebase.database','https://www.googleapis.com/auth/cloud-platform'];
export function parseArgs(a) {if(a.length!==6||a[0]!=='--packet'||a[2]!=='--sha256'||a[4]!=='--out'||!a[1]||!a[5]||!/^[a-f0-9]{64}$/.test(a[3]))throw Error('usage');return {packet:resolve(a[1]),digest:a[3],out:resolve(a[5])};}
async function runtimeCheck(p){for(const x of [p.runtime.node]){if(await realpath(x.path)!==x.realpath||sha(await readFile(x.path))!==x.sha256)throw Error('runtime pin');}if(await realpath(process.execPath)!==p.runtime.node.realpath)throw Error('node executable');}
async function mint(){const chunks=[];let total=0;for(;;){const b=Buffer.alloc(4097-total);const n=readSync(3,b,0,b.length,null);if(n===0)break;total+=n;if(total>4096)throw Error('credential too long');chunks.push(b.subarray(0,n));}return Buffer.concat(chunks,total).toString('utf8').trim();}
function authWire(token,fetchImpl){return async (request,onHeaders)=>{if(request.url!==TOKENINFO||request.method!=='POST')throw Error('auth request');const r=await fetchImpl(TOKENINFO,{method:'POST',redirect:'manual',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({access_token:token}).toString(),signal:AbortSignal.timeout(25000)});const headers={};for(const k of ['content-type','content-length']){const v=r.headers.get(k);if(v!==null)headers[k]=v;}await onHeaders(r.status,headers);if(r.status<200||r.status>=300)throw Error('auth status');let chunks=[],n=0;if(r.body){const reader=r.body.getReader();try{for(;;){const {done,value}=await reader.read();if(done)break;n+=value.byteLength;if(n>65536){await reader.cancel();throw Error('auth too large');}chunks.push(value);}}finally{reader.releaseLock();}}const doc=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks,n)));const ss=typeof doc.scope==='string'?doc.scope.split(/\s+/):[];const ok=ss.includes('https://www.googleapis.com/auth/userinfo.email')&&scopes.some(s=>ss.includes(s))&&typeof doc.email==='string'&&doc.email.trim().length>0;const body=JSON.stringify({ok});return {status:r.status,headers:{},body,raw:Buffer.from(body)};};}
export async function verifyClaim(packet,digest,nonce){if(typeof nonce!=='string'||!/^[a-f0-9]{64}$/.test(nonce))throw Error('invalid handoff');const path=packet instanceof URL?fileURLToPath(packet):resolve(packet);const marker=JSON.parse(await readFile(`${path}.spent`,'utf8'));if(marker.digest!==digest||marker.nonceSha256!==sha(nonce))throw Error('claim mismatch');}
function readHandoff(){const b=Buffer.alloc(65);let n=0;while(n<65){const k=readSync(4,b,n,65-n,null);if(!k)break;n+=k;}return b.subarray(0,n).toString('utf8');}
export async function launch({packet,digest,out},{mint:mintImpl=mint,fetchImpl=fetch,runtimeCheck:check=runtimeCheck,claimCheck=async()=>verifyClaim(packet,digest,readHandoff())}={}) {
 const p=await verifyPacket(packet,digest);await check(p);for(const k of Object.keys(process.env))if(k==='GOOGLE_APPLICATION_CREDENTIALS'||k==='FIREBASE_TOKEN'||k==='PYTHONPATH'||k==='PYTHONHOME'||k==='NODE_OPTIONS'||k.startsWith('DYLD_')||k.startsWith('LD_')||k.startsWith('CLOUDSDK_'))throw Error('credential environment refused');
 await claimCheck();
 await mkdir(out,{mode:0o700});const token=await mintImpl(p);if(typeof token!=='string'||! /^[\x21-\x7e]{20,4096}$/.test(token))throw Error('credential invalid');
 const sandbox=makeWire({instance:p.instance,project:p.project,token,fetchImpl,serviceOnly:p.mode==='api-recovery',managementOnly:p.mode==='instance-recovery'}),auth=authWire(token,fetchImpl);const wire=(r,h)=>r.step==='auth-preflight'?auth(r,h):sandbox(r,h);
 const counted=await createTransport({file:join(out,'requests.jsonl'),max:p.maxRequests,reserve:p.cleanupReserve,wire});
 try{const pre=await counted({step:'auth-preflight',method:'POST',url:TOKENINFO,phase:'normal'});if(JSON.parse(pre.body).ok!==true)return 'auth-refused';if(p.mode==='api-recovery')return await recoverApi(counted,p);if(p.mode==='instance-recovery')return await recoverInstance(counted,p);const prefix=`rnext1_${randomBytes(12).toString('hex')}`;return await runPacket({packet,digest,prefix,transport:counted});}finally{await counted.close();}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){try{const result=await launch(parseArgs(process.argv.slice(2)));process.stdout.write(`${result}\n`);if(result!=='closed')process.exitCode=3;}catch{process.stderr.write('R-next1 stopped; preserve output and seek reviewed recovery.\n');process.exitCode=2;}}
