import {isDeepStrictEqual} from 'node:util'; import {readFile} from 'node:fs/promises'; import {createHash} from 'node:crypto'; import {dirname,resolve,sep} from 'node:path'; import {fileURLToPath} from 'node:url';
const hash=b=>createHash('sha256').update(b).digest('hex');
export async function verifyPacket(file, expected) {
 if(!/^[a-f0-9]{64}$/.test(expected)) throw Error('invalid packet digest');
 const path=file instanceof URL?fileURLToPath(file):file; const bytes=await readFile(path);if(hash(bytes)!==expected)throw Error('packet digest');
 const p=JSON.parse(bytes);if(!/^[a-z][a-z0-9-]{3,62}$/.test(p.project)||!/^[0-9]{1,20}$/.test(p.projectNumber)||!/^[a-z][a-z0-9-]{3,62}$/.test(p.instance)||!/^[a-z0-9-]{3,32}$/.test(p.location)||!Number.isSafeInteger(p.maxRequests)||p.maxRequests<1||!Number.isSafeInteger(p.cleanupReserve)||p.cleanupReserve<0||p.cleanupReserve>=p.maxRequests||p.adcAcquisitions!==1||!/^[a-f0-9]{64}$/.test(p.baselineRulesSha256)||!Array.isArray(p.sources)||p.sources.length<1)throw Error('packet contract');
 const required=['runner.mjs','lifecycle.mjs','transport.mjs','orchestrator.mjs','packet-gate.mjs','launcher.mjs','provider.mjs','adc-preflight.mjs']; if(p.sources.length!==required.length || required.some(name=>!p.sources.some(e=>e.path===name))) throw Error('source closure');
 const base=dirname(resolve(path));const seen=new Set();for(const entry of p.sources){if(typeof entry.path!=='string'||!/^[-\w.]+$/.test(entry.path)||!/^([a-f0-9]{64})$/.test(entry.sha256)||seen.has(entry.path))throw Error('source pin');seen.add(entry.path);const source=resolve(base,entry.path);if(!source.startsWith(base+sep)||hash(await readFile(source))!==entry.sha256||hash(await readFile(new URL(entry.path,import.meta.url)))!==entry.sha256)throw Error('source digest');}
 return p;
}
export function checkAnchor(actual, expected, request) {
 if(actual.status!==expected.status||(actual.headers.etag??null)!==expected.etag)throw Error('anchor mismatch');
 const filtered=actual.status===200 && request?.method==='GET' && /^\/rnext1_[a-f0-9]{24}\/r[12]\/query\.json$/.test(request.path) && request.query==='orderBy=%22h%22&startAt=2';
 if(!filtered){if(actual.body!==expected.bodyText)throw Error('anchor mismatch');return;}
 let a,b;try{a=JSON.parse(actual.body);b=JSON.parse(expected.bodyText);}catch{throw Error('anchor mismatch');}
 if(!a||typeof a!=='object'||Array.isArray(a)||!b||typeof b!=='object'||Array.isArray(b)||!isDeepStrictEqual(a,b))throw Error('anchor mismatch');
}
