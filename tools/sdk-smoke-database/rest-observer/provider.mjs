import {spawn} from 'node:child_process';
import {createHash,randomBytes} from 'node:crypto';
import {readFile,realpath,open} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {resolve,dirname} from 'node:path';
import {verifyPacket} from './packet-gate.mjs';
import {parseArgs} from './launcher.mjs';
import {mintToken} from './adc-preflight.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
async function runtimeCheck(p){for(const x of [p.runtime.node,p.runtime.gcloud]){if(await realpath(x.path)!==x.realpath||sha(await readFile(x.path))!==x.sha256)throw Error('runtime pin');}if(await realpath(process.execPath)!==p.runtime.node.realpath)throw Error('node executable');}
function spawnChild(node,args,token,nonce){return new Promise((ok,fail)=>{const child=spawn(node,args,{stdio:['ignore','inherit','inherit','pipe','pipe']});child.on('error',fail);for(const fd of [3,4])child.stdio[fd].on('error',()=>{});child.on('close',code=>ok(code??2));child.stdio[3].end(token);child.stdio[4].end(nonce);});}
export async function provide(argv,{verify=verifyPacket,runtimeCheck:check=runtimeCheck,mint=mintToken,spawnChild:run=spawnChild}={}){
 const opts=parseArgs(argv);const p=await verify(opts.packet,opts.digest);await check(p);
 for(const k of Object.keys(process.env))if(k==='GOOGLE_APPLICATION_CREDENTIALS'||k==='FIREBASE_TOKEN'||k==='PYTHONPATH'||k==='PYTHONHOME'||k==='NODE_OPTIONS'||k.startsWith('DYLD_')||k.startsWith('LD_')||k.startsWith('CLOUDSDK_'))throw Error('credential environment refused');
 const nonce=randomBytes(32).toString('hex');const marker=await open(`${opts.packet}.spent`,'wx',0o600);try{await marker.write(JSON.stringify({digest:opts.digest,nonceSha256:sha(nonce)}));await marker.sync();}finally{await marker.close();}const dir=await open(dirname(opts.packet),'r');try{await dir.sync();}finally{await dir.close();}
 const token=mint(p.runtime.gcloud.path);if(typeof token!=='string'||!/^[\x21-\x7e]{20,4096}$/.test(token))throw Error('credential invalid');
 return run(p.runtime.node.path,[fileURLToPath(new URL('./launcher.mjs',import.meta.url)),...argv],token,nonce);
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){try{process.exitCode=await provide(process.argv.slice(2));}catch{process.stderr.write('R-next1 provider stopped; preserve any output and seek review.\n');process.exitCode=2;}}
