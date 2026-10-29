import {SANDBOX_PROJECT} from './harness.mjs';
import {createHash} from 'node:crypto';
import {readFileSync,mkdirSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {acquireStageToken} from './stage-context-adc.mjs';
import {createStageJournal} from './stage-context-journal.mjs';
import {createStageContext} from './stage-context-target.mjs';
import {runStringAdapter} from './string-batch-adapter.mjs';

export function validateStringPacket(p) {
  if(p?.status!=='AUTHORIZED BY ROOT AFTER REVIEW' || p.project!==SANDBOX_PROJECT || !/^[1-9]\d{5,}$/.test(p.projectNumber) || !/^entpipe2-[0-9]{8}$/.test(p.database) || typeof p.databaseUid!=='string' || !p.databaseUid || p.cases!==11 || p.rounds!==2 || p.maxRequests!==39 || p.recoveryReads!==2 || p.adcAcquisitions!==1)throw Error('unapproved numeric packet');return true;
}
export async function recordString({packetPath,packetSha256,out,marker,leasePath}) {
  if(!/^[a-f0-9]{64}$/.test(packetSha256))throw Error('invalid packet binding');
  const raw=readFileSync(packetPath);if(createHash('sha256').update(raw).digest('hex')!==packetSha256)throw Error('packet digest mismatch');const p=JSON.parse(raw);validateStringPacket(p);
  const lease=JSON.parse(readFileSync(leasePath));if(lease.pid!==process.pid || lease.envelopeId!==p.envelopeId || lease.head!==p.sourceCommit)throw Error('project lease mismatch');
  const token=acquireStageToken({marker,packetSha256,gcloud:'/etc/profiles/per-user/tk/bin/gcloud'});mkdirSync(out,{mode:0o700});const journal=createStageJournal(`${out}/requests.jsonl`,token);
  try{const ctx=createStageContext({run:1,database:p.database,approvedDatabase:p.database,target:{kind:'production',token,quotaProject:p.project}});const result=await runStringAdapter(ctx,{uid:p.databaseUid,projectNumber:p.projectNumber,journal:event=>journal.write(event)});await journal.write({phase:'campaign-complete',counts:result});return result;}finally{journal.close();}
}
if(process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href){const [packetPath,packetSha256,out,marker,leasePath]=process.argv.slice(2);recordString({packetPath,packetSha256,out,marker,leasePath}).catch(()=>{process.stderr.write('String observation stopped; retain claims for review.\n');process.exitCode=2;});}
