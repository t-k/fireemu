import { closeSync, fsyncSync, openSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { mintToken } from '../../../tools/sdk-smoke-database/rest-observer/adc-preflight.mjs';

// One invocation of the already-reviewed gcloud helper; its durable claim survives all failures.
export function acquireStageToken({marker,packetSha256,gcloud,env=process.env,mint=mintToken}) {
  if(typeof marker!=='string' || !/^[a-f0-9]{64}$/.test(packetSha256) || typeof gcloud!=='string')throw new Error('invalid ADC acquisition binding');
  for(const key of Object.keys(env)) if(key==='GOOGLE_APPLICATION_CREDENTIALS' || key==='FIREBASE_TOKEN' || key==='NODE_OPTIONS' || key==='PYTHONPATH' || key==='PYTHONHOME' || key.startsWith('CLOUDSDK_') || key.startsWith('DYLD_') || key.startsWith('LD_'))throw new Error('credential environment refused');
  const fd=openSync(marker,'wx',0o600);
  try {writeFileSync(fd,JSON.stringify({packetSha256})+'\n');fsyncSync(fd);} finally {closeSync(fd);}
  const directory=openSync(dirname(marker),'r');try{fsyncSync(directory);}finally{closeSync(directory);}
  let token;
  try {token=mint(gcloud);}catch{throw new Error('ADC acquisition failed; claim retained');}
  if(typeof token!=='string' || !/^[\x21-\x7e]{20,4096}$/.test(token))throw new Error('ADC acquisition invalid; claim retained');
  return token;
}
