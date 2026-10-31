import { writeFileSync } from 'node:fs';
const host = process.env.FIREBASE_DATABASE_EMULATOR_HOST;
const base = `http://${host}`;
const prefix = 'p'.repeat(26);
const rulesUrl = `${base}/.settings/rules.json?ns=identity&auth=owner`;
const path = `${base}/${prefix}/probe.json?ns=identity`;
async function req(url, init = {}) { const r = await fetch(url, init); return { status: r.status, body: await r.text() }; }
async function put(url, body) { return req(url, {method:'PUT', headers:{'content-type':'application/json'}, body}); }
const uid = 'synthetic-user';
const cases = [['C0',false],['C1',true],['I0','data == data'],['I1','query == query'],['D1','data != root'],['A0',`auth != null && auth.uid == '${uid}'`],['A1',`auth != null && auth.uid == '${uid}' && auth == auth`]];
await put(`${base}/${prefix}/probe.json?ns=identity&auth=owner`, '{"v":1}');
const rows = [];
for (const [id, value] of cases) {
  const rules = JSON.stringify({rules:{'.read':false,'.write':false,[prefix]:{probe:{'.read':value}}}});
  const load = await put(rulesUrl,rules);
  const readback = await req(rulesUrl);
  const reads = [];
  if(load.status === 200) for(let i=0;i<2;i++) reads.push(await req(path + (id[0] === 'A' ? '&auth_variable_override=' + encodeURIComponent(JSON.stringify({uid})) : '')));
  rows.push({id,load,readback,reads});
}
writeFileSync(process.argv[2], JSON.stringify(rows,null,2)+'\n', {flag:'wx'});
