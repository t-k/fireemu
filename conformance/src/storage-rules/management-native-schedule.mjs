import { buildNativeManifest, nativeDigest } from "./management-native-manifest.mjs";

/** Reject relabelled, mixed-branch or resealed inventories rather than filtering a full manifest. */
export function validateNativeManifest(manifest) {
  const params=Object.fromEntries(["runId","sourceCommit","sourceTree","bucket","baseline","limits","priorCompileProofs"].map(key=>[key,manifest?.[key]]));
  let canonical;
  try { canonical=buildNativeManifest(params); } catch { throw new Error("invalid native manifest"); }
  if(nativeDigest(manifest)!==nativeDigest(canonical))throw new Error("noncanonical native manifest");
  return canonical;
}

/** Every row belongs to one sequential step; bounded groups may stop only at complete proofs. */
export function buildNativeSchedule(input) {
  const manifest=validateNativeManifest(input);
  const phases={preflight:[],normal:[],recovery:[],credentials:[]};
  for(const row of manifest.rows) {
    if(row.kind==="owner-credential"&&row.phase!=="preflight") {phases.credentials.push({kind:"credential",phase:row.phase,ids:[row.id]});continue;}
    const group=row.settleBase??row.listBase;
    if(group) {
      let step=phases[row.phase].at(-1);
      if(step?.group!==group) {step={kind:row.settleBase?"settle":"pages",group,phase:row.phase,ids:[]};phases[row.phase].push(step);}
      step.ids.push(row.id);
    } else phases[row.phase].push({kind:"request",phase:row.phase,ids:[row.id]});
  }
  const allIds=Object.values(phases).flatMap(steps=>steps.flatMap(step=>step.ids));
  if(allIds.length!==manifest.rows.length||new Set(allIds).size!==allIds.length||manifest.rows.some(row=>!allIds.includes(row.id)))throw new Error("incomplete native schedule");
  const ids=phases.normal.flatMap(step=>step.ids);
  const required=["source/A/read","publish/guard","publish/A","before/release","before/source","before/allow/metadata","before/allow/media","before/allow/decision","before/deny/metadata","before/deny/media","before/deny/decision","invalid/test","after/release","after/source","after/allow/metadata","after/allow/media","after/allow/decision","after/deny/metadata","after/deny/media","after/deny/decision","restore/guard","restore/apply","restore/bucket","restore/bucketless","cleanup/A/guard","cleanup/A/delete","cleanup/A/absence","cleanup/allow/guard","cleanup/allow/delete","cleanup/allow/absence-metadata","cleanup/allow/absence-media","cleanup/deny/guard","cleanup/deny/delete","cleanup/deny/absence-metadata","cleanup/deny/absence-media","cleanup/prefix-empty"];
  if(required.some((id,i)=>!ids.includes(id)||(i>0&&ids.indexOf(id)<=ids.indexOf(required[i-1]))))throw new Error("invalid native schedule order");
  return Object.freeze({...phases,allIds,maximumRecoveryRuns:1,settleConsecutive:2,counts:manifest.counts});
}
