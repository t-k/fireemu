import {runPriorityCorpus} from './priority-corpus.mjs';
// The lifecycle and browser must be the separately verified, bounded implementations.
export async function runPriorityPacket(io,prefix){
 if(!io||typeof io.lifecycle!=='function'||typeof io.browser!=='function')throw Error('priority runner missing');let rows;
 await io.lifecycle(async()=>{const browser=await io.browser();let error;try{rows=await runPriorityCorpus({prefix,runCase:item=>browser.runCase(item)});}catch(e){error=e;}try{await browser.close();}catch(e){error??=e;}if(error){await (io.sleep??(ms=>new Promise(resolve=>setTimeout(resolve,ms))))(150000);throw error;}});return rows;
}
