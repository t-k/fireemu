import {readFile} from 'node:fs/promises';import {createRequire} from 'node:module';import {createHash} from 'node:crypto';import {startPriorityBrowser} from './priority-browser.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');const require=createRequire(import.meta.url);
export async function preparePriorityBrowser(packet,port,{load=require}={}){
 if(!packet?.browser||!Array.isArray(packet.browser.files)||!/^\d+$/.test(String(port))||Number(port)<1024||Number(port)>65535)throw Error('priority runtime');const get=name=>{const found=packet.browser.files.filter(x=>x.name===name);if(found.length!==1)throw Error('priority runtime pin');return found[0];};for(const f of packet.browser.files)if(sha(await readFile(f.path))!==f.sha256)throw Error('priority runtime pin');
 const playwright=get('playwright'),chrome=get('chrome'),app=get('app'),database=get('database'),chromium=load(playwright.path).chromium;if(!chromium||typeof chromium.launch!=='function')throw Error('priority runtime');
 const assets={html:'<!doctype html><script type="module" src="/priority-sdk-page.js"></script>',page:await readFile(new URL('./priority-sdk-page.js',import.meta.url),'utf8'),library:await readFile(new URL('./priority-page.mjs',import.meta.url),'utf8'),app:await readFile(app.path,'utf8'),database:await readFile(database.path,'utf8')};
 return ({record,readback})=>startPriorityBrowser({chromium,config:{...packet.browser,project:packet.project,instance:packet.instance,chrome:chrome.path},port:Number(port),assets,record,readback});
}
