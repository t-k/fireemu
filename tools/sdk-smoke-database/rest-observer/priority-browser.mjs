import {createPriorityMutationGuard} from './priority-mutation-guard.mjs';
const NAME=/^[a-z][a-z0-9-]{3,62}$/;
export function validatePriorityBrowser(p){if(!p||!NAME.test(p.project)||!NAME.test(p.instance)||!Number.isInteger(p.maxHttp)||p.maxHttp<1||p.maxHttp>160||!Number.isInteger(p.maxSockets)||p.maxSockets<1||p.maxSockets>32||!Number.isInteger(p.maxFrames)||p.maxFrames<1||p.maxFrames>1600)throw Error('invalid priority browser limits');}
export function createPriorityWireGuard(p,record){
 validatePriorityBrowser(p);if(typeof record!=='function')throw Error('journal required');let counts={http:0,sockets:0,frames:0},failure=null,pending=Promise.resolve();
 const log=value=>{pending=pending.then(()=>record(value)).catch(e=>{failure=e;});};
 const fail=message=>{failure??=Error(message);throw failure;};
 return {
  async http(url){const u=new URL(url);if(u.protocol!=='https:'||u.hostname!==`${p.instance}.firebaseio.com`||u.port||u.username||u.password||u.hash)return false;return false;},
  socket(url,owner){const u=new URL(url);if(u.protocol!=='wss:'||u.hostname!==`${p.instance}.firebaseio.com`||u.port||u.username||u.password||u.hash||u.pathname!=='/.ws'||u.searchParams.getAll('v').length!==1||u.searchParams.get('v')!=='5'||u.searchParams.getAll('ns').length>1||(u.searchParams.has('ns')&&u.searchParams.get('ns')!==p.instance)||[...u.searchParams.keys()].some(k=>!['v','ns'].includes(k)))fail('WebSocket target');if(++counts.sockets>p.maxSockets)fail('WebSocket cap');log({type:'socket-open',owner});},
  frame(direction,payload,owner){if(!['sent','received'].includes(direction)||typeof payload!=='string'||payload.length>1048576||/(?:AIza[\w-]{15,}|ya29\.[\w.-]+|Bearer\s+\S+)/i.test(payload))fail('frame refused');if(++counts.frames>p.maxFrames)fail('frame cap');log({type:'frame',owner,direction,payload});},
  close(owner){log({type:'socket-close',owner});},
  async flush(){await pending;if(failure)throw failure;},
  snapshot(){return {...counts};}
 };
}

// The runner takes already verified browser and SDK bytes; it never receives an admin token.
export async function startPriorityBrowser({chromium,config,port,assets,record,readback,serverFactory,sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms))}){
 validatePriorityBrowser(config);if(!chromium||!Number.isInteger(port)||port<1024||port>65535||!assets||typeof record!=='function'||typeof readback!=='function')throw Error('browser configuration');
 const {createServer}=await import('node:http');const guard=createPriorityWireGuard(config,record);let browser,server;
 const paths={'/':assets.html,'/priority-sdk-page.js':assets.page,'/priority-page.mjs':assets.library};
 if(Object.values(paths).some(x=>typeof x!=='string')||typeof assets.app!=='string'||typeof assets.database!=='string')throw Error('missing assets');
 const pages=new Set();const origin=`http://127.0.0.1:${port}`;
 try{
  server=(serverFactory??createServer)((req,res)=>{if(req.method!=='GET'||!Object.hasOwn(paths,req.url)){res.writeHead(404).end();return;}res.writeHead(200,{'content-type':req.url==='/'?'text/html':'text/javascript','content-security-policy':`default-src 'none'; script-src 'self' https://www.gstatic.com; connect-src https://${config.instance}.firebaseio.com wss://${config.instance}.firebaseio.com; worker-src 'none'`});res.end(paths[req.url]);});
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',resolve);});
  browser=await chromium.launch({headless:true,executablePath:config.chrome,args:[`--host-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE ${config.instance}.firebaseio.com`]});
 }catch(e){if(browser)await browser.close().catch(()=>{});if(server?.listening)await new Promise(resolve=>server.close(resolve));throw e;}
 const bounded=async promise=>{let timer;try{return await Promise.race([promise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('priority operation timeout')),20000);})]);}finally{clearTimeout(timer);}};
 const makePage=async(role,item)=>{
  const context=await browser.newContext({serviceWorkers:'block'});let socket,closed=false,socketError,events=[],claimed=false,closing=false,chain=Promise.resolve();const owner={role,round:item.round,id:item.id};const mutations=createPriorityMutationGuard(item,role);await context.routeWebSocket('**/*',async route=>{let remote;try{if(claimed)throw Error('WebSocket reconnect refused');guard.socket(route.url(),owner);claimed=true;const schedule=fn=>{chain=chain.then(async()=>{if(socketError)throw socketError;await fn();}).catch(async e=>{socketError??=e;await route.close().catch(()=>{});if(remote)await remote.close().catch(()=>{});});};route.onMessage(raw=>{try{if(socketError||typeof raw!=='string')throw Error('WebSocket frame refused');mutations.outbound(raw);schedule(async()=>{guard.frame('sent',raw,owner);await guard.flush();remote.send(raw);});}catch(e){socketError??=e;schedule(async()=>{throw socketError;});}});route.onClose(()=>{if(closing)return;closing=true;chain=chain.then(async()=>{await remote.close();closed=true;guard.close(owner);await guard.flush();if(role==='writer'&&!mutations.complete())socketError??=Error('writer closed before acknowledgements');}).catch(e=>{socketError??=e;});});await guard.flush();socket=route;remote=route.connectToServer();remote.onMessage(raw=>schedule(async()=>{if(typeof raw!=='string')throw Error('WebSocket frame refused');mutations.inbound(raw);guard.frame('received',raw,owner);await guard.flush();route.send(raw);}));remote.onClose(()=>{if(closing)return;closing=true;chain=chain.then(async()=>{await route.close();closed=true;guard.close(owner);await guard.flush();if(role==='writer'&&!mutations.complete())socketError??=Error('server closed before acknowledgements');}).catch(e=>{socketError??=e;});});}catch(e){socketError??=e;await route.close().catch(()=>{});if(remote)await remote.close().catch(()=>{});}});const page=await context.newPage();pages.add(page);
  await context.route('**/*',async route=>{const u=new URL(route.request().url());if(u.origin===origin)return route.continue();if(u.origin==='https://www.gstatic.com'&&u.pathname==='/firebasejs/12.18.0/firebase-app.js')return route.fulfill({contentType:'text/javascript',body:assets.app});if(u.origin==='https://www.gstatic.com'&&u.pathname==='/firebasejs/12.18.0/firebase-database.js')return route.fulfill({contentType:'text/javascript',body:assets.database});if(await guard.http(u.href))return route.continue();return route.abort();});

  await page.exposeFunction('__priorityEvent',async e=>{events.push(e);await record({type:'sdk-event',role,round:item.round,id:item.id,event:e});});
  await page.goto(origin);await page.waitForFunction(()=>typeof window.__priorityStart==='function',{timeout:20000});const base=`${item.prefix}/${item.round}/${item.id}`;await page.evaluate(({project,instance,role,base})=>window.__priorityStart({projectId:project,databaseURL:`https://${instance}.firebaseio.com`,name:base.replaceAll('/','-'),base},role),{project:config.project,instance:config.instance,role,base});
  return {page,context,events,base,getSocket:()=>socket,isClosed:()=>closed,error:()=>socketError,settled:()=>chain,complete:()=>mutations.complete()};
 };
 const closePage=async x=>{let error;try{await x.page.evaluate(()=>window.__priorityClose());}catch(e){error=e;}try{await x.page.close();pages.delete(x.page);}catch(e){error??=e;}try{await x.context.close();}catch(e){error??=e;}if(error)throw error;};
 return {
  async openObserver(item){const x=await makePage('observer',item);return {async watch(){const until=Date.now()+20000;while(!['s','t'].every(leaf=>x.events.some(e=>e.type==='value'&&e.leaf===leaf))){if(x.error()||Date.now()>=until)throw Error('observer readiness unknown');await sleep(50);}await guard.flush();},async readback(){return readback(item);},async close(){await closePage(x);},events:x.events};},
  async openWriter(item){const x=await makePage('writer',item);return {async register(spec){await bounded(x.page.evaluate(async({base,spec})=>{window.__prioritySetBase(base);await window.__priorityRegister(spec);},{base:x.base,spec}));await guard.flush();if(x.error())throw x.error();await x.settled();if(!x.complete())throw Error('registration wire incomplete');const acknowledgements=x.events.filter(e=>e.type==='ack');if(acknowledgements.length!==spec.operations.length||acknowledgements.some((e,i)=>e.id!==spec.id||e.index!==i))throw Error('registration acknowledgement incomplete');},async offline(){await x.page.evaluate(()=>window.__priorityOffline());},async waitClosed(){const until=Date.now()+20000;while(!x.isClosed()&&Date.now()<until){if(x.error())throw x.error();await sleep(50);}await x.settled();await guard.flush();if(x.error())throw x.error();return !!x.getSocket()&&x.isClosed();},async close(){await closePage(x);}};},
  async capture(observer){await sleep(20000);await guard.flush();return {observed:observer.events.some(e=>e.type==='value'),events:[...observer.events]};},
  async close(){let error;for(const page of pages)try{await page.close();}catch(e){error??=e;}try{await browser.close();}catch(e){error??=e;}try{await new Promise((resolve,reject)=>server.close(e=>e?reject(e):resolve()));}catch(e){error??=e;}try{await guard.flush();await record({type:'browser-counts',...guard.snapshot()});}catch(e){error??=e;}if(error)throw error;},
  counts:()=>guard.snapshot()
 };
}
