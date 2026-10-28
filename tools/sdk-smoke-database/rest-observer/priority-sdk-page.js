import {initializeApp,deleteApp} from 'https://www.gstatic.com/firebasejs/12.18.0/firebase-app.js';
import * as D from 'https://www.gstatic.com/firebasejs/12.18.0/firebase-database.js';
import {registerPriorityCase} from './priority-page.mjs';
D.forceWebSockets();
let app,database,unsubs=[];
window.__priorityStart = async (config,role) => {
 if(app||!config||!['writer','observer'].includes(role)||!/^rnext1_[a-f0-9]{24}\/r[12]\/[a-z-]+$/.test(config.base))throw Error('invalid priority page config');
 app=initializeApp({projectId:config.projectId,databaseURL:config.databaseURL},`${role}-${config.name}`);database=D.getDatabase(app);
 if(role==='observer')for(const leaf of ['s','t'])unsubs.push(D.onValue(D.ref(database,`${config.base}/${leaf}`),snapshot=>window.__priorityEvent({type:'value',leaf,value:snapshot.exportVal()}),()=>window.__priorityEvent({type:'cancel',leaf})));
};
window.__priorityRegister = async spec => registerPriorityCase(D,database,window.__priorityBase,spec,window.__priorityEvent);
window.__prioritySetBase = base => {if(!/^rnext1_[a-f0-9]{24}\/r[12]\/[a-z-]+$/.test(base))throw Error('invalid priority base');window.__priorityBase=base;};
window.__priorityOffline = () => {if(!database)throw Error('not started');D.goOffline(database);};
window.__priorityClose = async () => {for(const unsubscribe of unsubs)unsubscribe();unsubs=[];if(app)await deleteApp(app);app=undefined;database=undefined;};
