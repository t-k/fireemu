import test from 'node:test';import assert from 'node:assert/strict';import {preparePriorityBrowser} from './priority-bootstrap.mjs';
test('invalid priority runtime is refused before any browser launch',async()=>{let imported=false;await assert.rejects(preparePriorityBrowser({browser:{files:[]}},'invalid',{load:()=>{imported=true;}}));assert.equal(imported,false);});
