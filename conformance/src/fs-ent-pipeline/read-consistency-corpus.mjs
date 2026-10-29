import {documents,fld,readFromGrpc,select} from './builders.mjs';
// Fixed owner-only pipeline; each selector uses the same document and expression.
export function readConsistencyStep(){return readFromGrpc('consistency',documents('consistency/d1'),select({v:fld('v')}));}
