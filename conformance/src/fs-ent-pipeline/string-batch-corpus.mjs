import {collection,fn,fld,readFromGrpc,select} from './builders.mjs';

const str=x=>({stringValue:x}),num=x=>({integerValue:String(x)});
const expression=(name,field,...args)=>fn(name,fld(field),...args);
const recipe=(id,fields)=>({id,step:readFromGrpc(id,collection('strings'),select(fields))});
export function stringBatchRecipes(){return [
 recipe('string-byte-length',{ascii_len:expression('byte_length','ascii'),empty_len:expression('byte_length','empty'),utf8_len:expression('byte_length','utf8')}),
 recipe('string-index-of',{first_match:expression('string_index_of','ascii',str('ana')),not_found:expression('string_index_of','ascii',str('z'))}),
 recipe('string-repeat',{repeat3:expression('string_repeat','repeat',num(3)),empty_repeat3:expression('string_repeat','empty',num(3))}),
 recipe('string-replace-all',{replace_all:expression('string_replace_all','replace',str('a'),str('X')),replace_all_miss:expression('string_replace_all','replace',str('z'),str('X')),replace_all_empty_replacement:expression('string_replace_all','replace',str('a'),str(''))}),
 recipe('string-replace-one',{replace_one:expression('string_replace_one','replace',str('a'),str('X')),replace_one_miss:expression('string_replace_one','replace',str('z'),str('X')),replace_one_empty_replacement:expression('string_replace_one','replace',str('a'),str(''))}),
 recipe('string-reverse',{reverse_ascii:expression('string_reverse','ascii'),reverse_empty:expression('string_reverse','empty'),reverse_unicode:expression('string_reverse','unicode')}),
 recipe('string-index-of-empty-search',{empty_needle:expression('string_index_of','ascii',str(''))}),
 recipe('string-replace-all-empty-search',{empty_needle:expression('string_replace_all','replace',str(''),str('X'))}),
 recipe('string-replace-one-empty-search',{empty_needle:expression('string_replace_one','replace',str(''),str('X'))}),
 recipe('string-repeat-zero-count',{repeat_zero:expression('string_repeat','repeat',num(0))}),
 recipe('string-repeat-negative-count',{repeat_negative:expression('string_repeat','repeat',num(-1))}),
];}
export function stringBatchFields(){return Object.fromEntries(Object.entries({ascii:'banana',utf8:'Aé🙂',unicode:'A🙂B',empty:'',repeat:'ab',replace:'aba'}).map(([k,v])=>[k,str(v)]));}
