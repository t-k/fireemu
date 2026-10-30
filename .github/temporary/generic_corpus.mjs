// Preparation-only positive candidates. Codec validity does not imply production success.
const int = n => ({integerValue:String(n)});
const str = s => ({stringValue:s});
const arr = values => ({arrayValue:{values}});
const map = fields => ({mapValue:{fields}});
const nil = {nullValue:'NULL_VALUE'};
const bytes = s => ({bytesValue:Buffer.from(s).toString('base64')});
const vector = map({__type__:str('__vector__'),value:arr([{doubleValue:1},{doubleValue:2}])});
const fn = (name,...args) => ({functionValue:{name,args}});
export const seed = [{path:'positive/d1',fields:{n:int(1)}}];
export function cases(ctx) {
 const own=`projects/${ctx.project}/databases/${ctx.database}/documents/`;
 const ref = path => ({referenceValue:own+path});
 const v=[int(7),int(2),int(5)];
 const entries=[
  ['minimum-array','minimum',[arr(v)],'array[any?]'],
  ['minimum-variadic','minimum',[int(7),int(2)],'any? variadic >=2'],
  ['maximum-array','maximum',[arr(v)],'array[any?]'],
  ['maximum-variadic','maximum',[int(7),int(2)],'any? variadic >=2'],
  ['sum-array','sum',[arr(v)],'array[any]'],
  ['negate-int','negate',[int(7)],'number int64 representative'],
  ['bit-not-int','bit_not',[int(5)],'number int64 representative'],
  ['bit-left-shift-int','bit_left_shift',[int(5),int(1)],'number,int64'],
  ['bit-right-shift-int','bit_right_shift',[int(8),int(1)],'number,int64'],
  ['cmp-int','cmp',[int(2),int(7)],'any,any int64 representative'],
  ['storage-size-string','storage_size',[str('abc')],'any string representative'],
  ['coalesce-null-string','coalesce',[nil,str('fallback')],'any? variadic >=2'],
  ['namespace-reference','namespace',[ref('positive/d1')],'own document_reference'],
  ['has-ancestor-reference','has_ancestor',[ref('positive/d1/children/c1'),ref('positive/d1')],'own document_reference pair'],
  ['reference-slice','reference_slice',[ref('positive/d1/children/c1'),int(0),int(1)],'reference,int64,int64'],
  ['autogen-document-id','autogen_document_id',[],'zero arguments nondeterministic'],
  ['replace-document-id','replace_document_id',[ref('positive/d1'),str('d2')],'reference,new_id string representative'],
  ['get-field-map','get_field',[map({answer:int(7)}),str('answer')],'map,string'],
  ['offset-array','offset',[arr([int(10),int(20)]),int(1)],'array,int64'],
  ['reverse-string','reverse',[str('abc')],'string'],
  ['reverse-bytes','reverse',[bytes('abc')],'bytes'],
  ['reverse-array','reverse',[arr([int(1),int(2)])],'array[any]'],
  ['length-string','length',[str('abc')],'string'],
  ['length-bytes','length',[bytes('abc')],'bytes'],
  ['length-array','length',[arr([int(1),int(2)])],'array[any]'],
  ['length-map','length',[map({answer:int(7)})],'map[string,any]'],
  ['length-vector','length',[vector],'vector'],
  ['string-concat','string_concat',[str('ab'),str('cd')],'string variadic >=2'],
  ['geo-distance','geo_distance',[{geoPointValue:{latitude:0,longitude:0}},{geoPointValue:{latitude:0,longitude:1}}],'lat_lng,lat_lng'],
 ];
 return entries.map(([id,name,args,overload])=>({id,name,overload,nondeterministic:name==='autogen_document_id',request:{database:`projects/${ctx.project}/databases/${ctx.database}`,structuredPipeline:{pipeline:{stages:[{name:'collection',args:[{referenceValue:'/positive'}]},{name:'select',args:[map({value:fn(name,...args)})]}]}}}}));
}
