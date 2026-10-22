import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { PROGRAMS } from "./fs-ent-pipeline/corpus.mjs";
import { ceilings } from "./fs-query-index/run.mjs";

// Pre-edit program hashes bind all old steps, their order and their original seed contexts.
const OLD_PROGRAMS = [
  {
    "id": "fs-ent-pipeline/o5/names",
    "count": 5,
    "sha256": "2973e6f32cc346d207eca2f66b95e941f5ac1334135350e4f4bc503b5f8660ae"
  },
  {
    "id": "fs-ent-pipeline/o5/literal-keys",
    "count": 6,
    "sha256": "246d9d3bfcd726767afea3454c2431cf5744464fa22199a714e1634aa68c3fb2"
  },
  {
    "id": "fs-ent-pipeline/o5/function-order",
    "count": 13,
    "sha256": "b1bf67e049bfe57e0cd63941e8285e87f3887ac7a9f6e1c46484bd1b40da803e"
  },
  {
    "id": "fs-ent-pipeline/o5/stage-order",
    "count": 14,
    "sha256": "5508a7072b825d072fe3f106e4806afd40a719336ef7c706c436d574220fcb38"
  },
  {
    "id": "fs-ent-pipeline/o5/value-shapes",
    "count": 23,
    "sha256": "19525cdc6086f3ddfa0f618f88f087be0e3af77d5b3333cdbd5c280e444bc486"
  },
  {
    "id": "fs-ent-pipeline/o5/function-names",
    "count": 179,
    "sha256": "ecbdd2c300ea74a2bbcfacbe82389b4d1b63405a9bed2e8fa9f2ff8f7fcb563e"
  }
];

// Fixed typed request oracle prepared before the producer edit. Original probe rows retain
// their values and map order; proposed representatives are explicitly named as proposals.
const EXPECTED_CASES = [
  {"id":"proposed-n14-docid-where-then-empty","question":"195","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"where","args":[{"functionValue":{"name":"equal","args":[{"functionValue":{"name":"document_id","args":[{"integerValue":"1"}]}},{"stringValue":"x"}]}}]},{"name":"select","args":[{"mapValue":{"fields":{}}}]}]}}}},
  {"id":"proposed-n15-docid-add-then-empty","question":"196","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"add_fields","args":[{"mapValue":{"fields":{"a":{"functionValue":{"name":"document_id","args":[{"integerValue":"1"}]}}}}}]},{"name":"select","args":[{"mapValue":{"fields":{}}}]}]}}}},
  {"id":"proposed-n76-map-add-then-empty","question":"197","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"add_fields","args":[{"mapValue":{"fields":{"a":{"functionValue":{"name":"map","args":[{"doubleValue":1.5},{"fieldReferenceValue":"i"}]}}}}}]},{"name":"select","args":[{"mapValue":{"fields":{}}}]}]}}}},
  {"id":"proposed-n78-docid-double-then-limit","question":"198","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"v":{"functionValue":{"name":"document_id","args":[{"doubleValue":1.5}]}}}}}]},{"name":"limit","args":[{"stringValue":"x"}]}]}}}},
  {"id":"proposed-n79-map-where-then-empty","question":"199","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"where","args":[{"functionValue":{"name":"equal","args":[{"fieldReferenceValue":"i"},{"functionValue":{"name":"map","args":[{"doubleValue":1.5},{"fieldReferenceValue":"i"}]}}]}}]},{"name":"select","args":[{"mapValue":{"fields":{}}}]}]}}}},
  {"id":"proposed-n68-aggregate-bad-group-call","question":"200","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"aggregate","args":[{"mapValue":{"fields":{"c":{"functionValue":{"name":"count","args":[{"fieldReferenceValue":"n"}]}}}}},{"mapValue":{"fields":{"":{"functionValue":{"name":"document_id","args":[{"integerValue":"1"}]}}}}}]}]}}}},
  {"id":"proposed-type-tag-integer","question":"205","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"v":{"mapValue":{"fields":{"__type__":{"integerValue":"1"}}}}}}}]}]}}}},
  {"id":"proposed-type-tag-boolean","question":"205","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"v":{"mapValue":{"fields":{"__type__":{"booleanValue":true}}}}}}}]}]}}}},
  {"id":"proposed-type-tag-null","question":"205","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"v":{"mapValue":{"fields":{"__type__":{"nullValue":null}}}}}}}]}]}}}},
  {"id":"proposed-type-tag-double","question":"205","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"v":{"mapValue":{"fields":{"__type__":{"doubleValue":1.5}}}}}}}]}]}}}},
  {"id":"proposed-type-tag-map","question":"205","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"v":{"mapValue":{"fields":{"__type__":{"mapValue":{"fields":{}}}}}}}}}]}]}}}},
  {"id":"proposed-type-tag-array","question":"205","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"v":{"mapValue":{"fields":{"__type__":{"arrayValue":{"values":[]}}}}}}}}]}]}}}},
  {"id":"proposed-type-tag-nested","question":"205","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"v":{"mapValue":{"fields":{"a":{"mapValue":{"fields":{"__type__":{"integerValue":"1"}}}}}}}}}}]}]}}}},
  {"id":"proposed-type-tag-where","question":"205","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"where","args":[{"mapValue":{"fields":{"__type__":{"integerValue":"1"}}}}]}]}}}},
  {"id":"proposed-type-tag-function-argument","question":"205","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"v":{"functionValue":{"name":"equal","args":[{"mapValue":{"fields":{"__type__":{"integerValue":"1"}}}},{"integerValue":"1"}]}}}}}]}]}}}},
  {"id":"proposed-empty-alias-unknown","question":"206","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"":{"functionValue":{"name":"nope_fn","args":[]}}}}}]}]}}}},
  {"id":"proposed-invalid-alias-integer-vector","question":"206","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"a..b":{"fieldReferenceValue":"i"},"c":{"mapValue":{"fields":{"__type__":{"stringValue":"__vector__"},"value":{"arrayValue":{"values":[{"integerValue":"1"}]}}}}}}}}]}]}}}},
  {"id":"proposed-empty-alias-name-map","question":"206","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"":{"mapValue":{"fields":{"__name__":{"integerValue":"1"}}}}}}}]}]}}}},
  {"id":"proposed-empty-alias-equal-one","question":"206","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"":{"functionValue":{"name":"equal","args":[{"fieldReferenceValue":"i"}]}}}}}]}]}}}},
  {"id":"proposed-vector-positive-infinity","question":"207","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"v":{"mapValue":{"fields":{"__type__":{"stringValue":"__vector__"},"value":{"arrayValue":{"values":[{"doubleValue":"Infinity"}]}}}}}}}}]}]}}}},
  {"id":"proposed-vector-negative-infinity","question":"207","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"v":{"mapValue":{"fields":{"__type__":{"stringValue":"__vector__"},"value":{"arrayValue":{"values":[{"doubleValue":"-Infinity"}]}}}}}}}}]}]}}}},
  {"id":"proposed-reference-collection","question":"208","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"v":{"referenceValue":"{docs}/c"}}}}]}]}}}},
  {"id":"proposed-reference-empty-segment","question":"208","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"v":{"referenceValue":"{docs}/c//d"}}}}]}]}}}},
  {"id":"proposed-reference-garbage","question":"208","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"v":{"referenceValue":"garbage"}}}}]}]}}}},
  {"id":"proposed-reference-documents-root","question":"208","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"v":{"referenceValue":"{docs}"}}}}]}]}}}},
  {"id":"proposed-add-reserved-alias","question":"209","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"add_fields","args":[{"mapValue":{"fields":{"__x__":{"fieldReferenceValue":"top"}}}}]}]}}}},
  {"id":"proposed-distinct-dotted-alias","question":"209","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"distinct","args":[{"mapValue":{"fields":{"a.b":{"fieldReferenceValue":"top"}}}}]}]}}}},
  {"id":"proposed-aggregate-unrun-name","question":"209","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"aggregate","args":[{"mapValue":{"fields":{"v":{"functionValue":{"name":"count","args":[]}}}}},{"mapValue":{"fields":{"v":{"fieldReferenceValue":"top"}}}}]}]}}}},
  {"id":"proposed-two-invalid-select-aliases","question":"210","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"a..b":{"fieldReferenceValue":"i"},"c..d":{"fieldReferenceValue":"i"}}}}]}]}}}},
  {"id":"proposed-empty-add-then-negative-limit","question":"210","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"add_fields","args":[{"mapValue":{"fields":{}}}]},{"name":"limit","args":[{"integerValue":"-1"}]}]}}}},
  {"id":"proposed-two-empty-stages","question":"210,220","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{}}}]},{"name":"add_fields","args":[{"mapValue":{"fields":{}}}]}]}}}},
  {"id":"proposed-select-name-field","question":"211","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"__name__":{"fieldReferenceValue":"__name__"}}}}]}]}}}},
  {"id":"proposed-docid-map","question":"213,226","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"v":{"functionValue":{"name":"document_id","args":[{"mapValue":{"fields":{"a":{"integerValue":"1"}}}}]}}}}}]}]}}}},
  {"id":"proposed-docid-boolean","question":"213,226","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"v":{"functionValue":{"name":"document_id","args":[{"booleanValue":true}]}}}}}]}]}}}},
  {"id":"proposed-collectionid-integer","question":"213","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"v":{"functionValue":{"name":"collection_id","args":[{"integerValue":"1"}]}}}}}]}]}}}},
  {"id":"proposed-parent-integer","question":"213","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"v":{"functionValue":{"name":"parent","args":[{"integerValue":"1"}]}}}}}]}]}}}},
  {"id":"proposed-where-field-map","question":"218,227-P29","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"where","args":[{"mapValue":{"fields":{"a":{"fieldReferenceValue":"i"}}}}]}]}}}},
  {"id":"proposed-where-equal-array-field","question":"218","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"where","args":[{"functionValue":{"name":"equal","args":[{"fieldReferenceValue":"i"},{"arrayValue":{"values":[{"fieldReferenceValue":"i"}]}}]}}]}]}}}},
  {"id":"proposed-where-nonliteral-map-key","question":"218","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"where","args":[{"functionValue":{"name":"map","args":[{"fieldReferenceValue":"i"},{"fieldReferenceValue":"i"}]}}]}]}}}},
  {"id":"proposed-aggregate-alias-invalid","question":"219,229","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"aggregate","args":[{"mapValue":{"fields":{"a..b":{"functionValue":{"name":"count","args":[{"fieldReferenceValue":"n"}]}}}}},{"mapValue":{"fields":{}}}]}]}}}},
  {"id":"proposed-aggregate-alias-length","question":"219","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"aggregate","args":[{"mapValue":{"fields":{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":{"functionValue":{"name":"count","args":[{"fieldReferenceValue":"n"}]}}}}},{"mapValue":{"fields":{}}}]}]}}}},
  {"id":"proposed-distinct-alias-invalid","question":"219","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"distinct","args":[{"mapValue":{"fields":{"a..b":{"fieldReferenceValue":"top"}}}}]}]}}}},
  {"id":"proposed-distinct-alias-length","question":"219","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"distinct","args":[{"mapValue":{"fields":{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":{"fieldReferenceValue":"top"}}}}]}]}}}},
  {"id":"proposed-empty-add-then-empty-alias","question":"220","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"add_fields","args":[{"mapValue":{"fields":{}}}]},{"name":"select","args":[{"mapValue":{"fields":{"":{"fieldReferenceValue":"i"}}}}]}]}}}},
  {"id":"proposed-empty-add-alias-then-empty-select","question":"220","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"add_fields","args":[{"mapValue":{"fields":{"":{"fieldReferenceValue":"i"}}}}]},{"name":"select","args":[{"mapValue":{"fields":{}}}]}]}}}},
  {"id":"proposed-select-duplicate-quoted-path","question":"221","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"a":{"fieldReferenceValue":"i"},"`a`":{"fieldReferenceValue":"i"}}}}]}]}}}},
  {"id":"proposed-known-function-where-array-control","question":"227-draft-control","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"where","args":[{"arrayValue":{"values":[{"functionValue":{"name":"document_id","args":[{"fieldReferenceValue":"__name__"}]}}]}}]}]}}}},
  {"id":"proposed-limit-zero","question":"228","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"limit","args":[{"integerValue":"0"}]}]}}}},
  {"id":"proposed-offset-zero","question":"228","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"offset","args":[{"integerValue":"0"}]}]}}}},
  {"id":"proposed-offset-one","question":"228","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"offset","args":[{"integerValue":"1"}]}]}}}},
  {"id":"proposed-n41-unknown-type-double","question":"230","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"v":{"mapValue":{"fields":{"__type__":{"stringValue":"x"},"value":{"arrayValue":{"values":[{"doubleValue":1.0}]}}}}}}}}]}]}}}},
  {"id":"proposed-n60-array-holding-vector","question":"230","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"v":{"arrayValue":{"values":[{"mapValue":{"fields":{"__type__":{"stringValue":"__vector__"},"value":{"arrayValue":{"values":[{"doubleValue":1.0}]}}}}}]}}}}}]}]}}}},
  {"id":"proposed-n69-distinct-then-limit","question":"230","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"distinct","args":[{"mapValue":{"fields":{"a":{"fieldReferenceValue":"top"}}}}]},{"name":"limit","args":[{"stringValue":"x"}]}]}}}},
  {"id":"proposed-r11-unknown-type-integer","question":"231","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"v":{"mapValue":{"fields":{"__type__":{"stringValue":"x"},"value":{"arrayValue":{"values":[{"integerValue":"1"}]}}}}}}}}]}]}}}},
  {"id":"proposed-reversed-overlap","question":"235,245","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"m.r":{"fieldReferenceValue":"top"},"m":{"fieldReferenceValue":"top"}}}}]}]}}}},
  {"id":"proposed-missing-dotted-one","question":"237","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"a.b":{"fieldReferenceValue":"missing"}}}}]}]}}}},
  {"id":"proposed-missing-dotted-deep","question":"237","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"a.b.c":{"fieldReferenceValue":"missing"}}}}]}]}}}},
  {"id":"proposed-missing-dotted-sibling","question":"237","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"a.b":{"fieldReferenceValue":"missing"},"a.c":{"fieldReferenceValue":"top"}}}}]}]}}}},
  {"id":"proposed-collection-string","question":"243","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"stringValue":"ap5"}]}]}}}},
  {"id":"proposed-select-alias-shape-dotted","question":"244","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"a.b":{"functionValue":{"name":"document_id","args":[{"booleanValue":true}]}}}}}]}]}}}},
  {"id":"proposed-select-alias-shape-quoted","question":"244","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"`a`":{"functionValue":{"name":"document_id","args":[{"booleanValue":true}]}}}}}]}]}}}},
  {"id":"proposed-reversed-literal-field-map","question":"245","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"v":{"mapValue":{"fields":{"l":{"fieldReferenceValue":"i"},"k":{"fieldReferenceValue":"top"}}}}}}}]}]}}}},
  {"id":"proposed-reversed-function-field-map","question":"245","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"b":{"functionValue":{"name":"document_id","args":[{"fieldReferenceValue":"__name__"}]}},"a":{"fieldReferenceValue":"i"}}}}]}]}}}},
  {"id":"original-p30-where-unknown-array","question":"227","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"args":[{"arrayValue":{"values":[{"functionValue":{"args":[],"name":"nope_fn"}}]}}],"name":"where"}]}}}},
  {"id":"original-n19-count-field","question":"229","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"args":[{"mapValue":{"fields":{"c":{"functionValue":{"args":[{"fieldReferenceValue":"n"}],"name":"count"}}}}},{"mapValue":{"fields":{}}}],"name":"aggregate"},{"args":[{"mapValue":{"fields":{}}}],"name":"select"}]}}}},
  {"id":"original-n21-count-zero","question":"229","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"args":[{"mapValue":{"fields":{"c":{"functionValue":{"args":[],"name":"count"}}}}},{"mapValue":{"fields":{}}}],"name":"aggregate"},{"args":[{"mapValue":{"fields":{}}}],"name":"select"}]}}}},
  {"id":"original-q3-top-level-parent-chain","question":"212-original","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"args":[{"mapValue":{"fields":{"v":{"functionValue":{"args":[{"functionValue":{"args":[{"functionValue":{"args":[{"fieldReferenceValue":"__name__"}],"name":"parent"}}],"name":"parent"}}],"name":"document_id"}}}}}],"name":"select"},{"args":[{"stringValue":"x"}],"name":"limit"}]}}}},
  {"id":"original-h9-two-failing-calls","question":"236","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"a":{"functionValue":{"name":"document_id","args":[{"stringValue":"s"}]}},"b":{"functionValue":{"name":"parent","args":[{"booleanValue":true}]}}}}}]}]}}}},
  {"id":"original-m4242-00731","question":"236","subcollection":false,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/ap5"}]},{"name":"select","args":[{"mapValue":{"fields":{"v":{"functionValue":{"name":"collection_id","args":[{"fieldReferenceValue":"top"}]}},"`x y`":{"integerValue":"0"},"a.b":{"functionValue":{"name":"map","args":[{"stringValue":"k"},{"functionValue":{"name":"equal","args":[{"fieldReferenceValue":"n"},{"fieldReferenceValue":"top"}]}},{"stringValue":"k"},{"fieldReferenceValue":"top"}]}}}}}]}]}}}},
  {"id":"proposed-q3-subcollection-parent-chain","question":"212-subcollection","subcollection":true,"rpc":"executePipeline","body":{"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/qs5/p/children"}]},{"name":"select","args":[{"mapValue":{"fields":{"v":{"functionValue":{"name":"document_id","args":[{"functionValue":{"name":"parent","args":[{"functionValue":{"name":"parent","args":[{"fieldReferenceValue":"__name__"}]}}]}}]}}}}}]},{"name":"limit","args":[{"stringValue":"x"}]}]}}}},
];

function wireView(value, parent = "") {
  if (Array.isArray(value)) return value.map((item) => wireView(item));
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key,
    parent === "mapValue" && key === "fields"
      ? Object.entries(value[key]).map(([name, item]) => [name, wireView(item)])
      : wireView(value[key], key),
  ]));
}

const oldIds = new Set(OLD_PROGRAMS.map((program) => program.id));
const selected = PROGRAMS.filter((program) => program.id.startsWith("fs-ent-pipeline/o5/"));
const additions = selected.filter((program) => !oldIds.has(program.id));
const seed = (subcollection) => [[subcollection ? "qs5/p/children/d" : "ap5/d", {
  i: { integerValue: "1" }, n: { integerValue: "1" }, top: { stringValue: "t" },
}]];

test("O5 preserves all original 240 steps and their seed contexts", () => {
  for (const expected of OLD_PROGRAMS) {
    const actual = PROGRAMS.find((program) => program.id === expected.id);
    assert.ok(actual, expected.id);
    assert.equal(actual.steps.length, expected.count, expected.id);
    assert.equal(createHash("sha256").update(JSON.stringify(actual)).digest("hex"), expected.sha256, expected.id);
  }
});

for (const expected of EXPECTED_CASES) {
  test(`O5 exact typed question ${expected.id} (${expected.question})`, () => {
    const program = additions.find((candidate) => candidate.steps.some((step) => step.id === expected.id));
    assert.ok(program, `missing ${expected.id}`);
    assert.deepEqual(program.seed, seed(expected.subcollection));
    const actual = program.steps.find((step) => step.id === expected.id);
    assert.equal(actual.rpc, expected.rpc);
    assert.deepEqual(wireView(actual.body), wireView(expected.body), expected.id);
  });
}

test("O5 complete selector includes every reduced question and both Q3 contexts", () => {
  assert.equal(selected.length, 8);
  assert.equal(additions.length, 2);
  assert.deepEqual(additions.flatMap((program) => program.steps.map((step) => step.id)).sort(), EXPECTED_CASES.map((step) => step.id).sort());
  assert.equal(selected.reduce((count, program) => count + program.steps.length, 0), 310);
  assert.deepEqual(ceilings(selected), { maxRequests: 310, maxHarnessRequests: 100 });
});

test("O5 deduplicates complete typed requests with their fixture without losing order", () => {
  const seen = new Set();
  for (const program of additions) {
    for (const step of program.steps) {
      const key = JSON.stringify(wireView([program.seed, step.body]));
      assert.ok(!seen.has(key), `duplicate ${step.id}`);
      seen.add(key);
    }
  }
  const reused = PROGRAMS.find((program) => program.id === "fs-ent-pipeline/o5/function-order").steps.filter((step) => step.id === "unknown-in-array-literal");
  assert.equal(reused.length, 1, "P32 reuses the existing original case");
});
