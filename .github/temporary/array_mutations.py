import json, pathlib, subprocess, sys

cases = [
    ('scope', 'crates/fireemu-core-firestore/src/pipeline_exec.rs', '.iter()\n                .rev()\n                .find(|(key, _)| key == name)', '.iter()\n                .find(|(key, _)| key == name)', 'fireemu-core-firestore', 'array_variables_shadow_and_index_without_changing_row_fields'),
    ('filter', 'crates/fireemu-core-firestore/src/pipeline_exec.rs', 'Eval::Value(Value::Boolean(true)) if name == "array_filter" => output.push(value)', 'Eval::Value(Value::Boolean(true)) if name == "array_filter" => {}', 'fireemu-core-firestore', 'array_filter_keeps_true_values_and_skips_false_and_null'),
    ('random', 'crates/fireemu-core-firestore/src/pipeline_exec.rs', 'let value = ((word >> 11) as f64) / 9_007_199_254_740_992.0;', 'let value = ((word >> 11) as f64) * 0.0;', 'fireemu-core-firestore', 'rand_advances_per_request_and_skipped_lazy_branch_does_not_draw'),
    ('like', 'crates/fireemu-core-firestore/src/pipeline_exec/scalar.rs', 'regex.push_str(".*");', 'regex.push_str(".");', 'fireemu-adapter-grpc', 'like_wildcards_escapes_and_dynamic_pattern'),
    ('sample_independence', 'crates/fireemu-adapter-grpc/src/local.rs', 'self.expr_seeds\n            .lock()', 'self.sample_seeds\n            .lock()', 'fireemu-adapter-grpc', 'expression_requests_do_not_advance_sample_seed_stream'),
    ('infinity', 'crates/fireemu-adapter-grpc/src/pipeline.rs', 'if d.is_infinite()))', 'if d.is_finite()))', 'fireemu-adapter-grpc', 'recorded_infinite_vectors_and_documents_root_preserve_types'),
    ('root', 'crates/fireemu-adapter-grpc/src/pipeline.rs', 'let inside = name == own\n                || name', 'let inside = name', 'fireemu-adapter-grpc', 'recorded_infinite_vectors_and_documents_root_preserve_types'),
    ('preflight', 'crates/fireemu-adapter-grpc/src/pipeline.rs', '"current_document" | "array_filter" | "array_transform" | "rand"', '"current_document" | "array_filter" | "array_transform"', 'fireemu-adapter-grpc', 'captured_array_and_like_expressions_preserve_typed_results'),
    ('alias', 'crates/fireemu-adapter-grpc/src/pipeline.rs', '&& index == 0', '&& index == 1', 'fireemu-adapter-grpc', 'array_transform_element_alias_validation_and_priority'),
    ('root_function_guard', 'crates/fireemu-adapter-grpc/src/pipeline.rs', "if name.split('/').count() == 5 {", "if false && name.split('/').count() == 5 {", 'fireemu-adapter-grpc', 'strict_refuses_document_functions_of_a_root'),
    ('like_underscore', 'crates/fireemu-core-firestore/src/pipeline_exec/scalar.rs', "'_' => {\n                regex.push('.');", "'_' => {\n                regex.push('_');", 'fireemu-adapter-grpc', 'like_wildcards_escapes_and_dynamic_pattern'),
    ('nan_vector', 'crates/fireemu-adapter-grpc/src/pipeline.rs', 'Some(V::DoubleValue(d)) if d.is_nan()', 'Some(V::DoubleValue(d)) if d.is_nan() && false', 'fireemu-adapter-grpc', 'generated_infinity_reference_projection_cases'),
    ('index_alias', 'crates/fireemu-adapter-grpc/src/pipeline.rs', '&& index == 0', '&& index <= 1', 'fireemu-adapter-grpc', 'array_transform_unobserved_index_alias_remains_refused'),
]
output = pathlib.Path('/tmp/array-scalar-mutants')
output.mkdir(exist_ok=True)
results=[]
for name, file, old, new, package, test in cases:
    path=pathlib.Path(file); original=path.read_text()
    if original.count(old)!=1: raise RuntimeError(f'{name}: expected one mutation anchor, got {original.count(old)}')
    cmd=['cargo','nextest','run','--profile','pr','--locked','-p',package,'-E',f'test({test})']
    try:
        base=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=900)
        (output/f'{name}-noop.log').write_text(base.stdout)
        if base.returncode!=0: raise RuntimeError(f'{name}: noop failed ({base.returncode})')
        path.write_text(original.replace(old,new,1))
        changed=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=900)
        (output/f'{name}-mutant.log').write_text(changed.stdout)
        killed=changed.returncode!=0 and 'FAIL [' in changed.stdout and test in changed.stdout
        results.append({'name':name,'noop':base.returncode,'mutant':changed.returncode,'killed':killed})
        if not killed: raise RuntimeError(f'{name}: mutant not killed by expected test')
    finally:
        path.write_text(original)
        (output/'results.json').write_text(json.dumps(results,indent=2)+'\n')
print(json.dumps(results,indent=2))
