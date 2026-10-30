import json, pathlib, subprocess

cases = [
    ('strict_class', 'crates/fireemu-adapter-grpc/src/pipeline.rs', 'Unrecorded::Refuse if recorded_literal_error_class(&error)', 'Unrecorded::Refuse if false && recorded_literal_error_class(&error)', 'recorded_literal_refusal_gate_matrix'),
    ('type_tag', 'crates/fireemu-adapter-grpc/src/pipeline.rs', 'error.starts_with("Field __type__ must be a string; founds ")', 'error.starts_with("Unmatched type refusal ")', 'recorded_literal_refusal_gate_matrix'),
    ('vector_double', 'crates/fireemu-adapter-grpc/src/pipeline.rs', '.all(|e| matches!(e.value_type, Some(V::DoubleValue(_))))', '.all(|_| true)', 'recorded_literal_refusal_gate_matrix'),
    ('utf16', 'crates/fireemu-adapter-grpc/src/pipeline.rs', 'fn reference_literal_error(name: &str) -> Option<String> {\n    let units = |text: &str| text.encode_utf16().count();', 'fn reference_literal_error(name: &str) -> Option<String> {\n    let units = |text: &str| text.len();', 'literal_refusal_preserves_precedence_gate_and_utf16_index'),
    ('gate_bypass', 'crates/fireemu-adapter-grpc/src/pipeline_shape.rs', 'if error.code() != tonic::Code::InvalidArgument {', 'if error.code() == tonic::Code::InvalidArgument {', 'literal_refusal_preserves_precedence_gate_and_utf16_index'),
    ('unordered_map', 'crates/fireemu-adapter-grpc/src/pipeline_shape.rs', 'if map.len() > 1 {\n        return None;\n    }', 'if map.len() > 1000 {\n        return None;\n    }', 'recorded_literal_refusal_gate_matrix'),
    ('foreign_reference', 'crates/fireemu-adapter-grpc/src/pipeline.rs', '(!inside || elements > MAX_PATH_ELEMENTS || reserved).then(|| {', '(!inside && false || elements > MAX_PATH_ELEMENTS || reserved).then(|| {', 'literal_refusal_preserves_precedence_gate_and_utf16_index'),
    ('garbage_prepass', 'crates/fireemu-adapter-grpc/src/pipeline.rs', 'if !name.starts_with("projects/") {', 'if false && !name.starts_with("projects/") {', 'recorded_literal_refusal_gate_matrix'),
    ('outer_arity', 'crates/fireemu-adapter-grpc/src/pipeline.rs', 'Expr::call(&function.name, placeholders, Placement::Value)\n                .map_err(|e| expr_status(e, unrecorded))?;', 'let _ = Expr::call(&function.name, placeholders, Placement::Value);', 'literal_refusal_preserves_precedence_gate_and_utf16_index'),
]
out = pathlib.Path('/tmp/literal-mutants'); out.mkdir(exist_ok=True)
results = []
for name, file, old, new, test in cases:
    path = pathlib.Path(file); original = path.read_text()
    if original.count(old) != 1: raise RuntimeError(f'{name}: anchor count {original.count(old)}')
    cmd = ['cargo', 'nextest', 'run', '--profile', 'pr', '--locked', '-p', 'fireemu-adapter-grpc', '-E', f'test({test})']
    try:
        noop = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=900)
        (out / f'{name}-noop.log').write_text(noop.stdout)
        if noop.returncode != 0: raise RuntimeError(f'{name}: noop failed')
        path.write_text(original.replace(old, new, 1))
        mutant = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=900)
        (out / f'{name}-mutant.log').write_text(mutant.stdout)
        killed = mutant.returncode != 0 and 'FAIL [' in mutant.stdout and test in mutant.stdout
        results.append({'name': name, 'noop': noop.returncode, 'mutant': mutant.returncode, 'killed': killed})
        if not killed: raise RuntimeError(f'{name}: no target test failure')
    finally:
        path.write_text(original)
        (out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
print(json.dumps(results))
