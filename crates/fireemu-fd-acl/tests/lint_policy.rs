//! Keeps this crate the workspace's only exception to `unsafe_code = "forbid"`.

use std::path::{Path, PathBuf};

const THIS_CRATE: &str = "crates/fireemu-fd-acl";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf()
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// The `key = value` lines of one TOML table, without comments and blank lines.
fn table_lines<'a>(manifest: &'a str, table: &str) -> Vec<&'a str> {
    let header = format!("[{table}]");
    let mut lines = manifest.lines().map(str::trim);
    assert!(
        lines.by_ref().any(|line| line == header),
        "missing table {header}"
    );
    lines
        .take_while(|line| !line.starts_with('['))
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

fn workspace_members(manifest: &str) -> Vec<String> {
    let mut lines = manifest.lines().map(str::trim);
    assert!(lines.by_ref().any(|line| line == "members = ["));
    lines
        .take_while(|line| *line != "]")
        .map(|line| line.trim_end_matches(',').trim_matches('"').to_owned())
        .collect()
}

#[test]
fn every_other_workspace_member_inherits_the_forbidding_workspace_lints() {
    let root = workspace_root();
    let manifest = read(&root.join("Cargo.toml"));
    assert!(table_lines(&manifest, "workspace.lints.rust").contains(&"unsafe_code = \"forbid\""));

    let members = workspace_members(&manifest);
    assert!(members.iter().any(|member| member == THIS_CRATE));
    for member in members.iter().filter(|member| *member != THIS_CRATE) {
        let member_manifest = read(&root.join(member).join("Cargo.toml"));
        assert_eq!(
            table_lines(&member_manifest, "lints"),
            ["workspace = true"],
            "{member} must inherit the workspace lints"
        );
    }
}

#[test]
fn this_crate_restates_the_workspace_lints_with_unsafe_code_denied() {
    let root = workspace_root();
    let workspace = read(&root.join("Cargo.toml"));
    let own = read(&root.join(THIS_CRATE).join("Cargo.toml"));

    for (workspace_table, own_table) in [
        ("workspace.lints.rust", "lints.rust"),
        ("workspace.lints.clippy", "lints.clippy"),
    ] {
        let own_lines = table_lines(&own, own_table);
        for line in table_lines(&workspace, workspace_table) {
            let expected = if line == "unsafe_code = \"forbid\"" {
                "unsafe_code = \"deny\""
            } else {
                line
            };
            assert!(
                own_lines.contains(&expected),
                "{own_table} must contain {expected:?}"
            );
        }
    }
    let rust = table_lines(&own, "lints.rust");
    assert!(rust.contains(&"unsafe_op_in_unsafe_fn = \"deny\""));
    let clippy = table_lines(&own, "lints.clippy");
    for lint in [
        "undocumented_unsafe_blocks = \"deny\"",
        "multiple_unsafe_ops_per_block = \"deny\"",
        "missing_safety_doc = \"deny\"",
    ] {
        assert!(clippy.contains(&lint), "lints.clippy must contain {lint:?}");
    }
}

// The source scan below keeps the unsafe code where the manifest comment says it is. Clippy
// alone does not: `#[allow(unused, unsafe_code)]` or `#[expect(unsafe_code)]` on any item,
// in any file of the crate, would let a second unsafe block compile cleanly. So every `.rs`
// file under the crate directory (src/, tests/, benches/, examples/, build.rs and anything
// else) is tokenized, and the policy is checked on tokens rather than on text, so that
// spacing, list position and raw identifiers do not matter and comments and string literals
// do not count.

/// The only place where the crate names `unsafe_code`: the attribute on the FFI module.
const EXPECTED_ALLOWANCE: &str = "# [ allow ( unsafe_code ) ] mod ffi {";
/// The file that holds the FFI module.
const FFI_FILE: &str = "src/macos.rs";
/// The FFI module's name.
const FFI_MODULE: &str = "ffi";
/// `acl_get_fd_np`, `acl_get_entry` and `acl_free`, one `unsafe` block each.
const EXPECTED_UNSAFE_BLOCKS: usize = 3;

/// A token of Rust source and the line it starts on.
///
/// Whitespace and comments (line, block and doc comments, nested ones included) produce no
/// token. A string, byte-string, C-string or raw-string literal becomes the placeholder `""`,
/// and a char or byte literal becomes `''`, so their contents are never read as code. A raw
/// identifier `r#name` becomes `name`. A lifetime `'a` becomes `'` followed by `a`.
#[derive(Debug, Clone, PartialEq)]
struct Token {
    text: String,
    line: usize,
}

/// One tokenized source file, named by its path relative to the crate directory.
struct SourceFile {
    relative: String,
    tokens: Vec<Token>,
}

fn is_identifier_start(character: char) -> bool {
    character == '_' || character.is_alphabetic()
}

fn is_identifier_continue(character: char) -> bool {
    character == '_' || character.is_alphanumeric()
}

/// Skips a quoted literal whose opening quote is just before `start`, honouring backslash
/// escapes, and returns the index after the closing quote.
fn skip_quoted(characters: &[char], start: usize, quote: char, line: &mut usize) -> usize {
    let mut index = start;
    while let Some(&character) = characters.get(index) {
        match character {
            '\\' => {
                if characters.get(index + 1) == Some(&'\n') {
                    *line += 1;
                }
                index += 2;
            }
            '\n' => {
                *line += 1;
                index += 1;
            }
            _ if character == quote => return index + 1,
            _ => index += 1,
        }
    }
    panic!("unterminated {quote} literal");
}

/// Skips a raw string whose opening `"` is just before `start` and that closes with `"`
/// followed by `hashes` hash signs; returns the index after the closing delimiter.
fn skip_raw(characters: &[char], start: usize, hashes: usize, line: &mut usize) -> usize {
    let mut index = start;
    while let Some(&character) = characters.get(index) {
        if character == '\n' {
            *line += 1;
        }
        if character == '"'
            && (1..=hashes).all(|offset| characters.get(index + offset) == Some(&'#'))
        {
            return index + 1 + hashes;
        }
        index += 1;
    }
    panic!("unterminated raw string literal");
}

/// Skips a block comment starting at `start` (`/*`), nested ones included; returns the index
/// after it.
fn skip_block_comment(characters: &[char], start: usize, line: &mut usize) -> usize {
    let mut depth = 0_usize;
    let mut index = start;
    while index < characters.len() {
        match (characters[index], characters.get(index + 1)) {
            ('/', Some('*')) => {
                depth += 1;
                index += 2;
            }
            ('*', Some('/')) => {
                depth -= 1;
                index += 2;
                if depth == 0 {
                    return index;
                }
            }
            ('\n', _) => {
                *line += 1;
                index += 1;
            }
            _ => index += 1,
        }
    }
    panic!("unterminated block comment");
}

/// Reads a word that starts at `start` and may be a literal prefix (`r`, `b`, `br`, `c`,
/// `cr`) or a raw identifier. Returns the token text and the index after it.
fn word_or_prefixed_literal(
    characters: &[char],
    start: usize,
    line: &mut usize,
) -> (String, usize) {
    let mut end = start;
    while characters
        .get(end)
        .copied()
        .is_some_and(is_identifier_continue)
    {
        end += 1;
    }
    let word: String = characters[start..end].iter().collect();
    let next = characters.get(end).copied();
    if matches!(word.as_str(), "r" | "br" | "cr") {
        let mut after_hashes = end;
        while characters.get(after_hashes) == Some(&'#') {
            after_hashes += 1;
        }
        let hashes = after_hashes - end;
        if characters.get(after_hashes) == Some(&'"') {
            return (
                "\"\"".into(),
                skip_raw(characters, after_hashes + 1, hashes, line),
            );
        }
        if word == "r"
            && hashes == 1
            && characters
                .get(after_hashes)
                .copied()
                .is_some_and(is_identifier_start)
        {
            return word_or_prefixed_literal(characters, after_hashes, line);
        }
    }
    if matches!(word.as_str(), "b" | "c") && next == Some('"') {
        return ("\"\"".into(), skip_quoted(characters, end + 1, '"', line));
    }
    if word == "b" && next == Some('\'') {
        return ("''".into(), skip_quoted(characters, end + 1, '\'', line));
    }
    (word, end)
}

fn tokenize(source: &str) -> Vec<Token> {
    let characters: Vec<char> = source.chars().collect();
    let mut tokens = Vec::new();
    let mut line = 1;
    let mut index = 0;
    while let Some(&character) = characters.get(index) {
        let start_line = line;
        let next = characters.get(index + 1).copied();
        let (text, end) = match character {
            '\n' => {
                line += 1;
                index += 1;
                continue;
            }
            _ if character.is_whitespace() => {
                index += 1;
                continue;
            }
            '/' if next == Some('/') => {
                while characters.get(index).is_some_and(|&c| c != '\n') {
                    index += 1;
                }
                continue;
            }
            '/' if next == Some('*') => {
                index = skip_block_comment(&characters, index, &mut line);
                continue;
            }
            '"' => (
                "\"\"".into(),
                skip_quoted(&characters, index + 1, '"', &mut line),
            ),
            '\'' if next == Some('\\') => (
                "''".into(),
                skip_quoted(&characters, index + 1, '\'', &mut line),
            ),
            '\'' if characters.get(index + 2) == Some(&'\'') => ("''".into(), index + 3),
            _ if is_identifier_start(character) => {
                word_or_prefixed_literal(&characters, index, &mut line)
            }
            _ if character.is_ascii_digit() => {
                let mut end = index;
                while characters
                    .get(end)
                    .copied()
                    .is_some_and(is_identifier_continue)
                {
                    end += 1;
                }
                (characters[index..end].iter().collect(), end)
            }
            _ => (character.to_string(), index + 1),
        };
        tokens.push(Token {
            text,
            line: start_line,
        });
        index = end;
    }
    tokens
}

/// Every `.rs` file below `directory`, recursively. A symbolic link fails the scan, because
/// it could bring in a file from outside the crate.
fn rust_files(directory: &Path, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        let file_type = std::fs::symlink_metadata(&path).unwrap().file_type();
        assert!(
            !file_type.is_symlink(),
            "{} is a symbolic link",
            path.display()
        );
        if file_type.is_dir() {
            if path.file_name().is_some_and(|name| name != "target") {
                rust_files(&path, found);
            }
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
}

fn crate_sources() -> Vec<SourceFile> {
    let crate_directory = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut paths = Vec::new();
    rust_files(crate_directory, &mut paths);
    paths.sort();
    paths
        .iter()
        .map(|path| SourceFile {
            relative: path
                .strip_prefix(crate_directory)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/"),
            tokens: tokenize(&read(path)),
        })
        .collect()
}

fn joined(tokens: &[Token]) -> String {
    tokens
        .iter()
        .map(|token| token.text.as_str())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The token range of the body of `mod name { .. }`, braces excluded.
fn module_body(tokens: &[Token], name: &str) -> Option<std::ops::Range<usize>> {
    let open = tokens.windows(3).position(|window| {
        window[0].text == "mod" && window[1].text == name && window[2].text == "{"
    })? + 2;
    let mut depth = 0_usize;
    for (index, token) in tokens.iter().enumerate().skip(open) {
        match token.text.as_str() {
            "{" => depth += 1,
            "}" => {
                depth -= 1;
                if depth == 0 {
                    return Some(open + 1..index);
                }
            }
            _ => {}
        }
    }
    None
}

/// The index ranges of every attribute, `#[..]` or `#![..]`, brackets included.
fn attributes(tokens: &[Token]) -> Vec<std::ops::Range<usize>> {
    let mut found = Vec::new();
    for (start, token) in tokens.iter().enumerate() {
        if token.text != "#" {
            continue;
        }
        let mut open = start + 1;
        if tokens.get(open).is_some_and(|token| token.text == "!") {
            open += 1;
        }
        if tokens.get(open).is_none_or(|token| token.text != "[") {
            continue;
        }
        let mut depth = 0_usize;
        for (index, token) in tokens.iter().enumerate().skip(open) {
            match token.text.as_str() {
                "[" => depth += 1,
                "]" => {
                    depth -= 1;
                    if depth == 0 {
                        found.push(start..index + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
    }
    found
}

/// Every way `files` departs from the policy; empty when it holds.
///
/// - The identifier `unsafe_code` occurs exactly once in the crate, as
///   `#[allow(unsafe_code)]` directly on `mod ffi` in `src/macos.rs`. Any other mention,
///   whether in `allow`, `expect`, `warn` or `cfg_attr`, in any list position, is a violation.
/// - The keyword `unsafe` occurs only as `unsafe {` inside that module, exactly
///   `EXPECTED_UNSAFE_BLOCKS` times. `unsafe fn`, `unsafe impl`, `unsafe extern`,
///   `unsafe trait` and `unsafe(..)` attributes are violations anywhere.
/// - No attribute sets `path = ..` and no `include!` is used, since either could compile a
///   file that this scan does not read.
fn policy_violations(files: &[SourceFile]) -> Vec<String> {
    let mut violations = Vec::new();
    let mut allowances = Vec::new();
    let mut unsafe_blocks = 0;
    for file in files {
        let tokens = &file.tokens;
        let ffi_body = if file.relative == FFI_FILE {
            module_body(tokens, FFI_MODULE)
        } else {
            None
        };
        for (index, token) in tokens.iter().enumerate() {
            let site = format!("{}:{}", file.relative, token.line);
            let following = tokens
                .get(index + 1)
                .map_or("", |token| token.text.as_str());
            match token.text.as_str() {
                "unsafe_code" => {
                    let context =
                        joined(&tokens[index.saturating_sub(4)..tokens.len().min(index + 6)]);
                    allowances.push(format!("{site} `{context}`"));
                    if file.relative != FFI_FILE || context != EXPECTED_ALLOWANCE {
                        violations.push(format!("{site}: unsafe_code named in `{context}`"));
                    }
                }
                "unsafe" => {
                    let in_ffi = ffi_body.as_ref().is_some_and(|body| body.contains(&index));
                    if in_ffi && following == "{" {
                        unsafe_blocks += 1;
                    } else {
                        violations.push(format!(
                            "{site}: `unsafe {following}` outside the FFI module's unsafe blocks"
                        ));
                    }
                }
                "include" if following == "!" => {
                    violations.push(format!(
                        "{site}: include! compiles a file this scan does not read"
                    ));
                }
                _ => {}
            }
        }
        for attribute in attributes(tokens) {
            let body = &tokens[attribute.clone()];
            if body
                .windows(2)
                .any(|pair| pair[0].text == "path" && pair[1].text == "=")
            {
                violations.push(format!(
                    "{}:{}: `{}` points a module at a file this scan may not read",
                    file.relative,
                    body[0].line,
                    joined(body)
                ));
            }
        }
    }
    if allowances.len() != 1 {
        violations.push(format!(
            "unsafe_code must be named exactly once, as `{EXPECTED_ALLOWANCE}` in {FFI_FILE}; found {allowances:?}"
        ));
    }
    if unsafe_blocks != EXPECTED_UNSAFE_BLOCKS {
        violations.push(format!(
            "expected {EXPECTED_UNSAFE_BLOCKS} unsafe blocks in the FFI module, found {unsafe_blocks}"
        ));
    }
    violations
}

#[test]
fn unsafe_code_is_allowed_on_one_module_and_used_only_there() {
    let files = crate_sources();
    let names: Vec<&str> = files.iter().map(|file| file.relative.as_str()).collect();
    for expected in ["src/lib.rs", FFI_FILE, "tests/lint_policy.rs"] {
        assert!(
            names.contains(&expected),
            "the scan missed {expected}: {names:?}"
        );
    }
    assert_eq!(policy_violations(&files), Vec::<String>::new());
}

/// The crate's own sources with `extra` appended to the file named `relative`, which is
/// created if the crate has no such file.
fn crate_sources_with(relative: &str, extra: &str) -> Vec<SourceFile> {
    let crate_directory = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = crate_sources();
    let existing = crate_directory.join(relative);
    let text = if existing.exists() {
        read(&existing)
    } else {
        String::new()
    };
    files.retain(|file| file.relative != relative);
    files.push(SourceFile {
        relative: relative.into(),
        tokens: tokenize(&format!("{text}\n{extra}\n")),
    });
    files
}

#[test]
fn a_second_allowance_or_unsafe_use_anywhere_is_caught() {
    let cases: [(&str, &str); 14] = [
        // The review's bypass: another lint first in the list.
        (
            "src/lib.rs",
            "#[allow(unused, unsafe_code)]\npub fn sneaky() -> u8 { let x = 1u8; /* SAFETY: probe. */ unsafe { *std::ptr::addr_of!(x) } }",
        ),
        ("src/lib.rs", "#[expect(unsafe_code)]\nmod other {}"),
        ("src/lib.rs", "#[allow( unsafe_code )]\nmod other {}"),
        ("src/lib.rs", "#![cfg_attr(all(), allow(r#unsafe_code))]"),
        ("src/lib.rs", "#[warn(unsafe_code)]\nmod other {}"),
        ("tests/lint_policy.rs", "#[allow(unsafe_code)]\nfn other() {}"),
        ("build.rs", "#[allow(unsafe_code)]\nfn main() {}"),
        ("examples/probe.rs", "#[allow(unsafe_code)]\nfn main() {}"),
        ("benches/probe.rs", "fn main() { unsafe { } }"),
        ("src/lib.rs", "unsafe fn other() {}"),
        ("src/lib.rs", "struct S; unsafe impl Send for S {}"),
        ("src/lib.rs", "unsafe extern \"C\" { fn getpid() -> i32; }"),
        ("src/lib.rs", "#[path = \"../../other/src/lib.rs\"]\nmod other;"),
        ("src/lib.rs", "include!(\"../../other/src/lib.rs\");"),
    ];
    for (relative, extra) in cases {
        let violations = policy_violations(&crate_sources_with(relative, extra));
        assert!(!violations.is_empty(), "not caught in {relative}: {extra}");
    }
}

#[test]
fn unsafe_in_the_ffi_file_counts_only_inside_the_ffi_module() {
    let macos = read(&Path::new(env!("CARGO_MANIFEST_DIR")).join(FFI_FILE));
    let with_file = |text: String| {
        let mut files = crate_sources();
        files.retain(|file| file.relative != FFI_FILE);
        files.push(SourceFile {
            relative: FFI_FILE.into(),
            tokens: tokenize(&text),
        });
        policy_violations(&files)
    };
    assert_eq!(with_file(macos.clone()), Vec::<String>::new());

    // A fourth block inside the module, and a block outside it.
    let fourth = macos.replacen(
        "    impl Drop for ExtendedAcl {",
        "    fn extra() { unsafe { acl_free(std::ptr::null_mut()) }; }\n    impl Drop for ExtendedAcl {",
        1,
    );
    assert_ne!(fourth, macos);
    assert!(!with_file(fourth).is_empty());
    let outside = format!("{macos}\nfn extra() {{ unsafe {{ }} }}\n");
    assert!(!with_file(outside).is_empty());
}

#[test]
fn the_tokenizer_skips_comments_and_literals_but_not_code() {
    let names = |source: &str, name: &str| {
        tokenize(source)
            .iter()
            .filter(|token| token.text == name)
            .count()
    };
    let ignored = [
        "// #[allow(unsafe_code)] unsafe {}",
        "/// unsafe_code\n//! unsafe { }",
        "/* unsafe_code /* nested unsafe */ still unsafe_code */",
        "const A: &str = \"allow(unsafe_code) \\\" unsafe {\";",
        "const B: &str = r#\"allow(unsafe_code) \" unsafe {\"#;",
        "const C: &[u8] = br##\"unsafe_code \"# unsafe\"##;",
        "const D: &[u8] = b\"unsafe_code\\\\\";",
        "const E: char = '\"'; const F: u8 = b'\\''; const G: char = '\\u{22}';",
    ];
    for source in ignored {
        assert_eq!(names(source, "unsafe_code"), 0, "{source}");
        assert_eq!(names(source, "unsafe"), 0, "{source}");
    }
    let seen = [
        "const E: char = '\"'; #[allow(unsafe_code)] fn f() { unsafe {} }",
        "fn f<'a>(x: &'a str) -> &'a str { x } #[allow(r#unsafe_code)] fn g() { unsafe {} }",
        "const A: &str = \"\\\\\"; #[expect(unused, unsafe_code)] fn f() { unsafe {} }",
        "const B: &str = r\"\\\"; /* a */ #[allow(unsafe_code)] fn f() { unsafe {} }",
    ];
    for source in seen {
        assert_eq!(names(source, "unsafe_code"), 1, "{source}");
        assert_eq!(names(source, "unsafe"), 1, "{source}");
    }
    let lines: Vec<usize> = tokenize("a\n/* x\n y */ b \"\n\" c")
        .iter()
        .map(|token| token.line)
        .collect();
    assert_eq!(lines, [1, 3, 3, 4]);
}
