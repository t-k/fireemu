//! Load-time regressions for the official emulator's determinization resource refusal.
//! The eight expressions are direct observations against database emulator4.11.2.

use fireemu_core_database::rules::{RuleSource, RuleSpec, Rules, SourceExpr};

const RESOURCE_REASON: &str = "Illegal regular expression, could not determinize efficiently";

#[allow(
    clippy::unicode_not_nfc,
    reason = "Preserve the exact Unicode code points of the recorded canonical observations."
)]
const OBSERVED: [&str; 8] = [
    r"!('ａ [B'.matches(/^((k*?|-{0,2}[\]a]*){2,3}(k+?[@-[]+[@-[]{0,2}){0}!+?)+(-{0}()[A-z]*|[ -~]{0,2}[^a-z]{2,3}){2,3}\d|[@-[]+(\-+b+)*?([A-Z]?[Z-a]+?){2,3}$/))",
    r"' a'.matches(/k{0}([^a]{2}|[\d]{2,3}\.*)+?(a[`-{]?[A-Z]+|[0-9a-f]*[`-{]+){2,3}/i)",
    r"!(' a'.matches(/k{0}([^a]{2}|[\d]{2,3}\.*)+?(a[`-{]?[A-Z]+|[0-9a-f]*[`-{]+){2,3}/i))",
    r"'ａ [B'.matches(/^((k*?|-{0,2}[\]a]*){2,3}(k+?[@-[]+[@-[]{0,2}){0}!+?)+(-{0}()[A-z]*|[ -~]{0,2}[^a-z]{2,3}){2,3}\d|[@-[]+(\-+b+)*?([A-Z]?[Z-a]+?){2,3}$/)",
    r"'Kａ '.matches(/^([!-Z]+?[-a]+|[@-[]*?(.{0}[^a-z]{2}|k{2})+([\w-][Z-a]){0}){2,3}[\]a]+([^a-z]+){2}/i)",
    r"!('Kａ '.matches(/^([!-Z]+?[-a]+|[@-[]*?(.{0}[^a-z]{2}|k{2})+([\w-][Z-a]){0}){2,3}[\]a]+([^a-z]+){2}/i))",
    r"'ſsZ'.matches(/([^AZ\\a]{2}{2}\{+*Z??|.[i- ]){2}{2}[~]\D|IB|[a][\]][y-s\--I0-\-]/i)",
    r"!('ſsZ'.matches(/([^AZ\\a]{2}{2}\{+*Z??|.[i- ]){2}{2}[~]\D|IB|[a][\]][y-s\--I0-\-]/i))",
];

#[derive(Clone, Copy)]
enum Context {
    Read,
    Write,
    Validate,
}

fn compile(
    expr: &str,
    context: Context,
) -> Result<Rules, fireemu_core_database::rules::RulesError> {
    let source = RuleSource::Expr(SourceExpr {
        text: expr.to_owned(),
        positions: (0..=expr.chars().count()).map(|i| (1, i + 1)).collect(),
    });
    let mut node = RuleSpec::default();
    match context {
        Context::Read => node.read = Some(source),
        Context::Write => node.write = Some(source),
        Context::Validate => node.validate = Some(source),
    }
    let mut root = RuleSpec::default();
    root.children.insert("t".to_owned(), node);
    Rules::compile(&root)
}

fn assert_resource_refusal(expr: &str, context: Context) {
    let error =
        compile(expr, context).expect_err("the observed resource-limited literal must not load");
    assert_eq!(error.message, RESOURCE_REASON);
}

macro_rules! observed_case {
    ($name:ident, $row:expr, $context:ident) => {
        #[test]
        fn $name() {
            assert_resource_refusal(OBSERVED[$row], Context::$context);
        }
    };
}

// Test each context separately so one missing refusal cannot hide the remaining failures.
observed_case!(observed_resource_row_1_read, 0, Read);
observed_case!(observed_resource_row_1_write, 0, Write);
observed_case!(observed_resource_row_1_validate, 0, Validate);
observed_case!(observed_resource_row_2_read, 1, Read);
observed_case!(observed_resource_row_2_write, 1, Write);
observed_case!(observed_resource_row_2_validate, 1, Validate);
observed_case!(observed_resource_row_3_read, 2, Read);
observed_case!(observed_resource_row_3_write, 2, Write);
observed_case!(observed_resource_row_3_validate, 2, Validate);
observed_case!(observed_resource_row_4_read, 3, Read);
observed_case!(observed_resource_row_4_write, 3, Write);
observed_case!(observed_resource_row_4_validate, 3, Validate);
observed_case!(observed_resource_row_5_read, 4, Read);
observed_case!(observed_resource_row_5_write, 4, Write);
observed_case!(observed_resource_row_5_validate, 4, Validate);
observed_case!(observed_resource_row_6_read, 5, Read);
observed_case!(observed_resource_row_6_write, 5, Write);
observed_case!(observed_resource_row_6_validate, 5, Validate);
observed_case!(observed_resource_row_7_read, 6, Read);
observed_case!(observed_resource_row_7_write, 6, Write);
observed_case!(observed_resource_row_7_validate, 6, Validate);
observed_case!(observed_resource_row_8_read, 7, Read);
observed_case!(observed_resource_row_8_write, 7, Write);
observed_case!(observed_resource_row_8_validate, 7, Validate);

#[test]
fn resource_literals_are_refused_even_in_unreachable_branches() {
    for expr in OBSERVED {
        for derivative in [
            format!("false && ({expr})"),
            format!("true || ({expr})"),
            format!("true ? true : ({expr})"),
        ] {
            assert_resource_refusal(&derivative, Context::Read);
        }
    }
}

#[test]
fn ordinary_admitted_patterns_and_short_circuits_still_load() {
    for expr in [
        "'a'.matches(/^a$/)",
        "!('b'.matches(/^a$/))",
        "'aa'.matches(/^(a+?){2}$/)",
        "true || 'a'.matches(/\\W/)",
        "false && 'a'.matches(/\\W/)",
        "true ? true : 'a'.matches(/\\W/)",
    ] {
        for context in [Context::Read, Context::Write, Context::Validate] {
            compile(expr, context).expect("existing admitted syntax must still load");
        }
    }
}

#[test]
fn admission_refusal_points_at_the_literal_after_unicode_and_short_circuit_prefixes() {
    for observed in OBSERVED {
        let expr = format!("'😀' === '😀' || ({observed})");
        let error = compile(&expr, Context::Read).unwrap_err();
        assert_eq!(error.message, RESOURCE_REASON);
        assert_eq!(error.line, 1);
        assert_eq!(
            error.column,
            expr.chars().position(|c| c == '/').unwrap() + 1
        );
    }
}

#[test]
fn admission_receives_the_existing_literal_lexer_output() {
    for expr in [
        r"'a/'.matches(/^a\/$/)",
        "'a'.matches(/^a\u{200b}$/i\u{200b})",
        r"'a'.matches(/[\]a]/)",
        r"'a'.matches(/(?a)/)",
        r"'a'.matches(/a**/)",
        r"'a'.matches(/\D/)",
        "'😀'.matches(/^[😀]$/)",
    ] {
        for context in [Context::Read, Context::Write, Context::Validate] {
            compile(expr, context).expect("admission must preserve the existing lexical seam");
        }
    }
}
