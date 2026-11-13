//! What a started runner must satisfy before it serves, as pure decisions: the virtual clock it was
//! asked for and the debugger endpoint it was asked to open. `check_started_runner` asks the runner
//! and the network; these functions decide.

use serde_json::Value;

/// Whether a runner's `hello` clock capability gives the clock the configuration asks for: protocol
/// version 1, a virtual `Date`, and virtual timers when those are requested too. An absent or
/// differently shaped capability supports nothing.
pub(super) fn supports_virtual_clock(capability: Option<&Value>, timers_virtual: bool) -> bool {
    capability.is_some_and(|c| {
        c["version"] == 1 && c["date"] == true && (!timers_virtual || c["timers"] == true)
    })
}

/// The refusal for a runner that cannot give the requested virtual clock.
pub(super) fn virtual_clock_refusal(label: &str, python: bool) -> String {
    let why = if python {
        " (Python code runs on real time)"
    } else {
        ""
    };
    format!("the Functions codebase {label:?}: runner does not support the requested virtual clock{why}")
}

/// Whether the inspector a runner reports is the one asked for: it reports a port, its endpoint
/// answers, and the port is the requested one when a fixed port was requested.
pub(super) fn debugger_port_is_usable(
    reported: Option<u16>,
    requested: Option<u16>,
    endpoint_active: bool,
) -> bool {
    reported.is_some()
        && endpoint_active
        && requested.is_none_or(|expected| reported == Some(expected))
}

/// The refusal for a runner whose debugger port is not usable.
pub(super) fn debugger_port_refusal(label: &str, requested: Option<u16>) -> String {
    match requested {
        Some(expected) => format!(
            "the Functions codebase {label:?}: requested debugger port {expected} is not active"
        ),
        None => format!(
            "the Functions codebase {label:?}: the dynamically assigned debugger port is not active"
        ),
    }
}

/// The start-up notice that says how many processes serve the loaded codebases, if there is anything to
/// say: with one process per function, which codebases that is true of; otherwise, when several codebases are
/// loaded, that each has its own process. One codebase served by one process needs no notice.
pub(crate) fn process_notice(dedicated: bool, codebases: &[&str]) -> Option<String> {
    let names = codebases.join(", ");
    if dedicated {
        Some(format!(
            "functions: functions.isolation is \"function\": every function of {names} runs in its own runner process"
        ))
    } else if codebases.len() > 1 {
        Some(format!(
            "functions: {} codebases are loaded ({names}), one runner process each",
            codebases.len()
        ))
    } else {
        None
    }
}

/// Drops the state kept for a runner that is no longer current. The log pump keeps one cursor per
/// runner unit, keyed by [`RunnerUnit::key`](fireemu_adapter_functions::runtime::RunnerUnit::key):
/// a unit that is still current keeps its cursor, so its lines are forwarded once.
pub(crate) fn retain_current_cursors<V>(
    cursors: &mut std::collections::BTreeMap<String, V>,
    current: &[String],
) {
    cursors.retain(|key, _| current.contains(key));
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use serde_json::json;

    use super::*;

    #[test]
    fn a_clock_capability_must_be_version_one_with_a_virtual_date() {
        let capability = json!({"version": 1, "date": true, "timers": true});
        assert!(supports_virtual_clock(Some(&capability), true));
        assert!(supports_virtual_clock(Some(&capability), false));
        assert!(!supports_virtual_clock(None, false));
        for broken in [
            json!({"version": 2, "date": true, "timers": true}),
            json!({"version": 1, "date": false, "timers": true}),
            json!({"version": 1, "date": "true", "timers": true}),
            json!({"version": "1", "date": true, "timers": true}),
            json!({"date": true, "timers": true}),
            json!(null),
        ] {
            assert!(!supports_virtual_clock(Some(&broken), false), "{broken}");
        }
        // Timers matter only when virtual timers are asked for.
        let dates_only = json!({"version": 1, "date": true, "timers": false});
        assert!(supports_virtual_clock(Some(&dates_only), false));
        assert!(!supports_virtual_clock(Some(&dates_only), true));
        let no_timers = json!({"version": 1, "date": true});
        assert!(supports_virtual_clock(Some(&no_timers), false));
        assert!(!supports_virtual_clock(Some(&no_timers), true));
    }

    proptest! {
        #[test]
        fn the_clock_capability_decision_is_the_conjunction_of_its_parts(
            version in prop_oneof![Just(json!(0)), Just(json!(1)), Just(json!(2)), Just(json!("1")), Just(json!(null))],
            date in prop_oneof![Just(json!(true)), Just(json!(false)), Just(json!("true")), Just(json!(null))],
            timers in prop_oneof![Just(json!(true)), Just(json!(false)), Just(json!(1)), Just(json!(null))],
            timers_virtual in any::<bool>(),
        ) {
            let capability = json!({"version": version, "date": date, "timers": timers});
            let expected = version == json!(1)
                && date == json!(true)
                && (!timers_virtual || timers == json!(true));
            prop_assert_eq!(supports_virtual_clock(Some(&capability), timers_virtual), expected);
        }

        #[test]
        fn a_debugger_port_is_usable_when_reported_active_and_equal_to_the_requested_one(
            reported in proptest::option::of(1024u16..2048),
            requested in proptest::option::of(1024u16..2048),
            active in any::<bool>(),
        ) {
            let expected = reported.is_some()
                && active
                && (requested.is_none() || requested == reported);
            prop_assert_eq!(debugger_port_is_usable(reported, requested, active), expected);
        }
    }

    #[test]
    fn the_refusals_name_the_codebase_and_what_was_asked_for() {
        assert_eq!(
            virtual_clock_refusal("api", false),
            "the Functions codebase \"api\": runner does not support the requested virtual clock"
        );
        assert_eq!(
            virtual_clock_refusal("api", true),
            "the Functions codebase \"api\": runner does not support the requested virtual clock (Python code runs on real time)"
        );
        assert_eq!(
            debugger_port_refusal("api", Some(9330)),
            "the Functions codebase \"api\": requested debugger port 9330 is not active"
        );
        assert_eq!(
            debugger_port_refusal("api", None),
            "the Functions codebase \"api\": the dynamically assigned debugger port is not active"
        );
    }

    #[test]
    fn a_cursor_survives_only_while_its_runner_is_current() {
        let mut cursors: std::collections::BTreeMap<String, u64> =
            [("api/a", 1), ("api/b", 2), ("old", 3)]
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect();
        retain_current_cursors(
            &mut cursors,
            &["api/a".to_owned(), "api/b".to_owned(), "new".to_owned()],
        );
        assert_eq!(
            cursors.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["api/a", "api/b"]
        );
        assert_eq!(cursors["api/b"], 2);
        retain_current_cursors(&mut cursors, &[]);
        assert!(cursors.is_empty());
    }

    #[test]
    fn the_process_notice_names_the_codebases_that_have_dedicated_processes_or_their_own() {
        assert_eq!(
            process_notice(true, &["api"]).as_deref(),
            Some("functions: functions.isolation is \"function\": every function of api runs in its own runner process")
        );
        assert_eq!(
            process_notice(true, &["api", "workers"]).as_deref(),
            Some("functions: functions.isolation is \"function\": every function of api, workers runs in its own runner process")
        );
        assert_eq!(
            process_notice(false, &["api", "workers"]).as_deref(),
            Some("functions: 2 codebases are loaded (api, workers), one runner process each")
        );
        assert_eq!(
            process_notice(false, &["a", "b", "c"]).as_deref(),
            Some("functions: 3 codebases are loaded (a, b, c), one runner process each")
        );
        assert_eq!(process_notice(false, &["api"]), None);
        assert_eq!(process_notice(false, &[]), None);
    }
}
