//! Accepting connections without letting a transient `accept()` failure end the listener.
//!
//! Tokio's `TcpListener::accept` retries only `WouldBlock` and hands every other OS error to the
//! caller. Some of those errors concern a single connection that died in the backlog
//! (`ECONNABORTED`, `ECONNRESET`, and on Linux the pending network errors that `accept(2)` reports
//! on the new socket); others are a passing shortage of descriptors or buffers (`EMFILE`,
//! `ENFILE`, `ENOBUFS`, `ENOMEM`). Neither says the listener is broken, and a serve loop that
//! returns on them stops that emulator -- and with it the whole suite. [`accept_with_backoff`]
//! skips the first kind, waits out the second, and returns only what is left (`EBADF`,
//! `EINVAL`, `ENOTSOCK`, ...), which does mean the listener can no longer accept.

use std::future::Future;
use std::io;
use std::time::Duration;

/// The first wait after a resource error.
pub const FIRST_BACKOFF: Duration = Duration::from_millis(100);
/// The longest wait between two attempts while resources stay exhausted.
pub const MAX_BACKOFF: Duration = Duration::from_secs(1);

/// What an `accept()` error says about the listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptError {
    /// One pending connection failed before it was accepted; the next one may be fine.
    Connection,
    /// The process or the system ran out of descriptors or buffers for now.
    Resources,
    /// The listener itself cannot accept any more.
    Fatal,
}

/// Classifies an error returned by `accept()`.
///
/// Sources: `accept(2)` (man7.org, ERRORS and the Linux "Error handling" note) and the Winsock
/// `accept` reference, whose `WSAEMFILE` (10024) and `WSAENOBUFS` (10055) values come from
/// "Windows Sockets Error Codes".
#[must_use]
pub fn classify(error: &io::Error) -> AcceptError {
    use io::ErrorKind;
    if matches!(
        error.kind(),
        ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionRefused
            | ErrorKind::Interrupted
            | ErrorKind::NetworkDown
            | ErrorKind::NetworkUnreachable
            | ErrorKind::HostUnreachable
    ) {
        return AcceptError::Connection;
    }
    if error.kind() == ErrorKind::OutOfMemory {
        return AcceptError::Resources;
    }
    match error.raw_os_error() {
        Some(code) if RESOURCE_ERRORS.contains(&code) => AcceptError::Resources,
        Some(code) if CONNECTION_ERRORS.contains(&code) => AcceptError::Connection,
        _ => AcceptError::Fatal,
    }
}

#[cfg(unix)]
const RESOURCE_ERRORS: &[i32] = &[libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM];
#[cfg(windows)]
const RESOURCE_ERRORS: &[i32] = &[10024 /* WSAEMFILE */, 10055 /* WSAENOBUFS */];
#[cfg(not(any(unix, windows)))]
const RESOURCE_ERRORS: &[i32] = &[];

/// The pending network errors Linux reports from `accept()` on the new socket, which `accept(2)`
/// says to treat like `EAGAIN` (those without an [`io::ErrorKind`] of their own).
#[cfg(any(target_os = "linux", target_os = "android"))]
const CONNECTION_ERRORS: &[i32] = &[
    libc::EPROTO,
    libc::ENOPROTOOPT,
    libc::EHOSTDOWN,
    libc::ENONET,
    libc::EOPNOTSUPP,
];
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const CONNECTION_ERRORS: &[i32] = &[];

/// The wait after `failures` consecutive resource errors (`failures >= 1`): [`FIRST_BACKOFF`],
/// doubling, at most [`MAX_BACKOFF`].
#[must_use]
pub fn backoff(failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(16);
    FIRST_BACKOFF
        .saturating_mul(1 << doublings)
        .min(MAX_BACKOFF)
}

/// Calls `accept` until it yields a connection or an error that ends the listener.
///
/// A connection error is skipped at once. A resource error is reported on stderr, tagged with
/// `listener`, the first time in a run of failures, and retried after [`backoff`]; the waiting is
/// an ordinary Tokio sleep, so aborting the serving task ends it. Any other error is returned.
pub async fn accept_with_backoff<T, F, Fut>(listener: &str, mut accept: F) -> io::Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    let mut resource_failures = 0_u32;
    loop {
        match accept().await {
            Ok(accepted) => return Ok(accepted),
            Err(error) => match classify(&error) {
                AcceptError::Connection => {}
                AcceptError::Resources => {
                    resource_failures = resource_failures.saturating_add(1);
                    if resource_failures == 1 {
                        eprintln!(
                            "[{listener}] cannot accept a connection ({error}); retrying until resources are free"
                        );
                    }
                    tokio::time::sleep(backoff(resource_failures)).await;
                }
                AcceptError::Fatal => return Err(error),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    #[cfg(unix)]
    fn os(code: i32) -> io::Error {
        io::Error::from_raw_os_error(code)
    }

    /// A scripted listener: each call yields the next outcome; `Ok(n)` is the n-th connection.
    fn scripted(
        outcomes: Vec<io::Result<u32>>,
    ) -> (
        Arc<Mutex<usize>>,
        impl FnMut() -> std::future::Ready<io::Result<u32>>,
    ) {
        let calls = Arc::new(Mutex::new(0));
        let counter = Arc::clone(&calls);
        let mut queue: VecDeque<_> = outcomes.into();
        (calls, move || {
            *counter.lock().unwrap() += 1;
            std::future::ready(queue.pop_front().expect("accept called past the script"))
        })
    }

    #[cfg(unix)]
    #[test]
    fn errors_are_classified_by_what_they_say_about_the_listener() {
        for code in [libc::ECONNABORTED, libc::ECONNRESET, libc::EINTR] {
            assert_eq!(classify(&os(code)), AcceptError::Connection, "{code}");
        }
        for code in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
            assert_eq!(classify(&os(code)), AcceptError::Resources, "{code}");
        }
        for code in [libc::EBADF, libc::EINVAL, libc::ENOTSOCK, libc::EFAULT] {
            assert_eq!(classify(&os(code)), AcceptError::Fatal, "{code}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_pending_network_errors_are_connection_errors() {
        for code in [
            libc::ENETDOWN,
            libc::EPROTO,
            libc::ENOPROTOOPT,
            libc::EHOSTDOWN,
            libc::ENONET,
            libc::EHOSTUNREACH,
            libc::EOPNOTSUPP,
            libc::ENETUNREACH,
        ] {
            assert_eq!(classify(&os(code)), AcceptError::Connection, "{code}");
        }
    }

    #[test]
    fn backoff_starts_short_doubles_and_is_capped() {
        assert_eq!(backoff(1), Duration::from_millis(100));
        assert_eq!(backoff(2), Duration::from_millis(200));
        assert_eq!(backoff(3), Duration::from_millis(400));
        assert_eq!(backoff(4), Duration::from_millis(800));
        assert_eq!(backoff(5), MAX_BACKOFF);
        assert_eq!(backoff(u32::MAX), MAX_BACKOFF);
    }

    /// ACCEPT-2: aborted and reset connections are skipped without waiting, descriptor
    /// exhaustion is waited out, and `EBADF` ends the listener.
    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn transient_errors_are_retried_and_a_broken_listener_is_returned() {
        let start = tokio::time::Instant::now();
        let (calls, accept) = scripted(vec![
            Err(os(libc::ECONNABORTED)),
            Err(os(libc::ECONNRESET)),
            Ok(1),
        ]);
        let mut accept = accept;
        assert_eq!(accept_with_backoff("test", &mut accept).await.unwrap(), 1);
        assert_eq!(*calls.lock().unwrap(), 3);
        assert_eq!(start.elapsed(), Duration::ZERO);

        let (_, mut accept) = scripted(vec![
            Err(os(libc::EMFILE)),
            Err(os(libc::ENFILE)),
            Err(os(libc::EMFILE)),
            Ok(2),
        ]);
        let start = tokio::time::Instant::now();
        assert_eq!(accept_with_backoff("test", &mut accept).await.unwrap(), 2);
        assert_eq!(start.elapsed(), Duration::from_millis(100 + 200 + 400));

        let (calls, mut accept) =
            scripted(vec![Err(os(libc::EMFILE)), Err(os(libc::EBADF)), Ok(3)]);
        let error = accept_with_backoff("test", &mut accept).await.unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));
        assert_eq!(*calls.lock().unwrap(), 2);

        let (_, mut accept) = scripted(vec![Err(os(libc::EINVAL))]);
        let error = accept_with_backoff("test", &mut accept).await.unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EINVAL));
    }

    /// Aborting the task that waits out a resource error ends the wait.
    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn the_backoff_ends_when_the_task_is_aborted() {
        let task = tokio::spawn(accept_with_backoff("test", || {
            std::future::ready(Err::<(), _>(os(libc::EMFILE)))
        }));
        tokio::time::sleep(Duration::from_secs(5)).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }

    #[cfg(unix)]
    fn outcome() -> impl Strategy<Value = i32> {
        prop_oneof![
            Just(libc::ECONNABORTED),
            Just(libc::ECONNRESET),
            Just(libc::EINTR),
            Just(libc::EMFILE),
            Just(libc::ENFILE),
            Just(libc::ENOBUFS),
            Just(libc::EBADF),
            Just(libc::EINVAL),
        ]
    }

    #[cfg(unix)]
    proptest! {
        /// Against a reference model: the result is the connection after the errors, unless a
        /// fatal error comes first, which is returned; the time waited is the backoff schedule
        /// over the resource errors before that point, and nothing is called past it.
        #[test]
        fn accept_matches_the_reference_model(codes in proptest::collection::vec(outcome(), 0..24)) {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .start_paused(true)
                .build()
                .unwrap();
            let mut script: Vec<io::Result<u32>> = codes.iter().map(|&c| Err(os(c))).collect();
            script.push(Ok(7));

            let fatal = codes.iter().position(|&c| classify(&os(c)) == AcceptError::Fatal);
            let considered = &codes[..fatal.map_or(codes.len(), |i| i + 1)];
            let mut expected_wait = Duration::ZERO;
            let mut failures = 0;
            for &code in considered {
                if classify(&os(code)) == AcceptError::Resources {
                    failures += 1;
                    expected_wait += backoff(failures);
                }
            }

            let (calls, mut accept) = scripted(script);
            let (result, waited) = runtime.block_on(async {
                let start = tokio::time::Instant::now();
                let result = accept_with_backoff("test", &mut accept).await;
                (result, start.elapsed())
            });
            if let Some(i) = fatal {
                prop_assert_eq!(result.unwrap_err().raw_os_error(), Some(codes[i]));
                prop_assert_eq!(*calls.lock().unwrap(), i + 1);
            } else {
                prop_assert_eq!(result.unwrap(), 7);
                prop_assert_eq!(*calls.lock().unwrap(), codes.len() + 1);
            }
            prop_assert_eq!(waited, expected_wait);
        }
    }
}
