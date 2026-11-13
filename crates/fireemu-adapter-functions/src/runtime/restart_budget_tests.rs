use super::{RestartBudget, RUNNER_RESTART_WINDOW};
use std::time::{Duration, Instant};

#[test]
fn cleanup_dir_removes_the_snapshot_after_the_last_release() {
    let path = std::env::temp_dir().join(format!("fireemu-cleanup-release-{}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    let cleanup = super::CleanupDir(
        path.clone(),
        std::sync::Mutex::new(true),
        std::sync::atomic::AtomicUsize::new(2),
    );
    cleanup.release();
    assert!(path.is_dir());
    cleanup.release();
    assert!(!path.exists());
}

#[test]
fn rapid_restart_attempts_back_off_and_stop_until_the_window_expires() {
    let mut budget = RestartBudget::default();
    for delay in [0, 100, 200, 400, 800] {
        assert_eq!(budget.next_delay().unwrap(), Duration::from_millis(delay));
    }
    assert!(budget.next_delay().is_err());
    budget.window_started = Some(Instant::now().checked_sub(RUNNER_RESTART_WINDOW).unwrap());
    assert_eq!(budget.cooldown_remaining(), Some(Duration::ZERO));
    assert_eq!(budget.next_delay().unwrap(), Duration::ZERO);
}
