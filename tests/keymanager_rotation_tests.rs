// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use lithium_core::keys::{KeyManager, MkProvider, PublicCachePolicy, RotationErrorPolicy};
use lithium_core::secrets::SecByte32;
use lithium_core::{ErrorKind, LithiumError, Result};

struct FlakyMk {
    path: PathBuf,
    fail: Arc<AtomicBool>,
}

impl MkProvider for FlakyMk {
    fn load_mk(&self) -> Result<SecByte32> {
        if self.fail.load(Ordering::Acquire) {
            return Err(LithiumError::internal("injected_load_failure"));
        }
        let bytes = std::fs::read(&self.path).map_err(LithiumError::io)?;
        SecByte32::from_slice(&bytes)
    }

    fn store_mk(&self, mk: &SecByte32) -> Result<()> {
        std::fs::write(&self.path, mk.expose_as_slice()).map_err(LithiumError::io)
    }
}

struct CommitFailMk {
    path: PathBuf,
    fail_store: Arc<AtomicBool>,
}

impl MkProvider for CommitFailMk {
    fn load_mk(&self) -> Result<SecByte32> {
        let bytes = std::fs::read(&self.path).map_err(LithiumError::io)?;
        SecByte32::from_slice(&bytes)
    }

    fn store_mk(&self, mk: &SecByte32) -> Result<()> {
        if self.fail_store.load(Ordering::Acquire) {
            return Err(LithiumError::internal("injected_store_failure"));
        }
        std::fs::write(&self.path, mk.expose_as_slice()).map_err(LithiumError::io)
    }
}

fn tmp_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("lithium-km-rotation-{tag}-{}", std::process::id()))
}

fn wait_until(mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    cond()
}

#[test]
fn auto_rotation_rewraps_and_preserves_secrets() {
    let dir = tmp_dir("happy");
    std::fs::remove_dir_all(&dir).ok();

    let mk_path = dir.join("mk");
    let km = KeyManager::start(
        &dir,
        FlakyMk {
            path: mk_path.clone(),
            fail: Arc::new(AtomicBool::new(false)),
        },
        PublicCachePolicy::RepairMissingOnly,
        RotationErrorPolicy::Callback(Box::new(|_| {})),
    )
    .unwrap();

    let identity = km.public_keys();
    let secret_before = km.get_or_create_secret32(b"label").unwrap();
    let mk_before = std::fs::read(&mk_path).unwrap();

    km.set_rotate_interval(Duration::from_millis(40)).unwrap();
    assert!(
        wait_until(|| std::fs::read(&mk_path)
            .map(|b| b != mk_before)
            .unwrap_or(false)),
        "background rotation must replace the master key on disk"
    );

    let secret_after = km.get_or_create_secret32(b"label").unwrap();
    assert_eq!(
        secret_before, secret_after,
        "a derived secret must survive rotation unchanged (keyfiles rewrapped, not regenerated)"
    );
    assert_eq!(
        identity.ed25519,
        km.public_keys().ed25519,
        "rotation must not change the identity, only its wrapping"
    );

    drop(km);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn callback_policy_reports_error_and_keeps_running() {
    let dir = tmp_dir("callback");
    std::fs::remove_dir_all(&dir).ok();

    let fail = Arc::new(AtomicBool::new(false));
    let hits = Arc::new(AtomicUsize::new(0));
    let cb_hits = hits.clone();

    let km = KeyManager::start(
        &dir,
        FlakyMk {
            path: dir.join("mk"),
            fail: fail.clone(),
        },
        PublicCachePolicy::RepairMissingOnly,
        RotationErrorPolicy::Callback(Box::new(move |_| {
            cb_hits.fetch_add(1, Ordering::Release);
        })),
    )
    .unwrap();

    fail.store(true, Ordering::Release);
    km.set_rotate_interval(Duration::from_millis(40)).unwrap();

    assert!(
        wait_until(|| hits.load(Ordering::Acquire) > 0),
        "the callback must fire when a background rotation fails"
    );

    fail.store(false, Ordering::Release);
    assert!(
        km.get_or_create_secret32(b"still-alive").is_ok(),
        "Callback policy must not disable the manager"
    );

    drop(km);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn strict_policy_disables_manager_after_failure() {
    let dir = tmp_dir("strict");
    std::fs::remove_dir_all(&dir).ok();

    let fail = Arc::new(AtomicBool::new(false));
    let hits = Arc::new(AtomicUsize::new(0));
    let cb_hits = hits.clone();

    let km = KeyManager::start(
        &dir,
        FlakyMk {
            path: dir.join("mk"),
            fail: fail.clone(),
        },
        PublicCachePolicy::RepairMissingOnly,
        RotationErrorPolicy::Strict(Box::new(move |_| {
            cb_hits.fetch_add(1, Ordering::Release);
        })),
    )
    .unwrap();

    fail.store(true, Ordering::Release);
    km.set_rotate_interval(Duration::from_millis(40)).unwrap();

    assert!(
        wait_until(|| hits.load(Ordering::Acquire) > 0),
        "Strict must still fire the callback on failure"
    );

    fail.store(false, Ordering::Release);
    assert!(
        km.get_or_create_secret32(b"should-fail").is_err(),
        "Strict must fail-close: every op errors after a rotation failure, even once the fault clears"
    );

    drop(km);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn commit_phase_failure_fails_closed_even_under_callback() {
    let dir = tmp_dir("commit-fail");
    std::fs::remove_dir_all(&dir).ok();

    let fail_store = Arc::new(AtomicBool::new(false));
    let hits = Arc::new(AtomicUsize::new(0));
    let cb_hits = hits.clone();

    let km = KeyManager::start(
        &dir,
        CommitFailMk {
            path: dir.join("mk"),
            fail_store: fail_store.clone(),
        },
        PublicCachePolicy::RepairMissingOnly,
        RotationErrorPolicy::Callback(Box::new(move |_| {
            cb_hits.fetch_add(1, Ordering::Release);
        })),
    )
    .unwrap();

    km.get_or_create_secret32(b"before").unwrap();

    fail_store.store(true, Ordering::Release);
    km.set_rotate_interval(Duration::from_millis(40)).unwrap();

    assert!(
        wait_until(|| hits.load(Ordering::Acquire) > 0),
        "the callback must fire when the commit phase fails"
    );

    assert!(
        km.get_or_create_secret32(b"after").is_err(),
        "a commit-phase failure must fail closed even under Callback policy"
    );

    drop(km);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn concurrent_get_or_create_agrees_on_one_secret() {
    let dir = tmp_dir("race");
    std::fs::remove_dir_all(&dir).ok();

    let km = KeyManager::start(
        &dir,
        FlakyMk {
            path: dir.join("mk"),
            fail: Arc::new(AtomicBool::new(false)),
        },
        PublicCachePolicy::RepairMissingOnly,
        RotationErrorPolicy::Callback(Box::new(|_| {})),
    )
    .unwrap();

    let mut workers = Vec::new();
    for _ in 0..16 {
        let km = km.clone();
        workers.push(std::thread::spawn(move || {
            km.get_or_create_secret32(b"contended")
                .unwrap()
                .expose_as_slice()
                .to_vec()
        }));
    }
    let results: Vec<Vec<u8>> = workers.into_iter().map(|w| w.join().unwrap()).collect();

    let first = &results[0];
    assert!(
        results.iter().all(|r| r == first),
        "every racing caller must observe the same persisted secret"
    );
    let persisted = km
        .get_or_create_secret32(b"contended")
        .unwrap()
        .expose_as_slice()
        .to_vec();
    assert_eq!(
        &persisted, first,
        "the observed secret must be the one on disk"
    );

    drop(km);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn zero_rotate_interval_is_rejected() {
    let dir = tmp_dir("zero-interval");
    std::fs::remove_dir_all(&dir).ok();

    let km = KeyManager::start(
        &dir,
        FlakyMk {
            path: dir.join("mk"),
            fail: Arc::new(AtomicBool::new(false)),
        },
        PublicCachePolicy::RepairMissingOnly,
        RotationErrorPolicy::Callback(Box::new(|_| {})),
    )
    .unwrap();

    assert!(
        km.set_rotate_interval(Duration::ZERO).is_err(),
        "a zero rotation interval must be rejected to avoid a busy rotation loop"
    );

    drop(km);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn oversized_rotate_interval_is_rejected_without_corrupting_state() {
    let dir = tmp_dir("oversized-interval");
    std::fs::remove_dir_all(&dir).ok();

    let mk_path = dir.join("mk");
    let km = KeyManager::start(
        &dir,
        FlakyMk {
            path: mk_path.clone(),
            fail: Arc::new(AtomicBool::new(false)),
        },
        PublicCachePolicy::RepairMissingOnly,
        RotationErrorPolicy::Callback(Box::new(|_| {})),
    )
    .unwrap();

    let err = km.set_rotate_interval(Duration::MAX).unwrap_err();
    assert_eq!(
        err.kind,
        ErrorKind::TtlTooLarge,
        "an interval that overflows the clock must be rejected, not panic the worker"
    );

    let mk_before = std::fs::read(&mk_path).unwrap();
    km.set_rotate_interval(Duration::from_millis(40)).unwrap();
    assert!(
        wait_until(|| std::fs::read(&mk_path)
            .map(|b| b != mk_before)
            .unwrap_or(false)),
        "the rotation worker must stay healthy after a rejected oversized interval"
    );

    drop(km);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn secret_label_length_is_bounded() {
    let dir = tmp_dir("label-limit");
    std::fs::remove_dir_all(&dir).ok();

    let km = KeyManager::start(
        &dir,
        FlakyMk {
            path: dir.join("mk"),
            fail: Arc::new(AtomicBool::new(false)),
        },
        PublicCachePolicy::RepairMissingOnly,
        RotationErrorPolicy::Callback(Box::new(|_| {})),
    )
    .unwrap();

    assert!(
        km.get_or_create_secret32(&[b'a'; 64]).is_ok(),
        "a 64-byte label is at the limit and must be accepted"
    );

    let too_long = km.get_or_create_secret32(&[b'a'; 65]).unwrap_err();
    assert_eq!(
        too_long.kind,
        ErrorKind::MalformedInput {
            reason: "secret_label_len"
        }
    );

    let empty = km.get_or_create_secret32(b"").unwrap_err();
    assert_eq!(
        empty.kind,
        ErrorKind::MalformedInput {
            reason: "secret_label_len"
        }
    );

    std::fs::remove_dir_all(&dir).ok();
}
