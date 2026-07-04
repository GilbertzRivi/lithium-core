// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::ErrorKind;
use lithium_core::keys::{KeyManager, PublicCachePolicy, RotationErrorPolicy};

mod common;
use common::FileMk;

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("lithium-km-lock-{tag}-{}", std::process::id()))
}

fn start(dir: &std::path::Path) -> lithium_core::Result<KeyManager<FileMk>> {
    KeyManager::start(
        dir,
        FileMk {
            path: dir.join("mk"),
        },
        PublicCachePolicy::RepairMissingOnly,
        RotationErrorPolicy::Callback(Box::new(|_| {})),
    )
}

#[test]
fn second_instance_on_same_store_is_rejected() {
    let dir = tmp_dir("reject");
    std::fs::remove_dir_all(&dir).ok();

    let km1 = start(&dir).unwrap();

    match start(&dir) {
        Err(e) => assert!(
            matches!(e.kind, ErrorKind::KeystoreLocked),
            "second instance must be rejected as locked, got {e:?}"
        ),
        Ok(_) => panic!("second instance must not acquire the store"),
    }

    drop(km1);
    start(&dir).expect("lock is released once the first instance drops");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn different_kinds_do_not_contend() {
    let dir = tmp_dir("kinds");
    std::fs::remove_dir_all(&dir).ok();

    let _server = KeyManager::start(
        &dir.join("server"),
        FileMk {
            path: dir.join("server-mk"),
        },
        PublicCachePolicy::RepairMissingOnly,
        RotationErrorPolicy::Callback(Box::new(|_| {})),
    )
    .unwrap();
    let _user = KeyManager::start(
        &dir.join("user"),
        FileMk {
            path: dir.join("user-mk"),
        },
        PublicCachePolicy::RepairMissingOnly,
        RotationErrorPolicy::Callback(Box::new(|_| {})),
    )
    .expect("distinct store directories must not share a lock");

    std::fs::remove_dir_all(&dir).ok();
}
