// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::ErrorKind;
use lithium_core::keys::{KeyManager, PublicCachePolicy, RotationErrorPolicy};

mod common;
use common::FileMk;

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("lithium-km-pubcache-{tag}-{}", std::process::id()))
}

fn mk(dir: &std::path::Path) -> FileMk {
    FileMk {
        path: dir.join("mk"),
    }
}

fn ed_pub_path(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join("KeyManager").join("pub").join("ed25519.pub")
}

fn seed_store(dir: &std::path::Path) -> lithium_core::public::PubByte32 {
    let km = KeyManager::start(
        dir,
        mk(dir),
        PublicCachePolicy::RepairMissingOnly,
        RotationErrorPolicy::Callback(Box::new(|_| {})),
    )
    .unwrap();
    km.public_keys().ed25519
}

fn expect_invalid_pub(dir: &std::path::Path, policy: PublicCachePolicy, ctx: &str) {
    match KeyManager::start(
        dir,
        mk(dir),
        policy,
        RotationErrorPolicy::Callback(Box::new(|_| {})),
    ) {
        Ok(_) => panic!("{ctx}: start must fail"),
        Err(e) => assert!(
            matches!(e.kind, ErrorKind::InvalidPublicKey { .. }),
            "{ctx}: expected InvalidPublicKey, got {e:?}"
        ),
    }
}

#[test]
fn strict_rejects_missing_public_key() {
    let dir = tmp_dir("strict-missing");
    std::fs::remove_dir_all(&dir).ok();
    seed_store(&dir);

    std::fs::remove_file(ed_pub_path(&dir)).unwrap();
    expect_invalid_pub(&dir, PublicCachePolicy::Strict, "strict missing pub");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn strict_rejects_swapped_public_key() {
    let dir = tmp_dir("strict-swap");
    std::fs::remove_dir_all(&dir).ok();
    seed_store(&dir);

    std::fs::write(ed_pub_path(&dir), [0u8; 32]).unwrap();
    expect_invalid_pub(&dir, PublicCachePolicy::Strict, "strict swapped pub");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn repair_missing_rebuilds_public_key_from_secret() {
    let dir = tmp_dir("repair-missing");
    std::fs::remove_dir_all(&dir).ok();
    let ed = seed_store(&dir);

    std::fs::remove_file(ed_pub_path(&dir)).unwrap();

    let km = KeyManager::start(
        &dir,
        mk(&dir),
        PublicCachePolicy::RepairMissingOnly,
        RotationErrorPolicy::Callback(Box::new(|_| {})),
    )
    .unwrap();
    assert_eq!(
        km.public_keys().ed25519,
        ed,
        "repaired pub must match the identity"
    );
    assert_eq!(
        std::fs::read(ed_pub_path(&dir)).unwrap(),
        ed.as_slice(),
        "repair must derive from the secret and persist it"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn repair_missing_still_rejects_a_swapped_public_key() {
    let dir = tmp_dir("repair-swap");
    std::fs::remove_dir_all(&dir).ok();
    seed_store(&dir);

    std::fs::write(ed_pub_path(&dir), [0u8; 32]).unwrap();
    expect_invalid_pub(
        &dir,
        PublicCachePolicy::RepairMissingOnly,
        "a wrong pub is tampering, not a gap",
    );

    std::fs::remove_dir_all(&dir).ok();
}
