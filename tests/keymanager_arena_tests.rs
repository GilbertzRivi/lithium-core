// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::crypto::Context;
use lithium_core::keys::{KeyManager, PublicCachePolicy, RotationErrorPolicy};

mod common;
use common::FileMk;

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("lithium-km-arena-{tag}-{}", std::process::id()))
}

#[test]
fn arena_backed_signing_keys_sign_and_verify() {
    let dir = tmp_dir("sign");
    std::fs::remove_dir_all(&dir).ok();
    let km = KeyManager::start(
        &dir,
        FileMk {
            path: dir.join("mk"),
        },
        PublicCachePolicy::RepairMissingOnly,
        RotationErrorPolicy::Callback(Box::new(|_| {})),
    )
    .unwrap();

    let msg = b"born-locked signing path";
    let ctx = Context::base("test").unwrap().add("sign").unwrap();

    let sig = km.sign_double(msg, &ctx).unwrap();
    assert!(km.dual_verifying_key().verify(msg, &sig, &ctx));

    std::fs::remove_dir_all(&dir).ok();
}
