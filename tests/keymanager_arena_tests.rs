// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::crypto::{keys, sign};
use lithium_core::keys::{KeyManager, KeyStoreKind};

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
        KeyStoreKind::Server,
        FileMk {
            path: dir.join("mk"),
        },
    )
    .unwrap();

    let ed_pub = km.public_keys().ed25519;
    let dili_pub = km.public_keys().dilithium.clone();
    let msg = b"born-locked signing path";

    let (ed_sig, dili_sig) = km
        .with_signing_keys(|ed_seed, dili_sk| {
            let e = sign::sign_message(msg, ed_seed.as_slice())?;
            let d = sign::sign_message_dili(msg, dili_sk.as_slice())?;
            Ok((e, d))
        })
        .unwrap();

    assert!(sign::verify_signature(msg, &ed_sig, &ed_pub));
    assert!(sign::verify_signature_dili(msg, &dili_sig, &dili_pub));

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn arena_backed_x25519_kyber_load_is_correct() {
    let dir = tmp_dir("xkyber");
    std::fs::remove_dir_all(&dir).ok();
    let km = KeyManager::start(
        &dir,
        KeyStoreKind::Server,
        FileMk {
            path: dir.join("mk"),
        },
    )
    .unwrap();

    let x_pub = km.public_keys().x25519;
    let kyber_pub = km.public_keys().kyber.clone();

    km.with_x25519_and_kyber_sk(|x_seed, kyber_sk| {
        assert_eq!(x_seed.len(), 32);
        assert_eq!(kyber_sk.len(), 64);
        assert_eq!(keys::x25519_pub_from_seed(x_seed.as_array()), x_pub);
        assert_eq!(
            keys::mlkem1024_pub_from_seed(kyber_sk.as_slice())
                .unwrap()
                .as_slice(),
            kyber_pub.as_slice()
        );
        Ok(())
    })
    .unwrap();

    std::fs::remove_dir_all(&dir).ok();
}
