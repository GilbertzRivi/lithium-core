// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use lithium_core::crypto::context::Context;
use lithium_core::crypto::keys;
use lithium_core::crypto::kyberbox::{DualEncryptionPrivateKey, DualSealed};
use lithium_core::public::PubByte32;

static STATE: OnceLock<(DualEncryptionPrivateKey, Vec<u8>, PubByte32)> = OnceLock::new();
static CTX: OnceLock<Context<'static>> = OnceLock::new();

fn state() -> &'static (DualEncryptionPrivateKey, Vec<u8>, PubByte32) {
    STATE.get_or_init(|| {
        let (recipient_priv, _) = DualEncryptionPrivateKey::ephemeral().unwrap();
        let (_, reply_pub) = DualEncryptionPrivateKey::ephemeral().unwrap();
        let (_, sender_x_pub) = keys::ephemeral_x25519_keypair().unwrap();
        (recipient_priv, reply_pub.to_wire(), sender_x_pub)
    })
}

fn ctx() -> &'static Context<'static> {
    CTX.get_or_init(|| Context::base("fuzz").unwrap())
}

fuzz_target!(|data: &[u8]| {
    let (recipient_priv, reply_pub_wire, sender_x_pub) = state();

    let mut wire = Vec::with_capacity(reply_pub_wire.len() + 32 + data.len());
    wire.extend_from_slice(reply_pub_wire);
    wire.extend_from_slice(sender_x_pub.as_slice());
    wire.extend_from_slice(data);

    if let Ok(sealed) = DualSealed::from_wire(&wire) {
        let _ = recipient_priv.open(ctx(), b"fuzz-aad", &sealed);
    }
});
