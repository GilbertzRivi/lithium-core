// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use lithium_core::crypto::context::Context;
use lithium_core::crypto::keys;
use lithium_core::crypto::kyberbox::{self, KyberBoxSealed};
use lithium_core::public::PubByte32;
use lithium_core::secrets::{SecByte32, SecByte64};

static KP: OnceLock<(SecByte32, PubByte32, SecByte64)> = OnceLock::new();
static CTX: OnceLock<Context<'static>> = OnceLock::new();

fn kp() -> &'static (SecByte32, PubByte32, SecByte64) {
    KP.get_or_init(|| {
        let (x_priv, x_pub) = keys::ephemeral_x25519_keypair().unwrap();
        let (k_priv, _) = keys::ephemeral_kyber_mlkem1024_keypair().unwrap();
        (x_priv, x_pub, k_priv)
    })
}

fn ctx() -> &'static Context<'static> {
    CTX.get_or_init(|| Context::base("fuzz").unwrap())
}

fuzz_target!(|data: &[u8]| {
    let (x_priv, sender_x_pub, k_priv) = kp();

    let mut wire_bytes = Vec::with_capacity(32 + data.len());
    wire_bytes.extend_from_slice(sender_x_pub.as_slice());
    wire_bytes.extend_from_slice(data);

    if let Ok(wire) = KyberBoxSealed::from_wire(&wire_bytes) {
        let _ = kyberbox::open(ctx(), x_priv, k_priv, b"fuzz-aad", &wire);
    }
});
