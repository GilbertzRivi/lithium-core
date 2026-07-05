// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use lithium_core::crypto::context::Context;
use lithium_core::hpke::{self, HpkeSealed};
use lithium_core::secrets::{SecByte32, SecretBytes};

static SK: OnceLock<(SecByte32, SecretBytes)> = OnceLock::new();
static CTX: OnceLock<Context<'static>> = OnceLock::new();

fn ctx() -> &'static Context<'static> {
    CTX.get_or_init(|| Context::base("fuzz").unwrap())
}

fn sk() -> &'static (SecByte32, SecretBytes) {
    SK.get_or_init(|| {
        let (sk, _) = hpke::derive_keypair(ctx(), b"fuzz-recipient").unwrap();
        let w = sk.to_wire();
        let w = w.expose_as_slice();
        (
            SecByte32::from_slice(&w[..32]).unwrap(),
            SecretBytes::from_slice(&w[32..]),
        )
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 34 {
        return;
    }
    let (x_priv, k_priv) = sk();
    let mid = 33 + (data[0] as usize % (data.len() - 33));
    let enc_wire = &data[1..mid];
    let ct = &data[mid..];

    let mut wire = Vec::with_capacity(4 + enc_wire.len() + ct.len());
    wire.extend_from_slice(&(enc_wire.len() as u32).to_be_bytes());
    wire.extend_from_slice(enc_wire);
    wire.extend_from_slice(ct);

    if let Ok(sealed) = HpkeSealed::from_wire(&wire) {
        let _ = hpke::open_base(ctx(), x_priv, k_priv, b"info", b"aad", &sealed);
    }
});
