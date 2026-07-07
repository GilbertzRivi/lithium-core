// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use lithium_core::crypto::context::Context;
use lithium_core::hpke::{self, HpkePrivateKey, HpkeSealed};
use lithium_core::secrets::SecretBytes;

static SK: OnceLock<HpkePrivateKey> = OnceLock::new();
static CTX: OnceLock<Context<'static>> = OnceLock::new();

fn ctx() -> &'static Context<'static> {
    CTX.get_or_init(|| Context::base("fuzz").unwrap())
}

fn sk() -> &'static HpkePrivateKey {
    SK.get_or_init(|| {
        let (sk, _) = hpke::derive_keypair_from_high_entropy_ikm(
            ctx(),
            &SecretBytes::from_slice(b"fuzz-recipient-high-entropy-ikm-pad"),
        )
        .unwrap();
        sk
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 34 {
        return;
    }
    let sk = sk();
    let mid = 33 + (data[0] as usize % (data.len() - 33));
    let enc_wire = &data[1..mid];
    let ct = &data[mid..];

    let mut wire = Vec::with_capacity(4 + enc_wire.len() + ct.len());
    wire.extend_from_slice(&(enc_wire.len() as u32).to_be_bytes());
    wire.extend_from_slice(enc_wire);
    wire.extend_from_slice(ct);

    if let Ok(sealed) = HpkeSealed::from_wire(&wire) {
        let _ = hpke::open_base(ctx(), sk, b"info", b"aad", &sealed);
    }
});
