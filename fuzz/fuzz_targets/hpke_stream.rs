// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use lithium_core::crypto::context::Context;
use lithium_core::hpke::{self, HpkeEnc, HpkePrivateKey};
use lithium_core::public::PublicBytes;
use lithium_core::secrets::SecretBytes;

static SETUP: OnceLock<(HpkePrivateKey, HpkeEnc)> = OnceLock::new();
static CTX: OnceLock<Context<'static>> = OnceLock::new();

fn ctx() -> &'static Context<'static> {
    CTX.get_or_init(|| Context::base("fuzz").unwrap())
}

fn setup() -> &'static (HpkePrivateKey, HpkeEnc) {
    SETUP.get_or_init(|| {
        let (sk, pk) = hpke::derive_keypair_from_high_entropy_ikm(
            ctx(),
            &SecretBytes::from_slice(b"fuzz-recipient-high-entropy-ikm-pad"),
        )
        .unwrap();
        let (enc, _sender) = hpke::setup_sender(ctx(), &pk, b"info").unwrap();
        (sk, enc)
    })
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let (sk, enc) = setup();
    let Ok(mut receiver) = hpke::setup_receiver(ctx(), sk, enc, b"info") else {
        return;
    };
    let split = (data[0] as usize % data.len()).min(data.len() - 1);
    let (aad, ct) = data[1..].split_at(split);
    let _ = receiver.open(aad, &PublicBytes::from_slice(ct));
});
