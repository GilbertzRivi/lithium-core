// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use lithium_core::hpke::{self, HpkeEnc, HpkeSealed};
use lithium_core::public::PublicBytes;
use lithium_core::secrets::{SecByte32, SecretBytes};

static SK: OnceLock<(SecByte32, SecretBytes)> = OnceLock::new();

fn sk() -> &'static (SecByte32, SecretBytes) {
    SK.get_or_init(|| {
        let (sk, _) = hpke::derive_keypair("fuzz", b"fuzz-recipient").unwrap();
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
    let Ok(enc) = HpkeEnc::from_wire(&data[1..mid]) else {
        return;
    };
    let sealed = HpkeSealed {
        enc,
        ciphertext: PublicBytes::from_slice(&data[mid..]),
    };
    let _ = hpke::open_base("fuzz", x_priv, k_priv, b"info", b"aad", &sealed);
});
