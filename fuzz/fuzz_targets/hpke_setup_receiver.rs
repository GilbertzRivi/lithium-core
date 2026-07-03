// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use lithium_core::hpke::{self, HpkeEnc, HpkePrivateKey};

static SK: OnceLock<HpkePrivateKey> = OnceLock::new();

fn sk() -> &'static HpkePrivateKey {
    SK.get_or_init(|| hpke::derive_keypair("fuzz", b"fuzz-recipient").unwrap().0)
}

fuzz_target!(|data: &[u8]| {
    let Ok(enc) = HpkeEnc::from_wire(data) else {
        return;
    };
    let _ = hpke::setup_receiver_and_export("fuzz", sk(), &enc, b"info", b"exp", 64);
});
