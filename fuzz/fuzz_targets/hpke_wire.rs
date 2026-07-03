// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;
use lithium_core::hpke::{HpkeEnc, HpkePrivateKey, HpkePublicKey};

fuzz_target!(|data: &[u8]| {
    let _ = HpkeEnc::from_wire(data);
    let _ = HpkePublicKey::from_wire(data);
    let _ = HpkePrivateKey::from_wire(data);
});
