// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;
use lithium_core::crypto::aead;
use lithium_core::public::PublicBytes;
use lithium_core::secrets::SecByte32;

fuzz_target!(|data: &[u8]| {
    let key = SecByte32::new_zeroed();
    let blob = PublicBytes::from_slice(data);
    let _ = aead::decrypt(&blob, &key, b"fuzz-aad");
});
