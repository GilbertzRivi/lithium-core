// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;
use lithium_core::crypto::{Context, sign};
use lithium_core::public::{PubByte32, PublicBytes};

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    let ed_pub = PubByte32::from_slice(&data[..32]).unwrap_or_else(|_| PubByte32::new([0u8; 32]));
    let (sig, msg) = if data.len() > 96 {
        (&data[32..96], &data[96..])
    } else {
        (&data[32..], &[][..])
    };

    let ctx = Context::base("fuzz").unwrap();
    let _ = sign::verify_signature(msg, sig, &ed_pub, &ctx);
    let _ = sign::verify_signature_dili(msg, sig, &PublicBytes::from_slice(data), &ctx);
});
