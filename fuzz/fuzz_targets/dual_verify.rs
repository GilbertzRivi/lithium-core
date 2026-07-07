// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use lithium_core::crypto::Context;
use lithium_core::crypto::sign::{self, DoubleSig, DualVerifyingKey};

static SIG: OnceLock<DoubleSig> = OnceLock::new();

fn sig() -> &'static DoubleSig {
    SIG.get_or_init(|| {
        let ctx = Context::base("fuzz").unwrap();
        sign::raw::sign_double(b"fuzz-msg", [7u8; 32], [9u8; 32], &ctx).unwrap()
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(vk) = DualVerifyingKey::from_wire(data) {
        assert_eq!(vk.to_wire(), data, "from_wire/to_wire must round-trip");
        let ctx = Context::base("fuzz").unwrap();
        let _ = vk.verify(b"fuzz-msg", sig(), &ctx);
    }
});
