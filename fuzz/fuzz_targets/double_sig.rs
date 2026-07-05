// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use lithium_core::crypto::keys;
use lithium_core::crypto::sign::{self, DoubleSig};
use lithium_core::public::{PubByte32, PublicBytes};
use lithium_core::secrets::SecByte32;

static PUBKEYS: OnceLock<(PubByte32, PublicBytes)> = OnceLock::new();

fn pubkeys() -> &'static (PubByte32, PublicBytes) {
    PUBKEYS.get_or_init(|| {
        let ed_pub = keys::ed25519_pub_from_seed(&SecByte32::new([7u8; 32]));
        let dili_pub = keys::mldsa87_pub_from_seed(&SecByte32::new([9u8; 32]));
        (ed_pub, dili_pub)
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(sig) = DoubleSig::from_bytes(data) {
        assert_eq!(sig.to_bytes(), data, "from_bytes/to_bytes must round-trip");
        let (ed_pub, dili_pub) = pubkeys();
        let _ = sign::verify_double(b"fuzz-msg", &sig, ed_pub, dili_pub);
    }
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = DoubleSig::from_hex(s);
    }
});
