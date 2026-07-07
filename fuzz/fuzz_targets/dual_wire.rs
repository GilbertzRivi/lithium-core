// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;
use lithium_core::crypto::kyberbox::{
    DualEncryptionPrivateKey, DualEncryptionPublicKey, DualSealed,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(pk) = DualEncryptionPublicKey::from_wire(data) {
        assert_eq!(
            pk.to_wire(),
            data,
            "public from_wire/to_wire must round-trip"
        );
    }
    if let Ok(sk) = DualEncryptionPrivateKey::from_wire(data) {
        assert_eq!(
            sk.to_wire().expose_as_slice(),
            data,
            "private from_wire/to_wire must round-trip"
        );
    }
    if let Ok(sealed) = DualSealed::from_wire(data) {
        assert_eq!(
            sealed.to_wire(),
            data,
            "sealed from_wire/to_wire must round-trip"
        );
    }
});
