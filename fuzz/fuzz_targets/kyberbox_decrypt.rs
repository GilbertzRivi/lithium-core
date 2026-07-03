// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use lithium_core::crypto::context::Context;
use lithium_core::crypto::keys;
use lithium_core::crypto::kyberbox::{self, KyberBoxSealed};
use lithium_core::public::{PubByte32, PublicBytes};
use lithium_core::secrets::{SecByte32, SecretBytes};

static KP: OnceLock<(SecByte32, PubByte32, SecretBytes)> = OnceLock::new();
static CTX: OnceLock<Context<'static>> = OnceLock::new();

fn kp() -> &'static (SecByte32, PubByte32, SecretBytes) {
    KP.get_or_init(|| {
        let (x_priv, x_pub) = keys::random_x25519_keypair().unwrap();
        let (k_priv, _) = keys::random_kyber_mlkem1024_keypair().unwrap();
        (x_priv, x_pub, k_priv)
    })
}

fn ctx() -> &'static Context<'static> {
    CTX.get_or_init(|| Context::base("fuzz").unwrap())
}

fuzz_target!(|data: &[u8]| {
    let (x_priv, peer_pub_x, k_priv) = kp();

    let n = data.len();
    let kem_end = n / 3;
    let ct_end = 2 * n / 3;

    let wire = KyberBoxSealed {
        kem_ct: PublicBytes::from_slice(&data[..kem_end]),
        ciphertext: PublicBytes::from_slice(&data[kem_end..ct_end]),
    };
    let aad = &data[ct_end..];

    let _ = kyberbox::open(ctx(), x_priv, peer_pub_x, k_priv, aad, &wire);
});