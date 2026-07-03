// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use ml_kem::{DecapsulationKey1024, Seed, kem::KeyExport};

use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

use crate::{
    crypto::{context::Context, kdf},
    error::{LithiumError, Result},
    hpke::types::{HpkePrivateKey, HpkePublicKey},
    public::{PubByte32, PublicBytes},
    secrets::SecretBytes,
};

fn derive_label(ctx: &str, part: &[u8]) -> SecretBytes {
    let mut info = Vec::new();
    info.extend_from_slice(ctx.as_bytes());
    info.extend_from_slice(b"/derive-keypair/");
    info.extend_from_slice(part);
    SecretBytes::new(info)
}

pub fn derive_keypair(ctx: &Context, ikm: &[u8]) -> Result<(HpkePrivateKey, HpkePublicKey)> {
    let input = SecretBytes::from_slice(ikm);

    let x_priv = kdf::derive32(
        &input,
        None,
        derive_label(ctx.as_str(), b"x25519-priv").expose_as_slice(),
    )?;

    let x_pub =
        PubByte32::new(*XPublicKey::from(&XStaticSecret::from(*x_priv.as_array())).as_bytes());

    let k_seed_bytes = kdf::derive_bytes(
        &input,
        None,
        derive_label(ctx.as_str(), b"mlkem1024-seed").expose_as_slice(),
        64,
    )?;

    if k_seed_bytes.expose_as_slice().len() != 64 {
        return Err(LithiumError::internal("mlkem_seed_len"));
    }

    let mut seed = Seed::default();
    seed.copy_from_slice(k_seed_bytes.expose_as_slice());

    let dk = DecapsulationKey1024::from_seed(seed);
    let ek = dk.encapsulation_key();
    let ek_bytes = ek.to_bytes();

    let k_priv = k_seed_bytes;
    let k_pub = PublicBytes::from_slice(ek_bytes.as_ref());

    Ok((
        HpkePrivateKey { x_priv, k_priv },
        HpkePublicKey { x_pub, k_pub },
    ))
}
