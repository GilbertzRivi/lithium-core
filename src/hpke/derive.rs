// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use ml_kem::{DecapsulationKey1024, Seed as MlKemSeed, kem::KeyExport};

use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

use crate::{
    crypto::{context::Context, kdf, keys},
    error::{LithiumError, Result},
    hpke::types::{HpkePrivateKey, HpkePublicKey},
    public::{PubByte32, PublicBytes},
    secrets::SecretBytes,
};

pub fn derive_keypair_from_high_entropy_ikm(
    ctx: &Context,
    ikm: &SecretBytes,
) -> Result<(HpkePrivateKey, HpkePublicKey)> {
    let kp = ctx.add("hpke")?.add("derive-keypair")?;

    let x_priv = kdf::derive32_raw(ikm, None, kp.add("x25519-priv")?.label().as_slice())?;

    let x_pub = PubByte32::new(
        *XPublicKey::from(&XStaticSecret::from(*x_priv.expose_as_array())).as_bytes(),
    );

    let k_seed_bytes =
        kdf::derive_bytes_raw(ikm, None, kp.add("mlkem1024-seed")?.label().as_slice(), 64)?;

    if k_seed_bytes.expose_as_slice().len() != 64 {
        return Err(LithiumError::internal("mlkem_seed_len"));
    }

    let dk = DecapsulationKey1024::from_seed(
        MlKemSeed::try_from(k_seed_bytes.expose_as_slice())
            .map_err(|_| LithiumError::internal("mlkem_seed_len"))?,
    );
    let ek = dk.encapsulation_key();
    let ek_bytes = ek.to_bytes();

    let k_priv = k_seed_bytes;
    let k_pub = PublicBytes::from_slice(ek_bytes.as_ref());

    Ok((
        HpkePrivateKey { x_priv, k_priv },
        HpkePublicKey { x_pub, k_pub },
    ))
}

pub fn random_keypair(ctx: &Context) -> Result<(HpkePrivateKey, HpkePublicKey)> {
    let ikm = keys::random_32()?;
    derive_keypair_from_high_entropy_ikm(ctx, &SecretBytes::from_slice(ikm.expose_as_slice()))
}
