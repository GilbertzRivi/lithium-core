// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::hpke::aead::open;
use crate::hpke::kem::kem_decap;
use crate::{
    crypto::context::Context,
    error::Result,
    hpke::{
        aead::seal,
        kem::kem_encap,
        schedule::key_schedule,
        types::{HpkePrivateKey, HpkePublicKey, HpkeSealed},
    },
    secrets::SecretBytes,
};

pub fn seal_base(
    ctx: &Context,
    recipient_pk: &HpkePublicKey,
    info: &[u8],
    aad: &[u8],
    plaintext: &SecretBytes,
) -> Result<HpkeSealed> {
    let (shared_secret, enc) = kem_encap(ctx, &recipient_pk.x_pub, &recipient_pk.k_pub)?;

    let hpke_ctx = key_schedule(ctx, &shared_secret, info)?;

    let ciphertext = seal(&hpke_ctx, aad, plaintext)?;

    Ok(HpkeSealed { enc, ciphertext })
}

pub fn open_base(
    ctx: &Context,
    recipient_sk: &HpkePrivateKey,
    info: &[u8],
    aad: &[u8],
    sealed: &HpkeSealed,
) -> Result<SecretBytes> {
    let shared_secret = kem_decap(
        ctx,
        recipient_sk.x_priv.expose_as_slice(),
        recipient_sk.k_priv.expose_as_slice(),
        &sealed.enc,
    )?;

    let hpke_ctx = key_schedule(ctx, &shared_secret, info)?;

    open(&hpke_ctx, aad, &sealed.ciphertext)
}
