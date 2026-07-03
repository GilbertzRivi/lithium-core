// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::hpke::aead::open;
use crate::hpke::kem::kem_decap;
use crate::{
    crypto::context::Context,
    error::Result,
    hpke::{aead::seal, kem::kem_encap, schedule::key_schedule, types::HpkeSealed},
    public::{PubByte32, PublicBytes},
    secrets::{SecByte32, SecretBytes},
};

pub fn seal_base(
    ctx: &Context,
    recipient_x_pub: &PubByte32,
    recipient_k_pub: &PublicBytes,
    info: &[u8],
    aad: &[u8],
    plaintext: &SecretBytes,
) -> Result<HpkeSealed> {
    let (shared_secret, enc) = kem_encap(ctx, recipient_x_pub, recipient_k_pub)?;

    let hpke_ctx = key_schedule(ctx, &shared_secret, info)?;

    let ciphertext = seal(&hpke_ctx, aad, plaintext)?;

    Ok(HpkeSealed { enc, ciphertext })
}

pub fn open_base(
    ctx: &Context,
    recipient_x_priv: &SecByte32,
    recipient_k_priv: &SecretBytes,
    info: &[u8],
    aad: &[u8],
    sealed: &HpkeSealed,
) -> Result<SecretBytes> {
    let shared_secret = kem_decap(ctx, recipient_x_priv, recipient_k_priv, &sealed.enc)?;

    let hpke_ctx = key_schedule(ctx, &shared_secret, info)?;

    open(&hpke_ctx, aad, &sealed.ciphertext)
}
