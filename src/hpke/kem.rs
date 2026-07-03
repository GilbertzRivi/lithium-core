// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::crypto::context::Context;
use crate::crypto::keys;
use crate::crypto::kyberbox::{prep_base_key_for_decryption, prep_base_key_for_encryption};
use crate::error::Result;
use crate::hpke::types::HpkeEnc;
use crate::public::{PubByte32, PublicBytes};
use crate::secrets::{SecByte32, SecretBytes};

pub fn kem_encap(
    ctx: &Context,
    recipient_x_pub: &PubByte32,
    recipient_k_pub: &PublicBytes,
) -> Result<(SecByte32, HpkeEnc)> {
    let (eph_x_priv, eph_x_pub) = keys::random_x25519_keypair()?;

    let (shared_secret, kem_ct) =
        prep_base_key_for_encryption(ctx, &eph_x_priv, recipient_x_pub, recipient_k_pub)?;

    Ok((
        shared_secret,
        HpkeEnc {
            x_pub: eph_x_pub,
            kem_ct,
        },
    ))
}

pub fn kem_decap(
    ctx: &Context,
    recipient_x_priv: &SecByte32,
    recipient_k_priv: &SecretBytes,
    enc: &HpkeEnc,
) -> Result<SecByte32> {
    prep_base_key_for_decryption(
        ctx,
        recipient_x_priv,
        &enc.x_pub,
        recipient_k_priv,
        &enc.kem_ct,
    )
}
