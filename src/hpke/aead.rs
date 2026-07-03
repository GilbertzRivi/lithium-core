// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    crypto::aead, error::Result, hpke::types::HpkeContext, public::PublicBytes,
    secrets::SecretBytes,
};

pub fn seal(ctx: &HpkeContext, aad: &[u8], plaintext: &SecretBytes) -> Result<PublicBytes> {
    aead::encrypt_raw(plaintext, &ctx.key, &ctx.base_nonce, aad)
}

pub fn open(ctx: &HpkeContext, aad: &[u8], ciphertext: &PublicBytes) -> Result<SecretBytes> {
    aead::decrypt_raw(ciphertext, &ctx.key, &ctx.base_nonce, aad)
}
