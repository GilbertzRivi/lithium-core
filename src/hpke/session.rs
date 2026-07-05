// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    crypto::{aead, context::Context},
    error::{LithiumError, Result},
    hpke::{
        kem::{kem_decap, kem_encap},
        schedule::key_schedule,
        types::{HpkeContext, HpkeEnc, HpkePrivateKey, HpkePublicKey},
    },
    public::PublicBytes,
    secrets::{Nonce12, SecretBytes},
};

fn seq_nonce(base: &Nonce12, seq: u64) -> Result<Nonce12> {
    let mut n = *base.expose_as_array();
    let s = seq.to_be_bytes();
    for i in 0..8 {
        n[4 + i] ^= s[i];
    }
    Nonce12::from_slice(&n)
}

pub struct HpkeSenderContext {
    ctx: HpkeContext,
    seq: u64,
}

pub struct HpkeReceiverContext {
    ctx: HpkeContext,
    seq: u64,
}

pub fn setup_sender(
    ctx: &Context,
    recipient_pk: &HpkePublicKey,
    info: &[u8],
) -> Result<(HpkeEnc, HpkeSenderContext)> {
    let (shared_secret, enc) = kem_encap(ctx, &recipient_pk.x_pub, &recipient_pk.k_pub)?;
    let hpke_ctx = key_schedule(ctx, &shared_secret, info)?;
    Ok((
        enc,
        HpkeSenderContext {
            ctx: hpke_ctx,
            seq: 0,
        },
    ))
}

pub fn setup_receiver(
    ctx: &Context,
    recipient_sk: &HpkePrivateKey,
    enc: &HpkeEnc,
    info: &[u8],
) -> Result<HpkeReceiverContext> {
    let shared_secret = kem_decap(ctx, &recipient_sk.x_priv, &recipient_sk.k_priv, enc)?;
    let hpke_ctx = key_schedule(ctx, &shared_secret, info)?;
    Ok(HpkeReceiverContext {
        ctx: hpke_ctx,
        seq: 0,
    })
}

impl HpkeSenderContext {
    pub fn seal(&mut self, aad: &[u8], plaintext: &SecretBytes) -> Result<PublicBytes> {
        let nonce = seq_nonce(&self.ctx.base_nonce, self.seq)?;
        let ct = aead::encrypt_raw(plaintext, &self.ctx.key, &nonce, aad)?;
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| LithiumError::internal("hpke_seq_overflow"))?;
        Ok(ct)
    }
}

impl HpkeReceiverContext {
    pub fn open(&mut self, aad: &[u8], ciphertext: &PublicBytes) -> Result<SecretBytes> {
        let nonce = seq_nonce(&self.ctx.base_nonce, self.seq)?;
        let pt = aead::decrypt_raw(ciphertext, &self.ctx.key, &nonce, aad)?;
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| LithiumError::internal("hpke_seq_overflow"))?;
        Ok(pt)
    }
}
