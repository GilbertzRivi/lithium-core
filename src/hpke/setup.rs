// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    error::Result,
    hpke::{
        export::export_secret,
        kem::{kem_decap, kem_encap},
        schedule::key_schedule,
        types::{HpkeEnc, HpkePrivateKey, HpkePublicKey},
    },
    secrets::SecretBytes,
};

pub fn setup_sender_and_export(
    ctx: &str,
    recipient_pk: &HpkePublicKey,
    info: &[u8],
    exporter_context: &[u8],
    exporter_length: usize,
) -> Result<(HpkeEnc, SecretBytes)> {
    let (shared_secret, enc) = kem_encap(ctx, &recipient_pk.x_pub, &recipient_pk.k_pub)?;

    let hpke_ctx = key_schedule(ctx, &shared_secret, info)?;

    let exported = export_secret(ctx, &hpke_ctx, exporter_context, exporter_length)?;

    Ok((enc, exported))
}

pub fn setup_receiver_and_export(
    ctx: &str,
    recipient_sk: &HpkePrivateKey,
    enc: &HpkeEnc,
    info: &[u8],
    exporter_context: &[u8],
    exporter_length: usize,
) -> Result<SecretBytes> {
    let shared_secret = kem_decap(ctx, &recipient_sk.x_priv, &recipient_sk.k_priv, enc)?;

    let hpke_ctx = key_schedule(ctx, &shared_secret, info)?;

    export_secret(ctx, &hpke_ctx, exporter_context, exporter_length)
}
