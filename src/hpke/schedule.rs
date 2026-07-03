// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    crypto::{context::Context, kdf},
    error::Result,
    hpke::types::HpkeContext,
    secrets::{Nonce12, SecByte32, SecretBytes},
};

fn schedule_label(ctx: &str, part: &[u8], info: &[u8]) -> SecretBytes {
    let mut out = Vec::new();
    out.extend_from_slice(ctx.as_bytes());
    out.extend_from_slice(b"/schedule/");
    out.extend_from_slice(part);
    out.extend_from_slice(b"\0");
    out.extend_from_slice(info);
    SecretBytes::new(out)
}

pub fn key_schedule(ctx: &Context, shared_secret: &SecByte32, info: &[u8]) -> Result<HpkeContext> {
    let ikm = SecretBytes::from_slice(shared_secret.as_slice());
    let ctx = ctx.as_str();

    let key = kdf::derive32(
        &ikm,
        None,
        schedule_label(ctx, b"key", info).expose_as_slice(),
    )?;

    let nonce_material = kdf::derive32(
        &ikm,
        None,
        schedule_label(ctx, b"base-nonce", info).expose_as_slice(),
    )?;

    let exporter_secret = kdf::derive32(
        &ikm,
        None,
        schedule_label(ctx, b"exporter-secret", info).expose_as_slice(),
    )?;

    let base_nonce = Nonce12::from_slice(&nonce_material.as_slice()[..12])?;

    Ok(HpkeContext {
        key,
        base_nonce,
        exporter_secret,
    })
}
