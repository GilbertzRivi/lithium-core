// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    crypto::{context::Context, kdf},
    error::Result,
    hpke::types::HpkeContext,
    secrets::{Nonce12, SecByte32, SecretBytes},
};

pub fn key_schedule(ctx: &Context, shared_secret: &SecByte32, info: &[u8]) -> Result<HpkeContext> {
    let ikm = SecretBytes::from_slice(shared_secret.expose_as_slice());
    let sched = ctx.add("hpke")?.add("schedule")?;

    let key = kdf::derive32(&ikm, None, sched.add("key")?.bind_aad(info).as_slice())?;

    let nonce_material = kdf::derive32(
        &ikm,
        None,
        sched.add("base-nonce")?.bind_aad(info).as_slice(),
    )?;

    let exporter_secret = kdf::derive32(
        &ikm,
        None,
        sched.add("exporter-secret")?.bind_aad(info).as_slice(),
    )?;

    let base_nonce = Nonce12::from_slice(&nonce_material.expose_as_slice()[..12])?;

    Ok(HpkeContext {
        key,
        base_nonce,
        exporter_secret,
    })
}
