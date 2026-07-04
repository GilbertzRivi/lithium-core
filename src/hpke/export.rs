// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    crypto::{context::Context, kdf},
    error::Result,
    hpke::types::HpkeContext,
    secrets::SecretBytes,
};

pub fn export_secret(
    ctx: &Context,
    hpke_ctx: &HpkeContext,
    exporter_context: &[u8],
    len: usize,
) -> Result<SecretBytes> {
    let input = SecretBytes::from_slice(hpke_ctx.exporter_secret.as_slice());
    let label = ctx.add("hpke")?.add("export")?.bind_aad(exporter_context);

    kdf::derive_bytes(&input, None, label.as_slice(), len)
}
