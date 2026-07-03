// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{crypto::kdf, error::Result, hpke::types::HpkeContext, secrets::SecretBytes};

fn export_label(ctx: &str, exporter_context: &[u8]) -> SecretBytes {
    let mut info = Vec::new();
    info.extend_from_slice(ctx.as_bytes());
    info.extend_from_slice(b"/export\0");
    info.extend_from_slice(exporter_context);
    SecretBytes::new(info)
}

pub fn export_secret(
    ctx: &str,
    hpke_ctx: &HpkeContext,
    exporter_context: &[u8],
    len: usize,
) -> Result<SecretBytes> {
    let input = SecretBytes::from_slice(hpke_ctx.exporter_secret.as_slice());

    kdf::derive_bytes(&input, None, &export_label(ctx, exporter_context), len)
}
