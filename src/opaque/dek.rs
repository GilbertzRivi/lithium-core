// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::crypto::{aead, kdf, keys};
use crate::error::{LithiumError, Result};
use crate::public::PublicBytes;
use crate::secrets::bytes::SecretBytes;
use crate::secrets::{SecByte32, SecByte64, SecretString};

const DEK_WRAP_VER: u8 = 1;

fn wrap_key(export_key: &SecByte64, aad: &[u8]) -> Result<SecByte32> {
    kdf::derive32(
        &SecretBytes::from_slice(export_key.as_slice()),
        None,
        &SecretBytes::from_slice(aad),
    )
}

pub fn wrap_dek_under_export_key(
    dek: &SecByte32,
    export_key: &SecByte64,
    aad: &[u8],
) -> Result<SecretString> {
    let key = wrap_key(export_key, aad)?;
    let nonce = keys::random_12()?;
    let blob = aead::encrypt(&SecretBytes::from_slice(dek.as_slice()), &key, &nonce, aad)?;

    let mut out = Vec::with_capacity(1 + blob.len());
    out.push(DEK_WRAP_VER);
    out.extend_from_slice(blob.as_slice());

    Ok(SecretString::new(hex::encode(out)))
}

pub fn unwrap_dek_under_export_key(
    blob_hex: &SecretString,
    export_key: &SecByte64,
    aad: &[u8],
) -> Result<SecByte32> {
    let blob = SecretBytes::from_hex(blob_hex.expose().trim())?;

    if blob.len() < 1 + 1 + 12 + 16 {
        return Err(LithiumError::invalid_credentials("bad_dek_blob"));
    }
    if blob.expose_as_slice()[0] != DEK_WRAP_VER {
        return Err(LithiumError::invalid_credentials("bad_dek_blob"));
    }

    let key = wrap_key(export_key, aad)?;
    let wrapped = PublicBytes::from_slice(&blob.expose_as_slice()[1..]);
    let pt = aead::decrypt(&wrapped, &key, aad)?;

    SecByte32::from_slice(pt.expose_as_slice())
}
