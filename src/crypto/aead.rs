// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use aes_gcm_siv::{
    Aes256GcmSiv, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};

use crate::{
    error::{LithiumError, Result},
    public::PublicBytes,
    secrets::bytes::SecretBytes,
    secrets::{SecByte12, SecByte32},
};

const AEAD_BLOB_VERSION: u8 = 1;

pub fn encrypt_raw(
    plaintext: &SecretBytes,
    key: &SecByte32,
    nonce: &SecByte12,
    aad: &[u8],
) -> Result<PublicBytes> {
    let key: &Key<Aes256GcmSiv> = key.expose_as_slice().into();

    let nonce: &Nonce = nonce.expose_as_slice().into();

    let cipher = Aes256GcmSiv::new(key);
    let ct = cipher.encrypt(
        nonce,
        Payload {
            msg: plaintext.expose_as_slice(),
            aad,
        },
    )?;

    Ok(PublicBytes::new(ct))
}

pub fn decrypt_raw(
    ciphertext: &PublicBytes,
    key: &SecByte32,
    nonce: &SecByte12,
    aad: &[u8],
) -> Result<SecretBytes> {
    let key: &Key<Aes256GcmSiv> = key.expose_as_slice().into();

    let nonce: &Nonce = nonce.expose_as_slice().into();

    let cipher = Aes256GcmSiv::new(key);
    let pt = cipher.decrypt(
        nonce,
        Payload {
            msg: ciphertext.as_slice(),
            aad,
        },
    )?;

    Ok(SecretBytes::new(pt))
}

pub fn encrypt(
    plaintext: &SecretBytes,
    key: &SecByte32,
    nonce: &SecByte12,
    aad: &[u8],
) -> Result<PublicBytes> {
    let ct = encrypt_raw(plaintext, key, nonce, aad)?;
    let mut out = Vec::with_capacity(1 + 12 + ct.len());
    out.push(AEAD_BLOB_VERSION);
    out.extend_from_slice(nonce.expose_as_slice());
    out.extend_from_slice(ct.as_slice());
    Ok(PublicBytes::new(out))
}

pub fn decrypt(blob: &PublicBytes, key: &SecByte32, aad: &[u8]) -> Result<SecretBytes> {
    let bytes = blob.as_slice();
    if bytes.len() < 1 + 12 + 16 {
        return Err(LithiumError::aead_failed());
    }
    if bytes[0] != AEAD_BLOB_VERSION {
        return Err(LithiumError::aead_failed());
    }
    let nonce = SecByte12::from_slice(&bytes[1..13])?;
    decrypt_raw(&PublicBytes::from_slice(&bytes[13..]), key, &nonce, aad)
}
