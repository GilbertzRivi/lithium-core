// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use aes_gcm_siv::{
    Aes256GcmSiv, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};

use crate::{
    crypto::{context::Context, keys},
    error::{LithiumError, Result},
    public::PublicBytes,
    secrets::bytes::SecretBytes,
    secrets::{SecByte12, SecByte32},
};

const AEAD_BLOB_VERSION: u8 = 1;

pub(crate) fn encrypt_raw(
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

pub(crate) fn decrypt_raw(
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
    ctx: &Context,
    aad: &[u8],
) -> Result<PublicBytes> {
    let nonce = keys::random_12()?;
    encrypt_framed(plaintext, key, &nonce, ctx, aad)
}

fn encrypt_framed(
    plaintext: &SecretBytes,
    key: &SecByte32,
    nonce: &SecByte12,
    ctx: &Context,
    aad: &[u8],
) -> Result<PublicBytes> {
    let bound = ctx.bind_aad(aad);
    let ct = encrypt_raw(plaintext, key, nonce, bound.as_slice())?;
    let mut out = Vec::with_capacity(1 + 12 + ct.len());
    out.push(AEAD_BLOB_VERSION);
    out.extend_from_slice(nonce.expose_as_slice());
    out.extend_from_slice(ct.as_slice());
    Ok(PublicBytes::new(out))
}

pub fn decrypt(
    blob: &PublicBytes,
    key: &SecByte32,
    ctx: &Context,
    aad: &[u8],
) -> Result<SecretBytes> {
    let bytes = blob.as_slice();
    if bytes.len() < 1 + 12 + 16 {
        return Err(LithiumError::aead_failed());
    }
    if bytes[0] != AEAD_BLOB_VERSION {
        return Err(LithiumError::aead_failed());
    }
    let nonce = SecByte12::from_slice(&bytes[1..13])?;
    let bound = ctx.bind_aad(aad);
    decrypt_raw(
        &PublicBytes::from_slice(&bytes[13..]),
        key,
        &nonce,
        bound.as_slice(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actx() -> Context<'static> {
        Context::base("test").unwrap().add("aead").unwrap()
    }

    fn key32(fill: u8) -> SecByte32 {
        SecByte32::new([fill; 32])
    }

    fn nonce12(fill: u8) -> SecByte12 {
        SecByte12::new([fill; 12])
    }

    fn framed(fill_nonce: u8, aad: &[u8]) -> Vec<u8> {
        let key = key32(0x01);
        let nonce = nonce12(fill_nonce);
        encrypt_framed(
            &SecretBytes::from_slice(b"payload"),
            &key,
            &nonce,
            &actx(),
            aad,
        )
        .unwrap()
        .as_slice()
        .to_vec()
    }

    #[test]
    fn nonce_is_embedded_at_bytes_1_to_13() {
        let blob = framed(0xCC, b"aad");
        assert_eq!(&blob[1..13], &[0xCC; 12], "nonce must be at bytes 1..13");
    }

    #[test]
    fn bit_flip_in_nonce_first_byte_fails() {
        let key = key32(0x01);
        let mut blob = framed(0x10, b"ctx");
        blob[1] ^= 0x01;
        assert!(decrypt(&PublicBytes::new(blob), &key, &actx(), b"ctx").is_err());
    }

    #[test]
    fn bit_flip_in_nonce_last_byte_fails() {
        let key = key32(0x01);
        let mut blob = framed(0x11, b"ctx");
        blob[12] ^= 0x80;
        assert!(decrypt(&PublicBytes::new(blob), &key, &actx(), b"ctx").is_err());
    }

    #[test]
    fn framed_is_deterministic_for_fixed_nonce() {
        let a = framed(0x59, b"ctx");
        let b = framed(0x59, b"ctx");
        assert_eq!(a, b, "AES-GCM-SIV is deterministic for identical inputs");
    }

    #[test]
    fn encrypt_uses_random_nonce() {
        let key = key32(0x01);
        let pt = SecretBytes::from_slice(b"payload");
        let a = encrypt(&pt, &key, &actx(), b"ctx").unwrap();
        let b = encrypt(&pt, &key, &actx(), b"ctx").unwrap();
        assert_ne!(
            a.as_slice(),
            b.as_slice(),
            "public encrypt must randomize the nonce"
        );
    }
}
