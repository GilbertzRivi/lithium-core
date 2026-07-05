// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::{
    error::{LithiumError, Result},
    secrets::SecByte32,
    secrets::bytes::SecretBytes,
};

pub(crate) const ARGON2_M_COST: u32 = 64 * 1024;
pub(crate) const ARGON2_T_COST: u32 = 3;
pub(crate) const ARGON2_P_COST: u32 = 1;
pub(crate) const ARGON2_OUT_LEN: usize = 32;

pub fn derive32(input: &SecretBytes, salt: Option<&SecretBytes>, info: &[u8]) -> Result<SecByte32> {
    let out = derive_bytes(input, salt, info, 32)?;
    SecByte32::from_slice(out.expose_as_slice())
}

pub fn derive_bytes(
    input: &SecretBytes,
    salt: Option<&SecretBytes>,
    info: &[u8],
    len: usize,
) -> Result<SecretBytes> {
    let hk = Hkdf::<Sha256>::new(salt.map(|s| s.expose_as_slice()), input.expose_as_slice());

    let mut out = vec![0u8; len];
    hk.expand(info, &mut out)?;

    Ok(SecretBytes::new(out))
}

pub fn hkdf_extract(salt: Option<&SecretBytes>, ikm: &SecretBytes) -> SecByte32 {
    let (prk, _) =
        Hkdf::<Sha256>::extract(salt.map(|s| s.expose_as_slice()), ikm.expose_as_slice());

    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    SecByte32::from_wiped_array(&mut out)
}

pub fn hkdf_expand(prk: &SecByte32, info: &SecretBytes, len: usize) -> Result<SecretBytes> {
    let hk = Hkdf::<Sha256>::from_prk(prk.expose_as_slice())
        .map_err(|_| LithiumError::internal("hkdf_prk_len"))?;

    let mut out = vec![0u8; len];
    hk.expand(info.expose_as_slice(), &mut out)?;

    Ok(SecretBytes::new(out))
}

pub fn argon2id() -> Result<Argon2<'static>> {
    let params = Params::new(
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(ARGON2_OUT_LEN),
    )
    .map_err(|_| LithiumError::internal("argon2_params"))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}
