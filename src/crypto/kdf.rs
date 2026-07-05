// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::{
    crypto::context::Context,
    error::{LithiumError, Result},
    secrets::SecByte32,
    secrets::bytes::SecretBytes,
};

pub(crate) const ARGON2_M_COST: u32 = 64 * 1024;
pub(crate) const ARGON2_T_COST: u32 = 3;
pub(crate) const ARGON2_P_COST: u32 = 1;
pub(crate) const ARGON2_OUT_LEN: usize = 32;

pub const ARGON2_MIN_M_COST: u32 = 19 * 1024;
pub const ARGON2_MIN_T_COST: u32 = 2;
pub const ARGON2_MIN_P_COST: u32 = 1;

pub const HKDF_SHA256_MAX_OUTPUT: usize = 255 * 32;

#[inline]
fn validate_hkdf_len(len: usize) -> Result<()> {
    if len > HKDF_SHA256_MAX_OUTPUT {
        return Err(LithiumError::invalid_len(HKDF_SHA256_MAX_OUTPUT, len));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2Params {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

impl Argon2Params {
    pub const OWASP_DEFAULT: Self = Self {
        m_cost: ARGON2_M_COST,
        t_cost: ARGON2_T_COST,
        p_cost: ARGON2_P_COST,
    };

    pub fn new(m_cost: u32, t_cost: u32, p_cost: u32) -> Result<Self> {
        if m_cost < ARGON2_MIN_M_COST || t_cost < ARGON2_MIN_T_COST || p_cost < ARGON2_MIN_P_COST {
            return Err(LithiumError::malformed_input("argon2_params_below_minimum"));
        }
        Self::new_unchecked(m_cost, t_cost, p_cost)
    }

    pub(crate) fn new_unchecked(m_cost: u32, t_cost: u32, p_cost: u32) -> Result<Self> {
        Params::new(m_cost, t_cost, p_cost, Some(ARGON2_OUT_LEN))
            .map_err(|_| LithiumError::internal("argon2_params"))?;
        Ok(Self {
            m_cost,
            t_cost,
            p_cost,
        })
    }

    pub fn m_cost(&self) -> u32 {
        self.m_cost
    }
    pub fn t_cost(&self) -> u32 {
        self.t_cost
    }
    pub fn p_cost(&self) -> u32 {
        self.p_cost
    }

    pub(crate) fn to_params(self, out_len: Option<usize>) -> Result<Params> {
        Params::new(self.m_cost, self.t_cost, self.p_cost, out_len)
            .map_err(|_| LithiumError::internal("argon2_params"))
    }
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self::OWASP_DEFAULT
    }
}

pub fn derive32(
    input: &SecretBytes,
    salt: Option<&SecretBytes>,
    ctx: &Context,
    aad: &[u8],
) -> Result<SecByte32> {
    derive32_raw(input, salt, ctx.bind_aad(aad).as_slice())
}

pub fn derive_bytes(
    input: &SecretBytes,
    salt: Option<&SecretBytes>,
    ctx: &Context,
    aad: &[u8],
    len: usize,
) -> Result<SecretBytes> {
    derive_bytes_raw(input, salt, ctx.bind_aad(aad).as_slice(), len)
}

pub(crate) fn derive32_raw(
    input: &SecretBytes,
    salt: Option<&SecretBytes>,
    info: &[u8],
) -> Result<SecByte32> {
    let out = derive_bytes_raw(input, salt, info, 32)?;
    SecByte32::from_slice(out.expose_as_slice())
}

pub(crate) fn derive_bytes_raw(
    input: &SecretBytes,
    salt: Option<&SecretBytes>,
    info: &[u8],
    len: usize,
) -> Result<SecretBytes> {
    validate_hkdf_len(len)?;
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
    validate_hkdf_len(len)?;
    let hk = Hkdf::<Sha256>::from_prk(prk.expose_as_slice())
        .map_err(|_| LithiumError::internal("hkdf_prk_len"))?;

    let mut out = vec![0u8; len];
    hk.expand(info.expose_as_slice(), &mut out)?;

    Ok(SecretBytes::new(out))
}

pub fn argon2id() -> Result<Argon2<'static>> {
    argon2id_with(Argon2Params::OWASP_DEFAULT)
}

pub fn argon2id_with(params: Argon2Params) -> Result<Argon2<'static>> {
    let params = params.to_params(Some(ARGON2_OUT_LEN))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_bytes_rejects_over_hkdf_max() {
        let input = SecretBytes::from_slice(b"ikm");
        assert!(derive_bytes_raw(&input, None, b"info", HKDF_SHA256_MAX_OUTPUT).is_ok());
        assert!(derive_bytes_raw(&input, None, b"info", HKDF_SHA256_MAX_OUTPUT + 1).is_err());
    }

    #[test]
    fn hkdf_expand_rejects_over_hkdf_max() {
        let prk = hkdf_extract(None, &SecretBytes::from_slice(b"ikm"));
        let info = SecretBytes::from_slice(b"info");
        assert!(hkdf_expand(&prk, &info, HKDF_SHA256_MAX_OUTPUT).is_ok());
        assert!(hkdf_expand(&prk, &info, HKDF_SHA256_MAX_OUTPUT + 1).is_err());
    }

    #[test]
    fn argon2_params_new_enforces_minimum() {
        assert!(
            Argon2Params::new(ARGON2_MIN_M_COST - 1, ARGON2_MIN_T_COST, ARGON2_MIN_P_COST).is_err()
        );
        assert!(
            Argon2Params::new(ARGON2_MIN_M_COST, ARGON2_MIN_T_COST - 1, ARGON2_MIN_P_COST).is_err()
        );
        assert!(Argon2Params::new(ARGON2_MIN_M_COST, ARGON2_MIN_T_COST, ARGON2_MIN_P_COST).is_ok());
        assert!(Argon2Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST).is_ok());
    }
}
