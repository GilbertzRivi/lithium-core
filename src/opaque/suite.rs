// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use argon2::{Algorithm, Argon2, Version};
use opaque_ke::{CipherSuite, Ristretto255, TripleDh};
use sha2::Sha512;

use crate::crypto::kdf::Argon2Params;
use crate::error::Result;

pub struct LithiumCipherSuite;

impl CipherSuite for LithiumCipherSuite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, Sha512>;
    type Ksf = Argon2<'static>;
}

pub type ClientRegistrationState = opaque_ke::ClientRegistration<LithiumCipherSuite>;
pub type ClientLoginState = opaque_ke::ClientLogin<LithiumCipherSuite>;

pub(crate) fn opaque_ksf(params: Argon2Params) -> Result<Argon2<'static>> {
    let params = params.to_params(None)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}
