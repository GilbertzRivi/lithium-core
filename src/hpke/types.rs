// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::error::{LithiumError, Result};
use crate::public::{PubByte32, PublicBytes};
use crate::secrets::{Nonce12, SecByte32, SecretBytes};

const X25519_PUB_LEN: usize = 32;
const X25519_PRIV_LEN: usize = 32;
const MLKEM1024_PUB_LEN: usize = 1568;
const KEM_CT_LEN: usize = 1568 + 2;
const MLKEM1024_SEED_LEN: usize = 64;

#[derive(Clone, Debug)]
pub struct HpkeEnc {
    pub(crate) x_pub: PubByte32,
    pub(crate) kem_ct: PublicBytes,
}

#[derive(Debug)]
pub struct HpkeContext {
    pub(crate) key: SecByte32,
    pub(crate) base_nonce: Nonce12,
    pub(crate) exporter_secret: SecByte32,
}

#[derive(Clone, Debug)]
pub struct HpkeSealed {
    pub(crate) enc: HpkeEnc,
    pub(crate) ciphertext: PublicBytes,
}

#[derive(Clone, Debug)]
pub struct HpkePublicKey {
    pub(crate) x_pub: PubByte32,
    pub(crate) k_pub: PublicBytes,
}

#[derive(Clone, Debug)]
pub struct HpkePrivateKey {
    pub(crate) x_priv: SecByte32,
    pub(crate) k_priv: SecretBytes,
}

impl HpkeEnc {
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.kem_ct.as_slice().len());
        out.extend_from_slice(self.x_pub.as_slice());
        out.extend_from_slice(self.kem_ct.as_slice());
        out
    }

    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let expected = X25519_PUB_LEN + KEM_CT_LEN;
        if bytes.len() != expected {
            return Err(LithiumError::invalid_len(expected, bytes.len()));
        }

        let x_pub = PubByte32::from_slice(&bytes[..X25519_PUB_LEN])?;
        let kem_ct = PublicBytes::from_slice(&bytes[X25519_PUB_LEN..]);

        Ok(Self { x_pub, kem_ct })
    }
}

impl HpkeSealed {
    pub fn enc(&self) -> &HpkeEnc {
        &self.enc
    }

    pub fn ciphertext(&self) -> &PublicBytes {
        &self.ciphertext
    }

    pub fn to_wire(&self) -> Vec<u8> {
        let enc = self.enc.to_wire();
        let ct = self.ciphertext.as_slice();
        let mut out = Vec::with_capacity(4 + enc.len() + ct.len());
        out.extend_from_slice(&(enc.len() as u32).to_be_bytes());
        out.extend_from_slice(&enc);
        out.extend_from_slice(ct);
        out
    }

    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 {
            return Err(LithiumError::invalid_len(4, bytes.len()));
        }
        let enc_len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        let rest = &bytes[4..];
        let enc_bytes = rest
            .get(..enc_len)
            .ok_or_else(|| LithiumError::invalid_len(enc_len, rest.len()))?;
        let enc = HpkeEnc::from_wire(enc_bytes)?;
        let ciphertext = PublicBytes::from_slice(&rest[enc_len..]);
        Ok(Self { enc, ciphertext })
    }
}

impl HpkePublicKey {
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(X25519_PUB_LEN + MLKEM1024_PUB_LEN);
        out.extend_from_slice(self.x_pub.as_slice());
        out.extend_from_slice(self.k_pub.as_slice());
        out
    }

    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let expected = X25519_PUB_LEN + MLKEM1024_PUB_LEN;
        if bytes.len() != expected {
            return Err(LithiumError::invalid_len(expected, bytes.len()));
        }

        Ok(Self {
            x_pub: PubByte32::from_slice(&bytes[..X25519_PUB_LEN])?,
            k_pub: PublicBytes::from_slice(&bytes[X25519_PUB_LEN..]),
        })
    }
}

impl HpkePrivateKey {
    pub fn to_wire(&self) -> SecretBytes {
        let mut out = Vec::with_capacity(X25519_PRIV_LEN + MLKEM1024_SEED_LEN);
        out.extend_from_slice(self.x_priv.expose_as_slice());
        out.extend_from_slice(self.k_priv.expose_as_slice());
        SecretBytes::new(out)
    }

    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let expected = X25519_PRIV_LEN + MLKEM1024_SEED_LEN;
        if bytes.len() != expected {
            return Err(LithiumError::invalid_len(expected, bytes.len()));
        }

        Ok(Self {
            x_priv: SecByte32::from_slice(&bytes[..X25519_PRIV_LEN])?,
            k_priv: SecretBytes::from_slice(&bytes[X25519_PRIV_LEN..]),
        })
    }
}
