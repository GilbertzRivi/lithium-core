// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    crypto::context::Context,
    error::{LithiumError, Result},
    public::{PubByte32, PublicBytes},
    secrets::SecByte32,
};

use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as Ed25519Signer, SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey,
};

use ml_dsa::{
    KeyInit, MlDsa87, Signature as MlDsaSignature, SigningKey as MlDsaSigningKey,
    VerifyingKey as MlDsaVerifyingKey,
    signature::{SignatureEncoding, Signer as MlDsaSigner, Verifier as MlDsaVerifier},
};

const MLDSA87_SIG_LEN: usize = 4627;

pub fn sign_message<S: AsRef<[u8]>>(
    message: &[u8],
    priv_ed_seed: S,
    ctx: &Context,
) -> Result<Vec<u8>> {
    let seed = SecByte32::from_slice(priv_ed_seed.as_ref())?;
    let signing = Ed25519SigningKey::from_bytes(seed.expose_as_array());
    let sig: Ed25519Signature = signing.sign(ctx.bind_aad(message).as_slice());

    Ok(sig.to_bytes().to_vec())
}

pub fn verify_signature(
    message: &[u8],
    signature: &[u8],
    pub_key: &PubByte32,
    ctx: &Context,
) -> bool {
    if signature.len() != 64 {
        return false;
    }

    let sig = match Ed25519Signature::from_slice(signature) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let pk = match Ed25519VerifyingKey::from_bytes(pub_key.as_array()) {
        Ok(v) => v,
        Err(_) => return false,
    };

    pk.verify_strict(ctx.bind_aad(message).as_slice(), &sig)
        .is_ok()
}

pub fn sign_message_dili<S: AsRef<[u8]>>(
    message: &[u8],
    dili_sk_bytes: S,
    ctx: &Context,
) -> Result<Vec<u8>> {
    let sk = MlDsaSigningKey::<MlDsa87>::new_from_slice(dili_sk_bytes.as_ref())
        .map_err(|_| LithiumError::key_import_failed("mldsa_signing_key"))?;

    let sig: MlDsaSignature<MlDsa87> = sk.sign(ctx.bind_aad(message).as_slice());
    let sig_bytes = sig.to_bytes();

    Ok(sig_bytes.as_slice().to_vec())
}

pub fn verify_signature_dili(
    message: &[u8],
    signature: &[u8],
    dili_pk_bytes: &PublicBytes,
    ctx: &Context,
) -> bool {
    let Ok(pk) = MlDsaVerifyingKey::<MlDsa87>::new_from_slice(dili_pk_bytes.as_slice()) else {
        return false;
    };

    let Ok(sig) = MlDsaSignature::<MlDsa87>::try_from(signature) else {
        return false;
    };

    pk.verify(ctx.bind_aad(message).as_slice(), &sig).is_ok()
}

const ED25519_SIG_LEN: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DoubleSig {
    ed: [u8; ED25519_SIG_LEN],
    dili: Vec<u8>,
}

impl DoubleSig {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ED25519_SIG_LEN + self.dili.len());
        out.extend_from_slice(&self.ed);
        out.extend_from_slice(&self.dili);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let expected = ED25519_SIG_LEN + MLDSA87_SIG_LEN;
        if bytes.len() != expected {
            return Err(LithiumError::invalid_len(expected, bytes.len()));
        }
        let mut ed = [0u8; ED25519_SIG_LEN];
        ed.copy_from_slice(&bytes[..ED25519_SIG_LEN]);
        Ok(Self {
            ed,
            dili: bytes[ED25519_SIG_LEN..].to_vec(),
        })
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        Self::from_bytes(&crate::hexcodec::decode_vec(s)?)
    }
}

pub fn sign_double<E: AsRef<[u8]>, D: AsRef<[u8]>>(
    message: &[u8],
    ed_seed: E,
    dili_sk: D,
    ctx: &Context,
) -> Result<DoubleSig> {
    let ed: [u8; ED25519_SIG_LEN] = sign_message(message, ed_seed, ctx)?
        .try_into()
        .map_err(|_| LithiumError::internal("ed25519_sig_len"))?;
    let dili = sign_message_dili(message, dili_sk, ctx)?;
    Ok(DoubleSig { ed, dili })
}

pub fn verify_double(
    message: &[u8],
    sig: &DoubleSig,
    ed_pub: &PubByte32,
    dili_pub: &PublicBytes,
    ctx: &Context,
) -> bool {
    let sig_ed = verify_signature(message, &sig.ed, ed_pub, ctx);
    let sig_dili = verify_signature_dili(message, &sig.dili, dili_pub, ctx);
    sig_ed && sig_dili
}
