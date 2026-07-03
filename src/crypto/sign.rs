// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
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

pub fn sign_message<S: AsRef<[u8]>>(message: &[u8], priv_ed_seed: S) -> Result<Vec<u8>> {
    let seed = SecByte32::from_slice(priv_ed_seed.as_ref())?;
    let signing = Ed25519SigningKey::from_bytes(seed.as_array());
    let sig: Ed25519Signature = signing.sign(message);

    Ok(sig.to_bytes().to_vec())
}

pub fn verify_signature(message: &[u8], signature: &[u8], pub_key: &PubByte32) -> bool {
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

    pk.verify_strict(message, &sig).is_ok()
}

pub fn sign_message_dili<S: AsRef<[u8]>>(message: &[u8], dili_sk_bytes: S) -> Result<Vec<u8>> {
    let sk = MlDsaSigningKey::<MlDsa87>::new_from_slice(dili_sk_bytes.as_ref())
        .map_err(|_| LithiumError::key_import_failed("mldsa_signing_key"))?;

    let sig: MlDsaSignature<MlDsa87> = sk.sign(message);
    let sig_bytes = sig.to_bytes();

    Ok(sig_bytes.as_slice().to_vec())
}

pub fn verify_signature_dili(
    message: &[u8],
    signature: &[u8],
    dili_pk_bytes: &PublicBytes,
) -> bool {
    let Ok(pk) = MlDsaVerifyingKey::<MlDsa87>::new_from_slice(dili_pk_bytes.as_slice()) else {
        return false;
    };

    let Ok(sig) = MlDsaSignature::<MlDsa87>::try_from(signature) else {
        return false;
    };

    pk.verify(message, &sig).is_ok()
}
