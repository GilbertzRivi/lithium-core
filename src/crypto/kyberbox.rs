// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use ml_kem::{
    Ciphertext as MlKemCiphertext, DecapsulationKey1024, EncapsulationKey1024, MlKem1024, Seed,
    TryKeyInit,
    kem::{Decapsulate, Encapsulate},
};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

use crate::{
    crypto::{aead, context::Context, kdf, keys},
    error::{LithiumError, Result},
    public::{PubByte32, PublicBytes},
    secrets::{SecByte32, bytes::SecretBytes},
};

const KYBER_BOX_VERSION: u8 = 1;
const KYBER_KEM_ID: u8 = 1;

#[derive(Clone, Debug)]
pub struct KyberBoxSealed {
    pub ciphertext: PublicBytes,
    pub kem_ct: PublicBytes,
}

#[inline]
fn derive_ecdh_key(
    priv_x: &SecByte32,
    peer_pub_x: &PubByte32,
    ecdh_label: &PublicBytes,
) -> Result<SecByte32> {
    let my_secret = XStaticSecret::from(*priv_x.as_array());
    let peer_pub = XPublicKey::from(*peer_pub_x.as_array());
    let shared = my_secret.diffie_hellman(&peer_pub);

    if !shared.was_contributory() {
        return Err(LithiumError::invalid_public_key("x25519_low_order"));
    }

    let shared_secret = SecByte32::new(shared.to_bytes());

    kdf::derive32(
        &SecretBytes::from_slice(shared_secret.as_slice()),
        None,
        ecdh_label.as_slice(),
    )
}

// UniversalCombiner (draft-irtf-cfrg-hybrid-kems): HKDF-Extract dual-PRF over ss_kem (salt) and
// ecdh_key (IKM). ct_t/ek_t are bound explicitly because X25519 has no binding of its own; ek_PQ
// is already bound inside ss_kem by ML-KEM's H(ek), so only ct_PQ is added.
#[inline]
fn derive_base_key(
    ss_kem: &SecByte32,
    ecdh_key: &SecByte32,
    ct_t: &[u8; 32],
    ek_t: &[u8; 32],
    ct_pq_hash: &[u8; 32],
    base_label: &PublicBytes,
) -> Result<SecByte32> {
    let ecdh_input = SecretBytes::from_slice(ecdh_key.as_slice());
    let ss_salt = SecretBytes::from_slice(ss_kem.as_slice());

    let mut info = base_label.as_slice().to_vec();
    info.extend_from_slice(ct_t);
    info.extend_from_slice(ek_t);
    info.extend_from_slice(ct_pq_hash);

    kdf::derive32(&ecdh_input, Some(&ss_salt), &info)
}

fn encapsulate_kem(peer_kyber_pub: &[u8]) -> Result<(SecByte32, [u8; 32], PublicBytes)> {
    let pk = EncapsulationKey1024::new_from_slice(peer_kyber_pub)
        .map_err(|_| LithiumError::invalid_public_key("mlkem_encapsulation_key"))?;

    let (ct_kem, ss) = pk.encapsulate();

    let ct_bytes = ct_kem.as_slice();
    let ss_bytes = SecByte32::from_slice(ss.as_ref())
        .map_err(|_| LithiumError::internal("mlkem_shared_secret_len"))?;

    let digest = Sha256::digest(ct_bytes);
    let mut ct_hash = [0u8; 32];
    ct_hash.copy_from_slice(&digest);

    let mut blob = Vec::with_capacity(2 + ct_bytes.len());
    blob.push(KYBER_BOX_VERSION);
    blob.push(KYBER_KEM_ID);
    blob.extend_from_slice(ct_bytes);

    Ok((ss_bytes, ct_hash, PublicBytes::new(blob)))
}

fn decapsulate_kem(kyber_priv_bytes: &[u8], blob: &[u8]) -> Result<(SecByte32, [u8; 32])> {
    if blob.len() < 2 {
        return Err(LithiumError::kem_invalid_ciphertext());
    }
    if blob[0] != KYBER_BOX_VERSION || blob[1] != KYBER_KEM_ID {
        return Err(LithiumError::kem_invalid_ciphertext());
    }

    let ct_slice = &blob[2..];

    let digest = Sha256::digest(ct_slice);
    let mut ct_hash = [0u8; 32];
    ct_hash.copy_from_slice(&digest);

    if kyber_priv_bytes.len() != 64 {
        return Err(LithiumError::invalid_len(64, kyber_priv_bytes.len()));
    }

    let mut seed = Seed::default();
    seed.copy_from_slice(kyber_priv_bytes);

    let sk = DecapsulationKey1024::from_seed(seed);

    let ct = MlKemCiphertext::<MlKem1024>::try_from(ct_slice)
        .map_err(|_| LithiumError::kem_invalid_ciphertext())?;

    let ss = sk.decapsulate(&ct);
    let ss_bytes = SecByte32::from_slice(ss.as_ref())
        .map_err(|_| LithiumError::internal("mlkem_shared_secret_len"))?;

    Ok((ss_bytes, ct_hash))
}

pub(crate) fn prep_base_key_for_encryption(
    ctx: &Context,
    priv_x: &SecByte32,
    peer_pub_x: &PubByte32,
    peer_k_pub: &PublicBytes,
) -> Result<(SecByte32, PublicBytes)> {
    let ecdh_key = derive_ecdh_key(priv_x, peer_pub_x, &ctx.add("ecdh-key")?.label())?;

    let ct_t = *XPublicKey::from(&XStaticSecret::from(*priv_x.as_array())).as_bytes();
    let ek_t = *peer_pub_x.as_array();

    let (ss_kem, ct_hash, kem_ct) = encapsulate_kem(peer_k_pub.as_slice())?;

    let base_key = derive_base_key(
        &ss_kem,
        &ecdh_key,
        &ct_t,
        &ek_t,
        &ct_hash,
        &ctx.add("base-key")?.label(),
    )?;

    Ok((base_key, kem_ct))
}

pub(crate) fn prep_base_key_for_decryption(
    ctx: &Context,
    priv_x: &SecByte32,
    peer_pub_x: &PubByte32,
    kyber_priv: &SecretBytes,
    kem_ct: &PublicBytes,
) -> Result<SecByte32> {
    let ecdh_key = derive_ecdh_key(priv_x, peer_pub_x, &ctx.add("ecdh-key")?.label())?;

    let ct_t = *peer_pub_x.as_array();
    let ek_t = *XPublicKey::from(&XStaticSecret::from(*priv_x.as_array())).as_bytes();

    let (ss_kem, ct_hash) = decapsulate_kem(kyber_priv.expose_as_slice(), kem_ct.as_slice())?;

    let base_key = derive_base_key(
        &ss_kem,
        &ecdh_key,
        &ct_t,
        &ek_t,
        &ct_hash,
        &ctx.add("base-key")?.label(),
    )?;

    Ok(base_key)
}

// The 0x00 matters so you can’t bypass / can’t confuse / cannot impersonate another context.
fn data_aad(ctx: &Context, aad: &[u8]) -> Result<Vec<u8>> {
    let mut framed = ctx.add("data")?.label().as_slice().to_vec();
    if !aad.is_empty() {
        framed.push(0);
        framed.extend_from_slice(aad);
    }
    Ok(framed)
}

pub fn seal(
    ctx: &Context,
    priv_x: &SecByte32,
    peer_pub_x: &PubByte32,
    peer_k_pub: &PublicBytes,
    aad: &[u8],
    data: &SecretBytes,
) -> Result<KyberBoxSealed> {
    let (base_key, kem_ct) = prep_base_key_for_encryption(ctx, priv_x, peer_pub_x, peer_k_pub)?;
    let nonce = keys::random_12()?;
    let ciphertext = aead::encrypt(data, &base_key, &nonce, &data_aad(ctx, aad)?)?;

    Ok(KyberBoxSealed { ciphertext, kem_ct })
}

pub fn open(
    ctx: &Context,
    priv_x: &SecByte32,
    peer_pub_x: &PubByte32,
    kyber_priv: &SecretBytes,
    aad: &[u8],
    kyber_box_sealed: &KyberBoxSealed,
) -> Result<SecretBytes> {
    let base_key = prep_base_key_for_decryption(
        ctx,
        priv_x,
        peer_pub_x,
        kyber_priv,
        &kyber_box_sealed.kem_ct,
    )?;
    let plaintext = aead::decrypt(
        &kyber_box_sealed.ciphertext,
        &base_key,
        &data_aad(ctx, aad)?,
    )?;

    Ok(plaintext)
}
