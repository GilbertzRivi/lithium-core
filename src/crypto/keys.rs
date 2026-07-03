// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::error::Result;
use crate::public::{PubByte32, PublicBytes};
use crate::secrets::{MasterKey32, Nonce12, SecretBytes, SecretFixedBytes, SessionId32};
use ed25519_dalek::SigningKey;
use ml_dsa::{Generate, Keypair, MlDsa87, SigningKey as DsaSigningKey};
use ml_kem::{
    MlKem1024,
    kem::{Kem, KeyExport as KemKeyExport},
};
use rand::TryRng;
use rand::rngs::SysRng;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

#[inline]
pub fn random_fixed<const N: usize>() -> Result<SecretFixedBytes<N>> {
    let mut out = SecretFixedBytes::<N>::new_zeroed();
    let mut rng = SysRng;
    rng.try_fill_bytes(out.as_mut_slice())?;
    Ok(out)
}
#[inline]
pub fn random_12() -> Result<Nonce12> {
    random_fixed::<12>()
}
#[inline]
pub fn random_32() -> Result<SessionId32> {
    random_fixed::<32>()
}
#[inline]
pub fn random_master_key32() -> Result<MasterKey32> {
    random_fixed::<32>()
}

#[inline]
pub fn random_x25519_keypair() -> Result<(SecretFixedBytes<32>, PubByte32)> {
    let sk_seed = random_fixed::<32>()?;
    let secret = XStaticSecret::from(*sk_seed.as_array());
    let pk = XPublicKey::from(&secret);
    Ok((sk_seed, PubByte32::new(*pk.as_bytes())))
}

#[inline]
pub fn random_ed25519_keypair() -> Result<(SecretFixedBytes<32>, PubByte32)> {
    let seed = random_fixed::<32>()?;
    let signing = SigningKey::from_bytes(seed.as_array());
    let vk = signing.verifying_key().to_bytes();
    Ok((seed, PubByte32::new(vk)))
}

#[inline]
pub fn random_kyber_mlkem1024_keypair() -> Result<(SecretBytes, PublicBytes)> {
    let (sk, pk) = MlKem1024::generate_keypair();

    Ok((
        SecretBytes::from_wiped(sk.to_bytes()),
        PublicBytes::from_slice(pk.to_bytes().as_ref()),
    ))
}

#[inline]
pub fn random_dilithium_mldsa87_keypair() -> Result<(SecretBytes, PublicBytes)> {
    let sk = DsaSigningKey::<MlDsa87>::generate();
    let pk = sk.verifying_key();

    Ok((
        SecretBytes::from_wiped(sk.to_bytes()),
        PublicBytes::from_slice(pk.to_bytes().as_ref()),
    ))
}
