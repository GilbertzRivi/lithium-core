// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::error::Result;
use crate::secrets::{FixedBytes, MasterKey32, Nonce12, SecretBytes, SessionId32};
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
pub fn random_fixed<const N: usize>() -> Result<FixedBytes<N>> {
    let mut out = FixedBytes::<N>::new_zeroed();
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
pub fn random_x25519_keypair() -> Result<(FixedBytes<32>, FixedBytes<32>)> {
    let sk_seed = random_fixed::<32>()?;
    let secret = XStaticSecret::from(*sk_seed.as_array());
    let pk = XPublicKey::from(&secret);
    Ok((sk_seed, FixedBytes::new(*pk.as_bytes())))
}

#[inline]
pub fn random_ed25519_keypair() -> Result<(FixedBytes<32>, FixedBytes<32>)> {
    let seed = random_fixed::<32>()?;
    let signing = SigningKey::from_bytes(seed.as_array());
    let vk = signing.verifying_key().to_bytes();
    Ok((seed, FixedBytes::new(vk)))
}

#[inline]
pub fn random_kyber_mlkem1024_keypair() -> Result<(SecretBytes, SecretBytes)> {
    let (sk, pk) = MlKem1024::generate_keypair();

    let sk_bytes = sk.to_bytes();
    let pk_bytes = pk.to_bytes();

    Ok((
        SecretBytes::from_slice(sk_bytes.as_ref()),
        SecretBytes::from_slice(pk_bytes.as_ref()),
    ))
}

#[inline]
pub fn random_dilithium_mldsa87_keypair() -> Result<(SecretBytes, SecretBytes)> {
    let sk = DsaSigningKey::<MlDsa87>::generate();
    let pk = sk.verifying_key();

    let sk_bytes = sk.to_bytes();
    let pk_bytes = pk.to_bytes();

    Ok((
        SecretBytes::from_slice(sk_bytes.as_ref()),
        SecretBytes::from_slice(pk_bytes.as_ref()),
    ))
}
