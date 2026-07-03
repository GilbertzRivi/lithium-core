// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::error::{LithiumError, Result};
use crate::public::{PubByte32, PublicBytes};
use crate::secrets::{MasterKey32, Nonce12, SecretBytes, SecretFixedBytes, SessionId32};
use ed25519_dalek::SigningKey;
use ml_dsa::{B32, Keypair, MlDsa87, SigningKey as DsaSigningKey};
use ml_kem::{DecapsulationKey1024, Seed as MlKemSeed, kem::KeyExport as KemKeyExport};
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
pub fn ed25519_pub_from_seed(seed: &[u8; 32]) -> PubByte32 {
    let sk = SigningKey::from_bytes(seed);
    PubByte32::new(sk.verifying_key().to_bytes())
}

#[inline]
pub fn x25519_pub_from_seed(seed: &[u8; 32]) -> PubByte32 {
    let sk = XStaticSecret::from(*seed);
    PubByte32::new(*XPublicKey::from(&sk).as_bytes())
}

#[inline]
pub fn mlkem1024_pub_from_seed(seed: &[u8]) -> Result<PublicBytes> {
    if seed.len() != 64 {
        return Err(LithiumError::invalid_len(64, seed.len()));
    }
    let mut s = MlKemSeed::default();
    s.copy_from_slice(seed);
    let dk = DecapsulationKey1024::from_seed(s);
    let ek = dk.encapsulation_key();
    Ok(PublicBytes::from_slice(ek.to_bytes().as_ref()))
}

#[inline]
pub fn mldsa87_pub_from_seed(seed: &[u8]) -> Result<PublicBytes> {
    if seed.len() != 32 {
        return Err(LithiumError::invalid_len(32, seed.len()));
    }
    let mut xi = B32::default();
    xi.copy_from_slice(seed);
    let sk = DsaSigningKey::<MlDsa87>::from_seed(&xi);
    Ok(PublicBytes::from_slice(
        sk.verifying_key().to_bytes().as_ref(),
    ))
}

#[inline]
pub fn random_x25519_keypair() -> Result<(SecretFixedBytes<32>, PubByte32)> {
    let sk_seed = random_fixed::<32>()?;
    let pk = x25519_pub_from_seed(sk_seed.as_array());
    Ok((sk_seed, pk))
}

#[inline]
pub fn random_ed25519_keypair() -> Result<(SecretFixedBytes<32>, PubByte32)> {
    let seed = random_fixed::<32>()?;
    let pk = ed25519_pub_from_seed(seed.as_array());
    Ok((seed, pk))
}

#[inline]
pub fn random_kyber_mlkem1024_keypair() -> Result<(SecretBytes, PublicBytes)> {
    let seed = random_fixed::<64>()?;
    let pk = mlkem1024_pub_from_seed(seed.as_slice())?;
    Ok((SecretBytes::from_slice(seed.as_slice()), pk))
}

#[inline]
pub fn random_dilithium_mldsa87_keypair() -> Result<(SecretBytes, PublicBytes)> {
    let seed = random_fixed::<32>()?;
    let pk = mldsa87_pub_from_seed(seed.as_slice())?;
    Ok((SecretBytes::from_slice(seed.as_slice()), pk))
}
