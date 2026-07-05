// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::error::Result;
use crate::public::{PubByte32, PublicBytes};
use crate::secrets::{ArenaFixedBytes, Nonce12, SecByte32, SecByte64, SecretFixedBytes};
use ed25519_dalek::SigningKey;
use ml_dsa::{Keypair, MlDsa87, Seed as MlDsaSeed, SigningKey as MlDsaSigningKey};
use ml_kem::{DecapsulationKey1024, Seed as MlKemSeed, kem::KeyExport as KemKeyExport};
use rand::TryRng;
use rand::rngs::SysRng;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

mod sealed {
    pub trait Sealed {}
}

pub trait SeedBytes<const N: usize>: sealed::Sealed {
    fn seed(&self) -> &[u8; N];
}

impl<const N: usize> sealed::Sealed for SecretFixedBytes<N> {}
impl<const N: usize> SeedBytes<N> for SecretFixedBytes<N> {
    #[inline]
    fn seed(&self) -> &[u8; N] {
        self.expose_as_array()
    }
}

impl<const N: usize> sealed::Sealed for ArenaFixedBytes<N> {}
impl<const N: usize> SeedBytes<N> for ArenaFixedBytes<N> {
    #[inline]
    fn seed(&self) -> &[u8; N] {
        self.expose_as_array()
    }
}

#[inline]
pub fn random_fixed<const N: usize>() -> Result<SecretFixedBytes<N>> {
    let mut out = SecretFixedBytes::<N>::new_zeroed();
    let mut rng = SysRng;
    rng.try_fill_bytes(out.expose_as_mut_slice())?;
    Ok(out)
}
#[inline]
pub fn random_12() -> Result<Nonce12> {
    random_fixed::<12>()
}

#[inline]
pub fn random_32() -> Result<SecByte32> {
    random_fixed::<32>()
}
#[inline]
pub fn random_64() -> Result<SecByte64> {
    random_fixed::<64>()
}

#[inline]
pub fn ed25519_pub_from_seed<S: SeedBytes<32>>(seed: &S) -> PubByte32 {
    let sk = SigningKey::from_bytes(seed.seed());
    PubByte32::new(sk.verifying_key().to_bytes())
}

#[inline]
pub fn x25519_pub_from_seed<S: SeedBytes<32>>(seed: &S) -> PubByte32 {
    let sk = XStaticSecret::from(*seed.seed());
    PubByte32::new(*XPublicKey::from(&sk).as_bytes())
}

#[inline]
pub fn mldsa87_pub_from_seed<S: SeedBytes<32>>(seed: &S) -> PublicBytes {
    let sk = MlDsaSigningKey::<MlDsa87>::from_seed(MlDsaSeed::cast_from_core(seed.seed()));
    PublicBytes::from_slice(sk.verifying_key().to_bytes().as_ref())
}

#[inline]
pub fn mlkem1024_pub_from_seed<S: SeedBytes<64>>(seed: &S) -> PublicBytes {
    let dk = DecapsulationKey1024::from_seed(*MlKemSeed::cast_from_core(seed.seed()));
    let ek = dk.encapsulation_key();
    PublicBytes::from_slice(ek.to_bytes().as_ref())
}

#[inline]
pub fn ephemeral_x25519_keypair() -> Result<(SecByte32, PubByte32)> {
    let sk_seed = random_32()?;
    let pk = x25519_pub_from_seed(&sk_seed);
    Ok((sk_seed, pk))
}

#[inline]
pub fn ephemeral_ed25519_keypair() -> Result<(SecByte32, PubByte32)> {
    let seed = random_32()?;
    let pk = ed25519_pub_from_seed(&seed);
    Ok((seed, pk))
}

#[inline]
pub fn ephemeral_kyber_mlkem1024_keypair() -> Result<(SecByte64, PublicBytes)> {
    let seed = random_64()?;
    let pk = mlkem1024_pub_from_seed(&seed);
    Ok((seed, pk))
}

#[inline]
pub fn ephemeral_dilithium_mldsa87_keypair() -> Result<(SecByte32, PublicBytes)> {
    let seed = random_32()?;
    let pk = mldsa87_pub_from_seed(&seed);
    Ok((seed, pk))
}
