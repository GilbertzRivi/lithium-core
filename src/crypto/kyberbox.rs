// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use ml_kem::{
    Ciphertext as MlKemCiphertext, DecapsulationKey1024, EncapsulationKey1024, MlKem1024,
    Seed as MlKemSeed, TryKeyInit,
    kem::{Decapsulate, Encapsulate},
};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

use crate::{
    crypto::{aead, context::Context, kdf, keys},
    error::{LithiumError, Result},
    public::{PubByte32, PublicBytes},
    secrets::{SecByte32, SecByte64, bytes::SecretBytes},
};

const KYBER_BOX_VERSION: u8 = 1;
const KYBER_KEM_ID: u8 = 1;

const X25519_PUB_LEN: usize = 32;
const MLKEM1024_PUB_LEN: usize = 1568;
const KEM_CT_LEN: usize = 1568 + 2;

const DUAL_ENC_PUB_LEN: usize = X25519_PUB_LEN + MLKEM1024_PUB_LEN;
const DUAL_ENC_PRIV_LEN: usize = 32 + 64;

#[derive(Clone, Debug)]
pub struct KyberBoxSealed {
    pub(crate) sender_x_pub: PubByte32,
    pub(crate) kem_ct: PublicBytes,
    pub(crate) ciphertext: PublicBytes,
}

impl KyberBoxSealed {
    pub fn sender_x_pub(&self) -> &PubByte32 {
        &self.sender_x_pub
    }

    pub fn kem_ct(&self) -> &PublicBytes {
        &self.kem_ct
    }

    pub fn ciphertext(&self) -> &PublicBytes {
        &self.ciphertext
    }

    pub fn to_wire(&self) -> Vec<u8> {
        let ct = self.ciphertext.as_slice();
        let mut out = Vec::with_capacity(X25519_PUB_LEN + KEM_CT_LEN + ct.len());
        out.extend_from_slice(self.sender_x_pub.as_slice());
        out.extend_from_slice(self.kem_ct.as_slice());
        out.extend_from_slice(ct);
        out
    }

    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let prefix = X25519_PUB_LEN + KEM_CT_LEN;
        if bytes.len() < prefix {
            return Err(LithiumError::invalid_len(prefix, bytes.len()));
        }
        Ok(Self {
            sender_x_pub: PubByte32::from_slice(&bytes[..X25519_PUB_LEN])?,
            kem_ct: PublicBytes::from_slice(&bytes[X25519_PUB_LEN..prefix]),
            ciphertext: PublicBytes::from_slice(&bytes[prefix..]),
        })
    }
}

#[inline]
fn ecdh_kdf(
    my_secret: &XStaticSecret,
    peer_pub_x: &PubByte32,
    ecdh_label: &PublicBytes,
) -> Result<SecByte32> {
    let peer_pub = XPublicKey::from(*peer_pub_x.as_array());
    let shared = my_secret.diffie_hellman(&peer_pub);

    if !shared.was_contributory() {
        return Err(LithiumError::invalid_public_key("x25519", "low_order"));
    }

    kdf::derive32_raw(
        &SecretBytes::from_slice(shared.as_bytes()),
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
    let ecdh_input = SecretBytes::from_slice(ecdh_key.expose_as_slice());
    let ss_salt = SecretBytes::from_slice(ss_kem.expose_as_slice());

    let mut info = base_label.as_slice().to_vec();
    info.extend_from_slice(ct_t);
    info.extend_from_slice(ek_t);
    info.extend_from_slice(ct_pq_hash);

    kdf::derive32_raw(&ecdh_input, Some(&ss_salt), &info)
}

fn encapsulate_kem(peer_kyber_pub: &[u8]) -> Result<(SecByte32, [u8; 32], PublicBytes)> {
    let pk = EncapsulationKey1024::new_from_slice(peer_kyber_pub)
        .map_err(|_| LithiumError::invalid_public_key("kyber-mlkem1024", "encapsulation_key"))?;

    let (ct_kem, ss) = pk.encapsulate();

    let ct_bytes = ct_kem.as_slice();
    let ss_bytes =
        SecByte32::from_wiped(ss).map_err(|_| LithiumError::internal("mlkem_shared_secret_len"))?;

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

    let sk = DecapsulationKey1024::from_seed(
        MlKemSeed::try_from(kyber_priv_bytes)
            .map_err(|_| LithiumError::invalid_len(64, kyber_priv_bytes.len()))?,
    );

    let ct = MlKemCiphertext::<MlKem1024>::try_from(ct_slice)
        .map_err(|_| LithiumError::kem_invalid_ciphertext())?;

    let ss_bytes = SecByte32::from_wiped(sk.decapsulate(&ct))
        .map_err(|_| LithiumError::internal("mlkem_shared_secret_len"))?;

    Ok((ss_bytes, ct_hash))
}

pub(crate) fn prep_base_key_for_encryption(
    ctx: &Context,
    priv_x: impl AsRef<[u8]>,
    peer_pub_x: &PubByte32,
    peer_k_pub: &PublicBytes,
) -> Result<(SecByte32, PublicBytes, PubByte32)> {
    let priv_x_arr = <&[u8; 32]>::try_from(priv_x.as_ref())
        .map_err(|_| LithiumError::invalid_len(32, priv_x.as_ref().len()))?;
    let my_secret = XStaticSecret::from(*priv_x_arr);
    let ct_t = *XPublicKey::from(&my_secret).as_bytes();
    let ek_t = *peer_pub_x.as_array();

    let ecdh_key = ecdh_kdf(&my_secret, peer_pub_x, &ctx.add("ecdh-key")?.label())?;
    let (ss_kem, ct_hash, kem_ct) = encapsulate_kem(peer_k_pub.as_slice())?;

    let base_key = derive_base_key(
        &ss_kem,
        &ecdh_key,
        &ct_t,
        &ek_t,
        &ct_hash,
        &ctx.add("base-key")?.label(),
    )?;

    Ok((base_key, kem_ct, PubByte32::new(ct_t)))
}

pub(crate) fn prep_base_key_for_decryption(
    ctx: &Context,
    priv_x: impl AsRef<[u8]>,
    peer_pub_x: &PubByte32,
    kyber_priv: impl AsRef<[u8]>,
    kem_ct: &PublicBytes,
) -> Result<SecByte32> {
    let priv_x_arr = <&[u8; 32]>::try_from(priv_x.as_ref())
        .map_err(|_| LithiumError::invalid_len(32, priv_x.as_ref().len()))?;
    let my_secret = XStaticSecret::from(*priv_x_arr);
    let ecdh_key = ecdh_kdf(&my_secret, peer_pub_x, &ctx.add("ecdh-key")?.label())?;

    let ct_t = *peer_pub_x.as_array();
    let ek_t = *XPublicKey::from(&my_secret).as_bytes();

    let (ss_kem, ct_hash) = decapsulate_kem(kyber_priv.as_ref(), kem_ct.as_slice())?;

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

pub fn seal(
    ctx: &Context,
    peer_pub_x: &PubByte32,
    peer_k_pub: &PublicBytes,
    aad: &[u8],
    data: &SecretBytes,
) -> Result<(KyberBoxSealed, SecByte32)> {
    let (sender_priv_x, _) = keys::ephemeral_x25519_keypair()?;
    let (base_key, kem_ct, sender_x_pub) =
        prep_base_key_for_encryption(ctx, sender_priv_x.expose_as_slice(), peer_pub_x, peer_k_pub)?;
    let data_ctx = ctx.add("data")?;
    let ciphertext = aead::encrypt(data, &base_key, &data_ctx, aad)?;

    Ok((
        KyberBoxSealed {
            sender_x_pub,
            kem_ct,
            ciphertext,
        },
        sender_priv_x,
    ))
}

pub fn open(
    ctx: &Context,
    priv_x: impl AsRef<[u8]>,
    kyber_priv: impl AsRef<[u8]>,
    aad: &[u8],
    kyber_box_sealed: &KyberBoxSealed,
) -> Result<SecretBytes> {
    let base_key = prep_base_key_for_decryption(
        ctx,
        priv_x,
        &kyber_box_sealed.sender_x_pub,
        kyber_priv,
        &kyber_box_sealed.kem_ct,
    )?;
    let data_ctx = ctx.add("data")?;
    let plaintext = aead::decrypt(&kyber_box_sealed.ciphertext, &base_key, &data_ctx, aad)?;

    Ok(plaintext)
}

#[derive(Clone, Debug)]
pub struct DualEncryptionPublicKey {
    x25519: PubByte32,
    mlkem1024: PublicBytes,
}

impl DualEncryptionPublicKey {
    pub fn new(x25519: PubByte32, mlkem1024: PublicBytes) -> Result<Self> {
        if mlkem1024.as_slice().len() != MLKEM1024_PUB_LEN {
            return Err(LithiumError::invalid_len(
                MLKEM1024_PUB_LEN,
                mlkem1024.as_slice().len(),
            ));
        }
        Ok(Self { x25519, mlkem1024 })
    }

    pub fn x25519(&self) -> &PubByte32 {
        &self.x25519
    }

    pub fn mlkem1024(&self) -> &PublicBytes {
        &self.mlkem1024
    }

    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DUAL_ENC_PUB_LEN);
        out.extend_from_slice(self.x25519.as_slice());
        out.extend_from_slice(self.mlkem1024.as_slice());
        out
    }

    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != DUAL_ENC_PUB_LEN {
            return Err(LithiumError::invalid_len(DUAL_ENC_PUB_LEN, bytes.len()));
        }
        Ok(Self {
            x25519: PubByte32::from_slice(&bytes[..X25519_PUB_LEN])?,
            mlkem1024: PublicBytes::from_slice(&bytes[X25519_PUB_LEN..]),
        })
    }

    pub fn seal(
        &self,
        ctx: &Context,
        aad: &[u8],
        data: &SecretBytes,
    ) -> Result<(DualSealed, DualEncryptionPrivateKey)> {
        let (reply_priv, reply_pub) = DualEncryptionPrivateKey::ephemeral()?;
        let mut bound_aad = reply_pub.to_wire();
        bound_aad.extend_from_slice(aad);
        let (inner, _forward_eph_x) = seal(ctx, &self.x25519, &self.mlkem1024, &bound_aad, data)?;
        Ok((DualSealed { reply_pub, inner }, reply_priv))
    }
}

pub struct DualEncryptionPrivateKey {
    x25519: SecByte32,
    mlkem1024: SecByte64,
}

impl DualEncryptionPrivateKey {
    pub fn ephemeral() -> Result<(Self, DualEncryptionPublicKey)> {
        let (x_priv, x_pub) = keys::ephemeral_x25519_keypair()?;
        let (k_priv, k_pub) = keys::ephemeral_kyber_mlkem1024_keypair()?;
        Ok((
            Self {
                x25519: x_priv,
                mlkem1024: k_priv,
            },
            DualEncryptionPublicKey {
                x25519: x_pub,
                mlkem1024: k_pub,
            },
        ))
    }

    pub fn to_wire(&self) -> SecretBytes {
        let mut out = Vec::with_capacity(DUAL_ENC_PRIV_LEN);
        out.extend_from_slice(self.x25519.expose_as_slice());
        out.extend_from_slice(self.mlkem1024.expose_as_slice());
        SecretBytes::new(out)
    }

    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != DUAL_ENC_PRIV_LEN {
            return Err(LithiumError::invalid_len(DUAL_ENC_PRIV_LEN, bytes.len()));
        }
        Ok(Self {
            x25519: SecByte32::from_slice(&bytes[..32])?,
            mlkem1024: SecByte64::from_slice(&bytes[32..])?,
        })
    }

    pub fn open(
        &self,
        ctx: &Context,
        aad: &[u8],
        sealed: &DualSealed,
    ) -> Result<(SecretBytes, DualEncryptionPublicKey)> {
        let mut bound_aad = sealed.reply_pub.to_wire();
        bound_aad.extend_from_slice(aad);
        let plaintext = open(
            ctx,
            self.x25519.expose_as_slice(),
            self.mlkem1024.expose_as_slice(),
            &bound_aad,
            &sealed.inner,
        )?;
        Ok((plaintext, sealed.reply_pub.clone()))
    }
}

#[derive(Clone, Debug)]
pub struct DualSealed {
    reply_pub: DualEncryptionPublicKey,
    inner: KyberBoxSealed,
}

impl DualSealed {
    pub fn reply_public(&self) -> &DualEncryptionPublicKey {
        &self.reply_pub
    }

    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = self.reply_pub.to_wire();
        out.extend_from_slice(&self.inner.to_wire());
        out
    }

    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < DUAL_ENC_PUB_LEN {
            return Err(LithiumError::invalid_len(DUAL_ENC_PUB_LEN, bytes.len()));
        }
        Ok(Self {
            reply_pub: DualEncryptionPublicKey::from_wire(&bytes[..DUAL_ENC_PUB_LEN])?,
            inner: KyberBoxSealed::from_wire(&bytes[DUAL_ENC_PUB_LEN..])?,
        })
    }
}
