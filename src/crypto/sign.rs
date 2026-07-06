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
    signature::{SignatureEncoding, Verifier as MlDsaVerifier},
};

const MLDSA87_SIG_LEN: usize = 4627;

pub(crate) fn sign_message<S: AsRef<[u8]>>(
    message: &[u8],
    priv_ed_seed: S,
    ctx: &Context,
) -> Result<Vec<u8>> {
    let seed = SecByte32::from_slice(priv_ed_seed.as_ref())?;
    let signing = Ed25519SigningKey::from_bytes(seed.expose_as_array());
    let sig: Ed25519Signature = signing.sign(ctx.bind_aad(message).as_slice());

    Ok(sig.to_bytes().to_vec())
}

pub(crate) fn verify_signature(
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

pub(crate) fn sign_message_dili<S: AsRef<[u8]>>(
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

pub(crate) fn verify_signature_dili(
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

const ED25519_PUB_LEN: usize = 32;
const MLDSA87_PUB_LEN: usize = 2592;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DualVerifyingKey {
    ed25519: PubByte32,
    mldsa87: PublicBytes,
}

impl DualVerifyingKey {
    pub(crate) fn new(ed25519: PubByte32, mldsa87: PublicBytes) -> Self {
        Self { ed25519, mldsa87 }
    }

    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ED25519_PUB_LEN + self.mldsa87.len());
        out.extend_from_slice(self.ed25519.as_slice());
        out.extend_from_slice(self.mldsa87.as_slice());
        out
    }

    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let expected = ED25519_PUB_LEN + MLDSA87_PUB_LEN;
        if bytes.len() != expected {
            return Err(LithiumError::invalid_len(expected, bytes.len()));
        }
        Ok(Self {
            ed25519: PubByte32::from_slice(&bytes[..ED25519_PUB_LEN])?,
            mldsa87: PublicBytes::from_slice(&bytes[ED25519_PUB_LEN..]),
        })
    }

    pub fn verify(&self, message: &[u8], sig: &DoubleSig, ctx: &Context) -> bool {
        verify_double(message, sig, &self.ed25519, &self.mldsa87, ctx)
    }
}

pub(crate) fn sign_double<E: AsRef<[u8]>, D: AsRef<[u8]>>(
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

pub(crate) fn verify_double(
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

#[cfg(feature = "raw")]
pub mod raw {
    use super::*;

    pub fn sign_message<S: AsRef<[u8]>>(
        message: &[u8],
        priv_ed_seed: S,
        ctx: &Context,
    ) -> Result<Vec<u8>> {
        super::sign_message(message, priv_ed_seed, ctx)
    }

    pub fn verify_signature(
        message: &[u8],
        signature: &[u8],
        pub_key: &PubByte32,
        ctx: &Context,
    ) -> bool {
        super::verify_signature(message, signature, pub_key, ctx)
    }

    pub fn sign_message_dili<S: AsRef<[u8]>>(
        message: &[u8],
        dili_sk_bytes: S,
        ctx: &Context,
    ) -> Result<Vec<u8>> {
        super::sign_message_dili(message, dili_sk_bytes, ctx)
    }

    pub fn verify_signature_dili(
        message: &[u8],
        signature: &[u8],
        dili_pk_bytes: &PublicBytes,
        ctx: &Context,
    ) -> bool {
        super::verify_signature_dili(message, signature, dili_pk_bytes, ctx)
    }

    pub fn sign_double<E: AsRef<[u8]>, D: AsRef<[u8]>>(
        message: &[u8],
        ed_seed: E,
        dili_sk: D,
        ctx: &Context,
    ) -> Result<DoubleSig> {
        super::sign_double(message, ed_seed, dili_sk, ctx)
    }

    pub fn verify_double(
        message: &[u8],
        sig: &DoubleSig,
        ed_pub: &PubByte32,
        dili_pub: &PublicBytes,
        ctx: &Context,
    ) -> bool {
        super::verify_double(message, sig, ed_pub, dili_pub, ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorKind;
    use crate::crypto::keys;
    use std::collections::HashMap;

    fn sctx() -> Context<'static> {
        Context::base("test").unwrap().add("sign").unwrap()
    }

    fn sign_msg<S: AsRef<[u8]>>(msg: &[u8], seed: S) -> Result<Vec<u8>> {
        sign_message(msg, seed, &sctx())
    }

    fn verify_sig(msg: &[u8], sig: &[u8], pk: &PubByte32) -> bool {
        verify_signature(msg, sig, pk, &sctx())
    }

    fn sign_dili<S: AsRef<[u8]>>(msg: &[u8], sk: S) -> Result<Vec<u8>> {
        sign_message_dili(msg, sk, &sctx())
    }

    fn verify_dili(msg: &[u8], sig: &[u8], pk: &PublicBytes) -> bool {
        verify_signature_dili(msg, sig, pk, &sctx())
    }

    fn ctx_of(s: &str) -> Context<'_> {
        let mut parts = s.split('/');
        let mut c = Context::base(parts.next().unwrap()).unwrap();
        for p in parts {
            c = c.add(p).unwrap();
        }
        c
    }

    #[test]
    fn sign_ed25519_roundtrip() {
        let (seed, pk) = keys::ephemeral_ed25519_keypair().unwrap();
        let msg = b"test message to sign";

        let sig = sign_msg(msg, seed.expose_as_slice()).unwrap();
        assert!(verify_sig(msg, sig.as_slice(), &pk));
    }

    #[test]
    fn sign_ed25519_wrong_message_fails() {
        let (seed, pk) = keys::ephemeral_ed25519_keypair().unwrap();
        let sig = sign_msg(b"original", seed.expose_as_slice()).unwrap();
        assert!(!verify_sig(b"tampered", sig.as_slice(), &pk));
    }

    #[test]
    fn sign_ed25519_wrong_key_fails() {
        let (seed, _pk) = keys::ephemeral_ed25519_keypair().unwrap();
        let (_, wrong_pk) = keys::ephemeral_ed25519_keypair().unwrap();
        let msg = b"test";

        let sig = sign_msg(msg, seed.expose_as_slice()).unwrap();
        assert!(!verify_sig(msg, sig.as_slice(), &wrong_pk));
    }

    #[test]
    fn sign_ed25519_short_signature_fails() {
        let (_, pk) = keys::ephemeral_ed25519_keypair().unwrap();
        assert!(!verify_sig(b"msg", &[0u8; 32], &pk));
    }

    #[test]
    fn sign_ed25519_signature_is_64_bytes() {
        let (seed, _) = keys::ephemeral_ed25519_keypair().unwrap();
        let sig = sign_msg(b"data", seed.expose_as_slice()).unwrap();
        assert_eq!(sig.as_slice().len(), 64);
    }

    #[test]
    fn sign_ed25519_different_messages_different_sigs() {
        let (seed, _) = keys::ephemeral_ed25519_keypair().unwrap();
        let sig1 = sign_msg(b"message-one", seed.expose_as_slice()).unwrap();
        let sig2 = sign_msg(b"message-two", seed.expose_as_slice()).unwrap();
        assert_ne!(sig1.as_slice(), sig2.as_slice());
    }

    #[test]
    fn sign_ed25519_empty_message_roundtrip() {
        let (seed, pk) = keys::ephemeral_ed25519_keypair().unwrap();
        let sig = sign_msg(b"", seed.expose_as_slice()).unwrap();
        assert!(verify_sig(b"", sig.as_slice(), &pk));
        assert!(!verify_sig(b"x", sig.as_slice(), &pk));
    }

    #[test]
    fn sign_ed25519_deterministic() {
        let (seed, _pk) = keys::ephemeral_ed25519_keypair().unwrap();
        let msg = b"deterministic";
        let sig1 = sign_msg(msg, seed.expose_as_slice()).unwrap();
        let sig2 = sign_msg(msg, seed.expose_as_slice()).unwrap();
        assert_eq!(sig1.as_slice(), sig2.as_slice());
    }

    #[test]
    fn sign_ed25519_tampered_sig_first_byte_fails() {
        let (seed, pk) = keys::ephemeral_ed25519_keypair().unwrap();
        let msg = b"message";
        let mut sig = sign_msg(msg, seed.expose_as_slice()).unwrap();
        sig[0] ^= 0x01;
        assert!(!verify_sig(msg, &sig, &pk));
    }

    #[test]
    fn sign_ed25519_tampered_sig_last_byte_fails() {
        let (seed, pk) = keys::ephemeral_ed25519_keypair().unwrap();
        let msg = b"message";
        let mut sig = sign_msg(msg, seed.expose_as_slice()).unwrap();
        let last = sig.len() - 1;
        sig[last] ^= 0x01;
        assert!(!verify_sig(msg, &sig, &pk));
    }

    #[test]
    fn sign_ed25519_various_message_sizes() {
        let (seed, pk) = keys::ephemeral_ed25519_keypair().unwrap();
        for &size in &[0usize, 1, 31, 32, 33, 100, 1024] {
            let msg = vec![0x5Au8; size];
            let sig = sign_msg(&msg, seed.expose_as_slice()).unwrap();
            assert!(verify_sig(&msg, sig.as_slice(), &pk), "size={size}");
        }
    }

    #[test]
    fn sign_dili_seed_keypair_consistency() {
        let seed = SecByte32::new([7u8; 32]);
        let pk = keys::mldsa87_pub_from_seed(&seed);
        let msg = b"seed-consistency";
        let sig = sign_dili(msg, seed.expose_as_slice()).unwrap();
        assert!(verify_dili(msg, sig.as_slice(), &pk));
    }

    #[test]
    fn sign_dili_roundtrip() {
        let (sk, pk) = keys::ephemeral_dilithium_mldsa87_keypair().unwrap();
        let msg = b"dilithium test message";

        let sig = sign_dili(msg, sk.expose_as_slice()).unwrap();
        assert!(verify_dili(msg, sig.as_slice(), &pk));
    }

    #[test]
    fn sign_dili_wrong_message_fails() {
        let (sk, pk) = keys::ephemeral_dilithium_mldsa87_keypair().unwrap();
        let sig = sign_dili(b"original", sk.expose_as_slice()).unwrap();
        assert!(!verify_dili(b"tampered", sig.as_slice(), &pk));
    }

    #[test]
    fn sign_dili_wrong_key_fails() {
        let (sk, _pk) = keys::ephemeral_dilithium_mldsa87_keypair().unwrap();
        let (_, wrong_pk) = keys::ephemeral_dilithium_mldsa87_keypair().unwrap();
        let msg = b"test";

        let sig = sign_dili(msg, sk.expose_as_slice()).unwrap();
        assert!(!verify_dili(msg, sig.as_slice(), &wrong_pk));
    }

    #[test]
    fn sign_dili_garbage_signature_fails() {
        let (_, pk) = keys::ephemeral_dilithium_mldsa87_keypair().unwrap();
        assert!(!verify_dili(b"msg", &[0u8; 32], &pk));
    }

    #[test]
    fn sign_dili_empty_message_roundtrip() {
        let (sk, pk) = keys::ephemeral_dilithium_mldsa87_keypair().unwrap();
        let sig = sign_dili(b"", sk.expose_as_slice()).unwrap();
        assert!(verify_dili(b"", sig.as_slice(), &pk));
        assert!(!verify_dili(b"x", sig.as_slice(), &pk));
    }

    #[test]
    fn sign_dili_tampered_sig_last_byte_fails() {
        let (sk, pk) = keys::ephemeral_dilithium_mldsa87_keypair().unwrap();
        let msg = b"dili-test";
        let mut sig = sign_dili(msg, sk.expose_as_slice()).unwrap();
        let last = sig.len() - 1;
        sig[last] ^= 0xFF;
        assert!(!verify_dili(msg, &sig, &pk));
    }

    #[test]
    fn sign_dili_various_message_sizes() {
        let (sk, pk) = keys::ephemeral_dilithium_mldsa87_keypair().unwrap();
        for &size in &[0usize, 1, 31, 32, 64, 256] {
            let msg = vec![0xA5u8; size];
            let sig = sign_dili(&msg, sk.expose_as_slice()).unwrap();
            assert!(verify_dili(&msg, sig.as_slice(), &pk), "size={size}");
        }
    }

    #[test]
    fn cross_ed25519_sign_verify_cross_keypair_fails() {
        let (seed_a, _pk_a) = keys::ephemeral_ed25519_keypair().unwrap();
        let (_, pk_b) = keys::ephemeral_ed25519_keypair().unwrap();
        let msg = b"same message, different key";
        let sig = sign_msg(msg, seed_a.expose_as_slice()).unwrap();
        assert!(!verify_sig(msg, sig.as_slice(), &pk_b));
    }

    #[test]
    fn cross_dili_sign_verify_cross_keypair_fails() {
        let (sk_a, _) = keys::ephemeral_dilithium_mldsa87_keypair().unwrap();
        let (_, pk_b) = keys::ephemeral_dilithium_mldsa87_keypair().unwrap();
        let msg = b"cross-key dilithium";
        let sig = sign_dili(msg, sk_a.expose_as_slice()).unwrap();
        assert!(!verify_dili(msg, sig.as_slice(), &pk_b));
    }

    #[test]
    fn cross_ed25519_and_dili_sigs_are_not_interchangeable() {
        let (ed_seed, ed_pk) = keys::ephemeral_ed25519_keypair().unwrap();
        let (dili_sk, dili_pk) = keys::ephemeral_dilithium_mldsa87_keypair().unwrap();
        let msg = b"cross-scheme";

        let ed_sig = sign_msg(msg, ed_seed.expose_as_slice()).unwrap();
        let dili_sig = sign_dili(msg, dili_sk.expose_as_slice()).unwrap();

        assert!(!verify_dili(msg, ed_sig.as_slice(), &dili_pk));
        assert!(!verify_sig(msg, &dili_sig.as_slice()[..64], &ed_pk));
    }

    #[test]
    fn mldsa87_signature_verifies_pinned_vector() {
        let vectors: HashMap<&str, &str> = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/testdata/mldsa87_verify_golden_v1.txt"
        ))
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();

        let dili_pub = PublicBytes::from_hex(vectors["DILI_PUB"]).unwrap();
        let dili_sig = PublicBytes::from_hex(vectors["DILI_SIG"]).unwrap();
        let msg = b"golden-mldsa87-v1";

        assert_eq!(dili_pub.as_slice().len(), 2592);
        assert_eq!(dili_sig.as_slice().len(), 4627);

        let ctx = ctx_of("golden/mldsa/v1");
        assert!(verify_signature_dili(
            msg,
            dili_sig.as_slice(),
            &dili_pub,
            &ctx
        ));
        assert!(!verify_signature_dili(
            b"tampered",
            dili_sig.as_slice(),
            &dili_pub,
            &ctx
        ));
    }

    fn dctx() -> Context<'static> {
        Context::base("test").unwrap().add("double-sig").unwrap()
    }

    fn verify_ds(msg: &[u8], sig: &DoubleSig, ed_pub: &PubByte32, dili_pub: &PublicBytes) -> bool {
        verify_double(msg, sig, ed_pub, dili_pub, &dctx())
    }

    struct DoubleKeys {
        ed_seed: SecByte32,
        ed_pub: PubByte32,
        dili_sk: SecByte32,
        dili_pub: PublicBytes,
    }

    fn fresh_keys() -> DoubleKeys {
        let (ed_seed, ed_pub) = keys::ephemeral_ed25519_keypair().unwrap();
        let (dili_sk, dili_pub) = keys::ephemeral_dilithium_mldsa87_keypair().unwrap();
        DoubleKeys {
            ed_seed,
            ed_pub,
            dili_sk,
            dili_pub,
        }
    }

    fn ds_sign(k: &DoubleKeys, msg: &[u8]) -> DoubleSig {
        sign_double(
            msg,
            k.ed_seed.expose_as_slice(),
            k.dili_sk.expose_as_slice(),
            &dctx(),
        )
        .unwrap()
    }

    #[test]
    fn double_sig_roundtrips() {
        let k = fresh_keys();
        let msg = b"double-signed payload";
        let sig = ds_sign(&k, msg);
        assert!(verify_ds(msg, &sig, &k.ed_pub, &k.dili_pub));
    }

    #[test]
    fn double_sig_wrong_message_fails() {
        let k = fresh_keys();
        let sig = ds_sign(&k, b"original");
        assert!(!verify_ds(b"tampered", &sig, &k.ed_pub, &k.dili_pub));
    }

    #[test]
    fn double_sig_both_branches_are_required() {
        let k = fresh_keys();
        let sig_a = ds_sign(&k, b"message-a");
        let sig_b = ds_sign(&k, b"message-b");

        let mut bytes = sig_a.to_bytes();
        let b_bytes = sig_b.to_bytes();
        bytes[64..].copy_from_slice(&b_bytes[64..]);
        let mixed = DoubleSig::from_bytes(&bytes).unwrap();

        assert!(!verify_ds(b"message-a", &mixed, &k.ed_pub, &k.dili_pub));
        assert!(!verify_ds(b"message-b", &mixed, &k.ed_pub, &k.dili_pub));
    }

    #[test]
    fn double_sig_tamper_in_either_region_fails() {
        let k = fresh_keys();
        let msg = b"payload";
        let sig = ds_sign(&k, msg);

        let mut ed_tampered = sig.to_bytes();
        ed_tampered[0] ^= 0x01;
        assert!(!verify_ds(
            msg,
            &DoubleSig::from_bytes(&ed_tampered).unwrap(),
            &k.ed_pub,
            &k.dili_pub
        ));

        let mut dili_tampered = sig.to_bytes();
        let last = dili_tampered.len() - 1;
        dili_tampered[last] ^= 0x01;
        assert!(!verify_ds(
            msg,
            &DoubleSig::from_bytes(&dili_tampered).unwrap(),
            &k.ed_pub,
            &k.dili_pub
        ));
    }

    #[test]
    fn double_sig_wrong_public_keys_fail() {
        let k = fresh_keys();
        let other = fresh_keys();
        let msg = b"payload";
        let sig = ds_sign(&k, msg);

        assert!(!verify_ds(msg, &sig, &other.ed_pub, &k.dili_pub));
        assert!(!verify_ds(msg, &sig, &k.ed_pub, &other.dili_pub));
    }

    #[test]
    fn double_sig_bytes_roundtrip() {
        let k = fresh_keys();
        let sig = ds_sign(&k, b"payload");
        let decoded = DoubleSig::from_bytes(&sig.to_bytes()).unwrap();
        assert_eq!(sig, decoded);
    }

    #[test]
    fn double_sig_hex_roundtrip() {
        let k = fresh_keys();
        let msg = b"payload";
        let sig = ds_sign(&k, msg);
        let decoded = DoubleSig::from_hex(&sig.to_hex()).unwrap();
        assert_eq!(sig, decoded);
        assert!(verify_ds(msg, &decoded, &k.ed_pub, &k.dili_pub));
    }

    #[test]
    fn double_sig_from_bytes_rejects_too_short() {
        match DoubleSig::from_bytes(&[0u8; 64]) {
            Err(e) => assert!(matches!(e.kind, ErrorKind::InvalidLength { .. })),
            Ok(_) => panic!("64 bytes has no dilithium branch and must be rejected"),
        }
    }

    #[test]
    fn double_sig_from_hex_enforces_lowercase_no_prefix() {
        let k = fresh_keys();
        let hexed = ds_sign(&k, b"payload").to_hex();
        assert!(DoubleSig::from_hex(&hexed.to_uppercase()).is_err());
        assert!(DoubleSig::from_hex(&format!("0x{hexed}")).is_err());
    }

    #[test]
    fn double_sig_from_bytes_length_boundaries() {
        for bad in [
            0usize,
            1,
            63,
            64,
            ED25519_SIG_LEN + 1,
            ED25519_SIG_LEN + MLDSA87_SIG_LEN - 1,
            ED25519_SIG_LEN + MLDSA87_SIG_LEN + 1,
        ] {
            assert!(
                matches!(
                    DoubleSig::from_bytes(&vec![0u8; bad]).unwrap_err().kind,
                    ErrorKind::InvalidLength { .. }
                ),
                "{bad} bytes is not the exact DoubleSig length"
            );
        }
        assert!(
            DoubleSig::from_bytes(&vec![0u8; ED25519_SIG_LEN + MLDSA87_SIG_LEN]).is_ok(),
            "exactly ed25519 + ml-dsa-87 signature length is the only valid length"
        );
    }

    #[test]
    fn double_sig_from_bytes_roundtrips_exact_length() {
        let bytes: Vec<u8> = (0..ED25519_SIG_LEN + MLDSA87_SIG_LEN)
            .map(|i| (i as u8).wrapping_mul(31))
            .collect();
        let sig = DoubleSig::from_bytes(&bytes).unwrap();
        assert_eq!(sig.to_bytes(), bytes);
    }

    #[test]
    fn double_sig_verify_truncated_signature_is_rejected() {
        let k = fresh_keys();
        let msg = b"payload";
        let full = ds_sign(&k, msg).to_bytes();
        for cut in [1usize, 100, 2000, full.len() - (ED25519_SIG_LEN + 1)] {
            assert!(
                matches!(
                    DoubleSig::from_bytes(&full[..full.len() - cut])
                        .unwrap_err()
                        .kind,
                    ErrorKind::InvalidLength { .. }
                ),
                "a truncated signature must be rejected on parse (cut {cut})"
            );
        }
    }

    #[test]
    fn double_sig_verify_oversized_signature_is_rejected() {
        let k = fresh_keys();
        let msg = b"payload";
        for extra in [1usize, 100, MLDSA87_SIG_LEN] {
            let mut bytes = ds_sign(&k, msg).to_bytes();
            bytes.resize(bytes.len() + extra, 0xAB);
            assert!(
                matches!(
                    DoubleSig::from_bytes(&bytes).unwrap_err().kind,
                    ErrorKind::InvalidLength { .. }
                ),
                "an oversized signature must be rejected on parse (extra {extra})"
            );
        }
    }

    #[test]
    fn double_sig_verify_random_full_length_is_false() {
        let k = fresh_keys();
        let bytes: Vec<u8> = (0..ED25519_SIG_LEN + MLDSA87_SIG_LEN)
            .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
            .collect();
        let sig = DoubleSig::from_bytes(&bytes).unwrap();
        assert!(!verify_ds(b"payload", &sig, &k.ed_pub, &k.dili_pub));
    }

    #[test]
    fn double_sig_verify_valid_ed_garbage_dili_is_false() {
        let k = fresh_keys();
        let msg = b"payload";
        let mut bytes = ds_sign(&k, msg).to_bytes();
        for b in bytes[ED25519_SIG_LEN..].iter_mut() {
            *b ^= 0xFF;
        }
        let sig = DoubleSig::from_bytes(&bytes).unwrap();
        assert!(
            !verify_ds(msg, &sig, &k.ed_pub, &k.dili_pub),
            "a valid ed branch must not rescue a broken dili branch"
        );
    }

    #[test]
    fn double_sig_verify_off_by_one_dili_length_no_panic() {
        let k = fresh_keys();
        let msg = b"payload";
        let valid = ds_sign(&k, msg).to_bytes();
        for len in [
            ED25519_SIG_LEN + MLDSA87_SIG_LEN - 1,
            ED25519_SIG_LEN + MLDSA87_SIG_LEN + 1,
        ] {
            let mut bytes = valid.clone();
            bytes.resize(len, 0x00);
            assert!(
                matches!(
                    DoubleSig::from_bytes(&bytes).unwrap_err().kind,
                    ErrorKind::InvalidLength { .. }
                ),
                "an off-by-one length must be rejected on parse (len {len})"
            );
        }
    }
}
