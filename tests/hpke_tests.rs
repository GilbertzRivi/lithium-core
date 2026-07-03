// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::crypto::Context;
use lithium_core::hpke::{self, HpkeEnc, HpkePrivateKey, HpkePublicKey, HpkeSealed};
use lithium_core::public::{PubByte32, PublicBytes};
use lithium_core::secrets::{SecByte32, SecretBytes};

const CTX: &str = "test/hpke/v1";
const INFO: &[u8] = b"unit-info";
const AAD: &[u8] = b"unit-aad";

fn sb(data: &[u8]) -> SecretBytes {
    SecretBytes::from_slice(data)
}

fn ctx_of(s: &str) -> Context<'_> {
    let mut parts = s.split('/');
    let mut c = Context::base(parts.next().unwrap()).unwrap();
    for p in parts {
        c = c.add(p).unwrap();
    }
    c
}

fn kp(ctx: &str, ikm: &[u8]) -> (HpkePrivateKey, HpkePublicKey) {
    hpke::derive_keypair(&ctx_of(ctx), ikm).unwrap()
}

fn pub_raw(pk: &HpkePublicKey) -> (PubByte32, PublicBytes) {
    let w = pk.to_wire();
    (
        PubByte32::from_slice(&w[..32]).unwrap(),
        PublicBytes::from_slice(&w[32..]),
    )
}

fn priv_raw(sk: &HpkePrivateKey) -> (SecByte32, SecretBytes) {
    let w = sk.to_wire();
    let w = w.expose_as_slice();
    (SecByte32::from_slice(&w[..32]).unwrap(), sb(&w[32..]))
}

fn seal(pk: &HpkePublicKey, ctx: &str, info: &[u8], aad: &[u8], pt: &[u8]) -> HpkeSealed {
    let (x_pub, k_pub) = pub_raw(pk);
    hpke::seal_base(&ctx_of(ctx), &x_pub, &k_pub, info, aad, &sb(pt)).unwrap()
}

fn open(
    sk: &HpkePrivateKey,
    ctx: &str,
    info: &[u8],
    aad: &[u8],
    sealed: &HpkeSealed,
) -> lithium_core::Result<SecretBytes> {
    let (x_priv, k_priv) = priv_raw(sk);
    hpke::open_base(&ctx_of(ctx), &x_priv, &k_priv, info, aad, sealed)
}

fn enc_flip(enc: &HpkeEnc, idx: usize) -> HpkeEnc {
    let mut w = enc.to_wire();
    w[idx] ^= 0x01;
    HpkeEnc::from_wire(&w).unwrap()
}

// ---- roundtrip / happy path ----

#[test]
fn seal_open_roundtrip() {
    let (sk, pk) = kp(CTX, b"seed-a");
    let sealed = seal(&pk, CTX, INFO, AAD, b"hello hpke");
    let pt = open(&sk, CTX, INFO, AAD, &sealed).unwrap();
    assert_eq!(pt.expose_as_slice(), b"hello hpke");
}

#[test]
fn setup_export_sender_receiver_agree() {
    let (sk, pk) = kp(CTX, b"seed-b");
    let (enc, sent) =
        hpke::setup_sender_and_export(&ctx_of(CTX), &pk, INFO, b"exp-ctx", 32).unwrap();
    let recv =
        hpke::setup_receiver_and_export(&ctx_of(CTX), &sk, &enc, INFO, b"exp-ctx", 32).unwrap();
    assert_eq!(sent.expose_as_slice(), recv.expose_as_slice());
    assert_eq!(sent.len(), 32);
}

#[test]
fn derive_keypair_is_deterministic() {
    let (sk1, pk1) = kp(CTX, b"same-seed");
    let (sk2, pk2) = kp(CTX, b"same-seed");
    assert_eq!(pk1.to_wire(), pk2.to_wire());
    assert_eq!(
        sk1.to_wire().expose_as_slice(),
        sk2.to_wire().expose_as_slice()
    );
}

#[test]
fn derive_keypair_empty_ikm_is_ok_and_deterministic() {
    let (_, pk1) = kp(CTX, b"");
    let (_, pk2) = kp(CTX, b"");
    assert_eq!(pk1.to_wire(), pk2.to_wire());
}

// ---- domain separation ----

#[test]
fn derive_keypair_diff_ikm_diff_keys() {
    let (_, a) = kp(CTX, b"ikm-1");
    let (_, b) = kp(CTX, b"ikm-2");
    assert_ne!(a.to_wire(), b.to_wire());
}

#[test]
fn derive_keypair_diff_ctx_diff_keys() {
    let (_, a) = kp("ctx-1", b"same");
    let (_, b) = kp("ctx-2", b"same");
    assert_ne!(a.to_wire(), b.to_wire());
}

// ---- authenticated negatives: open must fail ----

#[test]
fn open_wrong_ctx_fails() {
    let (sk, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, INFO, AAD, b"m");
    assert!(open(&sk, "other-ctx", INFO, AAD, &sealed).is_err());
}

#[test]
fn open_wrong_info_fails() {
    let (sk, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, INFO, AAD, b"m");
    assert!(open(&sk, CTX, b"other-info", AAD, &sealed).is_err());
}

#[test]
fn open_wrong_aad_fails() {
    let (sk, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, INFO, AAD, b"m");
    assert!(open(&sk, CTX, INFO, b"other-aad", &sealed).is_err());
}

#[test]
fn open_aad_prefix_fails() {
    let (sk, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, INFO, b"aad-full", b"m");
    assert!(open(&sk, CTX, INFO, b"aad", &sealed).is_err());
}

#[test]
fn open_wrong_recipient_fails() {
    let (_, pk) = kp(CTX, b"recipient-a");
    let (sk_b, _) = kp(CTX, b"recipient-b");
    let sealed = seal(&pk, CTX, INFO, AAD, b"m");
    assert!(open(&sk_b, CTX, INFO, AAD, &sealed).is_err());
}

#[test]
fn open_tampered_ciphertext_fails() {
    let (sk, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, INFO, AAD, b"tamper-me");
    let mut ct = sealed.ciphertext.as_slice().to_vec();
    ct[0] ^= 0x01;
    let bad = HpkeSealed {
        enc: sealed.enc.clone(),
        ciphertext: PublicBytes::new(ct),
    };
    assert!(open(&sk, CTX, INFO, AAD, &bad).is_err());
}

#[test]
fn open_tampered_enc_xpub_fails() {
    let (sk, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, INFO, AAD, b"m");
    let bad = HpkeSealed {
        enc: enc_flip(&sealed.enc, 0),
        ciphertext: sealed.ciphertext.clone(),
    };
    assert!(open(&sk, CTX, INFO, AAD, &bad).is_err());
}

#[test]
fn open_tampered_enc_kemct_fails() {
    let (sk, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, INFO, AAD, b"m");
    let bad = HpkeSealed {
        enc: enc_flip(&sealed.enc, 40),
        ciphertext: sealed.ciphertext.clone(),
    };
    assert!(open(&sk, CTX, INFO, AAD, &bad).is_err());
}

#[test]
fn open_empty_ciphertext_fails() {
    let (sk, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, INFO, AAD, b"m");
    let bad = HpkeSealed {
        enc: sealed.enc.clone(),
        ciphertext: PublicBytes::new(vec![]),
    };
    assert!(open(&sk, CTX, INFO, AAD, &bad).is_err());
}

#[test]
fn open_truncated_kem_ct_fails() {
    let (sk, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, INFO, AAD, b"m");
    let mut w = sealed.enc.to_wire();
    w.truncate(w.len() - 100);
    let bad = HpkeSealed {
        enc: HpkeEnc::from_wire(&w).unwrap(),
        ciphertext: sealed.ciphertext.clone(),
    };
    assert!(open(&sk, CTX, INFO, AAD, &bad).is_err());
}

#[test]
fn seal_is_randomized() {
    let (_, pk) = kp(CTX, b"s");
    let a = seal(&pk, CTX, INFO, AAD, b"same-plaintext");
    let b = seal(&pk, CTX, INFO, AAD, b"same-plaintext");
    assert_ne!(a.enc.to_wire(), b.enc.to_wire());
    assert_ne!(a.ciphertext.as_slice(), b.ciphertext.as_slice());
}

// ---- unauthenticated export: mismatch => different secret, not an error ----

#[test]
fn export_wrong_ctx_disagrees() {
    let (sk, pk) = kp(CTX, b"s");
    let (enc, sent) = hpke::setup_sender_and_export(&ctx_of(CTX), &pk, INFO, b"e", 32).unwrap();
    let recv =
        hpke::setup_receiver_and_export(&ctx_of("bad-ctx"), &sk, &enc, INFO, b"e", 32).unwrap();
    assert_ne!(sent.expose_as_slice(), recv.expose_as_slice());
}

#[test]
fn export_wrong_info_disagrees() {
    let (sk, pk) = kp(CTX, b"s");
    let (enc, sent) = hpke::setup_sender_and_export(&ctx_of(CTX), &pk, INFO, b"e", 32).unwrap();
    let recv =
        hpke::setup_receiver_and_export(&ctx_of(CTX), &sk, &enc, b"bad-info", b"e", 32).unwrap();
    assert_ne!(sent.expose_as_slice(), recv.expose_as_slice());
}

#[test]
fn export_wrong_exporter_context_disagrees() {
    let (sk, pk) = kp(CTX, b"s");
    let (enc, sent) = hpke::setup_sender_and_export(&ctx_of(CTX), &pk, INFO, b"ctx-a", 32).unwrap();
    let recv =
        hpke::setup_receiver_and_export(&ctx_of(CTX), &sk, &enc, INFO, b"ctx-b", 32).unwrap();
    assert_ne!(sent.expose_as_slice(), recv.expose_as_slice());
}

#[test]
fn export_mismatched_keys_disagree() {
    let (_, pk) = kp(CTX, b"key-a");
    let (sk_b, _) = kp(CTX, b"key-b");
    let (enc, sent) = hpke::setup_sender_and_export(&ctx_of(CTX), &pk, INFO, b"e", 32).unwrap();
    let recv = hpke::setup_receiver_and_export(&ctx_of(CTX), &sk_b, &enc, INFO, b"e", 32).unwrap();
    assert_ne!(sent.expose_as_slice(), recv.expose_as_slice());
}

#[test]
fn export_len_zero_is_empty() {
    let (_, pk) = kp(CTX, b"s");
    let (_, sent) = hpke::setup_sender_and_export(&ctx_of(CTX), &pk, INFO, b"e", 0).unwrap();
    assert!(sent.expose_as_slice().is_empty());
}

#[test]
fn export_len_is_honored() {
    let (_, pk) = kp(CTX, b"s");
    for len in [1usize, 16, 32, 64, 255, 1000] {
        let (_, sent) = hpke::setup_sender_and_export(&ctx_of(CTX), &pk, INFO, b"e", len).unwrap();
        assert_eq!(sent.len(), len);
    }
}

#[test]
fn export_hkdf_max_len_ok_over_max_errors() {
    let (_, pk) = kp(CTX, b"s");
    // HKDF-SHA256 caps output at 255 * 32 = 8160 bytes.
    assert!(hpke::setup_sender_and_export(&ctx_of(CTX), &pk, INFO, b"e", 8160).is_ok());
    assert!(hpke::setup_sender_and_export(&ctx_of(CTX), &pk, INFO, b"e", 8161).is_err());
}

#[test]
fn export_shorter_len_is_prefix_of_longer() {
    let (sk, pk) = kp(CTX, b"s");
    let (enc, short) = hpke::setup_sender_and_export(&ctx_of(CTX), &pk, INFO, b"e", 32).unwrap();
    let long = hpke::setup_receiver_and_export(&ctx_of(CTX), &sk, &enc, INFO, b"e", 64).unwrap();
    assert_eq!(&long.expose_as_slice()[..32], short.expose_as_slice());
}

// ---- annoying / edge inputs ----

#[test]
fn seal_open_empty_plaintext() {
    let (sk, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, INFO, AAD, b"");
    let pt = open(&sk, CTX, INFO, AAD, &sealed).unwrap();
    assert!(pt.expose_as_slice().is_empty());
}

#[test]
fn seal_open_empty_info_and_aad() {
    let (sk, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, b"", b"", b"payload");
    let pt = open(&sk, CTX, b"", b"", &sealed).unwrap();
    assert_eq!(pt.expose_as_slice(), b"payload");
}

#[test]
fn seal_open_large_plaintext() {
    let (sk, pk) = kp(CTX, b"s");
    let big = vec![0xABu8; 200_000];
    let sealed = seal(&pk, CTX, INFO, AAD, &big);
    let pt = open(&sk, CTX, INFO, AAD, &sealed).unwrap();
    assert_eq!(pt.expose_as_slice(), big.as_slice());
}

#[test]
fn seal_open_binary_info_and_aad() {
    let (sk, pk) = kp(CTX, b"s");
    let info: Vec<u8> = (0u16..=255).map(|b| b as u8).collect();
    let aad = vec![0x00, 0xFF, 0x00, 0xFF];
    let sealed = seal(&pk, CTX, &info, &aad, b"bin");
    assert_eq!(
        open(&sk, CTX, &info, &aad, &sealed)
            .unwrap()
            .expose_as_slice(),
        b"bin"
    );
}

#[test]
fn info_with_null_bytes_still_separates() {
    // schedule labels join with a NUL; a NUL inside `info` must not let two
    // different infos collide.
    let (sk, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, b"a\0b", AAD, b"m");
    assert!(open(&sk, CTX, b"a\0c", AAD, &sealed).is_err());
    assert_eq!(
        open(&sk, CTX, b"a\0b", AAD, &sealed)
            .unwrap()
            .expose_as_slice(),
        b"m"
    );
}

// ---- wire format: to_wire / from_wire ----

#[test]
fn enc_wire_roundtrip() {
    let (_, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, INFO, AAD, b"m");
    let w = sealed.enc.to_wire();
    let back = HpkeEnc::from_wire(&w).unwrap();
    assert_eq!(back.to_wire(), w);
}

#[test]
fn enc_from_wire_rejects_len_at_or_below_xpub() {
    assert!(HpkeEnc::from_wire(&[]).is_err());
    assert!(HpkeEnc::from_wire(&[0u8; 32]).is_err());
    // 33 bytes is the minimum accepted (1-byte kem_ct); parsing succeeds even
    // though decap will later reject it.
    assert!(HpkeEnc::from_wire(&[0u8; 33]).is_ok());
}

#[test]
fn pubkey_wire_roundtrip() {
    let (_, pk) = kp(CTX, b"s");
    let w = pk.to_wire();
    assert_eq!(w.len(), 32 + 1568);
    let back = HpkePublicKey::from_wire(&w).unwrap();
    assert_eq!(back.to_wire(), w);
}

#[test]
fn pubkey_from_wire_wrong_len_err() {
    assert!(HpkePublicKey::from_wire(&[]).is_err());
    assert!(HpkePublicKey::from_wire(&[0u8; 32 + 1568 - 1]).is_err());
    assert!(HpkePublicKey::from_wire(&[0u8; 32 + 1568 + 1]).is_err());
}

#[test]
fn privkey_wire_roundtrip() {
    let (sk, _) = kp(CTX, b"s");
    let w = sk.to_wire();
    assert_eq!(w.len(), 32 + 64);
    let back = HpkePrivateKey::from_wire(w.expose_as_slice()).unwrap();
    assert_eq!(back.to_wire().expose_as_slice(), w.expose_as_slice());
}

#[test]
fn privkey_from_wire_wrong_len_err() {
    assert!(HpkePrivateKey::from_wire(&[]).is_err());
    assert!(HpkePrivateKey::from_wire(&[0u8; 32 + 64 - 1]).is_err());
    assert!(HpkePrivateKey::from_wire(&[0u8; 32 + 64 + 1]).is_err());
}

#[test]
fn full_wire_interop_seal_open() {
    // Everything crosses a serialization boundary, as a real peer would.
    let (sk, pk) = kp(CTX, b"s");

    let pk = HpkePublicKey::from_wire(&pk.to_wire()).unwrap();
    let (x_pub, k_pub) = pub_raw(&pk);
    let sealed = hpke::seal_base(&ctx_of(CTX), &x_pub, &k_pub, INFO, AAD, &sb(b"wire")).unwrap();

    let enc = HpkeEnc::from_wire(&sealed.enc.to_wire()).unwrap();
    let ct = PublicBytes::new(sealed.ciphertext.as_slice().to_vec());
    let sealed = HpkeSealed {
        enc,
        ciphertext: ct,
    };

    let sk = HpkePrivateKey::from_wire(sk.to_wire().expose_as_slice()).unwrap();
    let pt = open(&sk, CTX, INFO, AAD, &sealed).unwrap();
    assert_eq!(pt.expose_as_slice(), b"wire");
}
