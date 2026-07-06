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
    let mut seed = ikm.to_vec();
    if seed.len() < 32 {
        seed.resize(32, 0);
    }
    hpke::derive_keypair_from_high_entropy_ikm(&ctx_of(ctx), &SecretBytes::from_slice(&seed))
        .unwrap()
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

fn reseal(enc: &HpkeEnc, ct: &[u8]) -> HpkeSealed {
    let ew = enc.to_wire();
    let mut w = Vec::with_capacity(4 + ew.len() + ct.len());
    w.extend_from_slice(&(ew.len() as u32).to_be_bytes());
    w.extend_from_slice(&ew);
    w.extend_from_slice(ct);
    HpkeSealed::from_wire(&w).unwrap()
}

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
fn derive_keypair_short_ikm_is_rejected() {
    assert!(
        hpke::derive_keypair_from_high_entropy_ikm(&ctx_of(CTX), &sb(&[0u8; 31])).is_err(),
        "sub-32-byte ikm must be rejected"
    );
    assert!(
        hpke::derive_keypair_from_high_entropy_ikm(&ctx_of(CTX), &sb(&[0u8; 32])).is_ok(),
        "32-byte ikm must be accepted"
    );
}

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
    let mut ct = sealed.ciphertext().as_slice().to_vec();
    ct[0] ^= 0x01;
    let bad = reseal(sealed.enc(), &ct);
    assert!(open(&sk, CTX, INFO, AAD, &bad).is_err());
}

#[test]
fn open_tampered_enc_xpub_fails() {
    let (sk, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, INFO, AAD, b"m");
    let bad = reseal(&enc_flip(sealed.enc(), 0), sealed.ciphertext().as_slice());
    assert!(open(&sk, CTX, INFO, AAD, &bad).is_err());
}

#[test]
fn open_tampered_enc_kemct_fails() {
    let (sk, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, INFO, AAD, b"m");
    let bad = reseal(&enc_flip(sealed.enc(), 40), sealed.ciphertext().as_slice());
    assert!(open(&sk, CTX, INFO, AAD, &bad).is_err());
}

#[test]
fn open_empty_ciphertext_fails() {
    let (sk, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, INFO, AAD, b"m");
    let bad = reseal(sealed.enc(), &[]);
    assert!(open(&sk, CTX, INFO, AAD, &bad).is_err());
}

#[test]
fn truncated_enc_is_rejected_on_parse() {
    let (_sk, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, INFO, AAD, b"m");
    let mut w = sealed.enc().to_wire();
    w.truncate(w.len() - 100);
    assert!(
        HpkeEnc::from_wire(&w).is_err(),
        "a truncated enc must be rejected on parse"
    );
}

#[test]
fn sealed_wire_roundtrips() {
    let (_sk, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, INFO, AAD, b"roundtrip");
    let wire = sealed.to_wire();
    let back = HpkeSealed::from_wire(&wire).unwrap();
    assert_eq!(back.to_wire(), wire);
    assert_eq!(back.enc().to_wire(), sealed.enc().to_wire());
    assert_eq!(back.ciphertext().as_slice(), sealed.ciphertext().as_slice());
}

#[test]
fn seal_is_randomized() {
    let (_, pk) = kp(CTX, b"s");
    let a = seal(&pk, CTX, INFO, AAD, b"same-plaintext");
    let b = seal(&pk, CTX, INFO, AAD, b"same-plaintext");
    assert_ne!(a.enc().to_wire(), b.enc().to_wire());
    assert_ne!(a.ciphertext().as_slice(), b.ciphertext().as_slice());
}

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

#[test]
fn enc_wire_roundtrip() {
    let (_, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, INFO, AAD, b"m");
    let w = sealed.enc().to_wire();
    let back = HpkeEnc::from_wire(&w).unwrap();
    assert_eq!(back.to_wire(), w);
}

#[test]
fn enc_from_wire_requires_exact_len() {
    let exact = 32 + 1568 + 2;
    assert!(HpkeEnc::from_wire(&[]).is_err());
    assert!(HpkeEnc::from_wire(&[0u8; 32]).is_err());
    assert!(HpkeEnc::from_wire(&vec![0u8; exact - 1]).is_err());
    assert!(HpkeEnc::from_wire(&vec![0u8; exact + 1]).is_err());
    assert!(HpkeEnc::from_wire(&vec![0u8; exact]).is_ok());
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

    let sealed = HpkeSealed::from_wire(&sealed.to_wire()).unwrap();

    let sk = HpkePrivateKey::from_wire(sk.to_wire().expose_as_slice()).unwrap();
    let pt = open(&sk, CTX, INFO, AAD, &sealed).unwrap();
    assert_eq!(pt.expose_as_slice(), b"wire");
}

#[test]
fn open_prefix_like_ctx_fails() {
    let (sk, pk) = kp("app", b"s");
    let sealed = seal(&pk, "app", INFO, AAD, b"m");

    assert!(open(&sk, "app", INFO, AAD, &sealed).is_ok());
    assert!(
        open(&sk, "app/x", INFO, AAD, &sealed).is_err(),
        "an extra segment must not open the parent context"
    );
    assert!(
        open(&sk, "apple", INFO, AAD, &sealed).is_err(),
        "a string-prefix context must not collide"
    );
}

#[test]
fn caller_cannot_forge_internal_hpke_namespace() {
    let (_, plain) = kp("app", b"s");
    let (_, mirror) = kp("app/hpke/kem", b"s");
    assert_ne!(
        plain.to_wire(),
        mirror.to_wire(),
        "caller ctx mirroring the internal /hpke/kem path must stay a distinct domain"
    );

    let (sk, pk) = kp("app", b"s");
    let sealed = seal(&pk, "app", INFO, AAD, b"m");
    assert!(open(&sk, "app/hpke/kem", INFO, AAD, &sealed).is_err());
    assert!(open(&sk, "app/hpke/schedule", INFO, AAD, &sealed).is_err());
}

#[test]
fn open_ctx_segment_cannot_move_into_info() {
    let (sk, pk) = kp("app", b"s");
    let sealed = seal(&pk, "app/mail", b"", AAD, b"m");
    assert!(
        open(&sk, "app", b"mail", AAD, &sealed).is_err(),
        "a ctx segment and info live in separate namespaces"
    );
}

#[test]
fn open_empty_vs_null_info_disagree() {
    let (sk, pk) = kp(CTX, b"s");

    let empty_info = seal(&pk, CTX, b"", AAD, b"m");
    assert!(
        open(&sk, CTX, b"\0", AAD, &empty_info).is_err(),
        "a bare NUL info must not collide with empty info"
    );

    let null_info = seal(&pk, CTX, b"\0", AAD, b"m");
    assert!(open(&sk, CTX, b"", AAD, &null_info).is_err());
}

#[test]
fn open_info_aad_swap_fails() {
    let (sk, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, b"role-x", b"role-y", b"m");
    assert!(
        open(&sk, CTX, b"role-y", b"role-x", &sealed).is_err(),
        "info and aad are not interchangeable"
    );
}

#[test]
fn export_exporter_context_null_roundtrip_and_separates() {
    let (sk, pk) = kp(CTX, b"s");
    let (enc, sent) = hpke::setup_sender_and_export(&ctx_of(CTX), &pk, INFO, b"a\0b", 32).unwrap();

    let same = hpke::setup_receiver_and_export(&ctx_of(CTX), &sk, &enc, INFO, b"a\0b", 32).unwrap();
    assert_eq!(sent.expose_as_slice(), same.expose_as_slice());

    let flip = hpke::setup_receiver_and_export(&ctx_of(CTX), &sk, &enc, INFO, b"a\0c", 32).unwrap();
    assert_ne!(sent.expose_as_slice(), flip.expose_as_slice());

    let shift = hpke::setup_receiver_and_export(&ctx_of(CTX), &sk, &enc, INFO, b"ab", 32).unwrap();
    assert_ne!(
        sent.expose_as_slice(),
        shift.expose_as_slice(),
        "NUL framing: a\\0b must not equal ab"
    );
}

#[test]
fn export_binary_exporter_context_roundtrip() {
    let (sk, pk) = kp(CTX, b"s");
    let exp: Vec<u8> = (0u16..=255).map(|b| b as u8).collect();
    let (enc, sent) = hpke::setup_sender_and_export(&ctx_of(CTX), &pk, INFO, &exp, 48).unwrap();
    let recv = hpke::setup_receiver_and_export(&ctx_of(CTX), &sk, &enc, INFO, &exp, 48).unwrap();
    assert_eq!(sent.expose_as_slice(), recv.expose_as_slice());
}

#[test]
fn export_info_exporter_context_swap_disagrees() {
    let (sk, pk) = kp(CTX, b"s");
    let (enc, sent) =
        hpke::setup_sender_and_export(&ctx_of(CTX), &pk, b"role-x", b"role-y", 32).unwrap();
    let recv =
        hpke::setup_receiver_and_export(&ctx_of(CTX), &sk, &enc, b"role-y", b"role-x", 32).unwrap();
    assert_ne!(
        sent.expose_as_slice(),
        recv.expose_as_slice(),
        "info and exporter_context are bound at different stages, not interchangeable"
    );
}
