// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::ErrorKind;
use lithium_core::crypto::{keys, sign};
use lithium_core::crypto::sign::DoubleSig;

struct Keys {
    ed_seed: lithium_core::secrets::SecretFixedBytes<32>,
    ed_pub: lithium_core::public::PubByte32,
    dili_sk: lithium_core::secrets::SecretBytes,
    dili_pub: lithium_core::public::PublicBytes,
}

fn fresh_keys() -> Keys {
    let (ed_seed, ed_pub) = keys::random_ed25519_keypair().unwrap();
    let (dili_sk, dili_pub) = keys::random_dilithium_mldsa87_keypair().unwrap();
    Keys {
        ed_seed,
        ed_pub,
        dili_sk,
        dili_pub,
    }
}

fn sign(k: &Keys, msg: &[u8]) -> DoubleSig {
    sign::sign_double(msg, k.ed_seed.as_slice(), k.dili_sk.expose_as_slice()).unwrap()
}

#[test]
fn roundtrips() {
    let k = fresh_keys();
    let msg = b"double-signed payload";
    let sig = sign(&k, msg);
    assert!(sign::verify_double(msg, &sig, &k.ed_pub, &k.dili_pub));
}

#[test]
fn wrong_message_fails() {
    let k = fresh_keys();
    let sig = sign(&k, b"original");
    assert!(!sign::verify_double(b"tampered", &sig, &k.ed_pub, &k.dili_pub));
}

#[test]
fn both_branches_are_required() {
    // A valid ed branch from message A glued to a dili branch over message B
    // must fail: verify_double is AND, not OR.
    let k = fresh_keys();
    let sig_a = sign(&k, b"message-a");
    let sig_b = sign(&k, b"message-b");

    let mut bytes = sig_a.to_bytes();
    let b_bytes = sig_b.to_bytes();
    bytes[64..].copy_from_slice(&b_bytes[64..]); // keep ed(A), swap in dili(B)
    let mixed = DoubleSig::from_bytes(&bytes).unwrap();

    assert!(!sign::verify_double(b"message-a", &mixed, &k.ed_pub, &k.dili_pub));
    assert!(!sign::verify_double(b"message-b", &mixed, &k.ed_pub, &k.dili_pub));
}

#[test]
fn tamper_in_either_region_fails() {
    let k = fresh_keys();
    let msg = b"payload";
    let sig = sign(&k, msg);

    let mut ed_tampered = sig.to_bytes();
    ed_tampered[0] ^= 0x01;
    assert!(!sign::verify_double(
        msg,
        &DoubleSig::from_bytes(&ed_tampered).unwrap(),
        &k.ed_pub,
        &k.dili_pub
    ));

    let mut dili_tampered = sig.to_bytes();
    let last = dili_tampered.len() - 1;
    dili_tampered[last] ^= 0x01;
    assert!(!sign::verify_double(
        msg,
        &DoubleSig::from_bytes(&dili_tampered).unwrap(),
        &k.ed_pub,
        &k.dili_pub
    ));
}

#[test]
fn wrong_public_keys_fail() {
    let k = fresh_keys();
    let other = fresh_keys();
    let msg = b"payload";
    let sig = sign(&k, msg);

    assert!(!sign::verify_double(msg, &sig, &other.ed_pub, &k.dili_pub));
    assert!(!sign::verify_double(msg, &sig, &k.ed_pub, &other.dili_pub));
}

#[test]
fn bytes_roundtrip() {
    let k = fresh_keys();
    let sig = sign(&k, b"payload");
    let decoded = DoubleSig::from_bytes(&sig.to_bytes()).unwrap();
    assert_eq!(sig, decoded);
}

#[test]
fn hex_roundtrip() {
    let k = fresh_keys();
    let msg = b"payload";
    let sig = sign(&k, msg);
    let decoded = DoubleSig::from_hex(&sig.to_hex()).unwrap();
    assert_eq!(sig, decoded);
    assert!(sign::verify_double(msg, &decoded, &k.ed_pub, &k.dili_pub));
}

#[test]
fn from_bytes_rejects_too_short() {
    match DoubleSig::from_bytes(&[0u8; 64]) {
        Err(e) => assert!(matches!(e.kind, ErrorKind::InvalidLength { .. })),
        Ok(_) => panic!("64 bytes has no dilithium branch and must be rejected"),
    }
}

#[test]
fn from_hex_enforces_lowercase_no_prefix() {
    let k = fresh_keys();
    let hexed = sign(&k, b"payload").to_hex();
    assert!(DoubleSig::from_hex(&hexed.to_uppercase()).is_err());
    assert!(DoubleSig::from_hex(&format!("0x{hexed}")).is_err());
}
