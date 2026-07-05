// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::ErrorKind;
use lithium_core::crypto::sign::DoubleSig;
use lithium_core::crypto::{Context, keys, sign};
use lithium_core::public::{PubByte32, PublicBytes};

fn dctx() -> Context<'static> {
    Context::base("test").unwrap().add("double-sig").unwrap()
}

fn verify_ds(msg: &[u8], sig: &DoubleSig, ed_pub: &PubByte32, dili_pub: &PublicBytes) -> bool {
    sign::verify_double(msg, sig, ed_pub, dili_pub, &dctx())
}

struct Keys {
    ed_seed: lithium_core::secrets::SecretFixedBytes<32>,
    ed_pub: lithium_core::public::PubByte32,
    dili_sk: lithium_core::secrets::SecretFixedBytes<32>,
    dili_pub: lithium_core::public::PublicBytes,
}

fn fresh_keys() -> Keys {
    let (ed_seed, ed_pub) = keys::ephemeral_ed25519_keypair().unwrap();
    let (dili_sk, dili_pub) = keys::ephemeral_dilithium_mldsa87_keypair().unwrap();
    Keys {
        ed_seed,
        ed_pub,
        dili_sk,
        dili_pub,
    }
}

fn sign(k: &Keys, msg: &[u8]) -> DoubleSig {
    sign::sign_double(
        msg,
        k.ed_seed.expose_as_slice(),
        k.dili_sk.expose_as_slice(),
        &dctx(),
    )
    .unwrap()
}

#[test]
fn roundtrips() {
    let k = fresh_keys();
    let msg = b"double-signed payload";
    let sig = sign(&k, msg);
    assert!(verify_ds(msg, &sig, &k.ed_pub, &k.dili_pub));
}

#[test]
fn wrong_message_fails() {
    let k = fresh_keys();
    let sig = sign(&k, b"original");
    assert!(!verify_ds(b"tampered", &sig, &k.ed_pub, &k.dili_pub));
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

    assert!(!verify_ds(b"message-a", &mixed, &k.ed_pub, &k.dili_pub));
    assert!(!verify_ds(b"message-b", &mixed, &k.ed_pub, &k.dili_pub));
}

#[test]
fn tamper_in_either_region_fails() {
    let k = fresh_keys();
    let msg = b"payload";
    let sig = sign(&k, msg);

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
fn wrong_public_keys_fail() {
    let k = fresh_keys();
    let other = fresh_keys();
    let msg = b"payload";
    let sig = sign(&k, msg);

    assert!(!verify_ds(msg, &sig, &other.ed_pub, &k.dili_pub));
    assert!(!verify_ds(msg, &sig, &k.ed_pub, &other.dili_pub));
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
    assert!(verify_ds(msg, &decoded, &k.ed_pub, &k.dili_pub));
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

const ED_LEN: usize = 64;
const DILI_LEN: usize = 4627;

#[test]
fn from_bytes_length_boundaries() {
    for bad in [
        0usize,
        1,
        63,
        64,
        ED_LEN + 1,
        ED_LEN + DILI_LEN - 1,
        ED_LEN + DILI_LEN + 1,
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
        DoubleSig::from_bytes(&vec![0u8; ED_LEN + DILI_LEN]).is_ok(),
        "exactly ed25519 + ml-dsa-87 signature length is the only valid length"
    );
}

#[test]
fn from_bytes_roundtrips_exact_length() {
    let bytes: Vec<u8> = (0..ED_LEN + DILI_LEN)
        .map(|i| (i as u8).wrapping_mul(31))
        .collect();
    let sig = DoubleSig::from_bytes(&bytes).unwrap();
    assert_eq!(sig.to_bytes(), bytes);
}

#[test]
fn verify_double_truncated_signature_is_rejected() {
    let k = fresh_keys();
    let msg = b"payload";
    let full = sign(&k, msg).to_bytes();
    for cut in [1usize, 100, 2000, full.len() - (ED_LEN + 1)] {
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
fn verify_double_oversized_signature_is_rejected() {
    let k = fresh_keys();
    let msg = b"payload";
    for extra in [1usize, 100, DILI_LEN] {
        let mut bytes = sign(&k, msg).to_bytes();
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
fn verify_double_random_full_length_is_false() {
    let k = fresh_keys();
    let bytes: Vec<u8> = (0..ED_LEN + DILI_LEN)
        .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
        .collect();
    let sig = DoubleSig::from_bytes(&bytes).unwrap();
    assert!(!verify_ds(b"payload", &sig, &k.ed_pub, &k.dili_pub));
}

#[test]
fn verify_double_valid_ed_garbage_dili_is_false() {
    let k = fresh_keys();
    let msg = b"payload";
    let mut bytes = sign(&k, msg).to_bytes();
    for b in bytes[ED_LEN..].iter_mut() {
        *b ^= 0xFF;
    }
    let sig = DoubleSig::from_bytes(&bytes).unwrap();
    assert!(
        !verify_ds(msg, &sig, &k.ed_pub, &k.dili_pub),
        "a valid ed branch must not rescue a broken dili branch"
    );
}

#[test]
fn verify_double_off_by_one_dili_length_no_panic() {
    let k = fresh_keys();
    let msg = b"payload";
    let valid = sign(&k, msg).to_bytes();
    for len in [ED_LEN + DILI_LEN - 1, ED_LEN + DILI_LEN + 1] {
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
