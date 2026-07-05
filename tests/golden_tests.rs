// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;

use lithium_core::crypto::hash::sha256;
use lithium_core::crypto::kyberbox::KyberBoxSealed;
use lithium_core::crypto::{Context, aead, kyberbox, sign};
use lithium_core::hpke::{self, HpkeEnc, HpkeSealed};
use lithium_core::public::PublicBytes;
use lithium_core::secrets::{SecByte32, SecretBytes};

fn ctx_of(s: &str) -> Context<'_> {
    let mut parts = s.split('/');
    let mut c = Context::base(parts.next().unwrap()).unwrap();
    for p in parts {
        c = c.add(p).unwrap();
    }
    c
}

fn sealed_from_parts(enc_wire: &[u8], ct: &[u8]) -> HpkeSealed {
    let mut w = Vec::with_capacity(4 + enc_wire.len() + ct.len());
    w.extend_from_slice(&(enc_wire.len() as u32).to_be_bytes());
    w.extend_from_slice(enc_wire);
    w.extend_from_slice(ct);
    HpkeSealed::from_wire(&w).unwrap()
}

fn hpke_vectors() -> HashMap<&'static str, &'static str> {
    include_str!("testdata/hpke_golden_v1.txt")
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect()
}

#[test]
fn aead_blob_decrypts_to_pinned_plaintext() {
    let key =
        SecByte32::from_hex("9f2c1b8a4d6e0f3a57c9e1d2b40a8f6e7c5d3b1a09f8e7d6c5b4a39281706152")
            .unwrap();
    let aad = b"golden-aad-v1";
    let blob = PublicBytes::from_hex(
        "01a14b7e02c9d3f5081623ab9c05857d7c1ae77e0e52020ec0b973f4875a55aaf5d2299ac47ece5eb4392c621cedaa04bdc80282f1",
    )
    .unwrap();

    let ctx = ctx_of("golden/aead/v1");
    let pt = aead::decrypt(&blob, &key, &ctx, aad).unwrap();
    assert_eq!(pt.expose_as_slice(), b"golden-aead-plaintext-v1");

    let mut tampered = blob.as_slice().to_vec();
    *tampered.last_mut().unwrap() ^= 0x01;
    assert!(aead::decrypt(&PublicBytes::new(tampered), &key, &ctx, aad).is_err());
}

#[test]
fn kyberbox_wire_decrypts_to_pinned_plaintext() {
    let vectors: HashMap<&str, &str> = include_str!("testdata/kyberbox_golden_v1.txt")
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();

    let rx_x_priv = SecByte32::from_hex(vectors["RX_X_PRIV"]).unwrap();
    let kyber_priv = SecretBytes::from_hex(vectors["KYBER_PRIV"]).unwrap();
    let mut wire_bytes = Vec::new();
    wire_bytes.extend_from_slice(&hex::decode(vectors["MSG_X_PUB"]).unwrap());
    wire_bytes.extend_from_slice(&hex::decode(vectors["KEM_CT"]).unwrap());
    wire_bytes.extend_from_slice(&hex::decode(vectors["ENC_DATA"]).unwrap());
    let wire = KyberBoxSealed::from_wire(&wire_bytes).unwrap();

    let body = kyberbox::open(
        &ctx_of("golden/kyberbox/v1"),
        &rx_x_priv,
        &kyber_priv,
        b"",
        &wire,
    )
    .unwrap();

    assert_eq!(body.expose_as_slice(), b"golden-body-v1");
}

#[test]
fn mldsa87_signature_verifies_pinned_vector() {
    let vectors: HashMap<&str, &str> = include_str!("testdata/mldsa87_verify_golden_v1.txt")
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();

    let dili_pub = PublicBytes::from_hex(vectors["DILI_PUB"]).unwrap();
    let dili_sig = PublicBytes::from_hex(vectors["DILI_SIG"]).unwrap();
    let msg = b"golden-mldsa87-v1";

    assert_eq!(dili_pub.as_slice().len(), 2592);
    assert_eq!(dili_sig.as_slice().len(), 4627);

    let ctx = ctx_of("golden/mldsa/v1");
    assert!(sign::verify_signature_dili(
        msg,
        dili_sig.as_slice(),
        &dili_pub,
        &ctx
    ));
    assert!(!sign::verify_signature_dili(
        b"tampered",
        dili_sig.as_slice(),
        &dili_pub,
        &ctx
    ));
}

#[test]
fn hpke_derive_keypair_matches_pinned_vector() {
    let v = hpke_vectors();
    let ikm = hex::decode(v["KP_IKM"]).unwrap();

    let (sk, pk) = hpke::derive_keypair_from_high_entropy_ikm(
        &ctx_of(v["KP_CTX"]),
        &SecretBytes::from_slice(&ikm),
    )
    .unwrap();
    let pk_wire = pk.to_wire();

    assert_eq!(hex::encode(&pk_wire[..32]), v["KP_X_PUB"]);
    assert_eq!(
        hex::encode(sha256(&pk_wire).expose_as_slice()),
        v["KP_PK_SHA256"]
    );
    assert_eq!(
        hex::encode(sha256(sk.to_wire().expose_as_slice()).expose_as_slice()),
        v["KP_SK_SHA256"]
    );
}

#[test]
fn hpke_sealed_opens_to_pinned_plaintext() {
    let v = hpke_vectors();
    let (sk, _) = hpke::derive_keypair_from_high_entropy_ikm(
        &ctx_of(v["KP_CTX"]),
        &SecretBytes::from_slice(&hex::decode(v["KP_IKM"]).unwrap()),
    )
    .unwrap();
    let sk_wire = sk.to_wire();
    let sk_wire = sk_wire.expose_as_slice();
    let x_priv = SecByte32::from_slice(&sk_wire[..32]).unwrap();
    let k_priv = SecretBytes::from_slice(&sk_wire[32..]);

    let info = hex::decode(v["INFO"]).unwrap();
    let aad = hex::decode(v["AAD"]).unwrap();
    let sealed = sealed_from_parts(
        &hex::decode(v["ENC"]).unwrap(),
        &hex::decode(v["CIPHERTEXT"]).unwrap(),
    );

    let pt = hpke::open_base(
        &ctx_of(v["SEAL_CTX"]),
        &x_priv,
        &k_priv,
        &info,
        &aad,
        &sealed,
    )
    .unwrap();
    assert_eq!(
        pt.expose_as_slice(),
        hex::decode(v["PLAINTEXT"]).unwrap().as_slice()
    );

    let mut ct = sealed.ciphertext().as_slice().to_vec();
    *ct.last_mut().unwrap() ^= 0x01;
    let tampered = sealed_from_parts(&sealed.enc().to_wire(), &ct);
    assert!(
        hpke::open_base(
            &ctx_of(v["SEAL_CTX"]),
            &x_priv,
            &k_priv,
            &info,
            &aad,
            &tampered
        )
        .is_err()
    );
}

#[test]
fn hpke_export_reproduces_pinned_secret() {
    let v = hpke_vectors();
    let (sk, _) = hpke::derive_keypair_from_high_entropy_ikm(
        &ctx_of(v["KP_CTX"]),
        &SecretBytes::from_slice(&hex::decode(v["KP_IKM"]).unwrap()),
    )
    .unwrap();
    let enc = HpkeEnc::from_wire(&hex::decode(v["ENC2"]).unwrap()).unwrap();

    let exported = hpke::setup_receiver_and_export(
        &ctx_of(v["EXP_CTX"]),
        &sk,
        &enc,
        &hex::decode(v["INFO"]).unwrap(),
        &hex::decode(v["EXPORTER_CONTEXT"]).unwrap(),
        v["EXPORTER_LEN"].parse().unwrap(),
    )
    .unwrap();

    assert_eq!(hex::encode(exported.expose_as_slice()), v["EXPORTED"]);
}
