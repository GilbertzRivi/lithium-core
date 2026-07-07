// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::crypto::{Context, aead, kdf, keys, kyberbox};
use lithium_core::error::{ErrorKind, Result};
use lithium_core::public::{PubByte32, PublicBytes};
use lithium_core::secrets::{SecByte32, SecByte64, SecretBytes};

fn actx() -> Context<'static> {
    Context::base("test").unwrap().add("aead").unwrap()
}

fn kctx() -> Context<'static> {
    Context::base("test").unwrap().add("kdf").unwrap()
}

fn aenc(pt: &SecretBytes, key: &SecByte32, aad: &[u8]) -> Result<PublicBytes> {
    aead::encrypt(pt, key, &actx(), aad)
}

fn adec(blob: &PublicBytes, key: &SecByte32, aad: &[u8]) -> Result<SecretBytes> {
    aead::decrypt(blob, key, &actx(), aad)
}

fn kderive32(input: &SecretBytes, salt: Option<&SecretBytes>, info: &[u8]) -> Result<SecByte32> {
    kdf::derive32(input, salt, &kctx(), info)
}

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

fn pb(data: &[u8]) -> PublicBytes {
    PublicBytes::from_slice(data)
}

fn key32(fill: u8) -> SecByte32 {
    SecByte32::new([fill; 32])
}

#[test]
fn aead_raw_roundtrip() {
    let key = key32(0xAA);
    let plaintext = sb(b"hello aead");
    let aad = b"some-context";

    let blob = aenc(&plaintext, &key, aad).unwrap();
    let pt = adec(&blob, &key, aad).unwrap();

    assert_eq!(pt.expose_as_slice(), plaintext.expose_as_slice());
}

#[test]
fn aead_blob_roundtrip() {
    let key = key32(0xBB);
    let plaintext = sb(b"blob roundtrip test");
    let aad = b"aad-blob";

    let blob = aenc(&plaintext, &key, aad).unwrap();
    let recovered = adec(&blob, &key, aad).unwrap();

    assert_eq!(recovered.expose_as_slice(), plaintext.expose_as_slice());
}

#[test]
fn aead_blob_starts_with_version_byte() {
    let key = key32(0x01);
    let blob = aenc(&sb(b"x"), &key, b"aad").unwrap();
    assert_eq!(blob.as_slice()[0], 1, "first byte must be version 1");
}

#[test]
fn aead_wrong_key_fails() {
    let key = key32(0x10);
    let wrong_key = key32(0x11);
    let aad = b"ctx";

    let blob = aenc(&sb(b"secret"), &key, aad).unwrap();
    let err = adec(&blob, &wrong_key, aad).unwrap_err();
    assert_eq!(err.kind, ErrorKind::AeadFailed);
}

#[test]
fn aead_wrong_aad_fails() {
    let key = key32(0x20);

    let blob = aenc(&sb(b"secret"), &key, b"correct-aad").unwrap();
    let err = adec(&blob, &key, b"wrong-aad").unwrap_err();
    assert_eq!(err.kind, ErrorKind::AeadFailed);
}

#[test]
fn aead_tampered_ciphertext_fails() {
    let key = key32(0x30);
    let aad = b"tamper-test";

    let mut blob_vec = {
        let blob = aenc(&sb(b"original"), &key, aad).unwrap();
        blob.as_slice().to_vec()
    };
    let last = blob_vec.len() - 1;
    blob_vec[last] ^= 0xFF;

    let tampered = pb(&blob_vec);
    let result = adec(&tampered, &key, aad);
    assert!(result.is_err());
}

#[test]
fn aead_empty_plaintext() {
    let key = key32(0xAB);
    let aad = b"empty";

    let blob = aenc(&sb(b""), &key, aad).unwrap();
    let pt = adec(&blob, &key, aad).unwrap();
    assert!(pt.expose_as_slice().is_empty());
}

#[test]
fn aead_large_plaintext() {
    let key = key32(0xCD);
    let aad = b"large";
    let big = vec![0x42u8; 65536];

    let blob = aenc(&sb(&big), &key, aad).unwrap();
    let pt = adec(&blob, &key, aad).unwrap();
    assert_eq!(pt.expose_as_slice(), big.as_slice());
}

#[test]
fn aead_truncated_blob_fails() {
    let key = key32(0x01);
    let blob = aenc(&sb(b"data"), &key, b"aad").unwrap();

    let short = pb(&blob.as_slice()[..10]);
    assert!(adec(&short, &key, b"aad").is_err());
}

#[test]
fn kdf_deterministic() {
    let input = sb(b"master-key-material");
    let salt = sb(b"random-salt");
    let info = sb(b"test/v1");

    let k1 = kderive32(&input, Some(&salt), info.expose_as_slice()).unwrap();
    let k2 = kderive32(&input, Some(&salt), info.expose_as_slice()).unwrap();
    assert_eq!(k1, k2);
}

#[test]
fn kdf_different_info_gives_different_key() {
    let input = sb(b"material");
    let salt = sb(b"salt");

    let k1 = kderive32(&input, Some(&salt), sb(b"info-a/v1").expose_as_slice()).unwrap();
    let k2 = kderive32(&input, Some(&salt), sb(b"info-b/v1").expose_as_slice()).unwrap();
    assert_ne!(k1, k2);
}

#[test]
fn kdf_different_input_gives_different_key() {
    let info = sb(b"common-info/v1");

    let k1 = kderive32(&sb(b"input-a"), None, info.expose_as_slice()).unwrap();
    let k2 = kderive32(&sb(b"input-b"), None, info.expose_as_slice()).unwrap();
    assert_ne!(k1, k2);
}

#[test]
fn kdf_with_and_without_salt_differ() {
    let input = sb(b"ikm");
    let info = sb(b"label/v1");

    let k_with = kderive32(&input, Some(&sb(b"salt")), info.expose_as_slice()).unwrap();
    let k_without = kderive32(&input, None, info.expose_as_slice()).unwrap();
    assert_ne!(k_with, k_without);
}

#[test]
fn kdf_output_is_32_bytes() {
    let k = kderive32(&sb(b"ikm"), None, sb(b"info/v1").expose_as_slice()).unwrap();
    assert_eq!(k.expose_as_slice().len(), 32);
}

#[test]
fn kdf_output_is_not_all_zeros() {
    let k = kderive32(&sb(b"ikm"), None, sb(b"info/v1").expose_as_slice()).unwrap();
    assert_ne!(k.expose_as_slice(), &[0u8; 32]);
}

#[test]
fn keys_random_12_length() {
    let n = keys::random_12().unwrap();
    assert_eq!(n.expose_as_slice().len(), 12);
}

#[test]
fn keys_random_32_length() {
    let k = keys::random_32().unwrap();
    assert_eq!(k.expose_as_slice().len(), 32);
}

#[test]
fn keys_random_master_key_length() {
    let mk = keys::random_32().unwrap();
    assert_eq!(mk.expose_as_slice().len(), 32);
}

#[test]
fn keys_random_fixed_uniqueness() {
    let a = keys::random_fixed::<32>().unwrap();
    let b = keys::random_fixed::<32>().unwrap();
    assert_ne!(a, b);
}

#[test]
fn keys_x25519_keypair_sizes() {
    let (sk, pk) = keys::ephemeral_x25519_keypair().unwrap();
    assert_eq!(sk.expose_as_slice().len(), 32);
    assert_eq!(pk.as_slice().len(), 32);
}

#[test]
fn keys_x25519_keypairs_unique() {
    let (sk1, pk1) = keys::ephemeral_x25519_keypair().unwrap();
    let (sk2, pk2) = keys::ephemeral_x25519_keypair().unwrap();
    assert_ne!(sk1, sk2);
    assert_ne!(pk1, pk2);
}

#[test]
fn keys_ed25519_keypair_sizes() {
    let (seed, vk) = keys::ephemeral_ed25519_keypair().unwrap();
    assert_eq!(seed.expose_as_slice().len(), 32);
    assert_eq!(vk.as_slice().len(), 32);
}

#[test]
fn keys_kyber_keypair_sizes() {
    let (sk, pk) = keys::ephemeral_kyber_mlkem1024_keypair().unwrap();
    assert_eq!(sk.expose_as_slice().len(), 64);
    assert_eq!(pk.as_slice().len(), 1568);
}

#[test]
fn keys_dilithium_keypair_sizes() {
    let (sk, pk) = keys::ephemeral_dilithium_mldsa87_keypair().unwrap();
    assert_eq!(sk.expose_as_slice().len(), 32);
    assert_eq!(pk.as_slice().len(), 2592);
}

fn kyberbox_alice_bob() -> (
    SecByte32,
    PubByte32,
    SecByte64,
    PublicBytes,
    SecByte32,
    PubByte32,
) {
    let (alice_x_sk, alice_x_pk) = keys::ephemeral_x25519_keypair().unwrap();
    let (bob_x_sk, bob_x_pk) = keys::ephemeral_x25519_keypair().unwrap();
    let (bob_kyber_sk, bob_kyber_pk) = keys::ephemeral_kyber_mlkem1024_keypair().unwrap();
    (
        alice_x_sk,
        alice_x_pk,
        bob_kyber_sk,
        bob_kyber_pk,
        bob_x_sk,
        bob_x_pk,
    )
}

#[test]
fn kyberbox_roundtrip_body_and_headers() {
    let (_alice_x_sk, _alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();

    let body = sb(b"secret message");
    let ctx = "test-context";

    let (wire, _) = kyberbox::seal(&ctx_of(ctx), &bob_x_pk, &bob_kyber_pk, b"", &body).unwrap();
    let dec_body = kyberbox::open(&ctx_of(ctx), &bob_x_sk, &bob_kyber_sk, b"", &wire).unwrap();

    assert_eq!(dec_body.expose_as_slice(), body.expose_as_slice());
}

#[test]
fn kyberbox_sealed_wire_roundtrips_and_opens() {
    let (_alice_x_sk, _alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();
    let (wire, _) = kyberbox::seal(
        &ctx_of("wire"),
        &bob_x_pk,
        &bob_kyber_pk,
        b"",
        &sb(b"payload"),
    )
    .unwrap();

    let bytes = wire.to_wire();
    let back = kyberbox::KyberBoxSealed::from_wire(&bytes).unwrap();
    assert_eq!(back.to_wire(), bytes);

    let body = kyberbox::open(&ctx_of("wire"), &bob_x_sk, &bob_kyber_sk, b"", &back).unwrap();
    assert_eq!(body.expose_as_slice(), b"payload");
}

#[test]
fn kyberbox_empty_payload() {
    let (_alice_x_sk, _alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();

    let (wire, _) =
        kyberbox::seal(&ctx_of("ctx"), &bob_x_pk, &bob_kyber_pk, b"", &sb(b"")).unwrap();
    let body = kyberbox::open(&ctx_of("ctx"), &bob_x_sk, &bob_kyber_sk, b"", &wire).unwrap();

    assert!(body.expose_as_slice().is_empty());
}

#[test]
fn kyberbox_wrong_x25519_key_fails() {
    let (_alice_x_sk, _alice_x_pk, bob_kyber_sk, bob_kyber_pk, _bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();

    let (wire, _) =
        kyberbox::seal(&ctx_of("ctx"), &bob_x_pk, &bob_kyber_pk, b"", &sb(b"data")).unwrap();

    let (wrong_x_sk, _) = keys::ephemeral_x25519_keypair().unwrap();
    let result = kyberbox::open(&ctx_of("ctx"), &wrong_x_sk, &bob_kyber_sk, b"", &wire);
    assert!(result.is_err());
}

#[test]
fn kyberbox_aad_binds_ciphertext() {
    let (_alice_x_sk, _alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();

    let (wire, _) = kyberbox::seal(
        &ctx_of("ctx"),
        &bob_x_pk,
        &bob_kyber_pk,
        b"header-v1",
        &sb(b"data"),
    )
    .unwrap();

    let open = |aad: &[u8]| kyberbox::open(&ctx_of("ctx"), &bob_x_sk, &bob_kyber_sk, aad, &wire);

    assert!(open(b"header-v2").is_err(), "wrong aad must fail");
    assert!(open(b"").is_err(), "aad is bound; empty must fail");
    assert_eq!(
        open(b"header-v1").unwrap().expose_as_slice(),
        b"data",
        "matching aad must open"
    );
}

#[test]
fn kyberbox_wrong_kyber_key_fails() {
    let (_alice_x_sk, _alice_x_pk, _bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();

    let (wire, _) =
        kyberbox::seal(&ctx_of("ctx"), &bob_x_pk, &bob_kyber_pk, b"", &sb(b"data")).unwrap();

    let (wrong_kyber_sk, _) = keys::ephemeral_kyber_mlkem1024_keypair().unwrap();
    let result = kyberbox::open(&ctx_of("ctx"), &bob_x_sk, &wrong_kyber_sk, b"", &wire);
    assert!(result.is_err());
}

#[test]
fn kyberbox_different_contexts_incompatible() {
    let (_alice_x_sk, _alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();

    let (wire, _) = kyberbox::seal(
        &ctx_of("context-a"),
        &bob_x_pk,
        &bob_kyber_pk,
        b"",
        &sb(b"data"),
    )
    .unwrap();
    let result = kyberbox::open(&ctx_of("context-b"), &bob_x_sk, &bob_kyber_sk, b"", &wire);
    assert!(result.is_err());
}

#[test]
fn kyberbox_large_payload() {
    let (_alice_x_sk, _alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();

    let big_data = vec![0xABu8; 16384];

    let (wire, _) = kyberbox::seal(
        &ctx_of("large"),
        &bob_x_pk,
        &bob_kyber_pk,
        b"",
        &sb(&big_data),
    )
    .unwrap();
    let body = kyberbox::open(&ctx_of("large"), &bob_x_sk, &bob_kyber_sk, b"", &wire).unwrap();

    assert_eq!(body.expose_as_slice(), big_data.as_slice());
}

#[test]
fn aead_wrong_version_byte_fails() {
    let key = key32(0x01);
    let mut blob = aenc(&sb(b"data"), &key, b"aad")
        .unwrap()
        .as_slice()
        .to_vec();
    blob[0] = 2;
    assert!(adec(&pb(&blob), &key, b"aad").is_err());
}

#[test]
fn aead_version_zero_fails() {
    let key = key32(0x01);
    let mut blob = aenc(&sb(b"data"), &key, b"aad")
        .unwrap()
        .as_slice()
        .to_vec();
    blob[0] = 0;
    assert!(adec(&pb(&blob), &key, b"aad").is_err());
}

#[test]
fn aead_bit_flip_in_ciphertext_first_byte_fails() {
    let key = key32(0x52);
    let aad = b"ctx";
    let mut blob = aenc(&sb(b"hello world!!"), &key, aad)
        .unwrap()
        .as_slice()
        .to_vec();
    blob[13] ^= 0x01;
    assert!(adec(&pb(&blob), &key, aad).is_err());
}

#[test]
fn aead_bit_flip_in_auth_tag_fails() {
    let key = key32(0x53);
    let aad = b"ctx";
    let mut blob = aenc(&sb(b"message"), &key, aad)
        .unwrap()
        .as_slice()
        .to_vec();
    let last = blob.len() - 1;
    blob[last] ^= 0x01;
    assert!(adec(&pb(&blob), &key, aad).is_err());
}

#[test]
fn aead_aad_differs_by_one_byte_at_end_fails() {
    let key = key32(0x54);
    let blob = aenc(&sb(b"secret"), &key, b"correct-aad").unwrap();
    assert!(adec(&blob, &key, b"correct-aaf").is_err());
}

#[test]
fn aead_aad_differs_by_one_byte_at_start_fails() {
    let key = key32(0x55);
    let blob = aenc(&sb(b"secret"), &key, b"correct-aad").unwrap();
    assert!(adec(&blob, &key, b"Xorrect-aad").is_err());
}

#[test]
fn aead_empty_aad_roundtrip() {
    let key = key32(0x56);
    let blob = aenc(&sb(b"no-aad"), &key, b"").unwrap();
    let pt = adec(&blob, &key, b"").unwrap();
    assert_eq!(pt.expose_as_slice(), b"no-aad");
}

#[test]
fn aead_non_empty_aad_not_accepted_as_empty() {
    let key = key32(0x57);
    let blob = aenc(&sb(b"x"), &key, b"real-aad").unwrap();
    assert!(adec(&blob, &key, b"").is_err());
}

#[test]
fn aead_roundtrip_various_sizes() {
    let key = key32(0x58);
    let aad = b"size-sweep";
    for &size in &[0usize, 1, 7, 15, 16, 17, 31, 32, 33, 100, 1024, 8192] {
        let pt = vec![0x42u8; size];
        let blob = aenc(&sb(&pt), &key, aad).unwrap();
        let recovered = adec(&blob, &key, aad).unwrap();
        assert_eq!(recovered.expose_as_slice(), pt.as_slice(), "size={size}");
    }
}

#[test]
fn aead_min_size_blob_29_bytes() {
    let key = key32(0x5A);
    let blob = aenc(&sb(b""), &key, b"").unwrap();
    assert_eq!(blob.as_slice().len(), 29, "min blob size must be 29");
}

#[test]
fn aead_28_bytes_too_short_fails() {
    let key = key32(0x5B);
    let blob = aenc(&sb(b""), &key, b"").unwrap();
    let short = pb(&blob.as_slice()[..28]);
    assert!(adec(&short, &key, b"").is_err());
}

#[test]
fn kdf_empty_ikm_still_works() {
    let k = kderive32(&sb(b""), None, sb(b"info/v1").expose_as_slice()).unwrap();
    assert_eq!(k.expose_as_slice().len(), 32);
    assert_ne!(k.expose_as_slice(), &[0u8; 32]);
}

#[test]
fn kdf_empty_info_still_works() {
    let k = kderive32(&sb(b"ikm"), None, sb(b"").expose_as_slice()).unwrap();
    assert_eq!(k.expose_as_slice().len(), 32);
}

#[test]
fn kdf_domain_separation_all_distinct() {
    let ikm = sb(b"shared-ikm");
    let labels: &[&str] = &["a/v1", "b/v1", "c/v1", "d/v1", "e/v1"];
    let keys: Vec<_> = labels
        .iter()
        .map(|l| kderive32(&ikm, None, l.as_bytes()).unwrap())
        .collect();
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            assert_ne!(keys[i], keys[j], "labels[{i}] and [{j}] collide");
        }
    }
}

#[test]
fn kdf_salt_domain_separation() {
    let ikm = sb(b"ikm");
    let info = sb(b"info/v1");
    let salts: &[&[u8]] = &[b"salt-a", b"salt-b", b"salt-c"];
    let keys: Vec<_> = salts
        .iter()
        .map(|s| kderive32(&ikm, Some(&sb(s)), info.expose_as_slice()).unwrap())
        .collect();
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            assert_ne!(keys[i], keys[j], "salts[{i}] and [{j}] collide");
        }
    }
}

fn kb_wire(sender_x_pub: &[u8], kem_ct: &[u8], ct: &[u8]) -> Vec<u8> {
    let mut w = Vec::with_capacity(sender_x_pub.len() + kem_ct.len() + ct.len());
    w.extend_from_slice(sender_x_pub);
    w.extend_from_slice(kem_ct);
    w.extend_from_slice(ct);
    w
}

fn kyberbox_corrupt_kem_byte_at(offset: usize) {
    let (_alice_x_sk, _alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();
    let (wire, _) =
        kyberbox::seal(&ctx_of("ctx"), &bob_x_pk, &bob_kyber_pk, b"", &sb(b"body")).unwrap();

    let mut kem_bytes = wire.kem_ct().as_slice().to_vec();
    assert!(offset < kem_bytes.len());
    kem_bytes[offset] ^= 0xFF;

    let corrupted = kyberbox::KyberBoxSealed::from_wire(&kb_wire(
        wire.sender_x_pub().as_slice(),
        &kem_bytes,
        wire.ciphertext().as_slice(),
    ))
    .unwrap();
    assert!(
        kyberbox::open(&ctx_of("ctx"), &bob_x_sk, &bob_kyber_sk, b"", &corrupted).is_err(),
        "corrupt kem_ct byte at offset {offset} must cause failure"
    );
}

#[test]
fn kyberbox_corrupt_kem_version_byte_fails() {
    kyberbox_corrupt_kem_byte_at(0);
}

#[test]
fn kyberbox_corrupt_kem_id_fails() {
    kyberbox_corrupt_kem_byte_at(1);
}

#[test]
fn kyberbox_corrupt_kem_ciphertext_first_byte_fails() {
    kyberbox_corrupt_kem_byte_at(2);
}

#[test]
fn kyberbox_corrupt_kem_ciphertext_mid_byte_fails() {
    kyberbox_corrupt_kem_byte_at(800);
}

#[test]
fn kyberbox_truncated_kem_ciphertext_fails() {
    let (_alice_x_sk, _alice_x_pk, _bob_kyber_sk, bob_kyber_pk, _bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();
    let (wire, _) =
        kyberbox::seal(&ctx_of("ctx"), &bob_x_pk, &bob_kyber_pk, b"", &sb(b"body")).unwrap();

    let wire_bytes = kb_wire(
        wire.sender_x_pub().as_slice(),
        &wire.kem_ct().as_slice()[..36],
        wire.ciphertext().as_slice(),
    );
    assert!(
        kyberbox::KyberBoxSealed::from_wire(&wire_bytes).is_err(),
        "a truncated kem ciphertext must be rejected on parse"
    );
}

#[test]
fn kyberbox_empty_kem_ct_fails() {
    let (_alice_x_sk, _alice_x_pk, _bob_kyber_sk, bob_kyber_pk, _bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();
    let (wire, _) =
        kyberbox::seal(&ctx_of("ctx"), &bob_x_pk, &bob_kyber_pk, b"", &sb(b"body")).unwrap();
    let wire_bytes = kb_wire(
        wire.sender_x_pub().as_slice(),
        b"",
        wire.ciphertext().as_slice(),
    );
    assert!(
        kyberbox::KyberBoxSealed::from_wire(&wire_bytes).is_err(),
        "an empty kem ciphertext must be rejected on parse"
    );
}

#[test]
fn kyberbox_corrupt_enc_data_tag_fails() {
    let (_alice_x_sk, _alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();
    let (wire, _) =
        kyberbox::seal(&ctx_of("ctx"), &bob_x_pk, &bob_kyber_pk, b"", &sb(b"body")).unwrap();

    let mut body_bytes = wire.ciphertext().as_slice().to_vec();
    let last = body_bytes.len() - 1;
    body_bytes[last] ^= 0x01;

    let bad = kyberbox::KyberBoxSealed::from_wire(&kb_wire(
        wire.sender_x_pub().as_slice(),
        wire.kem_ct().as_slice(),
        &body_bytes,
    ))
    .unwrap();
    assert!(kyberbox::open(&ctx_of("ctx"), &bob_x_sk, &bob_kyber_sk, b"", &bad).is_err());
}

#[test]
fn kyberbox_corrupt_enc_data_version_fails() {
    let (_alice_x_sk, _alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();
    let (wire, _) =
        kyberbox::seal(&ctx_of("ctx"), &bob_x_pk, &bob_kyber_pk, b"", &sb(b"body")).unwrap();

    let mut body_bytes = wire.ciphertext().as_slice().to_vec();
    body_bytes[0] ^= 0xFF;

    let bad = kyberbox::KyberBoxSealed::from_wire(&kb_wire(
        wire.sender_x_pub().as_slice(),
        wire.kem_ct().as_slice(),
        &body_bytes,
    ))
    .unwrap();
    assert!(kyberbox::open(&ctx_of("ctx"), &bob_x_sk, &bob_kyber_sk, b"", &bad).is_err());
}

#[test]
fn kyberbox_truncated_enc_body_fails() {
    let (_alice_x_sk, _alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();
    let (wire, _) =
        kyberbox::seal(&ctx_of("ctx"), &bob_x_pk, &bob_kyber_pk, b"", &sb(b"body")).unwrap();

    let bad = kyberbox::KyberBoxSealed::from_wire(&kb_wire(
        wire.sender_x_pub().as_slice(),
        wire.kem_ct().as_slice(),
        &wire.ciphertext().as_slice()[..10],
    ))
    .unwrap();
    assert!(kyberbox::open(&ctx_of("ctx"), &bob_x_sk, &bob_kyber_sk, b"", &bad).is_err());
}

#[test]
fn kyberbox_roundtrip_various_payload_sizes() {
    let (_alice_x_sk, _alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();
    for &size in &[0usize, 1, 15, 16, 32, 100, 1024] {
        let body = vec![0xBBu8; size];
        let (wire, _) =
            kyberbox::seal(&ctx_of("sweep"), &bob_x_pk, &bob_kyber_pk, b"", &sb(&body)).unwrap();
        let dec_data =
            kyberbox::open(&ctx_of("sweep"), &bob_x_sk, &bob_kyber_sk, b"", &wire).unwrap();
        assert_eq!(
            dec_data.expose_as_slice(),
            body.as_slice(),
            "body size={size}"
        );
    }
}

#[test]
fn cross_kdf_then_aead_roundtrip() {
    let master = sb(b"master-key-material-for-cross-test");
    let aead_key = kderive32(&master, None, sb(b"aead-key/v1").expose_as_slice()).unwrap();

    let aad = b"cross-module-aad";
    let plaintext = sb(b"cross module plaintext");

    let blob = aenc(&plaintext, &aead_key, aad).unwrap();
    let recovered = adec(&blob, &aead_key, aad).unwrap();
    assert_eq!(recovered.expose_as_slice(), plaintext.expose_as_slice());
}

#[test]
fn cross_kdf_derived_keys_not_usable_cross_purpose() {
    let master = sb(b"shared-master");
    let key_a = kderive32(&master, None, sb(b"purpose-a/v1").expose_as_slice()).unwrap();
    let key_b = kderive32(&master, None, sb(b"purpose-b/v1").expose_as_slice()).unwrap();

    let aad = b"aad";
    let blob = aenc(&sb(b"secret"), &key_a, aad).unwrap();

    assert!(adec(&blob, &key_b, aad).is_err());
}

#[test]
fn cross_kyberbox_nondeterministic_wire() {
    let (_alice_x_sk, _alice_x_pk, _bob_kyber_sk, bob_kyber_pk, _bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();
    let body = sb(b"same body");

    let (wire1, _) = kyberbox::seal(&ctx_of("ctx"), &bob_x_pk, &bob_kyber_pk, b"", &body).unwrap();
    let (wire2, _) = kyberbox::seal(&ctx_of("ctx"), &bob_x_pk, &bob_kyber_pk, b"", &body).unwrap();

    assert_ne!(
        wire1.ciphertext().as_slice(),
        wire2.ciphertext().as_slice(),
        "KyberBox must produce non-deterministic ciphertexts"
    );
}

#[test]
fn kyberbox_cross_ctx_kem_ct_transplant_fails() {
    let (_alice_x_sk, _alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();

    let (wire_alpha, _) = kyberbox::seal(
        &ctx_of("ctx-alpha"),
        &bob_x_pk,
        &bob_kyber_pk,
        b"",
        &sb(b"body"),
    )
    .unwrap();
    let (wire_beta, _) = kyberbox::seal(
        &ctx_of("ctx-beta"),
        &bob_x_pk,
        &bob_kyber_pk,
        b"",
        &sb(b"body"),
    )
    .unwrap();

    let doctored = kyberbox::KyberBoxSealed::from_wire(&kb_wire(
        wire_alpha.sender_x_pub().as_slice(),
        wire_alpha.kem_ct().as_slice(),
        wire_beta.ciphertext().as_slice(),
    ))
    .unwrap();
    assert!(
        kyberbox::open(
            &ctx_of("ctx-beta"),
            &bob_x_sk,
            &bob_kyber_sk,
            b"",
            &doctored
        )
        .is_err(),
        "kem_ct from a different ctx must not verify"
    );
}

#[test]
fn kyberbox_cross_ctx_enc_body_transplant_fails() {
    let (_alice_x_sk, _alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();

    let (wire_alpha, _) = kyberbox::seal(
        &ctx_of("ctx-alpha"),
        &bob_x_pk,
        &bob_kyber_pk,
        b"",
        &sb(b"body"),
    )
    .unwrap();
    let (wire_beta, _) = kyberbox::seal(
        &ctx_of("ctx-beta"),
        &bob_x_pk,
        &bob_kyber_pk,
        b"",
        &sb(b"body"),
    )
    .unwrap();

    let doctored = kyberbox::KyberBoxSealed::from_wire(&kb_wire(
        wire_beta.sender_x_pub().as_slice(),
        wire_beta.kem_ct().as_slice(),
        wire_alpha.ciphertext().as_slice(),
    ))
    .unwrap();
    assert!(
        kyberbox::open(
            &ctx_of("ctx-beta"),
            &bob_x_sk,
            &bob_kyber_sk,
            b"",
            &doctored
        )
        .is_err(),
        "enc_body from a different ctx must not decrypt"
    );
}

#[test]
fn kyberbox_wire_replay_to_different_recipient_fails() {
    let (_alice_x_sk, _alice_x_pk, _bob_kyber_sk, bob_kyber_pk, _bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();
    let (carol_x_sk, carol_x_pk, carol_kyber_sk, carol_kyber_pk, _, _) = kyberbox_alice_bob();
    let _ = (carol_x_pk, carol_kyber_pk);

    let (wire, _) = kyberbox::seal(
        &ctx_of("session-a"),
        &bob_x_pk,
        &bob_kyber_pk,
        b"",
        &sb(b"secret"),
    )
    .unwrap();

    let result = kyberbox::open(
        &ctx_of("session-b"),
        &carol_x_sk,
        &carol_kyber_sk,
        b"",
        &wire,
    );
    assert!(
        result.is_err(),
        "WirePayload addressed to bob must not decrypt for carol"
    );
}

#[test]
fn dual_request_response_roundtrip() {
    use lithium_core::crypto::kyberbox::DualEncryptionPrivateKey;

    let (server_prekey_priv, server_prekey_pub) = DualEncryptionPrivateKey::ephemeral().unwrap();

    let request = sb(b"hello server");
    let (req_sealed, client_reply_priv) = server_prekey_pub
        .seal(&ctx_of("req"), b"aad-req", &request)
        .unwrap();

    let (got_request, reply_to) = server_prekey_priv
        .open(&ctx_of("req"), b"aad-req", &req_sealed)
        .unwrap();
    assert_eq!(got_request.expose_as_slice(), request.expose_as_slice());

    let response = sb(b"hello client");
    let (resp_sealed, _) = reply_to
        .seal(&ctx_of("resp"), b"aad-resp", &response)
        .unwrap();

    let (got_response, _) = client_reply_priv
        .open(&ctx_of("resp"), b"aad-resp", &resp_sealed)
        .unwrap();
    assert_eq!(got_response.expose_as_slice(), response.expose_as_slice());
}

#[test]
fn dual_sealed_wire_roundtrips_and_binds() {
    use lithium_core::crypto::kyberbox::{DualEncryptionPrivateKey, DualSealed};

    let (priv_a, pub_a) = DualEncryptionPrivateKey::ephemeral().unwrap();
    let (sealed, _reply) = pub_a.seal(&ctx_of("wire"), b"", &sb(b"payload")).unwrap();

    let back = DualSealed::from_wire(&sealed.to_wire()).unwrap();
    let (pt, _) = priv_a.open(&ctx_of("wire"), b"", &back).unwrap();
    assert_eq!(pt.expose_as_slice(), b"payload");

    let (priv_b, _pub_b) = DualEncryptionPrivateKey::ephemeral().unwrap();
    assert!(
        priv_b.open(&ctx_of("wire"), b"", &back).is_err(),
        "dual sealed for A must not open for B"
    );
}
