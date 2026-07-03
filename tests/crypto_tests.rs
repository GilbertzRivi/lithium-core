// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::crypto::{aead, kdf, keys, kyberbox, sign};
use lithium_core::error::ErrorKind;
use lithium_core::public::{PubByte32, PublicBytes};
use lithium_core::secrets::{SecByte12, SecByte32, SecretBytes};

fn sb(data: &[u8]) -> SecretBytes {
    SecretBytes::from_slice(data)
}

fn pb(data: &[u8]) -> PublicBytes {
    PublicBytes::from_slice(data)
}

fn key32(fill: u8) -> SecByte32 {
    SecByte32::new([fill; 32])
}

fn nonce12(fill: u8) -> SecByte12 {
    SecByte12::new([fill; 12])
}

#[test]
fn aead_raw_roundtrip() {
    let key = key32(0xAA);
    let nonce = nonce12(0x01);
    let plaintext = sb(b"hello aead");
    let aad = b"some-context";

    let ct = aead::encrypt_raw(&plaintext, &key, &nonce, aad).unwrap();
    let pt = aead::decrypt_raw(&ct, &key, &nonce, aad).unwrap();

    assert_eq!(pt.expose_as_slice(), plaintext.expose_as_slice());
}

#[test]
fn aead_blob_roundtrip() {
    let key = key32(0xBB);
    let nonce = nonce12(0x02);
    let plaintext = sb(b"blob roundtrip test");
    let aad = b"aad-blob";

    let blob = aead::encrypt(&plaintext, &key, &nonce, aad).unwrap();
    let recovered = aead::decrypt(&blob, &key, aad).unwrap();

    assert_eq!(recovered.expose_as_slice(), plaintext.expose_as_slice());
}

#[test]
fn aead_blob_starts_with_version_byte() {
    let key = key32(0x01);
    let nonce = nonce12(0x00);
    let blob = aead::encrypt(&sb(b"x"), &key, &nonce, b"aad").unwrap();
    assert_eq!(blob.as_slice()[0], 1, "first byte must be version 1");
}

#[test]
fn aead_blob_nonce_embedded() {
    let key = key32(0x01);
    let nonce = nonce12(0xCC);
    let blob = aead::encrypt(&sb(b"data"), &key, &nonce, b"aad").unwrap();
    assert_eq!(
        &blob.as_slice()[1..13],
        &[0xCC; 12],
        "nonce must be at bytes 1..13"
    );
}

#[test]
fn aead_wrong_key_fails() {
    let key = key32(0x10);
    let wrong_key = key32(0x11);
    let nonce = nonce12(0x03);
    let aad = b"ctx";

    let blob = aead::encrypt(&sb(b"secret"), &key, &nonce, aad).unwrap();
    let err = aead::decrypt(&blob, &wrong_key, aad).unwrap_err();
    assert_eq!(err.kind, ErrorKind::AeadFailed);
}

#[test]
fn aead_wrong_aad_fails() {
    let key = key32(0x20);
    let nonce = nonce12(0x04);

    let blob = aead::encrypt(&sb(b"secret"), &key, &nonce, b"correct-aad").unwrap();
    let err = aead::decrypt(&blob, &key, b"wrong-aad").unwrap_err();
    assert_eq!(err.kind, ErrorKind::AeadFailed);
}

#[test]
fn aead_tampered_ciphertext_fails() {
    let key = key32(0x30);
    let nonce = nonce12(0x05);
    let aad = b"tamper-test";

    let mut blob_vec = {
        let blob = aead::encrypt(&sb(b"original"), &key, &nonce, aad).unwrap();
        blob.as_slice().to_vec()
    };
    let last = blob_vec.len() - 1;
    blob_vec[last] ^= 0xFF;

    let tampered = pb(&blob_vec);
    let result = aead::decrypt(&tampered, &key, aad);
    assert!(result.is_err());
}

#[test]
fn aead_empty_plaintext() {
    let key = key32(0xAB);
    let nonce = nonce12(0x06);
    let aad = b"empty";

    let blob = aead::encrypt(&sb(b""), &key, &nonce, aad).unwrap();
    let pt = aead::decrypt(&blob, &key, aad).unwrap();
    assert!(pt.expose_as_slice().is_empty());
}

#[test]
fn aead_large_plaintext() {
    let key = key32(0xCD);
    let nonce = nonce12(0x07);
    let aad = b"large";
    let big = vec![0x42u8; 65536];

    let blob = aead::encrypt(&sb(&big), &key, &nonce, aad).unwrap();
    let pt = aead::decrypt(&blob, &key, aad).unwrap();
    assert_eq!(pt.expose_as_slice(), big.as_slice());
}

#[test]
fn aead_truncated_blob_fails() {
    let key = key32(0x01);
    let nonce = nonce12(0x00);
    let blob = aead::encrypt(&sb(b"data"), &key, &nonce, b"aad").unwrap();

    let short = pb(&blob.as_slice()[..10]);
    assert!(aead::decrypt(&short, &key, b"aad").is_err());
}

#[test]
fn kdf_deterministic() {
    let input = sb(b"master-key-material");
    let salt = sb(b"random-salt");
    let info = sb(b"test/v1");

    let k1 = kdf::derive32(&input, Some(&salt), &info).unwrap();
    let k2 = kdf::derive32(&input, Some(&salt), &info).unwrap();
    assert_eq!(k1, k2);
}

#[test]
fn kdf_different_info_gives_different_key() {
    let input = sb(b"material");
    let salt = sb(b"salt");

    let k1 = kdf::derive32(&input, Some(&salt), &sb(b"info-a/v1")).unwrap();
    let k2 = kdf::derive32(&input, Some(&salt), &sb(b"info-b/v1")).unwrap();
    assert_ne!(k1, k2);
}

#[test]
fn kdf_different_input_gives_different_key() {
    let info = sb(b"common-info/v1");

    let k1 = kdf::derive32(&sb(b"input-a"), None, &info).unwrap();
    let k2 = kdf::derive32(&sb(b"input-b"), None, &info).unwrap();
    assert_ne!(k1, k2);
}

#[test]
fn kdf_with_and_without_salt_differ() {
    let input = sb(b"ikm");
    let info = sb(b"label/v1");

    let k_with = kdf::derive32(&input, Some(&sb(b"salt")), &info).unwrap();
    let k_without = kdf::derive32(&input, None, &info).unwrap();
    assert_ne!(k_with, k_without);
}

#[test]
fn kdf_output_is_32_bytes() {
    let k = kdf::derive32(&sb(b"ikm"), None, &sb(b"info/v1")).unwrap();
    assert_eq!(k.as_slice().len(), 32);
}

#[test]
fn kdf_output_is_not_all_zeros() {
    let k = kdf::derive32(&sb(b"ikm"), None, &sb(b"info/v1")).unwrap();
    assert_ne!(k.as_slice(), &[0u8; 32]);
}

#[test]
fn keys_random_12_length() {
    let n = keys::random_12().unwrap();
    assert_eq!(n.as_slice().len(), 12);
}

#[test]
fn keys_random_32_length() {
    let k = keys::random_32().unwrap();
    assert_eq!(k.as_slice().len(), 32);
}

#[test]
fn keys_random_master_key_length() {
    let mk = keys::random_master_key32().unwrap();
    assert_eq!(mk.as_slice().len(), 32);
}

#[test]
fn keys_random_fixed_uniqueness() {
    let a = keys::random_fixed::<32>().unwrap();
    let b = keys::random_fixed::<32>().unwrap();
    assert_ne!(a, b);
}

#[test]
fn keys_x25519_keypair_sizes() {
    let (sk, pk) = keys::random_x25519_keypair().unwrap();
    assert_eq!(sk.as_slice().len(), 32);
    assert_eq!(pk.as_slice().len(), 32);
}

#[test]
fn keys_x25519_keypairs_unique() {
    let (sk1, pk1) = keys::random_x25519_keypair().unwrap();
    let (sk2, pk2) = keys::random_x25519_keypair().unwrap();
    assert_ne!(sk1, sk2);
    assert_ne!(pk1, pk2);
}

#[test]
fn keys_ed25519_keypair_sizes() {
    let (seed, vk) = keys::random_ed25519_keypair().unwrap();
    assert_eq!(seed.as_slice().len(), 32);
    assert_eq!(vk.as_slice().len(), 32);
}

#[test]
fn keys_kyber_keypair_sizes() {
    let (sk, pk) = keys::random_kyber_mlkem1024_keypair().unwrap();
    assert_eq!(sk.expose_as_slice().len(), 64);
    assert_eq!(pk.as_slice().len(), 1568);
}

#[test]
fn keys_dilithium_keypair_sizes() {
    let (sk, pk) = keys::random_dilithium_mldsa87_keypair().unwrap();
    assert_eq!(sk.expose_as_slice().len(), 32);
    assert_eq!(pk.as_slice().len(), 2592);
}

#[test]
fn sign_ed25519_roundtrip() {
    let (seed, pk) = keys::random_ed25519_keypair().unwrap();
    let msg = b"test message to sign";

    let sig = sign::sign_message(msg, seed.as_slice()).unwrap();
    assert!(sign::verify_signature(msg, sig.as_slice(), &pk));
}

#[test]
fn sign_ed25519_wrong_message_fails() {
    let (seed, pk) = keys::random_ed25519_keypair().unwrap();
    let sig = sign::sign_message(b"original", seed.as_slice()).unwrap();
    assert!(!sign::verify_signature(b"tampered", sig.as_slice(), &pk));
}

#[test]
fn sign_ed25519_wrong_key_fails() {
    let (seed, _pk) = keys::random_ed25519_keypair().unwrap();
    let (_, wrong_pk) = keys::random_ed25519_keypair().unwrap();
    let msg = b"test";

    let sig = sign::sign_message(msg, seed.as_slice()).unwrap();
    assert!(!sign::verify_signature(msg, sig.as_slice(), &wrong_pk));
}

#[test]
fn sign_ed25519_short_signature_fails() {
    let (_, pk) = keys::random_ed25519_keypair().unwrap();
    assert!(!sign::verify_signature(b"msg", &[0u8; 32], &pk));
}

#[test]
fn sign_ed25519_signature_is_64_bytes() {
    let (seed, _) = keys::random_ed25519_keypair().unwrap();
    let sig = sign::sign_message(b"data", seed.as_slice()).unwrap();
    assert_eq!(sig.as_slice().len(), 64);
}

#[test]
fn sign_ed25519_different_messages_different_sigs() {
    let (seed, _) = keys::random_ed25519_keypair().unwrap();
    let sig1 = sign::sign_message(b"message-one", seed.as_slice()).unwrap();
    let sig2 = sign::sign_message(b"message-two", seed.as_slice()).unwrap();
    assert_ne!(sig1.as_slice(), sig2.as_slice());
}

#[test]
fn sign_dili_roundtrip() {
    let (sk, pk) = keys::random_dilithium_mldsa87_keypair().unwrap();
    let msg = b"dilithium test message";

    let sig = sign::sign_message_dili(msg, sk.expose_as_slice()).unwrap();
    assert!(sign::verify_signature_dili(msg, sig.as_slice(), &pk));
}

#[test]
fn sign_dili_wrong_message_fails() {
    let (sk, pk) = keys::random_dilithium_mldsa87_keypair().unwrap();
    let sig = sign::sign_message_dili(b"original", sk.expose_as_slice()).unwrap();
    assert!(!sign::verify_signature_dili(
        b"tampered",
        sig.as_slice(),
        &pk
    ));
}

#[test]
fn sign_dili_wrong_key_fails() {
    let (sk, _pk) = keys::random_dilithium_mldsa87_keypair().unwrap();
    let (_, wrong_pk) = keys::random_dilithium_mldsa87_keypair().unwrap();
    let msg = b"test";

    let sig = sign::sign_message_dili(msg, sk.expose_as_slice()).unwrap();
    assert!(!sign::verify_signature_dili(msg, sig.as_slice(), &wrong_pk));
}

#[test]
fn sign_dili_garbage_signature_fails() {
    let (_, pk) = keys::random_dilithium_mldsa87_keypair().unwrap();
    assert!(!sign::verify_signature_dili(b"msg", &[0u8; 32], &pk));
}

/// Returns: (alice_x_sk, alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk)
fn kyberbox_alice_bob() -> (
    SecByte32,
    PubByte32,
    SecretBytes,
    PublicBytes,
    SecByte32,
    PubByte32,
) {
    let (alice_x_sk, alice_x_pk) = keys::random_x25519_keypair().unwrap();
    let (bob_x_sk, bob_x_pk) = keys::random_x25519_keypair().unwrap();
    let (bob_kyber_sk, bob_kyber_pk) = keys::random_kyber_mlkem1024_keypair().unwrap();
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
    let (alice_x_sk, alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();

    let body = sb(b"secret message");
    let ctx = "test-context";

    let wire = kyberbox::seal(ctx, &alice_x_sk, &bob_x_pk, &bob_kyber_pk, &body).unwrap();
    let dec_body = kyberbox::open(ctx, &bob_x_sk, &alice_x_pk, &bob_kyber_sk, &wire).unwrap();

    assert_eq!(dec_body.expose_as_slice(), body.expose_as_slice());
}

#[test]
fn kyberbox_empty_payload() {
    let (alice_x_sk, alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();

    let wire = kyberbox::seal("ctx", &alice_x_sk, &bob_x_pk, &bob_kyber_pk, &sb(b"")).unwrap();
    let body = kyberbox::open("ctx", &bob_x_sk, &alice_x_pk, &bob_kyber_sk, &wire).unwrap();

    assert!(body.expose_as_slice().is_empty());
}

#[test]
fn kyberbox_wrong_x25519_key_fails() {
    let (alice_x_sk, alice_x_pk, bob_kyber_sk, bob_kyber_pk, _bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();

    let wire = kyberbox::seal("ctx", &alice_x_sk, &bob_x_pk, &bob_kyber_pk, &sb(b"data")).unwrap();

    let (wrong_x_sk, _) = keys::random_x25519_keypair().unwrap();
    let result = kyberbox::open("ctx", &wrong_x_sk, &alice_x_pk, &bob_kyber_sk, &wire);
    assert!(result.is_err());
}

#[test]
fn kyberbox_wrong_kyber_key_fails() {
    let (alice_x_sk, alice_x_pk, _bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();

    let wire = kyberbox::seal("ctx", &alice_x_sk, &bob_x_pk, &bob_kyber_pk, &sb(b"data")).unwrap();

    let (wrong_kyber_sk, _) = keys::random_kyber_mlkem1024_keypair().unwrap();
    let result = kyberbox::open("ctx", &bob_x_sk, &alice_x_pk, &wrong_kyber_sk, &wire);
    assert!(result.is_err());
}

#[test]
fn kyberbox_different_contexts_incompatible() {
    let (alice_x_sk, alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();

    let wire = kyberbox::seal(
        "context-a",
        &alice_x_sk,
        &bob_x_pk,
        &bob_kyber_pk,
        &sb(b"data"),
    )
    .unwrap();
    let result = kyberbox::open("context-b", &bob_x_sk, &alice_x_pk, &bob_kyber_sk, &wire);
    assert!(result.is_err());
}

#[test]
fn kyberbox_large_payload() {
    let (alice_x_sk, alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();

    let big_data = vec![0xABu8; 16384];

    let wire = kyberbox::seal(
        "large",
        &alice_x_sk,
        &bob_x_pk,
        &bob_kyber_pk,
        &sb(&big_data),
    )
    .unwrap();
    let body = kyberbox::open("large", &bob_x_sk, &alice_x_pk, &bob_kyber_sk, &wire).unwrap();

    assert_eq!(body.expose_as_slice(), big_data.as_slice());
}

#[test]
fn aead_wrong_version_byte_fails() {
    let key = key32(0x01);
    let nonce = nonce12(0x00);
    let mut blob = aead::encrypt(&sb(b"data"), &key, &nonce, b"aad")
        .unwrap()
        .as_slice()
        .to_vec();
    blob[0] = 2;
    assert!(aead::decrypt(&pb(&blob), &key, b"aad").is_err());
}

#[test]
fn aead_version_zero_fails() {
    let key = key32(0x01);
    let nonce = nonce12(0x00);
    let mut blob = aead::encrypt(&sb(b"data"), &key, &nonce, b"aad")
        .unwrap()
        .as_slice()
        .to_vec();
    blob[0] = 0;
    assert!(aead::decrypt(&pb(&blob), &key, b"aad").is_err());
}

#[test]
fn aead_bit_flip_in_nonce_fails() {
    let key = key32(0x50);
    let nonce = nonce12(0x10);
    let aad = b"ctx";
    let mut blob = aead::encrypt(&sb(b"payload"), &key, &nonce, aad)
        .unwrap()
        .as_slice()
        .to_vec();
    blob[1] ^= 0x01;
    assert!(aead::decrypt(&pb(&blob), &key, aad).is_err());
}

#[test]
fn aead_bit_flip_in_nonce_last_byte_fails() {
    let key = key32(0x51);
    let nonce = nonce12(0x11);
    let aad = b"ctx";
    let mut blob = aead::encrypt(&sb(b"payload"), &key, &nonce, aad)
        .unwrap()
        .as_slice()
        .to_vec();
    blob[12] ^= 0x80;
    assert!(aead::decrypt(&pb(&blob), &key, aad).is_err());
}

#[test]
fn aead_bit_flip_in_ciphertext_first_byte_fails() {
    let key = key32(0x52);
    let nonce = nonce12(0x12);
    let aad = b"ctx";
    let mut blob = aead::encrypt(&sb(b"hello world!!"), &key, &nonce, aad)
        .unwrap()
        .as_slice()
        .to_vec();
    blob[13] ^= 0x01;
    assert!(aead::decrypt(&pb(&blob), &key, aad).is_err());
}

#[test]
fn aead_bit_flip_in_auth_tag_fails() {
    let key = key32(0x53);
    let nonce = nonce12(0x13);
    let aad = b"ctx";
    let mut blob = aead::encrypt(&sb(b"message"), &key, &nonce, aad)
        .unwrap()
        .as_slice()
        .to_vec();
    let last = blob.len() - 1;
    blob[last] ^= 0x01;
    assert!(aead::decrypt(&pb(&blob), &key, aad).is_err());
}

#[test]
fn aead_aad_differs_by_one_byte_at_end_fails() {
    let key = key32(0x54);
    let nonce = nonce12(0x14);
    let blob = aead::encrypt(&sb(b"secret"), &key, &nonce, b"correct-aad").unwrap();
    assert!(aead::decrypt(&blob, &key, b"correct-aaf").is_err());
}

#[test]
fn aead_aad_differs_by_one_byte_at_start_fails() {
    let key = key32(0x55);
    let nonce = nonce12(0x15);
    let blob = aead::encrypt(&sb(b"secret"), &key, &nonce, b"correct-aad").unwrap();
    assert!(aead::decrypt(&blob, &key, b"Xorrect-aad").is_err());
}

#[test]
fn aead_empty_aad_roundtrip() {
    let key = key32(0x56);
    let nonce = nonce12(0x16);
    let blob = aead::encrypt(&sb(b"no-aad"), &key, &nonce, b"").unwrap();
    let pt = aead::decrypt(&blob, &key, b"").unwrap();
    assert_eq!(pt.expose_as_slice(), b"no-aad");
}

#[test]
fn aead_non_empty_aad_not_accepted_as_empty() {
    let key = key32(0x57);
    let nonce = nonce12(0x17);
    let blob = aead::encrypt(&sb(b"x"), &key, &nonce, b"real-aad").unwrap();
    assert!(aead::decrypt(&blob, &key, b"").is_err());
}

#[test]
fn aead_roundtrip_various_sizes() {
    let key = key32(0x58);
    let nonce = nonce12(0x18);
    let aad = b"size-sweep";
    for &size in &[0usize, 1, 7, 15, 16, 17, 31, 32, 33, 100, 1024, 8192] {
        let pt = vec![0x42u8; size];
        let blob = aead::encrypt(&sb(&pt), &key, &nonce, aad).unwrap();
        let recovered = aead::decrypt(&blob, &key, aad).unwrap();
        assert_eq!(recovered.expose_as_slice(), pt.as_slice(), "size={size}");
    }
}

#[test]
fn aead_raw_deterministic_same_inputs() {
    let key = key32(0x59);
    let nonce = nonce12(0x19);
    let pt = sb(b"deterministic-test");
    let aad = b"ctx";
    let ct1 = aead::encrypt_raw(&pt, &key, &nonce, aad).unwrap();
    let ct2 = aead::encrypt_raw(&pt, &key, &nonce, aad).unwrap();
    assert_eq!(
        ct1.as_slice(),
        ct2.as_slice(),
        "AEAD-GCM-SIV must be deterministic for identical inputs"
    );
}

#[test]
fn aead_min_size_blob_29_bytes() {
    let key = key32(0x5A);
    let nonce = nonce12(0x1A);
    let blob = aead::encrypt(&sb(b""), &key, &nonce, b"").unwrap();
    assert_eq!(blob.as_slice().len(), 29, "min blob size must be 29");
}

#[test]
fn aead_28_bytes_too_short_fails() {
    let key = key32(0x5B);
    let nonce = nonce12(0x1B);
    let blob = aead::encrypt(&sb(b""), &key, &nonce, b"").unwrap();
    let short = pb(&blob.as_slice()[..28]);
    assert!(aead::decrypt(&short, &key, b"").is_err());
}

#[test]
fn kdf_empty_ikm_still_works() {
    let k = kdf::derive32(&sb(b""), None, &sb(b"info/v1")).unwrap();
    assert_eq!(k.as_slice().len(), 32);
    assert_ne!(k.as_slice(), &[0u8; 32]);
}

#[test]
fn kdf_empty_info_still_works() {
    let k = kdf::derive32(&sb(b"ikm"), None, &sb(b"")).unwrap();
    assert_eq!(k.as_slice().len(), 32);
}

#[test]
fn kdf_domain_separation_all_distinct() {
    let ikm = sb(b"shared-ikm");
    let labels: &[&str] = &["a/v1", "b/v1", "c/v1", "d/v1", "e/v1"];
    let keys: Vec<_> = labels
        .iter()
        .map(|l| kdf::derive32(&ikm, None, &sb(l.as_bytes())).unwrap())
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
        .map(|s| kdf::derive32(&ikm, Some(&sb(s)), &info).unwrap())
        .collect();
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            assert_ne!(keys[i], keys[j], "salts[{i}] and [{j}] collide");
        }
    }
}

#[test]
fn sign_ed25519_empty_message_roundtrip() {
    let (seed, pk) = keys::random_ed25519_keypair().unwrap();
    let sig = sign::sign_message(b"", seed.as_slice()).unwrap();
    assert!(sign::verify_signature(b"", sig.as_slice(), &pk));
    assert!(!sign::verify_signature(b"x", sig.as_slice(), &pk));
}

#[test]
fn sign_ed25519_deterministic() {
    let (seed, _pk) = keys::random_ed25519_keypair().unwrap();
    let msg = b"deterministic";
    let sig1 = sign::sign_message(msg, seed.as_slice()).unwrap();
    let sig2 = sign::sign_message(msg, seed.as_slice()).unwrap();
    assert_eq!(sig1.as_slice(), sig2.as_slice());
}

#[test]
fn sign_ed25519_tampered_sig_first_byte_fails() {
    let (seed, pk) = keys::random_ed25519_keypair().unwrap();
    let msg = b"message";
    let mut sig = sign::sign_message(msg, seed.as_slice()).unwrap();
    sig[0] ^= 0x01;
    assert!(!sign::verify_signature(msg, &sig, &pk));
}

#[test]
fn sign_ed25519_tampered_sig_last_byte_fails() {
    let (seed, pk) = keys::random_ed25519_keypair().unwrap();
    let msg = b"message";
    let mut sig = sign::sign_message(msg, seed.as_slice()).unwrap();
    let last = sig.len() - 1;
    sig[last] ^= 0x01;
    assert!(!sign::verify_signature(msg, &sig, &pk));
}

#[test]
fn sign_ed25519_various_message_sizes() {
    let (seed, pk) = keys::random_ed25519_keypair().unwrap();
    for &size in &[0usize, 1, 31, 32, 33, 100, 1024] {
        let msg = vec![0x5Au8; size];
        let sig = sign::sign_message(&msg, seed.as_slice()).unwrap();
        assert!(
            sign::verify_signature(&msg, sig.as_slice(), &pk),
            "size={size}"
        );
    }
}

#[test]
fn sign_dili_empty_message_roundtrip() {
    let (sk, pk) = keys::random_dilithium_mldsa87_keypair().unwrap();
    let sig = sign::sign_message_dili(b"", sk.expose_as_slice()).unwrap();
    assert!(sign::verify_signature_dili(b"", sig.as_slice(), &pk));
    assert!(!sign::verify_signature_dili(b"x", sig.as_slice(), &pk));
}

#[test]
fn sign_dili_tampered_sig_last_byte_fails() {
    let (sk, pk) = keys::random_dilithium_mldsa87_keypair().unwrap();
    let msg = b"dili-test";
    let mut sig = sign::sign_message_dili(msg, sk.expose_as_slice()).unwrap();
    let last = sig.len() - 1;
    sig[last] ^= 0xFF;
    assert!(!sign::verify_signature_dili(msg, &sig, &pk));
}

#[test]
fn sign_dili_various_message_sizes() {
    let (sk, pk) = keys::random_dilithium_mldsa87_keypair().unwrap();
    for &size in &[0usize, 1, 31, 32, 64, 256] {
        let msg = vec![0xA5u8; size];
        let sig = sign::sign_message_dili(&msg, sk.expose_as_slice()).unwrap();
        assert!(
            sign::verify_signature_dili(&msg, sig.as_slice(), &pk),
            "size={size}"
        );
    }
}

fn kyberbox_corrupt_kem_byte_at(offset: usize) {
    let (alice_x_sk, alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();
    let wire = kyberbox::seal("ctx", &alice_x_sk, &bob_x_pk, &bob_kyber_pk, &sb(b"body")).unwrap();

    let mut kem_bytes = wire.kem_ct.as_slice().to_vec();
    assert!(offset < kem_bytes.len());
    kem_bytes[offset] ^= 0xFF;

    let corrupted = kyberbox::KyberBoxSealed {
        kem_ct: PublicBytes::new(kem_bytes),
        ciphertext: wire.ciphertext.clone(),
    };
    assert!(
        kyberbox::open("ctx", &bob_x_sk, &alice_x_pk, &bob_kyber_sk, &corrupted).is_err(),
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
    let (alice_x_sk, alice_x_pk, _bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();
    let (fresh_kyber_sk, _) = keys::random_kyber_mlkem1024_keypair().unwrap();
    let wire = kyberbox::seal("ctx", &alice_x_sk, &bob_x_pk, &bob_kyber_pk, &sb(b"body")).unwrap();

    let truncated = PublicBytes::from_slice(&wire.kem_ct.as_slice()[..36]);
    let bad = kyberbox::KyberBoxSealed {
        kem_ct: truncated,
        ciphertext: wire.ciphertext.clone(),
    };
    assert!(kyberbox::open("ctx", &bob_x_sk, &alice_x_pk, &fresh_kyber_sk, &bad).is_err());
}

#[test]
fn kyberbox_empty_kem_ct_fails() {
    let (alice_x_sk, alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();
    let wire = kyberbox::seal("ctx", &alice_x_sk, &bob_x_pk, &bob_kyber_pk, &sb(b"body")).unwrap();
    let bad = kyberbox::KyberBoxSealed {
        kem_ct: pb(b""),
        ciphertext: wire.ciphertext.clone(),
    };
    assert!(kyberbox::open("ctx", &bob_x_sk, &alice_x_pk, &bob_kyber_sk, &bad).is_err());
}

#[test]
fn kyberbox_corrupt_enc_data_tag_fails() {
    let (alice_x_sk, alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();
    let wire = kyberbox::seal("ctx", &alice_x_sk, &bob_x_pk, &bob_kyber_pk, &sb(b"body")).unwrap();

    let mut body_bytes = wire.ciphertext.as_slice().to_vec();
    let last = body_bytes.len() - 1;
    body_bytes[last] ^= 0x01;

    let bad = kyberbox::KyberBoxSealed {
        kem_ct: wire.kem_ct.clone(),
        ciphertext: PublicBytes::new(body_bytes),
    };
    assert!(kyberbox::open("ctx", &bob_x_sk, &alice_x_pk, &bob_kyber_sk, &bad).is_err());
}

#[test]
fn kyberbox_corrupt_enc_data_version_fails() {
    let (alice_x_sk, alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();
    let wire = kyberbox::seal("ctx", &alice_x_sk, &bob_x_pk, &bob_kyber_pk, &sb(b"body")).unwrap();

    let mut body_bytes = wire.ciphertext.as_slice().to_vec();
    body_bytes[0] ^= 0xFF;

    let bad = kyberbox::KyberBoxSealed {
        kem_ct: wire.kem_ct.clone(),
        ciphertext: PublicBytes::new(body_bytes),
    };
    assert!(kyberbox::open("ctx", &bob_x_sk, &alice_x_pk, &bob_kyber_sk, &bad).is_err());
}

#[test]
fn kyberbox_truncated_enc_body_fails() {
    let (alice_x_sk, alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();
    let wire = kyberbox::seal("ctx", &alice_x_sk, &bob_x_pk, &bob_kyber_pk, &sb(b"body")).unwrap();

    let truncated = PublicBytes::from_slice(&wire.ciphertext.as_slice()[..10]);
    let bad = kyberbox::KyberBoxSealed {
        kem_ct: wire.kem_ct.clone(),
        ciphertext: truncated,
    };
    assert!(kyberbox::open("ctx", &bob_x_sk, &alice_x_pk, &bob_kyber_sk, &bad).is_err());
}

#[test]
fn kyberbox_roundtrip_various_payload_sizes() {
    let (alice_x_sk, alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();
    for &size in &[0usize, 1, 15, 16, 32, 100, 1024] {
        let body = vec![0xBBu8; size];
        let wire =
            kyberbox::seal("sweep", &alice_x_sk, &bob_x_pk, &bob_kyber_pk, &sb(&body)).unwrap();
        let dec_data =
            kyberbox::open("sweep", &bob_x_sk, &alice_x_pk, &bob_kyber_sk, &wire).unwrap();
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
    let aead_key = kdf::derive32(&master, None, &sb(b"aead-key/v1")).unwrap();

    let nonce = nonce12(0x42);
    let aad = b"cross-module-aad";
    let plaintext = sb(b"cross module plaintext");

    let blob = aead::encrypt(&plaintext, &aead_key, &nonce, aad).unwrap();
    let recovered = aead::decrypt(&blob, &aead_key, aad).unwrap();
    assert_eq!(recovered.expose_as_slice(), plaintext.expose_as_slice());
}

#[test]
fn cross_kdf_derived_keys_not_usable_cross_purpose() {
    let master = sb(b"shared-master");
    let key_a = kdf::derive32(&master, None, &sb(b"purpose-a/v1")).unwrap();
    let key_b = kdf::derive32(&master, None, &sb(b"purpose-b/v1")).unwrap();

    let nonce = nonce12(0x43);
    let aad = b"aad";
    let blob = aead::encrypt(&sb(b"secret"), &key_a, &nonce, aad).unwrap();

    assert!(aead::decrypt(&blob, &key_b, aad).is_err());
}

#[test]
fn cross_ed25519_sign_verify_cross_keypair_fails() {
    let (seed_a, _pk_a) = keys::random_ed25519_keypair().unwrap();
    let (_, pk_b) = keys::random_ed25519_keypair().unwrap();
    let msg = b"same message, different key";
    let sig = sign::sign_message(msg, seed_a.as_slice()).unwrap();
    assert!(!sign::verify_signature(msg, sig.as_slice(), &pk_b));
}

#[test]
fn cross_dili_sign_verify_cross_keypair_fails() {
    let (sk_a, _) = keys::random_dilithium_mldsa87_keypair().unwrap();
    let (_, pk_b) = keys::random_dilithium_mldsa87_keypair().unwrap();
    let msg = b"cross-key dilithium";
    let sig = sign::sign_message_dili(msg, sk_a.expose_as_slice()).unwrap();
    assert!(!sign::verify_signature_dili(msg, sig.as_slice(), &pk_b));
}

#[test]
fn cross_ed25519_and_dili_sigs_are_not_interchangeable() {
    let (ed_seed, ed_pk) = keys::random_ed25519_keypair().unwrap();
    let (dili_sk, dili_pk) = keys::random_dilithium_mldsa87_keypair().unwrap();
    let msg = b"cross-scheme";

    let ed_sig = sign::sign_message(msg, ed_seed.as_slice()).unwrap();
    let dili_sig = sign::sign_message_dili(msg, dili_sk.expose_as_slice()).unwrap();

    assert!(!sign::verify_signature_dili(
        msg,
        ed_sig.as_slice(),
        &dili_pk
    ));
    assert!(!sign::verify_signature(
        msg,
        &dili_sig.as_slice()[..64],
        &ed_pk
    ));
}

#[test]
fn cross_kyberbox_nondeterministic_wire() {
    let (alice_x_sk, _alice_x_pk, _bob_kyber_sk, bob_kyber_pk, _bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();
    let body = sb(b"same body");

    let wire1 = kyberbox::seal("ctx", &alice_x_sk, &bob_x_pk, &bob_kyber_pk, &body).unwrap();
    let wire2 = kyberbox::seal("ctx", &alice_x_sk, &bob_x_pk, &bob_kyber_pk, &body).unwrap();

    assert_ne!(
        wire1.ciphertext.as_slice(),
        wire2.ciphertext.as_slice(),
        "KyberBox must produce non-deterministic ciphertexts"
    );
}

#[test]
fn kyberbox_cross_ctx_kem_ct_transplant_fails() {
    let (alice_x_sk, alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();

    let wire_alpha = kyberbox::seal(
        "ctx-alpha",
        &alice_x_sk,
        &bob_x_pk,
        &bob_kyber_pk,
        &sb(b"body"),
    )
    .unwrap();
    let wire_beta = kyberbox::seal(
        "ctx-beta",
        &alice_x_sk,
        &bob_x_pk,
        &bob_kyber_pk,
        &sb(b"body"),
    )
    .unwrap();

    let doctored = kyberbox::KyberBoxSealed {
        kem_ct: wire_alpha.kem_ct,
        ciphertext: wire_beta.ciphertext,
    };
    assert!(
        kyberbox::open("ctx-beta", &bob_x_sk, &alice_x_pk, &bob_kyber_sk, &doctored).is_err(),
        "kem_ct from a different ctx must not verify"
    );
}

#[test]
fn kyberbox_cross_ctx_enc_body_transplant_fails() {
    let (alice_x_sk, alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();

    let wire_alpha = kyberbox::seal(
        "ctx-alpha",
        &alice_x_sk,
        &bob_x_pk,
        &bob_kyber_pk,
        &sb(b"body"),
    )
    .unwrap();
    let wire_beta = kyberbox::seal(
        "ctx-beta",
        &alice_x_sk,
        &bob_x_pk,
        &bob_kyber_pk,
        &sb(b"body"),
    )
    .unwrap();

    let doctored = kyberbox::KyberBoxSealed {
        kem_ct: wire_beta.kem_ct,
        ciphertext: wire_alpha.ciphertext,
    };
    assert!(
        kyberbox::open("ctx-beta", &bob_x_sk, &alice_x_pk, &bob_kyber_sk, &doctored).is_err(),
        "enc_body from a different ctx must not decrypt"
    );
}

#[test]
fn kyberbox_wire_replay_to_different_recipient_fails() {
    let (alice_x_sk, alice_x_pk, _bob_kyber_sk, bob_kyber_pk, _bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();
    let (carol_x_sk, carol_x_pk, carol_kyber_sk, carol_kyber_pk, _, _) = kyberbox_alice_bob();
    let _ = (carol_x_pk, carol_kyber_pk);

    let wire = kyberbox::seal(
        "session-a",
        &alice_x_sk,
        &bob_x_pk,
        &bob_kyber_pk,
        &sb(b"secret"),
    )
    .unwrap();

    let result = kyberbox::open(
        "session-b",
        &carol_x_sk,
        &alice_x_pk,
        &carol_kyber_sk,
        &wire,
    );
    assert!(
        result.is_err(),
        "WirePayload addressed to bob must not decrypt for carol"
    );
}
