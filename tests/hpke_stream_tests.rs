// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::hpke::{derive_keypair, setup_receiver, setup_sender};
use lithium_core::public::PublicBytes;
use lithium_core::secrets::SecretBytes;

const CTX: &str = "lithium/hpke-stream/test/v1";

fn msg(b: &[u8]) -> SecretBytes {
    SecretBytes::from_slice(b)
}

#[test]
fn multi_message_roundtrips_in_order() {
    let (sk, pk) = derive_keypair(CTX, b"stream-ikm-in-order").unwrap();
    let (enc, mut sender) = setup_sender(CTX, &pk, b"info").unwrap();

    let c0 = sender.seal(b"aad-0", &msg(b"chunk zero")).unwrap();
    let c1 = sender.seal(b"aad-1", &msg(b"chunk one")).unwrap();
    let c2 = sender.seal(b"aad-2", &msg(b"chunk two")).unwrap();

    let mut receiver = setup_receiver(CTX, &sk, &enc, b"info").unwrap();
    assert_eq!(receiver.open(b"aad-0", &c0).unwrap().expose_as_slice(), b"chunk zero");
    assert_eq!(receiver.open(b"aad-1", &c1).unwrap().expose_as_slice(), b"chunk one");
    assert_eq!(receiver.open(b"aad-2", &c2).unwrap().expose_as_slice(), b"chunk two");
}

#[test]
fn same_plaintext_gives_distinct_ciphertexts_per_sequence() {
    let (_, pk) = derive_keypair(CTX, b"stream-ikm-distinct").unwrap();
    let (_enc, mut sender) = setup_sender(CTX, &pk, b"info").unwrap();

    let a = sender.seal(b"", &msg(b"same")).unwrap();
    let b = sender.seal(b"", &msg(b"same")).unwrap();
    assert_ne!(a.as_slice(), b.as_slice(), "sequence nonce must advance");
}

#[test]
fn out_of_order_open_fails() {
    let (sk, pk) = derive_keypair(CTX, b"stream-ikm-order").unwrap();
    let (enc, mut sender) = setup_sender(CTX, &pk, b"info").unwrap();

    let _c0 = sender.seal(b"aad-0", &msg(b"first")).unwrap();
    let c1 = sender.seal(b"aad-1", &msg(b"second")).unwrap();

    let mut receiver = setup_receiver(CTX, &sk, &enc, b"info").unwrap();
    assert!(
        receiver.open(b"aad-1", &c1).is_err(),
        "receiver at seq 0 must reject the seq-1 ciphertext"
    );
}

#[test]
fn wrong_aad_fails() {
    let (sk, pk) = derive_keypair(CTX, b"stream-ikm-aad").unwrap();
    let (enc, mut sender) = setup_sender(CTX, &pk, b"info").unwrap();
    let c0 = sender.seal(b"bound-aad", &msg(b"payload")).unwrap();

    let mut receiver = setup_receiver(CTX, &sk, &enc, b"info").unwrap();
    assert!(receiver.open(b"other-aad", &c0).is_err());
}

#[test]
fn tampered_ciphertext_fails() {
    let (sk, pk) = derive_keypair(CTX, b"stream-ikm-tamper").unwrap();
    let (enc, mut sender) = setup_sender(CTX, &pk, b"info").unwrap();
    let c0 = sender.seal(b"aad", &msg(b"payload")).unwrap();

    let mut bytes = c0.as_slice().to_vec();
    bytes[0] ^= 0x01;
    let tampered = PublicBytes::from_slice(&bytes);

    let mut receiver = setup_receiver(CTX, &sk, &enc, b"info").unwrap();
    assert!(receiver.open(b"aad", &tampered).is_err());
}
