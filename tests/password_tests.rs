// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::opaque::dek::{unwrap_dek_under_export_key, wrap_dek_under_export_key};
use lithium_core::passwords::generate_dek;
use lithium_core::secrets::{SecByte64, SecretString};

const TEST_DEK_AAD: &[u8] = b"lithium-core/test/dek-wrap";

fn export_key(seed: u8) -> SecByte64 {
    SecByte64::from_slice(&[seed; 64]).unwrap()
}

#[test]
fn dek_generate_32_bytes() {
    let dek = generate_dek().unwrap();
    assert_eq!(dek.as_slice().len(), 32);
}

#[test]
fn dek_generate_unique() {
    let d1 = generate_dek().unwrap();
    let d2 = generate_dek().unwrap();
    assert_ne!(d1, d2);
}

#[test]
fn dek_wrap_unwrap_roundtrip() {
    let dek = generate_dek().unwrap();
    let ek = export_key(7);

    let wrapped = wrap_dek_under_export_key(&dek, &ek, TEST_DEK_AAD).unwrap();
    let unwrapped = unwrap_dek_under_export_key(&wrapped, &ek, TEST_DEK_AAD).unwrap();

    assert_eq!(dek, unwrapped);
}

#[test]
fn dek_wrap_wrong_export_key_fails() {
    let dek = generate_dek().unwrap();
    let wrapped = wrap_dek_under_export_key(&dek, &export_key(1), TEST_DEK_AAD).unwrap();
    assert!(unwrap_dek_under_export_key(&wrapped, &export_key(2), TEST_DEK_AAD).is_err());
}

#[test]
fn dek_wrap_produces_hex() {
    let dek = generate_dek().unwrap();
    let wrapped = wrap_dek_under_export_key(&dek, &export_key(3), TEST_DEK_AAD).unwrap();
    let hex_str = wrapped.expose();
    assert!(hex_str.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(hex_str.len() % 2, 0);
}

#[test]
fn dek_wrap_fresh_nonce_each_time() {
    let dek = generate_dek().unwrap();
    let ek = export_key(4);
    let w1 = wrap_dek_under_export_key(&dek, &ek, TEST_DEK_AAD).unwrap();
    let w2 = wrap_dek_under_export_key(&dek, &ek, TEST_DEK_AAD).unwrap();
    assert_ne!(w1.expose(), w2.expose());
}

#[test]
fn dek_unwrap_truncated_blob_fails() {
    let short_blob = SecretString::new("aabbccdd".to_owned());
    assert!(unwrap_dek_under_export_key(&short_blob, &export_key(5), TEST_DEK_AAD).is_err());
}
