// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::thread::sleep;
use std::time::Duration;

use lithium_core::secrets::SecretBytes;
use lithium_core::utils::store::EphemeralStoreManager;

fn sb(data: &[u8]) -> SecretBytes {
    SecretBytes::from_slice(data)
}

#[test]
fn store_set_and_peek() {
    let store = EphemeralStoreManager::new().unwrap();
    let ttl = Duration::from_secs(60);

    store.set("key1", sb(b"value1"), ttl).unwrap();
    let found = store.peek("key1").unwrap();

    assert!(found.is_some());
    assert_eq!(found.unwrap().expose_as_slice(), b"value1");
}

#[test]
fn store_peek_missing_key_returns_none() {
    let store = EphemeralStoreManager::new().unwrap();
    let result = store.peek("nonexistent").unwrap();
    assert!(result.is_none());
}

#[test]
fn store_take_removes_value() {
    let store = EphemeralStoreManager::new().unwrap();
    let ttl = Duration::from_secs(60);

    store.set("takekey", sb(b"takeval"), ttl).unwrap();
    let first = store.take("takekey").unwrap();
    let second = store.take("takekey").unwrap();

    assert!(first.is_some());
    assert_eq!(first.unwrap().expose_as_slice(), b"takeval");
    assert!(
        second.is_none(),
        "second take must return None after removal"
    );
}

#[test]
fn store_del_removes_value() {
    let store = EphemeralStoreManager::new().unwrap();
    store
        .set("delkey", sb(b"delval"), Duration::from_secs(60))
        .unwrap();

    store.del("delkey").unwrap();
    let result = store.peek("delkey").unwrap();
    assert!(result.is_none());
}

#[test]
fn store_del_missing_key_is_noop() {
    let store = EphemeralStoreManager::new().unwrap();
    store.del("does-not-exist").unwrap();
}

#[test]
fn store_set_overwrites_existing() {
    let store = EphemeralStoreManager::new().unwrap();
    let ttl = Duration::from_secs(60);

    store.set("k", sb(b"old"), ttl).unwrap();
    store.set("k", sb(b"new"), ttl).unwrap();

    let result = store.peek("k").unwrap().unwrap();
    assert_eq!(result.expose_as_slice(), b"new");
}

#[test]
fn store_set_if_absent_inserts_when_absent() {
    let store = EphemeralStoreManager::new().unwrap();
    let inserted = store
        .set_if_absent("fresh", sb(b"val"), Duration::from_secs(60))
        .unwrap();

    assert!(inserted, "should return true when key was absent");
    let got = store.peek("fresh").unwrap().unwrap();
    assert_eq!(got.expose_as_slice(), b"val");
}

#[test]
fn store_set_if_absent_does_not_overwrite() {
    let store = EphemeralStoreManager::new().unwrap();
    let ttl = Duration::from_secs(60);

    store.set("dup", sb(b"first"), ttl).unwrap();
    let inserted = store.set_if_absent("dup", sb(b"second"), ttl).unwrap();

    assert!(!inserted, "should return false when key already exists");
    let got = store.peek("dup").unwrap().unwrap();
    assert_eq!(
        got.expose_as_slice(),
        b"first",
        "original value must be unchanged"
    );
}

#[test]
fn store_peek_does_not_remove() {
    let store = EphemeralStoreManager::new().unwrap();
    let ttl = Duration::from_secs(60);

    store.set("peekonly", sb(b"data"), ttl).unwrap();

    let first = store.peek("peekonly").unwrap();
    let second = store.peek("peekonly").unwrap();

    assert!(first.is_some());
    assert!(second.is_some(), "peek must not consume the entry");
}

#[test]
fn store_expired_entry_not_returned_by_take() {
    let store = EphemeralStoreManager::new().unwrap();
    store
        .set("exp", sb(b"gone"), Duration::from_millis(1))
        .unwrap();

    sleep(Duration::from_millis(20));

    let result = store.take("exp").unwrap();
    assert!(result.is_none(), "expired entry must return None");
}

#[test]
fn store_expired_entry_not_returned_by_peek() {
    let store = EphemeralStoreManager::new().unwrap();
    store
        .set("exppeek", sb(b"gone"), Duration::from_millis(1))
        .unwrap();

    sleep(Duration::from_millis(20));

    let result = store.peek("exppeek").unwrap();
    assert!(
        result.is_none(),
        "expired entry must not be visible via peek"
    );
}

#[test]
fn store_zero_ttl_not_stored() {
    let store = EphemeralStoreManager::new().unwrap();
    store.set("zero", sb(b"val"), Duration::ZERO).unwrap();

    let result = store.peek("zero").unwrap();
    assert!(result.is_none(), "zero-TTL entry should not be present");
}

#[test]
fn store_multiple_independent_keys() {
    let store = EphemeralStoreManager::new().unwrap();
    let ttl = Duration::from_secs(60);

    store.set("a", sb(b"alpha"), ttl).unwrap();
    store.set("b", sb(b"beta"), ttl).unwrap();
    store.set("c", sb(b"gamma"), ttl).unwrap();

    assert_eq!(store.peek("a").unwrap().unwrap().expose_as_slice(), b"alpha");
    assert_eq!(store.peek("b").unwrap().unwrap().expose_as_slice(), b"beta");
    assert_eq!(store.peek("c").unwrap().unwrap().expose_as_slice(), b"gamma");
}

#[test]
fn store_set_if_absent_allows_reinsertion_after_expiry() {
    let store = EphemeralStoreManager::new().unwrap();
    let ttl = Duration::from_millis(5);

    let first = store.set_if_absent("key", sb(b"v1"), ttl).unwrap();
    assert!(first);

    sleep(Duration::from_millis(30));

    let second = store
        .set_if_absent("key", sb(b"v2"), Duration::from_secs(60))
        .unwrap();
    assert!(second, "should succeed after original TTL expired");
    assert_eq!(
        store.peek("key").unwrap().unwrap().expose_as_slice(),
        b"v2"
    );
}
