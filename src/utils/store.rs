// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::crypto::aead;
use crate::crypto::context::Context;
use crate::error::{LithiumError, Result};
use crate::public::PublicBytes;
use crate::secrets::SecByte32;
use crate::secrets::arena::{ArenaByte32, SecretArena};
use crate::secrets::bytes::SecretBytes;

fn store_ctx() -> Result<Context<'static>> {
    Context::base("lithium")?.add("ephemeral-store")
}

#[derive(Clone)]
pub struct EphemeralStoreManager {
    shared: Arc<Shared>,
    _cleanup: Arc<CleanupGuard>,
}

struct Shared {
    inner: Mutex<StoreInner>,
    signal: Condvar,
    key: ArenaByte32,
}

struct CleanupGuard {
    shared: Arc<Shared>,
    handle: Option<JoinHandle<()>>,
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        self.shared
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .stop = true;
        self.shared.signal.notify_all();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[derive(Default)]
struct StoreInner {
    map: HashMap<String, StoreEntry>,
    heap: BinaryHeap<HeapEntry>,
    next_version: u64,
    stop: bool,
}

struct StoreEntry {
    ciphertext: SecretBytes,
    expires_at: Instant,
    version: u64,
}

#[derive(Clone)]
struct HeapEntry {
    expires_at: Instant,
    version: u64,
    key: String,
}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .expires_at
            .cmp(&self.expires_at)
            .then_with(|| other.version.cmp(&self.version))
            .then_with(|| other.key.cmp(&self.key))
    }
}
impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl PartialEq for HeapEntry {
    fn eq(&self, other: &Self) -> bool {
        self.expires_at == other.expires_at
            && self.version == other.version
            && self.key == other.key
    }
}
impl Eq for HeapEntry {}

impl EphemeralStoreManager {
    pub fn new() -> Result<Self> {
        let arena = SecretArena::with_capacity_best_effort(4096)?;
        let key = arena.random_fixed::<32>()?;
        let shared = Arc::new(Shared {
            inner: Mutex::new(StoreInner::default()),
            signal: Condvar::new(),
            key,
        });
        let worker = shared.clone();
        let handle = thread::Builder::new()
            .name("lithium-store-cleanup".into())
            .spawn(move || Self::cleanup_loop(&worker))
            .map_err(LithiumError::io)?;
        Ok(Self {
            _cleanup: Arc::new(CleanupGuard {
                shared: shared.clone(),
                handle: Some(handle),
            }),
            shared,
        })
    }

    fn cleanup_loop(shared: &Shared) {
        let mut guard = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if guard.stop {
                return;
            }
            Self::sweep_expired(&mut guard, Instant::now());
            let next = guard.heap.peek().map(|e| e.expires_at);
            guard = match next {
                Some(deadline) => {
                    let wait = deadline.saturating_duration_since(Instant::now());
                    shared
                        .signal
                        .wait_timeout(guard, wait)
                        .unwrap_or_else(|e| e.into_inner())
                        .0
                }
                None => shared.signal.wait(guard).unwrap_or_else(|e| e.into_inner()),
            };
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, StoreInner>> {
        self.shared
            .inner
            .lock()
            .map_err(|_| LithiumError::internal("store_lock_poisoned"))
    }

    fn sweep_expired(guard: &mut StoreInner, now: Instant) {
        while let Some(top) = guard.heap.peek().cloned() {
            if top.expires_at > now {
                break;
            }
            guard.heap.pop();
            let should_remove = match guard.map.get(&top.key) {
                Some(cur) => cur.version == top.version && cur.expires_at <= now,
                None => false,
            };
            if should_remove {
                guard.map.remove(&top.key);
            }
        }
    }

    fn next_version(guard: &mut StoreInner) -> Result<u64> {
        let v = guard.next_version;
        guard.next_version = v
            .checked_add(1)
            .ok_or_else(|| LithiumError::internal("store_version_overflow"))?;
        Ok(v)
    }

    fn seal(&self, hkey: &str, value: &SecretBytes) -> Result<SecretBytes> {
        let key = SecByte32::from_slice(self.shared.key.expose_as_slice())?;
        let blob = aead::encrypt(value, &key, &store_ctx()?, hkey.as_bytes())?;
        Ok(SecretBytes::from_slice(blob.as_slice()))
    }

    fn unseal(&self, hkey: &str, blob: &SecretBytes) -> Result<SecretBytes> {
        let key = SecByte32::from_slice(self.shared.key.expose_as_slice())?;
        aead::decrypt(
            &PublicBytes::from_slice(blob.expose_as_slice()),
            &key,
            &store_ctx()?,
            hkey.as_bytes(),
        )
    }

    pub fn set(&self, key: &str, value: SecretBytes, ttl: Duration) -> Result<()> {
        if ttl.is_zero() {
            return Ok(());
        }
        let now = Instant::now();
        let expires_at = now
            .checked_add(ttl)
            .ok_or_else(LithiumError::ttl_too_large)?;
        let hkey = hash_sha256_hex(key.as_bytes());
        let ciphertext = self.seal(&hkey, &value)?;
        let mut guard = self.lock()?;
        Self::sweep_expired(&mut guard, now);
        let ver = Self::next_version(&mut guard)?;
        guard.map.insert(
            hkey.clone(),
            StoreEntry {
                ciphertext,
                expires_at,
                version: ver,
            },
        );
        guard.heap.push(HeapEntry {
            expires_at,
            version: ver,
            key: hkey,
        });
        self.shared.signal.notify_one();
        Ok(())
    }

    pub fn set_if_absent(&self, key: &str, value: SecretBytes, ttl: Duration) -> Result<bool> {
        if ttl.is_zero() {
            return Ok(false);
        }
        let now = Instant::now();
        let expires_at = now
            .checked_add(ttl)
            .ok_or_else(LithiumError::ttl_too_large)?;
        let hkey = hash_sha256_hex(key.as_bytes());
        let ciphertext = self.seal(&hkey, &value)?;
        let mut guard = self.lock()?;
        Self::sweep_expired(&mut guard, now);
        if let Some(e) = guard.map.get(&hkey)
            && e.expires_at > now
        {
            return Ok(false);
        }
        let ver = Self::next_version(&mut guard)?;
        guard.map.insert(
            hkey.clone(),
            StoreEntry {
                ciphertext,
                expires_at,
                version: ver,
            },
        );
        guard.heap.push(HeapEntry {
            expires_at,
            version: ver,
            key: hkey,
        });
        self.shared.signal.notify_one();
        Ok(true)
    }

    pub fn peek(&self, key: &str) -> Result<Option<SecretBytes>> {
        let now = Instant::now();
        let hkey = hash_sha256_hex(key.as_bytes());
        let mut guard = self.lock()?;
        let blob = match guard.map.get(&hkey) {
            Some(entry) if entry.expires_at > now => Some(entry.ciphertext.clone()),
            Some(_) => None,
            None => return Ok(None),
        };
        let Some(blob) = blob else {
            guard.map.remove(&hkey);
            return Ok(None);
        };
        drop(guard);
        Ok(Some(self.unseal(&hkey, &blob)?))
    }

    pub fn take(&self, key: &str) -> Result<Option<SecretBytes>> {
        let now = Instant::now();
        let hkey = hash_sha256_hex(key.as_bytes());
        let mut guard = self.lock()?;
        let Some(entry) = guard.map.remove(&hkey) else {
            return Ok(None);
        };
        if entry.expires_at <= now {
            return Ok(None);
        }
        let blob = entry.ciphertext;
        drop(guard);
        Ok(Some(self.unseal(&hkey, &blob)?))
    }

    pub fn del(&self, key: &str) -> Result<()> {
        let hkey = hash_sha256_hex(key.as_bytes());
        let mut guard = self.lock()?;
        guard.map.remove(&hkey);
        Ok(())
    }
}

pub fn hash_sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    fn sb(data: &[u8]) -> SecretBytes {
        SecretBytes::from_slice(data)
    }

    #[test]
    fn shorter_ttl_after_longer_is_scrubbed_proactively() {
        let store = EphemeralStoreManager::new().unwrap();
        store
            .set("long", sb(b"keep"), Duration::from_secs(60))
            .unwrap();
        store
            .set("short", sb(b"gone"), Duration::from_millis(80))
            .unwrap();

        sleep(Duration::from_millis(300));

        let guard = store.shared.inner.lock().unwrap();
        assert!(
            !guard.map.contains_key(&hash_sha256_hex(b"short")),
            "short-TTL entry must be scrubbed by the background thread without any access"
        );
        assert!(
            guard.map.contains_key(&hash_sha256_hex(b"long")),
            "long-TTL entry must remain"
        );
    }

    #[test]
    fn value_is_encrypted_at_rest() {
        let store = EphemeralStoreManager::new().unwrap();
        let plaintext = b"super-secret-value";
        store
            .set("k", sb(plaintext), Duration::from_secs(60))
            .unwrap();

        let guard = store.shared.inner.lock().unwrap();
        let entry = guard.map.get(&hash_sha256_hex(b"k")).unwrap();
        let stored = entry.ciphertext.expose_as_slice();
        assert!(
            !stored.windows(plaintext.len()).any(|w| w == plaintext),
            "plaintext must not appear in the at-rest ciphertext"
        );
    }

    #[test]
    fn roundtrips_through_peek_and_take() {
        let store = EphemeralStoreManager::new().unwrap();
        store
            .set("k", sb(b"value"), Duration::from_secs(60))
            .unwrap();

        assert_eq!(
            store.peek("k").unwrap().unwrap().expose_as_slice(),
            b"value"
        );
        assert_eq!(
            store.take("k").unwrap().unwrap().expose_as_slice(),
            b"value"
        );
        assert!(store.peek("k").unwrap().is_none());
    }
}
