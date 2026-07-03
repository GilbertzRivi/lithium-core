// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::error::{LithiumError, Result};
use crate::secrets::bytes::SecretBytes;

#[derive(Clone)]
pub struct EphemeralStoreManager {
    shared: Arc<Shared>,
    _cleanup: Arc<CleanupGuard>,
}

struct Shared {
    inner: Mutex<StoreInner>,
    signal: Condvar,
}

struct CleanupGuard {
    shared: Arc<Shared>,
    handle: Option<JoinHandle<()>>,
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.shared.inner.lock() {
            guard.stop = true;
        }
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
        let shared = Arc::new(Shared {
            inner: Mutex::new(StoreInner::default()),
            signal: Condvar::new(),
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

    fn next_version(guard: &mut StoreInner) -> u64 {
        let v = guard.next_version;
        guard.next_version = guard.next_version.wrapping_add(1);
        v
    }

    pub fn set(&self, key: &str, value: SecretBytes, ttl: Duration) -> Result<()> {
        if ttl.is_zero() {
            return Ok(());
        }
        let now = Instant::now();
        let expires_at = now + ttl;
        let mut guard = self.lock()?;
        Self::sweep_expired(&mut guard, now);
        let ver = Self::next_version(&mut guard);
        guard.map.insert(
            key.to_owned(),
            StoreEntry {
                ciphertext: value,
                expires_at,
                version: ver,
            },
        );
        guard.heap.push(HeapEntry {
            expires_at,
            version: ver,
            key: key.to_owned(),
        });
        self.shared.signal.notify_one();
        Ok(())
    }

    pub fn set_if_absent(&self, key: &str, value: SecretBytes, ttl: Duration) -> Result<bool> {
        if ttl.is_zero() {
            return Ok(false);
        }
        let now = Instant::now();
        let expires_at = now + ttl;
        let mut guard = self.lock()?;
        Self::sweep_expired(&mut guard, now);
        if let Some(e) = guard.map.get(key)
            && e.expires_at > now
        {
            return Ok(false);
        }
        let ver = Self::next_version(&mut guard);
        guard.map.insert(
            key.to_owned(),
            StoreEntry {
                ciphertext: value,
                expires_at,
                version: ver,
            },
        );
        guard.heap.push(HeapEntry {
            expires_at,
            version: ver,
            key: key.to_owned(),
        });
        self.shared.signal.notify_one();
        Ok(true)
    }

    pub fn peek(&self, key: &str) -> Result<Option<SecretBytes>> {
        let now = Instant::now();
        let mut guard = self.lock()?;
        if let Some(entry) = guard.map.get(key) {
            if entry.expires_at <= now {
                let _ = guard.map.remove(key);
                return Ok(None);
            }
            return Ok(Some(entry.ciphertext.clone()));
        }
        Ok(None)
    }

    pub fn take(&self, key: &str) -> Result<Option<SecretBytes>> {
        let now = Instant::now();
        let mut guard = self.lock()?;
        let Some(entry) = guard.map.remove(key) else {
            return Ok(None);
        };
        if entry.expires_at <= now {
            return Ok(None);
        }
        Ok(Some(entry.ciphertext))
    }

    pub fn del(&self, key: &str) -> Result<()> {
        let mut guard = self.lock()?;
        guard.map.remove(key);
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
            !guard.map.contains_key("short"),
            "short-TTL entry must be scrubbed by the background thread without any access"
        );
        assert!(guard.map.contains_key("long"), "long-TTL entry must remain");
    }
}
