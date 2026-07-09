// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::crypto::context::Context;
use crate::crypto::sign::{DoubleSig, DualVerifyingKey};
use crate::crypto::{aead, keys};
use crate::error::{LithiumError, Result};
use crate::public::{PubByte32, PublicBytes};
use crate::secrets::{
    ArenaByte32, ArenaFixedBytes, MasterKey32, SecByte32, SecretArena, SecretBytes,
};

use super::keyfile;

const LOCK_FILE: &str = ".lock";

const PUB_DIR: &str = "pub";
const PRIV_DIR: &str = "priv";
const SECRETS_DIR: &str = "secrets";
const ROTATE_DIR: &str = ".rotate";
const ROTATE_STAGE_DIR: &str = "staged";
const ROTATE_READY_FILE: &str = "ready";
const ROTATE_NEXT_OLD_FILE: &str = "next-mk-old.keyf";
const ROTATE_NEXT_NEW_FILE: &str = "next-mk-new.keyf";

const ED_PUB: &str = "ed25519.pub";
const DILI_PUB: &str = "dilithium-mldsa87.pub";

const ED_PRIV: &str = "ed25519.keyf";
const DILI_PRIV: &str = "dilithium-mldsa87.keyf";
const KT_ED_SEED: &str = "ed25519-seed-v1";
const KT_DILI_SEED: &str = "dilithium-mldsa87-seed-v1";
const KT_ROTATE_NEXT_OLD: &str = "rotate-next-mk-old-v1";
const KT_ROTATE_NEXT_NEW: &str = "rotate-next-mk-new-v1";

pub trait MkProvider {
    fn load_mk(&self) -> Result<SecByte32>;
    fn store_mk(&self, mk: &SecByte32) -> Result<()>;

    fn get_or_create_secret32(
        &self,
        mk: &SecByte32,
        label: &[u8],
        secrets_dir: &Path,
    ) -> Result<SecByte32> {
        load_or_create_label_secret32(secrets_dir, mk, label)
    }
}

/// Stores the master key in cleartext on disk. Gated behind the
/// "insecure-plaintext-mk" feature so it cannot reach production by accident
#[cfg(feature = "insecure-plaintext-mk")]
pub struct InsecurePlaintextMkProvider {
    path: PathBuf,
}

#[cfg(feature = "insecure-plaintext-mk")]
impl InsecurePlaintextMkProvider {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

#[cfg(feature = "insecure-plaintext-mk")]
impl MkProvider for InsecurePlaintextMkProvider {
    fn load_mk(&self) -> Result<SecByte32> {
        let bytes = keyfile::read_keyfile_bytes(&self.path)?;
        SecByte32::from_slice(bytes.expose_as_slice())
    }

    fn store_mk(&self, mk: &SecByte32) -> Result<()> {
        keyfile::write_secure(&self.path, mk.expose_as_slice())
    }
}

#[derive(Clone)]
pub struct PublicKeys {
    pub ed25519: PubByte32,
    pub dilithium: PublicBytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryLocking {
    Require,
    BestEffort,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicCachePolicy {
    Strict,
    RepairMissingOnly,
}

pub enum RotationErrorPolicy {
    Strict(Box<dyn Fn(&LithiumError) + Send + Sync>),
    Callback(Box<dyn Fn(&LithiumError) + Send + Sync>),
}

#[derive(Clone)]
pub enum FileLockPolicy {
    Require,
    #[cfg(feature = "best-effort")]
    BestEffort(Arc<dyn Fn(&LithiumError) + Send + Sync>),
}

impl std::fmt::Debug for FileLockPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileLockPolicy::Require => f.write_str("Require"),
            #[cfg(feature = "best-effort")]
            FileLockPolicy::BestEffort(_) => f.write_str("BestEffort(..)"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct KeyManagerConfig {
    locking: MemoryLocking,
    file_lock: FileLockPolicy,
    public_cache_policy: PublicCachePolicy,
    rotate_every: Duration,
    rotation_enabled: bool,
    arena_capacity: usize,
}

impl KeyManagerConfig {
    pub const DEFAULT_ROTATE_EVERY: Duration = Duration::from_secs(3600);
    pub const MIN_ROTATE_EVERY: Duration = Duration::from_millis(1);
    pub const DEFAULT_ARENA_CAPACITY: usize = 8 * 1024;

    pub fn new(locking: MemoryLocking, public_cache_policy: PublicCachePolicy) -> Self {
        Self {
            locking,
            file_lock: FileLockPolicy::Require,
            public_cache_policy,
            rotate_every: Self::DEFAULT_ROTATE_EVERY,
            rotation_enabled: true,
            arena_capacity: Self::DEFAULT_ARENA_CAPACITY,
        }
    }

    #[cfg(feature = "best-effort")]
    pub fn file_lock_best_effort(
        mut self,
        on_unlocked: impl Fn(&LithiumError) + Send + Sync + 'static,
    ) -> Self {
        self.file_lock = FileLockPolicy::BestEffort(Arc::new(on_unlocked));
        self
    }

    pub fn rotate_every(mut self, interval: Duration) -> Self {
        self.rotate_every = interval;
        self
    }

    // Disable master-key rotation entirely: no rotation thread is spawned. Only sound
    // when the MK is derived deterministically from a hardware-backed key and never
    // persists in raw form, so there is nothing to rotate.
    #[cfg(feature = "no-mk-rotation")]
    pub fn never_rotate(mut self) -> Self {
        self.rotation_enabled = false;
        self
    }

    pub fn arena_capacity(mut self, bytes: usize) -> Self {
        self.arena_capacity = bytes;
        self
    }
}

struct WorkerCtl {
    stop: bool,
    rotate_every: Duration,
    next_rotation_at: Instant,
}

struct Shared<P: MkProvider> {
    root_dir: PathBuf,
    pub_dir: PathBuf,
    priv_dir: PathBuf,
    secrets_dir: PathBuf,
    rotate_dir: PathBuf,
    mk_provider: P,
    arena: SecretArena,
    public_cache_policy: PublicCachePolicy,
    keys: RwLock<PublicKeys>,
    error_policy: RotationErrorPolicy,
    poisoned: AtomicBool,
    ctl: Mutex<WorkerCtl>,
    signal: Condvar,
    _lock_file: Option<fs::File>,
}

struct RotationGuard<P: MkProvider> {
    shared: Arc<Shared<P>>,
    handle: Option<JoinHandle<()>>,
}

impl<P: MkProvider> Drop for RotationGuard<P> {
    fn drop(&mut self) {
        self.shared
            .ctl
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .stop = true;
        self.shared.signal.notify_all();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

pub struct KeyManager<P: MkProvider> {
    shared: Arc<Shared<P>>,
    _rotation: Arc<RotationGuard<P>>,
}

impl<P: MkProvider> Clone for KeyManager<P> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
            _rotation: self._rotation.clone(),
        }
    }
}

#[derive(Clone)]
struct RewrapTarget {
    live_path: PathBuf,
    relative_path: PathBuf,
    key_type: String,
}

fn acquire_exclusive_lock(root_dir: &Path, policy: &FileLockPolicy) -> Result<Option<fs::File>> {
    let file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(root_dir.join(LOCK_FILE))
        .map_err(LithiumError::io)?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(fs::TryLockError::WouldBlock) => Err(LithiumError::keystore_locked()),
        Err(fs::TryLockError::Error(e)) => match policy {
            FileLockPolicy::Require => Err(LithiumError::io(e)),
            #[cfg(feature = "best-effort")]
            FileLockPolicy::BestEffort(on_unlocked) => {
                on_unlocked(&LithiumError::io(e));
                Ok(None)
            }
        },
    }
}

#[inline]
fn sync_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        if !path.exists() {
            return Ok(());
        }
        let dir = fs::File::open(path).map_err(LithiumError::io)?;
        dir.sync_all().map_err(LithiumError::io)?;
    }
    let _ = path;
    Ok(())
}

#[inline]
fn write_marker(path: &Path, data: &[u8]) -> Result<()> {
    keyfile::write_secure(path, data)?;
    if let Some(parent) = path.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

fn reconcile_public_cache(
    pub_path: &Path,
    authoritative: &[u8],
    policy: PublicCachePolicy,
    key_type: &'static str,
) -> Result<()> {
    match keyfile::read_keyfile_bytes(pub_path) {
        Ok(on_disk) => {
            if on_disk.expose_as_slice() != authoritative {
                return Err(LithiumError::invalid_public_key(
                    key_type,
                    "public_key_mismatch",
                ));
            }
            Ok(())
        }
        Err(e) if e.is_not_found() => match policy {
            PublicCachePolicy::Strict => Err(LithiumError::invalid_public_key(
                key_type,
                "public_key_missing",
            )),
            PublicCachePolicy::RepairMissingOnly => {
                keyfile::write_secure(pub_path, authoritative)?;
                if let Some(parent) = pub_path.parent() {
                    sync_dir(parent)?;
                }
                Ok(())
            }
        },
        Err(e) => Err(e),
    }
}

fn ensure_seed_keypair<const N: usize, T: AsRef<[u8]>>(
    arena: &SecretArena,
    priv_path: &Path,
    pub_path: &Path,
    mk: &MasterKey32,
    key_type: &'static str,
    policy: PublicCachePolicy,
    pub_from_seed: impl Fn(&ArenaFixedBytes<N>) -> T,
) -> Result<T> {
    if priv_path.exists() {
        let seed = arena.store_fixed_wiped(
            keyfile::load_bytes_decrypted(priv_path, mk, key_type)?.expose_into_array::<N>()?,
        )?;
        if seed.len() != N {
            return Err(LithiumError::malformed_keyfile());
        }
        let pk = pub_from_seed(&seed);
        reconcile_public_cache(pub_path, pk.as_ref(), policy, key_type)?;
        return Ok(pk);
    }

    match keyfile::read_keyfile_bytes(pub_path) {
        Ok(_) => {
            return Err(LithiumError::invalid_public_key(
                key_type,
                "public_key_without_secret",
            ));
        }
        Err(e) if !e.is_not_found() => return Err(e),
        Err(_) => {}
    }

    let seed = arena.random_fixed::<N>()?;
    let pk = pub_from_seed(&seed);
    keyfile::save_bytes_encrypted(priv_path, mk, seed.expose_as_slice(), key_type)?;
    keyfile::write_secure(pub_path, pk.as_ref())?;
    if let Some(parent) = pub_path.parent() {
        sync_dir(parent)?;
    }
    Ok(pk)
}

const MAX_SECRET_LABEL_LEN: usize = 64;

fn validate_secret_label(label: &[u8]) -> Result<()> {
    if label.is_empty() || label.len() > MAX_SECRET_LABEL_LEN {
        return Err(LithiumError::malformed_input("secret_label_len"));
    }
    Ok(())
}

fn label_hex(label: &[u8]) -> String {
    hex::encode(label)
}

fn label_key_type(label: &[u8]) -> String {
    format!("secret32:{}", label_hex(label))
}

fn label_key_type_from_hex(hex_label: &str) -> String {
    format!("secret32:{}", hex_label)
}

fn label_secret_path(secrets_dir: &Path, label: &[u8]) -> PathBuf {
    secrets_dir.join(format!("{}.keyf", label_hex(label)))
}

fn load_or_create_label_secret32(
    secrets_dir: &Path,
    mk: &MasterKey32,
    label: &[u8],
) -> Result<SecByte32> {
    validate_secret_label(label)?;
    let path = label_secret_path(secrets_dir, label);
    let key_type = label_key_type(label);

    if path.exists() {
        return keyfile::load_secret32_decrypted(&path, mk, &key_type);
    }

    let v = keys::random_32()?;
    match keyfile::save_secret32_encrypted_new(&path, mk, &v, &key_type) {
        Ok(()) => Ok(v),
        Err(e) if e.is_already_exists() => keyfile::load_secret32_decrypted(&path, mk, &key_type),
        Err(e) => Err(e),
    }
}

fn load_or_create_label_bytes(
    secrets_dir: &Path,
    mk: &MasterKey32,
    label: &[u8],
    generate: impl FnOnce() -> Result<SecretBytes>,
) -> Result<SecretBytes> {
    validate_secret_label(label)?;
    let path = label_secret_path(secrets_dir, label);
    let key_type = label_key_type(label);

    if path.exists() {
        return keyfile::load_bytes_decrypted(&path, mk, &key_type);
    }

    let v = generate()?;
    match keyfile::save_bytes_encrypted_new(&path, mk, v.expose_as_slice(), &key_type) {
        Ok(()) => Ok(v),
        Err(e) if e.is_already_exists() => keyfile::load_bytes_decrypted(&path, mk, &key_type),
        Err(e) => Err(e),
    }
}

fn ensure_asymmetric_material(
    pub_dir: &Path,
    priv_dir: &Path,
    mk: &MasterKey32,
    arena: &SecretArena,
    public_cache_policy: PublicCachePolicy,
) -> Result<PublicKeys> {
    keyfile::ensure_private_dir(pub_dir)?;
    keyfile::ensure_private_dir(priv_dir)?;

    let ed25519 = ensure_seed_keypair::<32, PubByte32>(
        arena,
        &priv_dir.join(ED_PRIV),
        &pub_dir.join(ED_PUB),
        mk,
        KT_ED_SEED,
        public_cache_policy,
        keys::ed25519_pub_from_seed,
    )?;

    let dilithium = ensure_seed_keypair::<32, PublicBytes>(
        arena,
        &priv_dir.join(DILI_PRIV),
        &pub_dir.join(DILI_PUB),
        mk,
        KT_DILI_SEED,
        public_cache_policy,
        keys::mldsa87_pub_from_seed,
    )?;

    Ok(PublicKeys { ed25519, dilithium })
}

fn list_dir_keyfiles(dir: &Path) -> Result<Vec<PathBuf>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    for ent in fs::read_dir(dir).map_err(LithiumError::io)? {
        let ent = ent.map_err(LithiumError::io)?;
        let path = ent.path();
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("keyf") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

fn collect_rewrap_targets(
    root_dir: &Path,
    priv_dir: &Path,
    secrets_dir: &Path,
) -> Result<Vec<RewrapTarget>> {
    let mut out = Vec::new();

    let fixed = [
        (priv_dir.join(ED_PRIV), KT_ED_SEED.to_owned()),
        (priv_dir.join(DILI_PRIV), KT_DILI_SEED.to_owned()),
    ];

    for (path, key_type) in fixed {
        if path.exists() {
            let relative_path = path
                .strip_prefix(root_dir)
                .map_err(|_| LithiumError::internal("path_not_under_root"))?
                .to_path_buf();
            out.push(RewrapTarget {
                live_path: path,
                relative_path,
                key_type,
            });
        }
    }

    for path in list_dir_keyfiles(secrets_dir)? {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| LithiumError::internal("keyfile_stem_utf8"))?
            .to_owned();

        let relative_path = path
            .strip_prefix(root_dir)
            .map_err(|_| LithiumError::internal("path_not_under_root"))?
            .to_path_buf();

        out.push(RewrapTarget {
            live_path: path,
            relative_path,
            key_type: label_key_type_from_hex(&stem),
        });
    }

    out.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    Ok(out)
}

fn stage_target_path(rotate_dir: &Path, relative_path: &Path) -> PathBuf {
    rotate_dir.join(ROTATE_STAGE_DIR).join(relative_path)
}

fn cleanup_rotation_dir(rotate_dir: &Path) -> Result<()> {
    if rotate_dir.exists() {
        fs::remove_dir_all(rotate_dir).map_err(LithiumError::io)?;
        if let Some(parent) = rotate_dir.parent() {
            sync_dir(parent)?;
        }
    }
    Ok(())
}

fn apply_staged_files(rotate_dir: &Path, targets: &[RewrapTarget]) -> Result<()> {
    for target in targets {
        let staged_path = stage_target_path(rotate_dir, &target.relative_path);
        let staged = keyfile::read_keyfile_bytes(&staged_path)?;
        keyfile::write_secure(&target.live_path, staged.expose_as_slice())?;
        if let Some(parent) = target.live_path.parent() {
            sync_dir(parent)?;
        }
    }
    Ok(())
}

fn prepare_staged_files(
    rotate_dir: &Path,
    old_mk: &MasterKey32,
    new_mk: &MasterKey32,
    targets: &[RewrapTarget],
) -> Result<()> {
    let staged_root = rotate_dir.join(ROTATE_STAGE_DIR);
    keyfile::ensure_private_dir(&staged_root)?;

    for target in targets {
        let out = keyfile::rewrap_keyfile_dek_to_bytes(
            &target.live_path,
            old_mk,
            new_mk,
            &target.key_type,
        )?;
        let staged_path = stage_target_path(rotate_dir, &target.relative_path);
        if let Some(parent) = staged_path.parent() {
            keyfile::ensure_private_dir(parent)?;
        }
        keyfile::write_secure(&staged_path, out.expose_as_slice())?;
        if let Some(parent) = staged_path.parent() {
            sync_dir(parent)?;
        }
    }

    sync_dir(&staged_root)?;
    Ok(())
}

fn recover_pending_rotation_if_any<P: MkProvider>(
    root_dir: &Path,
    priv_dir: &Path,
    secrets_dir: &Path,
    rotate_dir: &Path,
    mk_provider: &P,
) -> Result<()> {
    if !rotate_dir.exists() {
        return Ok(());
    }

    let ready_path = rotate_dir.join(ROTATE_READY_FILE);
    if !ready_path.exists() {
        cleanup_rotation_dir(rotate_dir)?;
        return Ok(());
    }

    let targets = collect_rewrap_targets(root_dir, priv_dir, secrets_dir)?;
    let current_mk = mk_provider.load_mk()?;
    let next_old_path = rotate_dir.join(ROTATE_NEXT_OLD_FILE);
    let next_new_path = rotate_dir.join(ROTATE_NEXT_NEW_FILE);

    let (new_mk, provider_already_switched) = if next_new_path.exists() {
        match keyfile::load_secret32_decrypted(&next_new_path, &current_mk, KT_ROTATE_NEXT_NEW) {
            Ok(candidate) => (candidate, true),
            Err(_) => {
                let candidate = keyfile::load_secret32_decrypted(
                    &next_old_path,
                    &current_mk,
                    KT_ROTATE_NEXT_OLD,
                )?;
                (candidate, false)
            }
        }
    } else {
        let candidate =
            keyfile::load_secret32_decrypted(&next_old_path, &current_mk, KT_ROTATE_NEXT_OLD)?;
        (candidate, false)
    };

    apply_staged_files(rotate_dir, &targets)?;

    if !provider_already_switched {
        mk_provider.store_mk(&new_mk)?;
    }

    cleanup_rotation_dir(rotate_dir)?;
    Ok(())
}

impl<P: MkProvider> Shared<P> {
    fn check_live(&self) -> Result<()> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(LithiumError::internal("keymanager_rotation_disabled"));
        }
        Ok(())
    }

    fn read_gate(&self) -> Result<std::sync::RwLockReadGuard<'_, PublicKeys>> {
        self.check_live()?;
        self.keys
            .read()
            .map_err(|_| LithiumError::internal("keymanager_gate_poisoned"))
    }

    fn rotate_now(&self) -> Result<()> {
        let _write = self
            .keys
            .write()
            .map_err(|_| LithiumError::internal("keymanager_gate_poisoned"))?;

        recover_pending_rotation_if_any(
            &self.root_dir,
            &self.priv_dir,
            &self.secrets_dir,
            &self.rotate_dir,
            &self.mk_provider,
        )?;

        cleanup_rotation_dir(&self.rotate_dir)?;
        keyfile::ensure_private_dir(&self.rotate_dir)?;
        sync_dir(&self.rotate_dir)?;

        let old_mk = self.mk_provider.load_mk()?;
        let new_mk = keys::random_32()?;
        let targets = collect_rewrap_targets(&self.root_dir, &self.priv_dir, &self.secrets_dir)?;

        let next_old_path = self.rotate_dir.join(ROTATE_NEXT_OLD_FILE);
        let next_new_path = self.rotate_dir.join(ROTATE_NEXT_NEW_FILE);
        keyfile::save_secret32_encrypted(&next_old_path, &old_mk, &new_mk, KT_ROTATE_NEXT_OLD)?;
        keyfile::save_secret32_encrypted(&next_new_path, &new_mk, &new_mk, KT_ROTATE_NEXT_NEW)?;
        sync_dir(&self.rotate_dir)?;

        prepare_staged_files(&self.rotate_dir, &old_mk, &new_mk, &targets)?;
        write_marker(&self.rotate_dir.join(ROTATE_READY_FILE), b"ready")?;

        self.commit_rotation(&targets, &new_mk)
    }

    fn commit_rotation(&self, targets: &[RewrapTarget], new_mk: &MasterKey32) -> Result<()> {
        let attempt = (|| -> Result<()> {
            apply_staged_files(&self.rotate_dir, targets)?;
            self.mk_provider.store_mk(new_mk)?;
            cleanup_rotation_dir(&self.rotate_dir)?;
            Ok(())
        })();

        let Err(e) = attempt else {
            return Ok(());
        };

        // Past the ready marker a failed commit leaves a mixed store: finish it or fail closed.
        match recover_pending_rotation_if_any(
            &self.root_dir,
            &self.priv_dir,
            &self.secrets_dir,
            &self.rotate_dir,
            &self.mk_provider,
        ) {
            Ok(()) => Ok(()),
            Err(_) => {
                self.poisoned.store(true, Ordering::Release);
                Err(e)
            }
        }
    }

    fn handle_rotation_error(&self, e: &LithiumError) -> bool {
        match &self.error_policy {
            RotationErrorPolicy::Strict(cb) => {
                self.poisoned.store(true, Ordering::Release);
                cb(e);
                true
            }
            RotationErrorPolicy::Callback(cb) => {
                cb(e);
                false
            }
        }
    }
}

fn rotate_loop<P: MkProvider>(shared: &Arc<Shared<P>>) {
    let mut ctl = shared.ctl.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        if ctl.stop {
            return;
        }
        let now = Instant::now();
        if now >= ctl.next_rotation_at {
            let every = ctl.rotate_every;
            drop(ctl);
            let stop = match shared.rotate_now() {
                Ok(()) => false,
                Err(e) => shared.handle_rotation_error(&e),
            };
            if stop {
                return;
            }
            ctl = shared.ctl.lock().unwrap_or_else(|e| e.into_inner());
            if ctl.stop {
                return;
            }
            match Instant::now().checked_add(every) {
                Some(next) => ctl.next_rotation_at = next,
                None => return,
            }
            continue;
        }
        let wait = ctl.next_rotation_at.saturating_duration_since(now);
        ctl = shared
            .signal
            .wait_timeout(ctl, wait)
            .unwrap_or_else(|e| e.into_inner())
            .0;
    }
}

impl<P: MkProvider + Send + Sync + 'static> KeyManager<P> {
    pub fn start(
        base_dir: &Path,
        mk_provider: P,
        public_cache_policy: PublicCachePolicy,
        rotation_error_policy: RotationErrorPolicy,
    ) -> Result<Self> {
        Self::start_with_config(
            base_dir,
            mk_provider,
            KeyManagerConfig::new(MemoryLocking::Require, public_cache_policy),
            rotation_error_policy,
        )
    }

    #[cfg(feature = "best-effort")]
    pub fn start_best_effort(
        base_dir: &Path,
        mk_provider: P,
        public_cache_policy: PublicCachePolicy,
        rotation_error_policy: RotationErrorPolicy,
    ) -> Result<Self> {
        Self::start_with_config(
            base_dir,
            mk_provider,
            KeyManagerConfig::new(MemoryLocking::BestEffort, public_cache_policy),
            rotation_error_policy,
        )
    }

    pub fn start_with_config(
        base_dir: &Path,
        mk_provider: P,
        config: KeyManagerConfig,
        rotation_error_policy: RotationErrorPolicy,
    ) -> Result<Self> {
        let KeyManagerConfig {
            locking,
            file_lock,
            public_cache_policy,
            rotate_every,
            rotation_enabled,
            arena_capacity,
        } = config;
        if rotation_enabled && rotate_every < KeyManagerConfig::MIN_ROTATE_EVERY {
            return Err(LithiumError::malformed_input("rotate_every_too_small"));
        }
        let root_dir = base_dir.join("KeyManager");
        let pub_dir = root_dir.join(PUB_DIR);
        let priv_dir = root_dir.join(PRIV_DIR);
        let secrets_dir = root_dir.join(SECRETS_DIR);
        let rotate_dir = root_dir.join(ROTATE_DIR);

        keyfile::ensure_private_dir(&root_dir)?;
        keyfile::ensure_private_dir(&pub_dir)?;
        keyfile::ensure_private_dir(&priv_dir)?;
        keyfile::ensure_private_dir(&secrets_dir)?;

        let lock_file = acquire_exclusive_lock(&root_dir, &file_lock)?;

        match mk_provider.load_mk() {
            Ok(_) => {}
            Err(e) if e.is_not_found() => {
                let new_mk = keys::random_32()?;
                mk_provider.store_mk(&new_mk)?;
            }
            Err(e) => return Err(e),
        }

        recover_pending_rotation_if_any(
            &root_dir,
            &priv_dir,
            &secrets_dir,
            &rotate_dir,
            &mk_provider,
        )?;

        let root_mk = mk_provider.load_mk()?;

        let arena = match locking {
            MemoryLocking::Require => SecretArena::with_capacity(arena_capacity)?,
            MemoryLocking::BestEffort => SecretArena::with_capacity_best_effort(arena_capacity)?,
        };
        let public_keys =
            ensure_asymmetric_material(&pub_dir, &priv_dir, &root_mk, &arena, public_cache_policy)?;

        let next_rotation_at = Instant::now()
            .checked_add(rotate_every)
            .ok_or_else(LithiumError::ttl_too_large)?;
        let shared = Arc::new(Shared {
            root_dir,
            pub_dir,
            priv_dir,
            secrets_dir,
            rotate_dir,
            mk_provider,
            arena,
            public_cache_policy,
            keys: RwLock::new(public_keys),
            error_policy: rotation_error_policy,
            poisoned: AtomicBool::new(false),
            ctl: Mutex::new(WorkerCtl {
                stop: false,
                rotate_every,
                next_rotation_at,
            }),
            signal: Condvar::new(),
            _lock_file: lock_file,
        });

        let handle = if rotation_enabled {
            let worker = shared.clone();
            Some(
                thread::Builder::new()
                    .name("lithium-mk-rotation".into())
                    .spawn(move || rotate_loop(&worker))
                    .map_err(LithiumError::io)?,
            )
        } else {
            None
        };

        Ok(Self {
            shared: shared.clone(),
            _rotation: Arc::new(RotationGuard { shared, handle }),
        })
    }

    #[cfg(feature = "insecure-plaintext-mk")]
    pub fn start_plain(
        base_dir: &Path,
        public_cache_policy: PublicCachePolicy,
        rotation_error_policy: RotationErrorPolicy,
    ) -> Result<KeyManager<InsecurePlaintextMkProvider>> {
        let provider = InsecurePlaintextMkProvider::new(base_dir.join("mk"));
        KeyManager::start(
            base_dir,
            provider,
            public_cache_policy,
            rotation_error_policy,
        )
    }

    pub fn public_keys(&self) -> PublicKeys {
        self.shared
            .keys
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn dual_verifying_key(&self) -> DualVerifyingKey {
        let pk = self.public_keys();
        DualVerifyingKey::new(pk.ed25519, pk.dilithium)
    }

    pub fn sign_double(&self, message: &[u8], ctx: &Context) -> Result<DoubleSig> {
        self.signing_seeds(|ed_seed, dili_seed| {
            crate::crypto::sign::sign_double(
                message,
                ed_seed.expose_as_slice(),
                dili_seed.expose_as_slice(),
                ctx,
            )
        })
    }

    pub fn memory_locked(&self) -> bool {
        self.shared.arena.is_locked()
    }

    pub fn set_rotate_interval(&self, interval: Duration) -> Result<()> {
        if interval < KeyManagerConfig::MIN_ROTATE_EVERY {
            return Err(LithiumError::malformed_input("rotate_every_too_small"));
        }
        let next_rotation_at = Instant::now()
            .checked_add(interval)
            .ok_or_else(LithiumError::ttl_too_large)?;
        {
            let mut ctl = self.shared.ctl.lock().unwrap_or_else(|e| e.into_inner());
            ctl.rotate_every = interval;
            ctl.next_rotation_at = next_rotation_at;
        }
        self.shared.signal.notify_all();
        Ok(())
    }

    pub fn reload_public_keys(&self) -> Result<()> {
        self.shared.check_live()?;
        let mut guard = self
            .shared
            .keys
            .write()
            .map_err(|_| LithiumError::internal("keymanager_gate_poisoned"))?;
        let mk = self.shared.mk_provider.load_mk()?;
        *guard = ensure_asymmetric_material(
            &self.shared.pub_dir,
            &self.shared.priv_dir,
            &mk,
            &self.shared.arena,
            self.shared.public_cache_policy,
        )?;
        Ok(())
    }

    pub fn get_or_create_secret32(&self, label: &[u8]) -> Result<SecByte32> {
        let _gate = self.shared.read_gate()?;
        let root_mk = self.shared.mk_provider.load_mk()?;
        self.shared
            .mk_provider
            .get_or_create_secret32(&root_mk, label, &self.shared.secrets_dir)
    }

    pub fn encrypt_with_label(
        &self,
        label: &[u8],
        plaintext: &SecretBytes,
        aad: &[u8],
    ) -> Result<PublicBytes> {
        let dek = self.get_or_create_secret32(label)?;
        let ctx = Context::base("lithium")?
            .add("keymanager")?
            .add("label-aead")?;
        aead::encrypt(plaintext, &dek, &ctx, aad)
    }

    pub fn decrypt_with_label(
        &self,
        label: &[u8],
        blob: &PublicBytes,
        aad: &[u8],
    ) -> Result<SecretBytes> {
        let dek = self.get_or_create_secret32(label)?;
        let ctx = Context::base("lithium")?
            .add("keymanager")?
            .add("label-aead")?;
        aead::decrypt(blob, &dek, &ctx, aad)
    }

    pub fn load_or_create_sealed_blob(
        &self,
        label: &[u8],
        generate: impl FnOnce() -> Result<SecretBytes>,
    ) -> Result<SecretBytes> {
        let _gate = self.shared.read_gate()?;
        let root_mk = self.shared.mk_provider.load_mk()?;
        load_or_create_label_bytes(&self.shared.secrets_dir, &root_mk, label, generate)
    }

    fn signing_seeds<R>(&self, f: impl FnOnce(ArenaByte32, ArenaByte32) -> Result<R>) -> Result<R> {
        let (ed_locked, dili_locked) = {
            let _gate = self.shared.read_gate()?;
            let mk = self.shared.mk_provider.load_mk()?;
            let ed_seed = keyfile::load_secret32_decrypted(
                &self.shared.priv_dir.join(ED_PRIV),
                &mk,
                KT_ED_SEED,
            )?;
            let dili_seed = keyfile::load_bytes_decrypted(
                &self.shared.priv_dir.join(DILI_PRIV),
                &mk,
                KT_DILI_SEED,
            )?;
            let ed_locked = self
                .shared
                .arena
                .store_fixed::<32>(ed_seed.expose_as_array())?;
            let dili_locked = self
                .shared
                .arena
                .store_slice_fixed::<32>(dili_seed.expose_as_slice())?;
            (ed_locked, dili_locked)
        };
        f(ed_locked, dili_locked)
    }

    #[cfg(feature = "raw")]
    pub fn with_signing_seeds<R>(
        &self,
        f: impl FnOnce(ArenaByte32, ArenaByte32) -> Result<R>,
    ) -> Result<R> {
        self.signing_seeds(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_values_are_pinned() {
        assert_eq!(KT_ED_SEED, "ed25519-seed-v1");
        assert_eq!(KT_DILI_SEED, "dilithium-mldsa87-seed-v1");
        assert_eq!(KT_ROTATE_NEXT_OLD, "rotate-next-mk-old-v1");
        assert_eq!(KT_ROTATE_NEXT_NEW, "rotate-next-mk-new-v1");
        assert_eq!(label_key_type(b"ab"), "secret32:6162");

        assert_eq!(ED_PRIV, "ed25519.keyf");
        assert_eq!(DILI_PRIV, "dilithium-mldsa87.keyf");
    }
}
