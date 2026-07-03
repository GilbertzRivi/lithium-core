// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(unsafe_code)]

use core::fmt;
use core::ptr;
use core::slice;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rand::TryRng;
use rand::rngs::SysRng;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::error::{LithiumError, Result};

const ALIGN: usize = 16;

#[inline]
fn round_up(v: usize, to: usize) -> usize {
    v.div_ceil(to) * to
}

mod os {
    use crate::error::{LithiumError, Result};

    #[cfg(unix)]
    mod imp {
        use super::*;
        use core::ptr;

        pub fn page_size() -> usize {
            unsafe { libc::sysconf(libc::_SC_PAGESIZE).max(1) as usize }
        }

        pub unsafe fn map(size: usize, require_lock: bool) -> Result<(*mut u8, bool)> {
            unsafe {
                let base = libc::mmap(
                    ptr::null_mut(),
                    size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                if base == libc::MAP_FAILED {
                    return Err(LithiumError::io(std::io::Error::last_os_error()));
                }
                let base = base as *mut u8;

                let locked = if libc::mlock(base as *const libc::c_void, size) == 0 {
                    true
                } else if require_lock {
                    let e = std::io::Error::last_os_error();
                    libc::munmap(base as *mut libc::c_void, size);
                    return Err(LithiumError::io(e));
                } else {
                    false
                };

                #[cfg(any(target_os = "linux", target_os = "android"))]
                libc::madvise(base as *mut libc::c_void, size, libc::MADV_DONTDUMP);

                Ok((base, locked))
            }
        }

        pub unsafe fn unmap(base: *mut u8, size: usize) {
            unsafe {
                libc::munlock(base as *const libc::c_void, size);
                libc::munmap(base as *mut libc::c_void, size);
            }
        }
    }

    #[cfg(windows)]
    mod imp {
        use super::*;
        use core::ffi::c_void;
        use core::ptr;
        use windows_sys::Win32::System::Memory::{
            MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree,
            VirtualLock, VirtualUnlock,
        };
        use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

        pub fn page_size() -> usize {
            unsafe {
                let mut info: SYSTEM_INFO = core::mem::zeroed();
                GetSystemInfo(&mut info);
                (info.dwPageSize as usize).max(1)
            }
        }

        pub unsafe fn map(size: usize, require_lock: bool) -> Result<(*mut u8, bool)> {
            unsafe {
                let base =
                    VirtualAlloc(ptr::null(), size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if base.is_null() {
                    return Err(LithiumError::io(std::io::Error::last_os_error()));
                }
                let base = base as *mut u8;

                let locked = if VirtualLock(base as *const c_void, size) != 0 {
                    true
                } else if require_lock {
                    let e = std::io::Error::last_os_error();
                    VirtualFree(base as *mut c_void, 0, MEM_RELEASE);
                    return Err(LithiumError::io(e));
                } else {
                    false
                };

                Ok((base, locked))
            }
        }

        pub unsafe fn unmap(base: *mut u8, size: usize) {
            unsafe {
                VirtualUnlock(base as *const c_void, size);
                VirtualFree(base as *mut c_void, 0, MEM_RELEASE);
            }
        }
    }

    #[cfg(not(any(unix, windows)))]
    mod imp {
        use super::*;

        pub fn page_size() -> usize {
            4096
        }

        pub unsafe fn map(_size: usize, _require_lock: bool) -> Result<(*mut u8, bool)> {
            Err(LithiumError::internal("locked_memory_unsupported_platform"))
        }

        pub unsafe fn unmap(_base: *mut u8, _size: usize) {}
    }

    pub use imp::{map, page_size, unmap};
}

#[derive(Clone)]
pub(crate) struct SecretArena {
    inner: Arc<Mutex<ArenaInner>>,
    locked: bool,
}

struct ArenaInner {
    base: *mut u8,
    size: usize,
    offset: usize,
    free: HashMap<usize, Vec<usize>>,
}

// SAFETY: `base` is a private mmap region reached only through the Mutex; the
// regions handed to `Region` are disjoint and each is owned exclusively.
unsafe impl Send for ArenaInner {}

impl ArenaInner {
    fn alloc(&mut self, len: usize) -> Result<usize> {
        let len = round_up(len.max(1), ALIGN);
        if let Some(slots) = self.free.get_mut(&len)
            && let Some(off) = slots.pop()
        {
            return Ok(off);
        }
        if self.offset + len > self.size {
            return Err(LithiumError::internal("arena_exhausted"));
        }
        let off = self.offset;
        self.offset += len;
        Ok(off)
    }

    fn dealloc(&mut self, off: usize, len: usize) {
        let len = round_up(len.max(1), ALIGN);
        // SAFETY: [off, off+len) is a live, disjoint slice inside the region.
        unsafe {
            ptr::write_bytes(self.base.add(off), 0, len);
        }
        self.free.entry(len).or_default().push(off);
    }
}

impl Drop for ArenaInner {
    fn drop(&mut self) {
        // SAFETY: `base`/`size` come from the successful `os::map` in the constructor
        // and are released exactly once here; zero before unmapping.
        unsafe {
            ptr::write_bytes(self.base, 0, self.size);
            os::unmap(self.base, self.size);
        }
    }
}

struct Region {
    arena: Arc<Mutex<ArenaInner>>,
    ptr: *mut u8,
    off: usize,
    len: usize,
}

// SAFETY: the region is disjoint, address-stable (the mapping never moves) and
// kept alive by `arena`; shared access is read-only, mutation needs `&mut`.
unsafe impl Send for Region {}

unsafe impl Sync for Region {}

impl Region {
    #[inline]
    fn as_slice(&self) -> &[u8] {
        // SAFETY: exclusive, live region for this handle's lifetime.
        unsafe { slice::from_raw_parts(self.ptr, self.len) }
    }

    #[inline]
    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: exclusive, live region; `&mut self` rules out aliasing.
        unsafe { slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.arena.lock() {
            guard.dealloc(self.off, self.len);
        }
    }
}

impl SecretArena {
    pub fn with_capacity(bytes: usize) -> Result<Self> {
        Self::build(bytes, true)
    }

    pub fn with_capacity_best_effort(bytes: usize) -> Result<Self> {
        Self::build(bytes, false)
    }

    fn build(bytes: usize, require_lock: bool) -> Result<Self> {
        let size = round_up(bytes.max(1), os::page_size());
        // SAFETY: `os::map` returns a live, page-aligned mapping of exactly `size`
        // bytes (locked, or unlocked only when `require_lock` is false), or an error.
        let (base, locked) = unsafe { os::map(size, require_lock)? };
        Ok(Self {
            inner: Arc::new(Mutex::new(ArenaInner {
                base,
                size,
                offset: 0,
                free: HashMap::new(),
            })),
            locked,
        })
    }

    pub fn is_locked(&self) -> bool {
        self.locked
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, ArenaInner>> {
        self.inner
            .lock()
            .map_err(|_| LithiumError::internal("arena_lock_poisoned"))
    }

    fn claim(&self, len: usize) -> Result<Region> {
        let mut guard = self.lock()?;
        let off = guard.alloc(len)?;
        let ptr = unsafe { guard.base.add(off) };
        Ok(Region {
            arena: self.inner.clone(),
            ptr,
            off,
            len,
        })
    }

    pub fn random_fixed<const N: usize>(&self) -> Result<ArenaFixedBytes<N>> {
        let mut region = self.claim(N)?;
        let mut rng = SysRng;
        rng.try_fill_bytes(region.as_mut_slice())?;
        Ok(ArenaFixedBytes(region))
    }

    pub fn store_fixed<const N: usize>(&self, secret: &[u8; N]) -> Result<ArenaFixedBytes<N>> {
        let mut region = self.claim(N)?;
        region.as_mut_slice().copy_from_slice(secret);
        Ok(ArenaFixedBytes(region))
    }

    pub fn store_slice_fixed<const N: usize>(&self, slice: &[u8]) -> Result<ArenaFixedBytes<N>> {
        if slice.len() != N {
            return Err(LithiumError::invalid_len(N, slice.len()));
        }
        let mut region = self.claim(N)?;
        region.as_mut_slice().copy_from_slice(slice);
        Ok(ArenaFixedBytes(region))
    }
}

pub struct ArenaFixedBytes<const N: usize>(Region);

pub type ArenaByte32 = ArenaFixedBytes<32>;
pub type ArenaByte64 = ArenaFixedBytes<64>;

impl<const N: usize> ArenaFixedBytes<N> {
    pub const LEN: usize = N;

    #[inline]
    pub fn as_array(&self) -> &[u8; N] {
        <&[u8; N]>::try_from(self.0.as_slice()).expect("region length is N")
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }

    #[inline]
    pub fn len(&self) -> usize {
        N
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        N == 0
    }
}

impl<const N: usize> core::ops::Deref for ArenaFixedBytes<N> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<const N: usize> core::ops::DerefMut for ArenaFixedBytes<N> {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl<const N: usize> AsRef<[u8]> for ArenaFixedBytes<N> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<const N: usize> Zeroize for ArenaFixedBytes<N> {
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
    }
}

impl<const N: usize> PartialEq for ArenaFixedBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice().ct_eq(other.as_slice()).into()
    }
}

impl<const N: usize> Eq for ArenaFixedBytes<N> {}

impl<const N: usize> fmt::Debug for ArenaFixedBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ArenaFixedBytes<{}>(..)", N)
    }
}

pub fn harden_process() -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // SAFETY: prctl with scalar args has no memory effects.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(LithiumError::io(std::io::Error::last_os_error()));
        }
    }

    #[cfg(unix)]
    {
        let rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `rl` is a valid initialized rlimit for the duration of the call.
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rl) } != 0 {
            return Err(LithiumError::io(std::io::Error::last_os_error()));
        }
    }

    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Diagnostics::Debug::{
            SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SetErrorMode,
        };
        use windows_sys::Win32::System::ErrorReporting::{
            WER_FAULT_REPORTING_FLAG_NOHEAP, WerSetFlags,
        };
        // SAFETY: scalar-only Win32 calls with no memory effects.
        unsafe {
            SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
            if WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP) != 0 {
                return Err(LithiumError::io(std::io::Error::last_os_error()));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_arena_reports_locked() {
        let arena = SecretArena::with_capacity(4096).unwrap();
        assert!(
            arena.is_locked(),
            "with_capacity only succeeds when the pages are locked"
        );
    }

    #[test]
    fn best_effort_arena_is_usable_and_reports_lock_state() {
        let arena = SecretArena::with_capacity_best_effort(4096).unwrap();
        let h = arena.store_fixed::<32>(&[0x5A; 32]).unwrap();
        assert_eq!(h.as_array(), &[0x5A; 32]);
        let _ = arena.is_locked();
    }

    #[test]
    fn random_fixed_is_filled_and_distinct() {
        let arena = SecretArena::with_capacity(4096).unwrap();
        let a = arena.random_fixed::<32>().unwrap();
        let b = arena.random_fixed::<32>().unwrap();
        assert_eq!(a.len(), 32);
        assert_eq!(a.as_array().len(), 32);
        assert_ne!(a.as_slice(), b.as_slice());
        assert_ne!(a.as_slice(), [0u8; 32]);
    }

    #[test]
    fn store_roundtrips() {
        let arena = SecretArena::with_capacity(4096).unwrap();
        let f = arena.store_fixed::<4>(&[1, 2, 3, 4]).unwrap();
        assert_eq!(f.as_array(), &[1, 2, 3, 4]);
    }

    #[test]
    fn freed_region_is_zeroized_and_reused() {
        let arena = SecretArena::with_capacity(4096).unwrap();
        let off = {
            let s = arena.store_fixed::<48>(&[0xAB; 48]).unwrap();
            s.0.off
        };
        let reused = arena.claim(48).unwrap();
        assert_eq!(reused.off, off, "same size class must reuse the freed slot");
        assert_eq!(
            reused.as_slice(),
            [0u8; 48],
            "dealloc must have zeroized the freed slot"
        );
    }

    #[test]
    fn exhaustion_is_an_error_not_a_panic() {
        let arena = SecretArena::with_capacity(4096).unwrap();
        let mut held = Vec::new();
        let mut refused = false;
        for _ in 0..1000 {
            match arena.store_fixed::<64>(&[7u8; 64]) {
                Ok(h) => held.push(h),
                Err(_) => {
                    refused = true;
                    break;
                }
            }
        }
        assert!(refused, "arena must refuse allocation past capacity");
    }

    #[test]
    fn harden_process_succeeds() {
        harden_process().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn arena_pages_are_actually_mlocked() {
        fn vmlck_kb() -> u64 {
            std::fs::read_to_string("/proc/self/status")
                .unwrap()
                .lines()
                .find(|l| l.starts_with("VmLck"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse().ok())
                .unwrap()
        }
        let before = vmlck_kb();
        let arena = SecretArena::with_capacity(1 << 20).unwrap();
        let after = vmlck_kb();
        drop(arena);
        assert!(
            after >= before + 512,
            "VmLck must grow by roughly 1 MiB: {before} -> {after}"
        );
    }

    #[test]
    fn dropped_random_secret_does_not_leak_into_reused_slot() {
        let arena = SecretArena::with_capacity(4096).unwrap();
        let (off, leaked) = {
            let s = arena.random_fixed::<32>().unwrap();
            assert_ne!(s.as_array(), &[0u8; 32], "precondition: secret is random");
            (s.0.off, *s.as_array())
        };
        let reused = arena.claim(32).unwrap();
        assert_eq!(reused.off, off, "same size class must reuse the freed slot");
        assert_eq!(
            reused.as_slice(),
            [0u8; 32],
            "freed secret must be zeroized"
        );
        assert_ne!(reused.as_slice(), leaked, "must not observe the old secret");
    }

    #[test]
    fn distinct_live_handles_never_alias() {
        let arena = SecretArena::with_capacity(4096).unwrap();
        let mut a = arena.store_fixed::<32>(&[0xAA; 32]).unwrap();
        let b = arena.store_fixed::<32>(&[0xBB; 32]).unwrap();
        assert_ne!(a.0.ptr, b.0.ptr, "two live handles must be disjoint");
        a.as_mut_slice().fill(0x11);
        assert_eq!(a.as_array(), &[0x11; 32]);
        assert_eq!(
            b.as_array(),
            &[0xBB; 32],
            "mutating one handle must not touch the other"
        );
    }

    #[test]
    fn store_slice_fixed_rejects_wrong_length_without_allocating() {
        let arena = SecretArena::with_capacity(4096).unwrap();
        let base = arena.lock().unwrap().offset;
        assert!(
            arena.store_slice_fixed::<32>(&[0u8; 31]).is_err(),
            "too short"
        );
        assert!(
            arena.store_slice_fixed::<32>(&[0u8; 33]).is_err(),
            "too long"
        );
        assert!(arena.store_slice_fixed::<32>(&[0u8; 0]).is_err(), "empty");
        assert_eq!(
            arena.lock().unwrap().offset,
            base,
            "a rejected input must not consume any arena space"
        );
    }

    #[test]
    fn zero_length_handle_is_harmless() {
        let arena = SecretArena::with_capacity(4096).unwrap();
        let z = arena.store_fixed::<0>(&[0u8; 0]).unwrap();
        assert!(z.is_empty());
        assert_eq!(z.len(), 0);
        assert_eq!(z.as_array(), &[0u8; 0]);
        assert!(arena.random_fixed::<0>().unwrap().is_empty());
    }

    #[test]
    fn handle_outlives_the_arena() {
        let h = {
            let arena = SecretArena::with_capacity(4096).unwrap();
            arena.store_fixed::<32>(&[0x5A; 32]).unwrap()
        };
        assert_eq!(h.as_array(), &[0x5A; 32], "handle valid after arena drop");
        drop(h);
    }

    #[test]
    fn handle_can_move_across_threads() {
        let arena = SecretArena::with_capacity(4096).unwrap();
        let h = arena.store_fixed::<64>(&[0x7E; 64]).unwrap();
        let out = std::thread::spawn(move || *h.as_array()).join().unwrap();
        assert_eq!(out, [0x7E; 64]);
    }

    #[test]
    fn size_classes_that_round_together_share_and_zeroize_slots() {
        let arena = SecretArena::with_capacity(4096).unwrap();
        let off = {
            let one = arena.store_fixed::<1>(&[0xFF]).unwrap();
            one.0.off
        };
        let sixteen = arena.store_fixed::<16>(&[0u8; 16]).unwrap();
        assert_eq!(sixteen.0.off, off, "shared size class must reuse the slot");
        assert_eq!(
            sixteen.as_array(),
            &[0u8; 16],
            "reused slot must be fully zeroed"
        );
    }

    #[test]
    fn regions_are_aligned() {
        let arena = SecretArena::with_capacity(4096).unwrap();
        for n in 0..8u8 {
            let h = arena.store_fixed::<17>(&[n; 17]).unwrap();
            assert_eq!(
                h.0.ptr as usize % ALIGN,
                0,
                "every region must be {ALIGN}-aligned"
            );
        }
    }

    #[test]
    fn exhaustion_recovers_after_a_free() {
        let arena = SecretArena::with_capacity(4096).unwrap();
        let mut held: Vec<_> = Vec::new();
        while let Ok(h) = arena.store_fixed::<64>(&[1u8; 64]) {
            held.push(h);
        }
        assert!(!held.is_empty(), "some allocations must have succeeded");
        held.pop(); // free exactly one slot
        assert!(
            arena.store_fixed::<64>(&[2u8; 64]).is_ok(),
            "a freed slot must be immediately reusable"
        );
    }

    #[test]
    fn poisoned_lock_degrades_to_error_not_panic() {
        let arena = SecretArena::with_capacity(4096).unwrap();
        let live = arena.store_fixed::<32>(&[0xC3; 32]).unwrap();

        let poisoner = arena.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.lock().unwrap();
            panic!("poison the arena mutex");
        })
        .join();

        assert!(
            arena.random_fixed::<32>().is_err(),
            "claim on a poisoned lock must return an error"
        );
        drop(live); // must not panic despite the poisoned lock
    }

    #[test]
    fn concurrent_allocations_stay_isolated() {
        let arena = SecretArena::with_capacity(1 << 16).unwrap();
        let mut workers = Vec::new();
        for tid in 0u8..8 {
            let arena = arena.clone();
            workers.push(std::thread::spawn(move || {
                let pattern = [tid.wrapping_add(1); 48];
                for _ in 0..2000 {
                    let h = arena.store_fixed::<48>(&pattern).unwrap();
                    assert_eq!(h.as_array(), &pattern);
                    drop(h);
                }
            }));
        }
        for w in workers {
            w.join().expect("no worker may panic");
        }
    }

    #[test]
    fn randomized_alloc_free_model() {
        // Deterministic op-sequence stress: in-repo stand-in for fuzzing the allocator.
        enum H {
            B1(ArenaFixedBytes<1>),
            B16(ArenaFixedBytes<16>),
            B17(ArenaFixedBytes<17>),
            B32(ArenaFixedBytes<32>),
            B48(ArenaFixedBytes<48>),
            B64(ArenaFixedBytes<64>),
        }
        impl H {
            fn as_slice(&self) -> &[u8] {
                match self {
                    H::B1(h) => h.as_slice(),
                    H::B16(h) => h.as_slice(),
                    H::B17(h) => h.as_slice(),
                    H::B32(h) => h.as_slice(),
                    H::B48(h) => h.as_slice(),
                    H::B64(h) => h.as_slice(),
                }
            }
            fn as_mut_slice(&mut self) -> &mut [u8] {
                match self {
                    H::B1(h) => h.as_mut_slice(),
                    H::B16(h) => h.as_mut_slice(),
                    H::B17(h) => h.as_mut_slice(),
                    H::B32(h) => h.as_mut_slice(),
                    H::B48(h) => h.as_mut_slice(),
                    H::B64(h) => h.as_mut_slice(),
                }
            }
        }

        fn make(arena: &SecretArena, class: u64, fill: u8) -> Result<H> {
            Ok(match class % 6 {
                0 => H::B1(arena.store_fixed::<1>(&[fill; 1])?),
                1 => H::B16(arena.store_fixed::<16>(&[fill; 16])?),
                2 => H::B17(arena.store_fixed::<17>(&[fill; 17])?),
                3 => H::B32(arena.store_fixed::<32>(&[fill; 32])?),
                4 => H::B48(arena.store_fixed::<48>(&[fill; 48])?),
                _ => H::B64(arena.store_fixed::<64>(&[fill; 64])?),
            })
        }

        let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut rng = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        let arena = SecretArena::with_capacity(1 << 16).unwrap();
        let mut live: Vec<(H, Vec<u8>)> = Vec::new();

        for _ in 0..8_000 {
            let r = rng();
            match r % 3 {
                0 if live.len() < 128 => {
                    let fill = ((r >> 32) as u8) | 1; // non-zero: freed slots read as 0
                    if let Ok(h) = make(&arena, r >> 8, fill) {
                        let expected = vec![fill; h.as_slice().len()];
                        live.push((h, expected));
                    }
                }
                1 if !live.is_empty() => {
                    let idx = (r >> 16) as usize % live.len();
                    live.swap_remove(idx);
                }
                _ if !live.is_empty() => {
                    let idx = (r >> 16) as usize % live.len();
                    let (h, expected) = &mut live[idx];
                    for b in h.as_mut_slice() {
                        *b ^= 0x5A;
                    }
                    for b in expected.iter_mut() {
                        *b ^= 0x5A;
                    }
                }
                _ => {}
            }

            for (h, expected) in &live {
                assert_eq!(
                    h.as_slice(),
                    expected.as_slice(),
                    "handle diverged from model"
                );
                assert!(
                    h.as_slice().iter().any(|&b| b != 0),
                    "live handle read as zeroed"
                );
            }
        }
    }
}
