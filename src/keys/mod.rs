// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

pub mod keyfile;
pub mod manager;

pub use manager::{
    FileLockPolicy, KeyManager, KeyManagerConfig, MemoryLocking, MkProvider, PublicCachePolicy,
    PublicKeys, RotationErrorPolicy,
};

#[cfg(feature = "insecure-plaintext-mk")]
pub use manager::InsecurePlaintextMkProvider;
