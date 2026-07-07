// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

//! At-rest key management lifecycle (Pillar 1): `KeyManager` generates and persists the hybrid
//! identity, then reloads it unchanged across a restart.
//!
//! Uses the dev-only cleartext master-key provider, so it needs the `insecure-plaintext-mk`
//! feature. For a production-shaped sealing provider see the `password_mkprovider` example.
//!
//! Run with: `cargo run --features insecure-plaintext-mk -p lithium_core --example keyfile`

use lithium_core::keys::keyfile::ensure_private_dir;
use lithium_core::keys::{
    InsecurePlaintextMkProvider, KeyManager, PublicCachePolicy, RotationErrorPolicy,
};

fn main() -> lithium_core::Result<()> {
    let dir = std::env::temp_dir().join(format!("lithium_keyfile_example_{}", std::process::id()));
    ensure_private_dir(&dir)?;

    // First run generates the Ed25519/ML-DSA-87 signing identity and seals each private key
    // under the master key held by the provider.
    let km = KeyManager::start(
        &dir,
        InsecurePlaintextMkProvider::new(dir.join("mk")),
        PublicCachePolicy::RepairMissingOnly,
        RotationErrorPolicy::Callback(Box::new(|_| {})),
    )?;
    let first = km.public_keys();

    // Release the exclusive store lock before reopening (one instance per store).
    drop(km);

    // A fresh KeyManager over the same directory loads the identity back unchanged.
    let reopened = KeyManager::start(
        &dir,
        InsecurePlaintextMkProvider::new(dir.join("mk")),
        PublicCachePolicy::RepairMissingOnly,
        RotationErrorPolicy::Callback(Box::new(|_| {})),
    )?;
    let again = reopened.public_keys();

    assert_eq!(first.ed25519.as_slice(), again.ed25519.as_slice());
    assert_eq!(first.dilithium.as_slice(), again.dilithium.as_slice());

    println!("identity persisted and stable across restart");

    std::fs::remove_dir_all(&dir).ok();
    Ok(())
}
