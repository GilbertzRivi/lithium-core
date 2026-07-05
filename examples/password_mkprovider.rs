// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

//! Example `MkProvider`: seal the master key under a passphrase.
//!
//! The master key is wrapped with AES-256-GCM-SIV under a key derived from the
//! passphrase via Argon2id, so it never touches disk in cleartext. This is the
//! kind of provider a real deployment supplies instead of the cleartext dev one.
//!
//! Run with: `cargo run -p lithium_core --example password_mkprovider`

use std::path::PathBuf;

use argon2::Argon2;
use zeroize::Zeroize;

use lithium_core::crypto::{Context, aead, keys};
use lithium_core::keys::keyfile::{read_keyfile_bytes, write_secure};
use lithium_core::keys::{KeyManager, MkProvider, PublicCachePolicy, RotationErrorPolicy};
use lithium_core::public::PublicBytes;
use lithium_core::secrets::{SecByte32, SecretBytes};
use lithium_core::{LithiumError, Result};

const SALT_LEN: usize = 32;
const WRAP_AAD: &[u8] = b"lithium/example/password-mk/v1";

struct PasswordMkProvider {
    path: PathBuf,
    passphrase: SecretBytes,
}

impl PasswordMkProvider {
    fn derive_kek(&self, salt: &[u8]) -> Result<SecByte32> {
        let mut kek = [0u8; 32];
        Argon2::default()
            .hash_password_into(self.passphrase.expose_as_slice(), salt, &mut kek)
            .map_err(|_| LithiumError::kdf_failed())?;
        let key = SecByte32::from_slice(&kek);
        kek.zeroize();
        key
    }
}

impl MkProvider for PasswordMkProvider {
    fn load_mk(&self) -> Result<SecByte32> {
        // A missing file surfaces as not-found, which tells KeyManager to
        // generate a fresh master key and call store_mk.
        let data = read_keyfile_bytes(&self.path)?;
        let data = data.expose_as_slice();
        if data.len() <= SALT_LEN {
            return Err(LithiumError::malformed_keyfile());
        }
        let (salt, blob) = data.split_at(SALT_LEN);
        let kek = self.derive_kek(salt)?;
        let ctx = Context::base("lithium")?
            .add("example")?
            .add("password-mk")?;
        let mk = aead::decrypt(&PublicBytes::from_slice(blob), &kek, &ctx, WRAP_AAD)?;
        SecByte32::from_slice(mk.expose_as_slice())
    }

    fn store_mk(&self, mk: &SecByte32) -> Result<()> {
        let salt = keys::random_32()?;
        let kek = self.derive_kek(salt.expose_as_slice())?;
        let ctx = Context::base("lithium")?
            .add("example")?
            .add("password-mk")?;
        let blob = aead::encrypt(
            &SecretBytes::from_slice(mk.expose_as_slice()),
            &kek,
            &ctx,
            WRAP_AAD,
        )?;
        let mut out = Vec::with_capacity(SALT_LEN + blob.len());
        out.extend_from_slice(salt.expose_as_slice());
        out.extend_from_slice(blob.as_slice());
        write_secure(&self.path, &out)
    }
}

fn main() -> Result<()> {
    let dir = std::env::temp_dir().join(format!(
        "lithium_password_mk_example_{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).ok();

    let make = || PasswordMkProvider {
        path: dir.join("mk.sealed"),
        passphrase: SecretBytes::from_slice(b"correct horse battery staple"),
    };

    let km = KeyManager::start(
        &dir,
        make(),
        PublicCachePolicy::RepairMissingOnly,
        RotationErrorPolicy::Callback(Box::new(|_| {})),
    )?;
    let first = km.public_keys();

    // Release the exclusive store lock before reopening (one instance per store).
    drop(km);

    let reopened = KeyManager::start(
        &dir,
        make(),
        PublicCachePolicy::RepairMissingOnly,
        RotationErrorPolicy::Callback(Box::new(|_| {})),
    )?;
    let again = reopened.public_keys();

    assert_eq!(first.ed25519.as_slice(), again.ed25519.as_slice());
    assert_eq!(first.x25519.as_slice(), again.x25519.as_slice());

    println!("password-sealed identity persisted and stable across restart");

    std::fs::remove_dir_all(&dir).ok();
    Ok(())
}
