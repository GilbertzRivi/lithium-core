// CONCATENATED *.rs FILES — 2026-07-04T00:57:59+02:00


// ===== FILE: ./examples/keyfile.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

//! At-rest key management lifecycle (Pillar 1): `KeyManager` generates and persists the hybrid
//! identity, then reloads it unchanged across a restart.
//!
//! Run with: `cargo run -p lithium_core --example keyfile`

use lithium_core::keys::{InsecurePlaintextMkProvider, KeyManager, KeyStoreKind};

fn main() -> lithium_core::Result<()> {
    let dir = std::env::temp_dir().join(format!("lithium_keyfile_example_{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok();

    // First run generates the X25519/Ed25519/ML-KEM/ML-DSA identity and seals each private key
    // under the master key held by the provider.
    let km = KeyManager::start(
        &dir,
        KeyStoreKind::User,
        InsecurePlaintextMkProvider::new(dir.join("mk")),
    )?;
    let first = km.public_keys().clone();

    // Release the exclusive store lock before reopening (one instance per store).
    drop(km);

    // A fresh KeyManager over the same directory loads the identity back unchanged.
    let reopened = KeyManager::start(
        &dir,
        KeyStoreKind::User,
        InsecurePlaintextMkProvider::new(dir.join("mk")),
    )?;
    let again = reopened.public_keys();

    assert_eq!(first.ed25519.as_slice(), again.ed25519.as_slice());
    assert_eq!(first.x25519.as_slice(), again.x25519.as_slice());

    println!("identity persisted and stable across restart");

    std::fs::remove_dir_all(&dir).ok();
    Ok(())
}


// ===== FILE: ./examples/kyberbox.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

//! Hybrid X25519 + ML-KEM-1024 authenticated encryption round-trip (Pillar 2).
//!
//! Run with: `cargo run -p lithium_core --example kyberbox`

use lithium_core::crypto::{Context, keys, kyberbox};
use lithium_core::secrets::SecretBytes;

fn main() -> lithium_core::Result<()> {
    // Caller-chosen domain separation; binds the ciphertext to one usage.
    let ctx = Context::base("myapp")?.add("message")?;

    // Recipient advertises both a classical and a post-quantum public key.
    let (recipient_priv_x, recipient_pub_x) = keys::random_x25519_keypair()?;
    let (recipient_kyber_priv, recipient_kyber_pub) = keys::random_kyber_mlkem1024_keypair()?;

    // Sender draws a fresh ephemeral X25519 keypair per message.
    let (sender_priv_x, sender_pub_x) = keys::random_x25519_keypair()?;

    let body = SecretBytes::from_slice(b"attack at dawn");

    let wire = kyberbox::seal(
        &ctx,
        &sender_priv_x,
        &recipient_pub_x,
        &recipient_kyber_pub,
        b"",
        &body,
    )?;

    let plain_data = kyberbox::open(
        &ctx,
        &recipient_priv_x,
        &sender_pub_x,
        &recipient_kyber_priv,
        b"",
        &wire,
    )?;

    assert_eq!(plain_data.expose_as_slice(), body.expose_as_slice());

    println!(
        "kyberbox round-trip ok ({} sealed body bytes)",
        wire.ciphertext.as_slice().len()
    );
    Ok(())
}


// ===== FILE: ./examples/password_mkprovider.rs =====
// ----------------------------------------

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

use lithium_core::crypto::{aead, keys};
use lithium_core::keys::{KeyManager, KeyStoreKind, MkProvider};
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
        let data = std::fs::read(&self.path).map_err(LithiumError::io)?;
        if data.len() <= SALT_LEN {
            return Err(LithiumError::malformed_keyfile());
        }
        let (salt, blob) = data.split_at(SALT_LEN);
        let kek = self.derive_kek(salt)?;
        let mk = aead::decrypt(&PublicBytes::from_slice(blob), &kek, WRAP_AAD)?;
        SecByte32::from_slice(mk.expose_as_slice())
    }

    fn store_mk(&self, mk: &SecByte32) -> Result<()> {
        let salt = keys::random_32()?;
        let kek = self.derive_kek(salt.as_slice())?;
        let nonce = keys::random_12()?;
        let blob = aead::encrypt(
            &SecretBytes::from_slice(mk.as_slice()),
            &kek,
            &nonce,
            WRAP_AAD,
        )?;
        let mut out = Vec::with_capacity(SALT_LEN + blob.len());
        out.extend_from_slice(salt.as_slice());
        out.extend_from_slice(blob.as_slice());
        std::fs::write(&self.path, &out).map_err(LithiumError::io)
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

    let km = KeyManager::start(&dir, KeyStoreKind::User, make())?;
    let first = km.public_keys().clone();

    // Release the exclusive store lock before reopening (one instance per store).
    drop(km);

    let reopened = KeyManager::start(&dir, KeyStoreKind::User, make())?;
    let again = reopened.public_keys();

    assert_eq!(first.ed25519.as_slice(), again.ed25519.as_slice());
    assert_eq!(first.x25519.as_slice(), again.x25519.as_slice());

    println!("password-sealed identity persisted and stable across restart");

    std::fs::remove_dir_all(&dir).ok();
    Ok(())
}


// ===== FILE: ./fuzz/fuzz_targets/aead_decrypt.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;
use lithium_core::crypto::aead;
use lithium_core::public::PublicBytes;
use lithium_core::secrets::SecByte32;

fuzz_target!(|data: &[u8]| {
    let key = SecByte32::new_zeroed();
    let blob = PublicBytes::from_slice(data);
    let _ = aead::decrypt(&blob, &key, b"fuzz-aad");
});


// ===== FILE: ./fuzz/fuzz_targets/double_sig.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use lithium_core::crypto::keys;
use lithium_core::crypto::sign::{self, DoubleSig};
use lithium_core::public::{PubByte32, PublicBytes};

static PUBKEYS: OnceLock<(PubByte32, PublicBytes)> = OnceLock::new();

fn pubkeys() -> &'static (PubByte32, PublicBytes) {
    PUBKEYS.get_or_init(|| {
        let ed_pub = keys::ed25519_pub_from_seed(&[7u8; 32]);
        let dili_pub = keys::mldsa87_pub_from_seed(&[9u8; 32]).unwrap();
        (ed_pub, dili_pub)
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(sig) = DoubleSig::from_bytes(data) {
        assert_eq!(sig.to_bytes(), data, "from_bytes/to_bytes must round-trip");
        let (ed_pub, dili_pub) = pubkeys();
        let _ = sign::verify_double(b"fuzz-msg", &sig, ed_pub, dili_pub);
    }
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = DoubleSig::from_hex(s);
    }
});


// ===== FILE: ./fuzz/fuzz_targets/hpke_open.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use lithium_core::crypto::context::Context;
use lithium_core::hpke::{self, HpkeEnc, HpkeSealed};
use lithium_core::public::PublicBytes;
use lithium_core::secrets::{SecByte32, SecretBytes};

static SK: OnceLock<(SecByte32, SecretBytes)> = OnceLock::new();
static CTX: OnceLock<Context<'static>> = OnceLock::new();

fn ctx() -> &'static Context<'static> {
    CTX.get_or_init(|| Context::base("fuzz").unwrap())
}

fn sk() -> &'static (SecByte32, SecretBytes) {
    SK.get_or_init(|| {
        let (sk, _) = hpke::derive_keypair(ctx(), b"fuzz-recipient").unwrap();
        let w = sk.to_wire();
        let w = w.expose_as_slice();
        (
            SecByte32::from_slice(&w[..32]).unwrap(),
            SecretBytes::from_slice(&w[32..]),
        )
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 34 {
        return;
    }
    let (x_priv, k_priv) = sk();
    let mid = 33 + (data[0] as usize % (data.len() - 33));
    let Ok(enc) = HpkeEnc::from_wire(&data[1..mid]) else {
        return;
    };
    let sealed = HpkeSealed {
        enc,
        ciphertext: PublicBytes::from_slice(&data[mid..]),
    };
    let _ = hpke::open_base(ctx(), x_priv, k_priv, b"info", b"aad", &sealed);
});


// ===== FILE: ./fuzz/fuzz_targets/hpke_setup_receiver.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use lithium_core::crypto::context::Context;
use lithium_core::hpke::{self, HpkeEnc, HpkePrivateKey};

static SK: OnceLock<HpkePrivateKey> = OnceLock::new();
static CTX: OnceLock<Context<'static>> = OnceLock::new();

fn ctx() -> &'static Context<'static> {
    CTX.get_or_init(|| Context::base("fuzz").unwrap())
}

fn sk() -> &'static HpkePrivateKey {
    SK.get_or_init(|| hpke::derive_keypair(ctx(), b"fuzz-recipient").unwrap().0)
}

fuzz_target!(|data: &[u8]| {
    let Ok(enc) = HpkeEnc::from_wire(data) else {
        return;
    };
    let _ = hpke::setup_receiver_and_export(ctx(), sk(), &enc, b"info", b"exp", 64);
});


// ===== FILE: ./fuzz/fuzz_targets/hpke_stream.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use lithium_core::crypto::context::Context;
use lithium_core::hpke::{self, HpkeEnc, HpkePrivateKey};
use lithium_core::public::PublicBytes;

static SETUP: OnceLock<(HpkePrivateKey, HpkeEnc)> = OnceLock::new();
static CTX: OnceLock<Context<'static>> = OnceLock::new();

fn ctx() -> &'static Context<'static> {
    CTX.get_or_init(|| Context::base("fuzz").unwrap())
}

fn setup() -> &'static (HpkePrivateKey, HpkeEnc) {
    SETUP.get_or_init(|| {
        let (sk, pk) = hpke::derive_keypair(ctx(), b"fuzz-recipient").unwrap();
        let (enc, _sender) = hpke::setup_sender(ctx(), &pk, b"info").unwrap();
        (sk, enc)
    })
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let (sk, enc) = setup();
    let Ok(mut receiver) = hpke::setup_receiver(ctx(), sk, enc, b"info") else {
        return;
    };
    let split = (data[0] as usize % data.len()).min(data.len() - 1);
    let (aad, ct) = data[1..].split_at(split);
    let _ = receiver.open(aad, &PublicBytes::from_slice(ct));
});


// ===== FILE: ./fuzz/fuzz_targets/hpke_wire.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;
use lithium_core::hpke::{HpkeEnc, HpkePrivateKey, HpkePublicKey};

fuzz_target!(|data: &[u8]| {
    let _ = HpkeEnc::from_wire(data);
    let _ = HpkePublicKey::from_wire(data);
    let _ = HpkePrivateKey::from_wire(data);
});


// ===== FILE: ./fuzz/fuzz_targets/keyfile_parse.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = lithium_core::keys::keyfile::parse_keyfile_fuzz(data);
});


// ===== FILE: ./fuzz/fuzz_targets/kyberbox_decrypt.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use lithium_core::crypto::context::Context;
use lithium_core::crypto::keys;
use lithium_core::crypto::kyberbox::{self, KyberBoxSealed};
use lithium_core::public::{PubByte32, PublicBytes};
use lithium_core::secrets::{SecByte32, SecretBytes};

static KP: OnceLock<(SecByte32, PubByte32, SecretBytes)> = OnceLock::new();
static CTX: OnceLock<Context<'static>> = OnceLock::new();

fn kp() -> &'static (SecByte32, PubByte32, SecretBytes) {
    KP.get_or_init(|| {
        let (x_priv, x_pub) = keys::random_x25519_keypair().unwrap();
        let (k_priv, _) = keys::random_kyber_mlkem1024_keypair().unwrap();
        (x_priv, x_pub, k_priv)
    })
}

fn ctx() -> &'static Context<'static> {
    CTX.get_or_init(|| Context::base("fuzz").unwrap())
}

fuzz_target!(|data: &[u8]| {
    let (x_priv, peer_pub_x, k_priv) = kp();

    let n = data.len();
    let kem_end = n / 3;
    let ct_end = 2 * n / 3;

    let wire = KyberBoxSealed {
        kem_ct: PublicBytes::from_slice(&data[..kem_end]),
        ciphertext: PublicBytes::from_slice(&data[kem_end..ct_end]),
    };
    let aad = &data[ct_end..];

    let _ = kyberbox::open(ctx(), x_priv, peer_pub_x, k_priv, aad, &wire);
});

// ===== FILE: ./fuzz/fuzz_targets/opaque_parse.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    lithium_core::opaque::server::opaque_parse_fuzz(data);
});


// ===== FILE: ./fuzz/fuzz_targets/secret_json.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = lithium_core::secrets::SecretJson::from_bytes(data);
});


// ===== FILE: ./fuzz/fuzz_targets/sign_verify.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;
use lithium_core::crypto::sign;
use lithium_core::public::{PubByte32, PublicBytes};

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    let ed_pub = PubByte32::from_slice(&data[..32]).unwrap_or_else(|_| PubByte32::new([0u8; 32]));
    let (sig, msg) = if data.len() > 96 {
        (&data[32..96], &data[96..])
    } else {
        (&data[32..], &[][..])
    };

    let _ = sign::verify_signature(msg, sig, &ed_pub);
    let _ = sign::verify_signature_dili(msg, sig, &PublicBytes::from_slice(data));
});


// ===== FILE: ./fuzz/target/debug/build/serde-1d0bc57d932fdf57/out/private.rs =====
// ----------------------------------------

#[doc(hidden)]
pub mod __private228 {
    #[doc(hidden)]
    pub use crate::private::*;
}
use serde_core::__private228 as serde_core_private;


// ===== FILE: ./fuzz/target/debug/build/serde-b7d6bd1946fd92ab/out/private.rs =====
// ----------------------------------------

#[doc(hidden)]
pub mod __private228 {
    #[doc(hidden)]
    pub use crate::private::*;
}
use serde_core::__private228 as serde_core_private;


// ===== FILE: ./fuzz/target/debug/build/serde_core-25ee74d02b86f26d/out/private.rs =====
// ----------------------------------------

#[doc(hidden)]
pub mod __private228 {
    #[doc(hidden)]
    pub use crate::private::*;
}


// ===== FILE: ./fuzz/target/debug/build/serde_core-65eed7f7203d3051/out/private.rs =====
// ----------------------------------------

#[doc(hidden)]
pub mod __private228 {
    #[doc(hidden)]
    pub use crate::private::*;
}


// ===== FILE: ./fuzz/target/x86_64-unknown-linux-gnu/release/build/serde-0af4575e53182d0b/out/private.rs =====
// ----------------------------------------

#[doc(hidden)]
pub mod __private228 {
    #[doc(hidden)]
    pub use crate::private::*;
}
use serde_core::__private228 as serde_core_private;


// ===== FILE: ./fuzz/target/x86_64-unknown-linux-gnu/release/build/serde_core-edeb9dd8975370ec/out/private.rs =====
// ----------------------------------------

#[doc(hidden)]
pub mod __private228 {
    #[doc(hidden)]
    pub use crate::private::*;
}


// ===== FILE: ./src/crypto/aead.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use aes_gcm_siv::{
    Aes256GcmSiv, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};

use crate::{
    error::{LithiumError, Result},
    public::PublicBytes,
    secrets::bytes::SecretBytes,
    secrets::{SecByte12, SecByte32},
};

const AEAD_BLOB_VERSION: u8 = 1;

pub fn encrypt_raw(
    plaintext: &SecretBytes,
    key: &SecByte32,
    nonce: &SecByte12,
    aad: &[u8],
) -> Result<PublicBytes> {
    let key: &Key<Aes256GcmSiv> = key.as_slice().into();

    let nonce: &Nonce = nonce.as_slice().into();

    let cipher = Aes256GcmSiv::new(key);
    let ct = cipher.encrypt(
        nonce,
        Payload {
            msg: plaintext.expose_as_slice(),
            aad,
        },
    )?;

    Ok(PublicBytes::new(ct))
}

pub fn decrypt_raw(
    ciphertext: &PublicBytes,
    key: &SecByte32,
    nonce: &SecByte12,
    aad: &[u8],
) -> Result<SecretBytes> {
    let key: &Key<Aes256GcmSiv> = key.as_slice().into();

    let nonce: &Nonce = nonce.as_slice().into();

    let cipher = Aes256GcmSiv::new(key);
    let pt = cipher.decrypt(
        nonce,
        Payload {
            msg: ciphertext.as_slice(),
            aad,
        },
    )?;

    Ok(SecretBytes::new(pt))
}

pub fn encrypt(
    plaintext: &SecretBytes,
    key: &SecByte32,
    nonce: &SecByte12,
    aad: &[u8],
) -> Result<PublicBytes> {
    let ct = encrypt_raw(plaintext, key, nonce, aad)?;
    let mut out = Vec::with_capacity(1 + 12 + ct.len());
    out.push(AEAD_BLOB_VERSION);
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(ct.as_slice());
    Ok(PublicBytes::new(out))
}

pub fn decrypt(blob: &PublicBytes, key: &SecByte32, aad: &[u8]) -> Result<SecretBytes> {
    let bytes = blob.as_slice();
    if bytes.len() < 1 + 12 + 16 {
        return Err(LithiumError::aead_failed());
    }
    if bytes[0] != AEAD_BLOB_VERSION {
        return Err(LithiumError::aead_failed());
    }
    let nonce = SecByte12::from_slice(&bytes[1..13])?;
    decrypt_raw(&PublicBytes::from_slice(&bytes[13..]), key, &nonce, aad)
}


// ===== FILE: ./src/crypto/context.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::borrow::Cow;

use crate::error::{LithiumError, Result};
use crate::public::PublicBytes;

const VERSION: &str = "v1";
const MAX_CONTEXT_LEN: usize = 255;

fn validate_segment(seg: &str) -> Result<()> {
    if seg.is_empty() {
        return Err(LithiumError::invalid_context("empty_segment"));
    }
    if !seg.bytes().all(|b| (0x21..=0x7e).contains(&b) && b != b'/') {
        return Err(LithiumError::invalid_context("segment_charset"));
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Context<'a>(Cow<'a, str>);

impl<'a> Context<'a> {
    pub fn base(root: &'a str) -> Result<Self> {
        validate_segment(root)?;
        if root.len() > MAX_CONTEXT_LEN {
            return Err(LithiumError::invalid_context("too_long"));
        }
        Ok(Self(Cow::Borrowed(root)))
    }

    pub fn add(&self, segment: &str) -> Result<Context<'static>> {
        validate_segment(segment)?;
        let joined = format!("{}/{}", self.0, segment);
        if joined.len() > MAX_CONTEXT_LEN {
            return Err(LithiumError::invalid_context("too_long"));
        }
        Ok(Context(Cow::Owned(joined)))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn label(&self) -> PublicBytes {
        PublicBytes::from_slice(format!("{}/{}", self.0, VERSION).as_bytes())
    }
}


// ===== FILE: ./src/crypto/hash.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use sha2::{Digest, Sha256};

use crate::secrets::SecByte32;

pub fn sha256(data: &[u8]) -> SecByte32 {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    SecByte32::new(out)
}


// ===== FILE: ./src/crypto/kdf.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::{
    error::{LithiumError, Result},
    secrets::SecByte32,
    secrets::bytes::SecretBytes,
};

pub(crate) const ARGON2_M_COST: u32 = 64 * 1024;
pub(crate) const ARGON2_T_COST: u32 = 3;
pub(crate) const ARGON2_P_COST: u32 = 1;
pub(crate) const ARGON2_OUT_LEN: usize = 32;

pub fn derive32(input: &SecretBytes, salt: Option<&SecretBytes>, info: &[u8]) -> Result<SecByte32> {
    let out = derive_bytes(input, salt, info, 32)?;
    SecByte32::from_slice(out.expose_as_slice())
}

pub fn derive_bytes(
    input: &SecretBytes,
    salt: Option<&SecretBytes>,
    info: &[u8],
    len: usize,
) -> Result<SecretBytes> {
    let hk = Hkdf::<Sha256>::new(salt.map(|s| s.expose_as_slice()), input.expose_as_slice());

    let mut out = vec![0u8; len];
    hk.expand(info, &mut out)?;

    Ok(SecretBytes::new(out))
}

pub fn hkdf_extract(salt: Option<&SecretBytes>, ikm: &SecretBytes) -> SecByte32 {
    let (prk, _) =
        Hkdf::<Sha256>::extract(salt.map(|s| s.expose_as_slice()), ikm.expose_as_slice());

    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    SecByte32::new(out)
}

pub fn hkdf_expand(prk: &SecByte32, info: &SecretBytes, len: usize) -> Result<SecretBytes> {
    let hk = Hkdf::<Sha256>::from_prk(prk.as_slice())
        .map_err(|_| LithiumError::internal("hkdf_prk_len"))?;

    let mut out = vec![0u8; len];
    hk.expand(info.expose_as_slice(), &mut out)?;

    Ok(SecretBytes::new(out))
}

pub fn argon2id() -> Result<Argon2<'static>> {
    let params = Params::new(
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(ARGON2_OUT_LEN),
    )
    .map_err(|_| LithiumError::internal("argon2_params"))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}


// ===== FILE: ./src/crypto/keys.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::error::{LithiumError, Result};
use crate::public::{PubByte32, PublicBytes};
use crate::secrets::{MasterKey32, Nonce12, SecretBytes, SecretFixedBytes, SessionId32};
use ed25519_dalek::SigningKey;
use ml_dsa::{B32, Keypair, MlDsa87, SigningKey as DsaSigningKey};
use ml_kem::{DecapsulationKey1024, Seed as MlKemSeed, kem::KeyExport as KemKeyExport};
use rand::TryRng;
use rand::rngs::SysRng;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

#[inline]
pub fn random_fixed<const N: usize>() -> Result<SecretFixedBytes<N>> {
    let mut out = SecretFixedBytes::<N>::new_zeroed();
    let mut rng = SysRng;
    rng.try_fill_bytes(out.as_mut_slice())?;
    Ok(out)
}
#[inline]
pub fn random_12() -> Result<Nonce12> {
    random_fixed::<12>()
}
#[inline]
pub fn random_32() -> Result<SessionId32> {
    random_fixed::<32>()
}
#[inline]
pub fn random_master_key32() -> Result<MasterKey32> {
    random_fixed::<32>()
}

#[inline]
pub fn ed25519_pub_from_seed(seed: &[u8; 32]) -> PubByte32 {
    let sk = SigningKey::from_bytes(seed);
    PubByte32::new(sk.verifying_key().to_bytes())
}

#[inline]
pub fn x25519_pub_from_seed(seed: &[u8; 32]) -> PubByte32 {
    let sk = XStaticSecret::from(*seed);
    PubByte32::new(*XPublicKey::from(&sk).as_bytes())
}

#[inline]
pub fn mlkem1024_pub_from_seed(seed: &[u8]) -> Result<PublicBytes> {
    if seed.len() != 64 {
        return Err(LithiumError::invalid_len(64, seed.len()));
    }
    let mut s = MlKemSeed::default();
    s.copy_from_slice(seed);
    let dk = DecapsulationKey1024::from_seed(s);
    let ek = dk.encapsulation_key();
    Ok(PublicBytes::from_slice(ek.to_bytes().as_ref()))
}

#[inline]
pub fn mldsa87_pub_from_seed(seed: &[u8]) -> Result<PublicBytes> {
    if seed.len() != 32 {
        return Err(LithiumError::invalid_len(32, seed.len()));
    }
    let mut xi = B32::default();
    xi.copy_from_slice(seed);
    let sk = DsaSigningKey::<MlDsa87>::from_seed(&xi);
    Ok(PublicBytes::from_slice(
        sk.verifying_key().to_bytes().as_ref(),
    ))
}

#[inline]
pub fn random_x25519_keypair() -> Result<(SecretFixedBytes<32>, PubByte32)> {
    let sk_seed = random_fixed::<32>()?;
    let pk = x25519_pub_from_seed(sk_seed.as_array());
    Ok((sk_seed, pk))
}

#[inline]
pub fn random_ed25519_keypair() -> Result<(SecretFixedBytes<32>, PubByte32)> {
    let seed = random_fixed::<32>()?;
    let pk = ed25519_pub_from_seed(seed.as_array());
    Ok((seed, pk))
}

#[inline]
pub fn random_kyber_mlkem1024_keypair() -> Result<(SecretBytes, PublicBytes)> {
    let seed = random_fixed::<64>()?;
    let pk = mlkem1024_pub_from_seed(seed.as_slice())?;
    Ok((SecretBytes::from_slice(seed.as_slice()), pk))
}

#[inline]
pub fn random_dilithium_mldsa87_keypair() -> Result<(SecretBytes, PublicBytes)> {
    let seed = random_fixed::<32>()?;
    let pk = mldsa87_pub_from_seed(seed.as_slice())?;
    Ok((SecretBytes::from_slice(seed.as_slice()), pk))
}


// ===== FILE: ./src/crypto/kyberbox.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use ml_kem::{
    Ciphertext as MlKemCiphertext, DecapsulationKey1024, EncapsulationKey1024, MlKem1024, Seed,
    TryKeyInit,
    kem::{Decapsulate, Encapsulate},
};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

use crate::{
    crypto::{aead, context::Context, kdf, keys},
    error::{LithiumError, Result},
    public::{PubByte32, PublicBytes},
    secrets::{SecByte32, bytes::SecretBytes},
};

const KYBER_BOX_VERSION: u8 = 1;
const KYBER_KEM_ID: u8 = 1;

#[derive(Clone, Debug)]
pub struct KyberBoxSealed {
    pub ciphertext: PublicBytes,
    pub kem_ct: PublicBytes,
}

#[inline]
fn derive_ecdh_key(
    priv_x: &SecByte32,
    peer_pub_x: &PubByte32,
    ecdh_label: &PublicBytes,
) -> Result<SecByte32> {
    let my_secret = XStaticSecret::from(*priv_x.as_array());
    let peer_pub = XPublicKey::from(*peer_pub_x.as_array());
    let shared = my_secret.diffie_hellman(&peer_pub);

    if !shared.was_contributory() {
        return Err(LithiumError::invalid_public_key("x25519_low_order"));
    }

    let shared_secret = SecByte32::new(shared.to_bytes());

    kdf::derive32(
        &SecretBytes::from_slice(shared_secret.as_slice()),
        None,
        ecdh_label.as_slice(),
    )
}

// UniversalCombiner (draft-irtf-cfrg-hybrid-kems): HKDF-Extract dual-PRF over ss_kem (salt) and
// ecdh_key (IKM). ct_t/ek_t are bound explicitly because X25519 has no binding of its own; ek_PQ
// is already bound inside ss_kem by ML-KEM's H(ek), so only ct_PQ is added.
#[inline]
fn derive_base_key(
    ss_kem: &SecByte32,
    ecdh_key: &SecByte32,
    ct_t: &[u8; 32],
    ek_t: &[u8; 32],
    ct_pq_hash: &[u8; 32],
    base_label: &PublicBytes,
) -> Result<SecByte32> {
    let ecdh_input = SecretBytes::from_slice(ecdh_key.as_slice());
    let ss_salt = SecretBytes::from_slice(ss_kem.as_slice());

    let mut info = base_label.as_slice().to_vec();
    info.extend_from_slice(ct_t);
    info.extend_from_slice(ek_t);
    info.extend_from_slice(ct_pq_hash);

    kdf::derive32(&ecdh_input, Some(&ss_salt), &info)
}

fn encapsulate_kem(peer_kyber_pub: &[u8]) -> Result<(SecByte32, [u8; 32], PublicBytes)> {
    let pk = EncapsulationKey1024::new_from_slice(peer_kyber_pub)
        .map_err(|_| LithiumError::invalid_public_key("mlkem_encapsulation_key"))?;

    let (ct_kem, ss) = pk.encapsulate();

    let ct_bytes = ct_kem.as_slice();
    let ss_bytes = SecByte32::from_slice(ss.as_ref())
        .map_err(|_| LithiumError::internal("mlkem_shared_secret_len"))?;

    let digest = Sha256::digest(ct_bytes);
    let mut ct_hash = [0u8; 32];
    ct_hash.copy_from_slice(&digest);

    let mut blob = Vec::with_capacity(2 + ct_bytes.len());
    blob.push(KYBER_BOX_VERSION);
    blob.push(KYBER_KEM_ID);
    blob.extend_from_slice(ct_bytes);

    Ok((ss_bytes, ct_hash, PublicBytes::new(blob)))
}

fn decapsulate_kem(kyber_priv_bytes: &[u8], blob: &[u8]) -> Result<(SecByte32, [u8; 32])> {
    if blob.len() < 2 {
        return Err(LithiumError::kem_invalid_ciphertext());
    }
    if blob[0] != KYBER_BOX_VERSION || blob[1] != KYBER_KEM_ID {
        return Err(LithiumError::kem_invalid_ciphertext());
    }

    let ct_slice = &blob[2..];

    let digest = Sha256::digest(ct_slice);
    let mut ct_hash = [0u8; 32];
    ct_hash.copy_from_slice(&digest);

    if kyber_priv_bytes.len() != 64 {
        return Err(LithiumError::invalid_len(64, kyber_priv_bytes.len()));
    }

    let mut seed = Seed::default();
    seed.copy_from_slice(kyber_priv_bytes);

    let sk = DecapsulationKey1024::from_seed(seed);

    let ct = MlKemCiphertext::<MlKem1024>::try_from(ct_slice)
        .map_err(|_| LithiumError::kem_invalid_ciphertext())?;

    let ss = sk.decapsulate(&ct);
    let ss_bytes = SecByte32::from_slice(ss.as_ref())
        .map_err(|_| LithiumError::internal("mlkem_shared_secret_len"))?;

    Ok((ss_bytes, ct_hash))
}

pub(crate) fn prep_base_key_for_encryption(
    ctx: &Context,
    priv_x: &SecByte32,
    peer_pub_x: &PubByte32,
    peer_k_pub: &PublicBytes,
) -> Result<(SecByte32, PublicBytes)> {
    let ecdh_key = derive_ecdh_key(priv_x, peer_pub_x, &ctx.add("ecdh-key")?.label())?;

    let ct_t = *XPublicKey::from(&XStaticSecret::from(*priv_x.as_array())).as_bytes();
    let ek_t = *peer_pub_x.as_array();

    let (ss_kem, ct_hash, kem_ct) = encapsulate_kem(peer_k_pub.as_slice())?;

    let base_key = derive_base_key(
        &ss_kem,
        &ecdh_key,
        &ct_t,
        &ek_t,
        &ct_hash,
        &ctx.add("base-key")?.label(),
    )?;

    Ok((base_key, kem_ct))
}

pub(crate) fn prep_base_key_for_decryption(
    ctx: &Context,
    priv_x: &SecByte32,
    peer_pub_x: &PubByte32,
    kyber_priv: &SecretBytes,
    kem_ct: &PublicBytes,
) -> Result<SecByte32> {
    let ecdh_key = derive_ecdh_key(priv_x, peer_pub_x, &ctx.add("ecdh-key")?.label())?;

    let ct_t = *peer_pub_x.as_array();
    let ek_t = *XPublicKey::from(&XStaticSecret::from(*priv_x.as_array())).as_bytes();

    let (ss_kem, ct_hash) = decapsulate_kem(kyber_priv.expose_as_slice(), kem_ct.as_slice())?;

    let base_key = derive_base_key(
        &ss_kem,
        &ecdh_key,
        &ct_t,
        &ek_t,
        &ct_hash,
        &ctx.add("base-key")?.label(),
    )?;

    Ok(base_key)
}

// The 0x00 matters so you can’t bypass / can’t confuse / cannot impersonate another context.
fn data_aad(ctx: &Context, aad: &[u8]) -> Result<Vec<u8>> {
    let mut framed = ctx.add("data")?.label().as_slice().to_vec();
    if !aad.is_empty() {
        framed.push(0);
        framed.extend_from_slice(aad);
    }
    Ok(framed)
}

pub fn seal(
    ctx: &Context,
    priv_x: &SecByte32,
    peer_pub_x: &PubByte32,
    peer_k_pub: &PublicBytes,
    aad: &[u8],
    data: &SecretBytes,
) -> Result<KyberBoxSealed> {
    let (base_key, kem_ct) = prep_base_key_for_encryption(ctx, priv_x, peer_pub_x, peer_k_pub)?;
    let nonce = keys::random_12()?;
    let ciphertext = aead::encrypt(data, &base_key, &nonce, &data_aad(ctx, aad)?)?;

    Ok(KyberBoxSealed { ciphertext, kem_ct })
}

pub fn open(
    ctx: &Context,
    priv_x: &SecByte32,
    peer_pub_x: &PubByte32,
    kyber_priv: &SecretBytes,
    aad: &[u8],
    kyber_box_sealed: &KyberBoxSealed,
) -> Result<SecretBytes> {
    let base_key = prep_base_key_for_decryption(
        ctx,
        priv_x,
        peer_pub_x,
        kyber_priv,
        &kyber_box_sealed.kem_ct,
    )?;
    let plaintext = aead::decrypt(
        &kyber_box_sealed.ciphertext,
        &base_key,
        &data_aad(ctx, aad)?,
    )?;

    Ok(plaintext)
}


// ===== FILE: ./src/crypto/mod.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

pub mod aead;
pub mod context;
pub mod hash;
pub mod kdf;
pub mod keys;
pub mod kyberbox;
pub mod sign;

pub use context::Context;


// ===== FILE: ./src/crypto/sign.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    error::{LithiumError, Result},
    public::{PubByte32, PublicBytes},
    secrets::SecByte32,
};

use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as Ed25519Signer, SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey,
};

use ml_dsa::{
    KeyInit, MlDsa87, Signature as MlDsaSignature, SigningKey as MlDsaSigningKey,
    VerifyingKey as MlDsaVerifyingKey,
    signature::{SignatureEncoding, Signer as MlDsaSigner, Verifier as MlDsaVerifier},
};

pub fn sign_message<S: AsRef<[u8]>>(message: &[u8], priv_ed_seed: S) -> Result<Vec<u8>> {
    let seed = SecByte32::from_slice(priv_ed_seed.as_ref())?;
    let signing = Ed25519SigningKey::from_bytes(seed.as_array());
    let sig: Ed25519Signature = signing.sign(message);

    Ok(sig.to_bytes().to_vec())
}

pub fn verify_signature(message: &[u8], signature: &[u8], pub_key: &PubByte32) -> bool {
    if signature.len() != 64 {
        return false;
    }

    let sig = match Ed25519Signature::from_slice(signature) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let pk = match Ed25519VerifyingKey::from_bytes(pub_key.as_array()) {
        Ok(v) => v,
        Err(_) => return false,
    };

    pk.verify_strict(message, &sig).is_ok()
}

pub fn sign_message_dili<S: AsRef<[u8]>>(message: &[u8], dili_sk_bytes: S) -> Result<Vec<u8>> {
    let sk = MlDsaSigningKey::<MlDsa87>::new_from_slice(dili_sk_bytes.as_ref())
        .map_err(|_| LithiumError::key_import_failed("mldsa_signing_key"))?;

    let sig: MlDsaSignature<MlDsa87> = sk.sign(message);
    let sig_bytes = sig.to_bytes();

    Ok(sig_bytes.as_slice().to_vec())
}

pub fn verify_signature_dili(
    message: &[u8],
    signature: &[u8],
    dili_pk_bytes: &PublicBytes,
) -> bool {
    let Ok(pk) = MlDsaVerifyingKey::<MlDsa87>::new_from_slice(dili_pk_bytes.as_slice()) else {
        return false;
    };

    let Ok(sig) = MlDsaSignature::<MlDsa87>::try_from(signature) else {
        return false;
    };

    pk.verify(message, &sig).is_ok()
}

const ED25519_SIG_LEN: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DoubleSig {
    ed: [u8; ED25519_SIG_LEN],
    dili: Vec<u8>,
}

impl DoubleSig {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ED25519_SIG_LEN + self.dili.len());
        out.extend_from_slice(&self.ed);
        out.extend_from_slice(&self.dili);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() <= ED25519_SIG_LEN {
            return Err(LithiumError::invalid_len(ED25519_SIG_LEN + 1, bytes.len()));
        }
        let mut ed = [0u8; ED25519_SIG_LEN];
        ed.copy_from_slice(&bytes[..ED25519_SIG_LEN]);
        Ok(Self {
            ed,
            dili: bytes[ED25519_SIG_LEN..].to_vec(),
        })
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        Self::from_bytes(&crate::hexcodec::decode_vec(s)?)
    }
}

pub fn sign_double<E: AsRef<[u8]>, D: AsRef<[u8]>>(
    message: &[u8],
    ed_seed: E,
    dili_sk: D,
) -> Result<DoubleSig> {
    let ed: [u8; ED25519_SIG_LEN] = sign_message(message, ed_seed)?
        .try_into()
        .map_err(|_| LithiumError::internal("ed25519_sig_len"))?;
    let dili = sign_message_dili(message, dili_sk)?;
    Ok(DoubleSig { ed, dili })
}

pub fn verify_double(
    message: &[u8],
    sig: &DoubleSig,
    ed_pub: &PubByte32,
    dili_pub: &PublicBytes,
) -> bool {
    verify_signature(message, &sig.ed, ed_pub)
        && verify_signature_dili(message, &sig.dili, dili_pub)
}


// ===== FILE: ./src/error.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use core::fmt;

pub type Result<T> = core::result::Result<T, LithiumError>;

#[derive(Debug)]
pub struct LithiumError {
    pub kind: ErrorKind,
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl LithiumError {
    #[inline]
    pub fn new(kind: ErrorKind) -> Self {
        Self { kind, source: None }
    }

    #[inline]
    pub fn with_source<E>(mut self, err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        self.source = Some(Box::new(err));
        self
    }

    #[inline]
    pub fn is_verbose() -> bool {
        cfg!(debug_assertions)
    }

    #[inline]
    pub fn invalid_len(expected: usize, got: usize) -> Self {
        Self::new(ErrorKind::InvalidLength { expected, got })
    }

    #[inline]
    pub fn invalid_hex_len(expected: usize, got: usize) -> Self {
        Self::new(ErrorKind::InvalidHexLength { expected, got })
    }

    #[inline]
    pub fn invalid_hex<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::new(ErrorKind::InvalidHex).with_source(err)
    }

    #[inline]
    pub fn hex_prefix_disallowed() -> Self {
        Self::new(ErrorKind::HexDisallowedPrefix)
    }

    #[inline]
    pub fn hex_must_be_lowercase() -> Self {
        Self::new(ErrorKind::HexMustBeLowercase)
    }

    #[inline]
    pub fn string_policy() -> Self {
        Self::new(ErrorKind::StringPolicy)
    }

    #[inline]
    pub fn missing_header(name: &'static str) -> Self {
        Self::new(ErrorKind::MissingHeader { name })
    }

    #[inline]
    pub fn invalid_utf8_header<E>(name: &'static str, err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::new(ErrorKind::InvalidUtf8Header { name }).with_source(err)
    }

    #[inline]
    pub fn json_parse<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::new(ErrorKind::JsonParse).with_source(err)
    }

    #[inline]
    pub fn json_not_object() -> Self {
        Self::new(ErrorKind::JsonNotObject)
    }

    #[inline]
    pub fn json_missing_field(key: &'static str) -> Self {
        Self::new(ErrorKind::JsonMissingField { key })
    }

    #[inline]
    pub fn json_type_mismatch(key: &'static str, expected: &'static str) -> Self {
        Self::new(ErrorKind::JsonTypeMismatch { key, expected })
    }

    #[inline]
    pub fn aead_failed() -> Self {
        Self::new(ErrorKind::AeadFailed)
    }

    #[inline]
    pub fn kdf_failed() -> Self {
        Self::new(ErrorKind::KdfFailed)
    }

    #[inline]
    pub fn kem_invalid_ciphertext() -> Self {
        Self::new(ErrorKind::KemInvalidCiphertext)
    }

    #[inline]
    pub fn invalid_public_key(reason: &'static str) -> Self {
        Self::new(ErrorKind::InvalidPublicKey { reason })
    }

    #[inline]
    pub fn key_import_failed(reason: &'static str) -> Self {
        Self::new(ErrorKind::KeyImportFailed { reason })
    }

    #[inline]
    pub fn invalid_context(reason: &'static str) -> Self {
        Self::new(ErrorKind::InvalidContext { reason })
    }

    #[inline]
    pub fn random_failed() -> Self {
        Self::new(ErrorKind::RandomFailed)
    }

    #[inline]
    pub fn io<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::new(ErrorKind::Io).with_source(err)
    }

    #[inline]
    pub fn internal(reason: &'static str) -> Self {
        Self::new(ErrorKind::Internal { reason })
    }

    #[inline]
    pub fn malformed_keyfile() -> Self {
        Self::new(ErrorKind::MalformedKeyfile)
    }

    #[inline]
    pub fn keystore_locked() -> Self {
        Self::new(ErrorKind::KeystoreLocked)
    }

    #[inline]
    pub fn invalid_credentials(msg: &'static str) -> Self {
        Self::new(ErrorKind::InvalidCredentials { msg })
    }

    #[inline]
    pub fn invalid_perms(msg: &'static str) -> Self {
        Self::new(ErrorKind::InvalidPermissions { msg })
    }

    #[inline]
    pub fn invalid_utf(msg: &'static str) -> Self {
        Self::new(ErrorKind::InvalidUtf { msg })
    }

    #[inline]
    pub fn env_missing(name: &'static str) -> Self {
        Self::new(ErrorKind::EnvMissing { name })
    }

    #[inline]
    pub fn env_invalid(name: &'static str) -> Self {
        Self::new(ErrorKind::EnvInvalid { name })
    }

    #[inline]
    pub fn state_missing(name: &'static str) -> Self {
        Self::new(ErrorKind::StateMissing { name })
    }

    #[inline]
    pub fn timeout<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::new(ErrorKind::Timeout).with_source(err)
    }

    #[inline]
    pub fn transport<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::new(ErrorKind::Transport).with_source(err)
    }

    #[inline]
    pub fn http_status(code: u16) -> Self {
        Self::new(ErrorKind::HttpStatus { code })
    }

    #[inline]
    pub fn is_not_found(&self) -> bool {
        if self.kind != ErrorKind::Io {
            return false;
        }
        let Some(src) = self.source.as_deref() else {
            return false;
        };
        if let Some(ioe) = src.downcast_ref::<std::io::Error>() {
            return ioe.kind() == std::io::ErrorKind::NotFound;
        }
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    InvalidLength {
        expected: usize,
        got: usize,
    },
    InvalidHexLength {
        expected: usize,
        got: usize,
    },
    InvalidHex,
    HexDisallowedPrefix,
    HexMustBeLowercase,
    StringPolicy,
    InvalidUtf {
        msg: &'static str,
    },
    MissingHeader {
        name: &'static str,
    },
    InvalidUtf8Header {
        name: &'static str,
    },
    JsonParse,
    JsonNotObject,
    JsonMissingField {
        key: &'static str,
    },
    JsonTypeMismatch {
        key: &'static str,
        expected: &'static str,
    },
    AeadFailed,
    KdfFailed,
    KemInvalidCiphertext,
    InvalidPublicKey {
        reason: &'static str,
    },
    KeyImportFailed {
        reason: &'static str,
    },
    InvalidContext {
        reason: &'static str,
    },
    RandomFailed,
    InvalidCredentials {
        msg: &'static str,
    },
    InvalidPermissions {
        msg: &'static str,
    },
    MalformedKeyfile,
    KeystoreLocked,
    EnvMissing {
        name: &'static str,
    },
    EnvInvalid {
        name: &'static str,
    },
    StateMissing {
        name: &'static str,
    },
    Io,
    Timeout,
    Transport,
    HttpStatus {
        code: u16,
    },
    Internal {
        reason: &'static str,
    },
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::InvalidLength { expected, got } => {
                write!(f, "invalid length: expected {expected}, got {got}")
            }
            ErrorKind::InvalidHexLength { expected, got } => {
                write!(f, "invalid hex length: expected {expected}, got {got}")
            }
            ErrorKind::InvalidHex => write!(f, "invalid hex"),
            ErrorKind::HexDisallowedPrefix => write!(f, "hex prefix disallowed"),
            ErrorKind::HexMustBeLowercase => write!(f, "hex must be lowercase"),
            ErrorKind::StringPolicy => write!(f, "input rejected by policy"),
            ErrorKind::InvalidUtf { msg } => write!(f, "invalid utf-8: {msg}"),
            ErrorKind::MissingHeader { name } => write!(f, "missing header: {name}"),
            ErrorKind::InvalidUtf8Header { name } => write!(f, "invalid utf-8 in header: {name}"),
            ErrorKind::JsonParse => write!(f, "invalid json"),
            ErrorKind::JsonNotObject => write!(f, "json is not an object"),
            ErrorKind::JsonMissingField { key } => write!(f, "json missing field: {key}"),
            ErrorKind::JsonTypeMismatch { key, expected } => {
                write!(f, "json type mismatch at {key}: expected {expected}")
            }
            ErrorKind::AeadFailed => write!(f, "aead operation failed"),
            ErrorKind::KdfFailed => write!(f, "key derivation failed"),
            ErrorKind::KemInvalidCiphertext => write!(f, "invalid kem ciphertext"),
            ErrorKind::InvalidPublicKey { reason } => write!(f, "invalid public key: {reason}"),
            ErrorKind::KeyImportFailed { reason } => write!(f, "key import failed: {reason}"),
            ErrorKind::InvalidContext { reason } => write!(f, "invalid context: {reason}"),
            ErrorKind::RandomFailed => write!(f, "random number generation failed"),
            ErrorKind::InvalidCredentials { msg } => write!(f, "invalid credentials: {msg}"),
            ErrorKind::InvalidPermissions { msg } => write!(f, "permission denied: {msg}"),
            ErrorKind::MalformedKeyfile => write!(f, "malformed keyfile"),
            ErrorKind::KeystoreLocked => {
                write!(f, "keystore already locked by another instance")
            }
            ErrorKind::EnvMissing { name } => write!(f, "missing environment variable: {name}"),
            ErrorKind::EnvInvalid { name } => write!(f, "invalid environment variable: {name}"),
            ErrorKind::StateMissing { name } => write!(f, "missing state: {name}"),
            ErrorKind::Io => write!(f, "i/o error"),
            ErrorKind::Timeout => write!(f, "timeout"),
            ErrorKind::Transport => write!(f, "transport error"),
            ErrorKind::HttpStatus { code } => write!(f, "http status {code}"),
            ErrorKind::Internal { reason } => write!(f, "internal error: {reason}"),
        }
    }
}

impl fmt::Display for LithiumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        if let (true, Some(src)) = (Self::is_verbose(), &self.source) {
            write!(f, " | source: {src}")?;
        }
        Ok(())
    }
}

impl std::error::Error for LithiumError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().map(|e| e as _)
    }
}

impl From<std::io::Error> for LithiumError {
    fn from(value: std::io::Error) -> Self {
        LithiumError::io(value)
    }
}
impl From<hex::FromHexError> for LithiumError {
    fn from(value: hex::FromHexError) -> Self {
        LithiumError::invalid_hex(value)
    }
}
impl From<serde_json::Error> for LithiumError {
    fn from(value: serde_json::Error) -> Self {
        LithiumError::json_parse(value)
    }
}
impl From<hkdf::InvalidLength> for LithiumError {
    fn from(_: hkdf::InvalidLength) -> Self {
        LithiumError::kdf_failed()
    }
}
impl From<aes_gcm_siv::aead::Error> for LithiumError {
    fn from(_: aes_gcm_siv::aead::Error) -> Self {
        LithiumError::aead_failed()
    }
}
impl From<rand::rngs::SysError> for LithiumError {
    fn from(err: rand::rngs::SysError) -> Self {
        LithiumError::random_failed().with_source(err)
    }
}


// ===== FILE: ./src/hexcodec.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::error::{ErrorKind, LithiumError, Result};

#[inline]
fn reject_prefix(s: &str) -> Result<()> {
    if s.starts_with("0x") || s.starts_with("0X") {
        return Err(LithiumError::hex_prefix_disallowed());
    }
    Ok(())
}

#[inline]
fn validate_charset(s: &str) -> Result<()> {
    for &b in s.as_bytes() {
        match b {
            b'0'..=b'9' | b'a'..=b'f' => {}
            b'A'..=b'F' => return Err(LithiumError::hex_must_be_lowercase()),
            _ => return Err(LithiumError::new(ErrorKind::InvalidHex)),
        }
    }
    Ok(())
}

#[inline]
pub(crate) fn decode_into(s: &str, dst: &mut [u8]) -> Result<()> {
    reject_prefix(s)?;
    let expected = 2 * dst.len();
    if s.len() != expected {
        return Err(LithiumError::new(ErrorKind::InvalidHexLength {
            expected,
            got: s.len(),
        }));
    }
    validate_charset(s)?;
    hex::decode_to_slice(s, dst).map_err(LithiumError::from)
}

#[inline]
pub(crate) fn decode_vec(s: &str) -> Result<Vec<u8>> {
    reject_prefix(s)?;
    if !s.len().is_multiple_of(2) {
        return Err(LithiumError::new(ErrorKind::InvalidHexLength {
            expected: s.len() + 1,
            got: s.len(),
        }));
    }
    validate_charset(s)?;
    let mut out = vec![0u8; s.len() / 2];
    hex::decode_to_slice(s, &mut out).map_err(LithiumError::from)?;
    Ok(out)
}


// ===== FILE: ./src/hpke/aead.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    crypto::aead, error::Result, hpke::types::HpkeContext, public::PublicBytes,
    secrets::SecretBytes,
};

pub fn seal(ctx: &HpkeContext, aad: &[u8], plaintext: &SecretBytes) -> Result<PublicBytes> {
    aead::encrypt_raw(plaintext, &ctx.key, &ctx.base_nonce, aad)
}

pub fn open(ctx: &HpkeContext, aad: &[u8], ciphertext: &PublicBytes) -> Result<SecretBytes> {
    aead::decrypt_raw(ciphertext, &ctx.key, &ctx.base_nonce, aad)
}


// ===== FILE: ./src/hpke/derive.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use ml_kem::{DecapsulationKey1024, Seed, kem::KeyExport};

use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

use crate::{
    crypto::{context::Context, kdf},
    error::{LithiumError, Result},
    hpke::types::{HpkePrivateKey, HpkePublicKey},
    public::{PubByte32, PublicBytes},
    secrets::SecretBytes,
};

fn derive_label(ctx: &str, part: &[u8]) -> SecretBytes {
    let mut info = Vec::new();
    info.extend_from_slice(ctx.as_bytes());
    info.extend_from_slice(b"/derive-keypair/");
    info.extend_from_slice(part);
    SecretBytes::new(info)
}

pub fn derive_keypair(ctx: &Context, ikm: &[u8]) -> Result<(HpkePrivateKey, HpkePublicKey)> {
    let input = SecretBytes::from_slice(ikm);

    let x_priv = kdf::derive32(
        &input,
        None,
        derive_label(ctx.as_str(), b"x25519-priv").expose_as_slice(),
    )?;

    let x_pub =
        PubByte32::new(*XPublicKey::from(&XStaticSecret::from(*x_priv.as_array())).as_bytes());

    let k_seed_bytes = kdf::derive_bytes(
        &input,
        None,
        derive_label(ctx.as_str(), b"mlkem1024-seed").expose_as_slice(),
        64,
    )?;

    if k_seed_bytes.expose_as_slice().len() != 64 {
        return Err(LithiumError::internal("mlkem_seed_len"));
    }

    let mut seed = Seed::default();
    seed.copy_from_slice(k_seed_bytes.expose_as_slice());

    let dk = DecapsulationKey1024::from_seed(seed);
    let ek = dk.encapsulation_key();
    let ek_bytes = ek.to_bytes();

    let k_priv = k_seed_bytes;
    let k_pub = PublicBytes::from_slice(ek_bytes.as_ref());

    Ok((
        HpkePrivateKey { x_priv, k_priv },
        HpkePublicKey { x_pub, k_pub },
    ))
}


// ===== FILE: ./src/hpke/export.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    crypto::{context::Context, kdf},
    error::Result,
    hpke::types::HpkeContext,
    secrets::SecretBytes,
};

fn export_label(ctx: &str, exporter_context: &[u8]) -> SecretBytes {
    let mut info = Vec::new();
    info.extend_from_slice(ctx.as_bytes());
    info.extend_from_slice(b"/export\0");
    info.extend_from_slice(exporter_context);
    SecretBytes::new(info)
}

pub fn export_secret(
    ctx: &Context,
    hpke_ctx: &HpkeContext,
    exporter_context: &[u8],
    len: usize,
) -> Result<SecretBytes> {
    let input = SecretBytes::from_slice(hpke_ctx.exporter_secret.as_slice());

    kdf::derive_bytes(
        &input,
        None,
        export_label(ctx.as_str(), exporter_context).expose_as_slice(),
        len,
    )
}


// ===== FILE: ./src/hpke/kem.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::crypto::context::Context;
use crate::crypto::keys;
use crate::crypto::kyberbox::{prep_base_key_for_decryption, prep_base_key_for_encryption};
use crate::error::Result;
use crate::hpke::types::HpkeEnc;
use crate::public::{PubByte32, PublicBytes};
use crate::secrets::{SecByte32, SecretBytes};

pub fn kem_encap(
    ctx: &Context,
    recipient_x_pub: &PubByte32,
    recipient_k_pub: &PublicBytes,
) -> Result<(SecByte32, HpkeEnc)> {
    let (eph_x_priv, eph_x_pub) = keys::random_x25519_keypair()?;

    let (shared_secret, kem_ct) =
        prep_base_key_for_encryption(ctx, &eph_x_priv, recipient_x_pub, recipient_k_pub)?;

    Ok((
        shared_secret,
        HpkeEnc {
            x_pub: eph_x_pub,
            kem_ct,
        },
    ))
}

pub fn kem_decap(
    ctx: &Context,
    recipient_x_priv: &SecByte32,
    recipient_k_priv: &SecretBytes,
    enc: &HpkeEnc,
) -> Result<SecByte32> {
    prep_base_key_for_decryption(
        ctx,
        recipient_x_priv,
        &enc.x_pub,
        recipient_k_priv,
        &enc.kem_ct,
    )
}


// ===== FILE: ./src/hpke/mod.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

mod aead;
mod derive;
mod export;
mod kem;
mod schedule;
mod seal;
mod session;
mod setup;
mod types;

pub use derive::derive_keypair;
pub use seal::{open_base, seal_base};
pub use session::{HpkeReceiverContext, HpkeSenderContext, setup_receiver, setup_sender};
pub use setup::{setup_receiver_and_export, setup_sender_and_export};
pub use types::{HpkeEnc, HpkePrivateKey, HpkePublicKey, HpkeSealed};


// ===== FILE: ./src/hpke/schedule.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    crypto::{context::Context, kdf},
    error::Result,
    hpke::types::HpkeContext,
    secrets::{Nonce12, SecByte32, SecretBytes},
};

fn schedule_label(ctx: &str, part: &[u8], info: &[u8]) -> SecretBytes {
    let mut out = Vec::new();
    out.extend_from_slice(ctx.as_bytes());
    out.extend_from_slice(b"/schedule/");
    out.extend_from_slice(part);
    out.extend_from_slice(b"\0");
    out.extend_from_slice(info);
    SecretBytes::new(out)
}

pub fn key_schedule(ctx: &Context, shared_secret: &SecByte32, info: &[u8]) -> Result<HpkeContext> {
    let ikm = SecretBytes::from_slice(shared_secret.as_slice());
    let ctx = ctx.as_str();

    let key = kdf::derive32(
        &ikm,
        None,
        schedule_label(ctx, b"key", info).expose_as_slice(),
    )?;

    let nonce_material = kdf::derive32(
        &ikm,
        None,
        schedule_label(ctx, b"base-nonce", info).expose_as_slice(),
    )?;

    let exporter_secret = kdf::derive32(
        &ikm,
        None,
        schedule_label(ctx, b"exporter-secret", info).expose_as_slice(),
    )?;

    let base_nonce = Nonce12::from_slice(&nonce_material.as_slice()[..12])?;

    Ok(HpkeContext {
        key,
        base_nonce,
        exporter_secret,
    })
}


// ===== FILE: ./src/hpke/seal.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::hpke::aead::open;
use crate::hpke::kem::kem_decap;
use crate::{
    crypto::context::Context,
    error::Result,
    hpke::{aead::seal, kem::kem_encap, schedule::key_schedule, types::HpkeSealed},
    public::{PubByte32, PublicBytes},
    secrets::{SecByte32, SecretBytes},
};

pub fn seal_base(
    ctx: &Context,
    recipient_x_pub: &PubByte32,
    recipient_k_pub: &PublicBytes,
    info: &[u8],
    aad: &[u8],
    plaintext: &SecretBytes,
) -> Result<HpkeSealed> {
    let (shared_secret, enc) = kem_encap(ctx, recipient_x_pub, recipient_k_pub)?;

    let hpke_ctx = key_schedule(ctx, &shared_secret, info)?;

    let ciphertext = seal(&hpke_ctx, aad, plaintext)?;

    Ok(HpkeSealed { enc, ciphertext })
}

pub fn open_base(
    ctx: &Context,
    recipient_x_priv: &SecByte32,
    recipient_k_priv: &SecretBytes,
    info: &[u8],
    aad: &[u8],
    sealed: &HpkeSealed,
) -> Result<SecretBytes> {
    let shared_secret = kem_decap(ctx, recipient_x_priv, recipient_k_priv, &sealed.enc)?;

    let hpke_ctx = key_schedule(ctx, &shared_secret, info)?;

    open(&hpke_ctx, aad, &sealed.ciphertext)
}


// ===== FILE: ./src/hpke/session.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    crypto::{aead, context::Context},
    error::{LithiumError, Result},
    hpke::{
        kem::{kem_decap, kem_encap},
        schedule::key_schedule,
        types::{HpkeContext, HpkeEnc, HpkePrivateKey, HpkePublicKey},
    },
    public::PublicBytes,
    secrets::{Nonce12, SecretBytes},
};

fn seq_nonce(base: &Nonce12, seq: u64) -> Result<Nonce12> {
    let mut n = *base.as_array();
    let s = seq.to_be_bytes();
    for i in 0..8 {
        n[4 + i] ^= s[i];
    }
    Nonce12::from_slice(&n)
}

pub struct HpkeSenderContext {
    ctx: HpkeContext,
    seq: u64,
}

pub struct HpkeReceiverContext {
    ctx: HpkeContext,
    seq: u64,
}

pub fn setup_sender(
    ctx: &Context,
    recipient_pk: &HpkePublicKey,
    info: &[u8],
) -> Result<(HpkeEnc, HpkeSenderContext)> {
    let (shared_secret, enc) = kem_encap(ctx, &recipient_pk.x_pub, &recipient_pk.k_pub)?;
    let hpke_ctx = key_schedule(ctx, &shared_secret, info)?;
    Ok((
        enc,
        HpkeSenderContext {
            ctx: hpke_ctx,
            seq: 0,
        },
    ))
}

pub fn setup_receiver(
    ctx: &Context,
    recipient_sk: &HpkePrivateKey,
    enc: &HpkeEnc,
    info: &[u8],
) -> Result<HpkeReceiverContext> {
    let shared_secret = kem_decap(ctx, &recipient_sk.x_priv, &recipient_sk.k_priv, enc)?;
    let hpke_ctx = key_schedule(ctx, &shared_secret, info)?;
    Ok(HpkeReceiverContext {
        ctx: hpke_ctx,
        seq: 0,
    })
}

impl HpkeSenderContext {
    pub fn seal(&mut self, aad: &[u8], plaintext: &SecretBytes) -> Result<PublicBytes> {
        let nonce = seq_nonce(&self.ctx.base_nonce, self.seq)?;
        let ct = aead::encrypt_raw(plaintext, &self.ctx.key, &nonce, aad)?;
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| LithiumError::internal("hpke_seq_overflow"))?;
        Ok(ct)
    }
}

impl HpkeReceiverContext {
    pub fn open(&mut self, aad: &[u8], ciphertext: &PublicBytes) -> Result<SecretBytes> {
        let nonce = seq_nonce(&self.ctx.base_nonce, self.seq)?;
        let pt = aead::decrypt_raw(ciphertext, &self.ctx.key, &nonce, aad)?;
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| LithiumError::internal("hpke_seq_overflow"))?;
        Ok(pt)
    }
}


// ===== FILE: ./src/hpke/setup.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    crypto::context::Context,
    error::Result,
    hpke::{
        export::export_secret,
        kem::{kem_decap, kem_encap},
        schedule::key_schedule,
        types::{HpkeEnc, HpkePrivateKey, HpkePublicKey},
    },
    secrets::SecretBytes,
};

pub fn setup_sender_and_export(
    ctx: &Context,
    recipient_pk: &HpkePublicKey,
    info: &[u8],
    exporter_context: &[u8],
    exporter_length: usize,
) -> Result<(HpkeEnc, SecretBytes)> {
    let (shared_secret, enc) = kem_encap(ctx, &recipient_pk.x_pub, &recipient_pk.k_pub)?;

    let hpke_ctx = key_schedule(ctx, &shared_secret, info)?;

    let exported = export_secret(ctx, &hpke_ctx, exporter_context, exporter_length)?;

    Ok((enc, exported))
}

pub fn setup_receiver_and_export(
    ctx: &Context,
    recipient_sk: &HpkePrivateKey,
    enc: &HpkeEnc,
    info: &[u8],
    exporter_context: &[u8],
    exporter_length: usize,
) -> Result<SecretBytes> {
    let shared_secret = kem_decap(ctx, &recipient_sk.x_priv, &recipient_sk.k_priv, enc)?;

    let hpke_ctx = key_schedule(ctx, &shared_secret, info)?;

    export_secret(ctx, &hpke_ctx, exporter_context, exporter_length)
}


// ===== FILE: ./src/hpke/types.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::error::{LithiumError, Result};
use crate::public::{PubByte32, PublicBytes};
use crate::secrets::{Nonce12, SecByte32, SecretBytes};

const X25519_PUB_LEN: usize = 32;
const X25519_PRIV_LEN: usize = 32;
const MLKEM1024_PUB_LEN: usize = 1568;
const MLKEM1024_SEED_LEN: usize = 64;

#[derive(Clone, Debug)]
pub struct HpkeEnc {
    pub(crate) x_pub: PubByte32,
    pub(crate) kem_ct: PublicBytes,
}

#[derive(Debug)]
pub struct HpkeContext {
    pub(crate) key: SecByte32,
    pub(crate) base_nonce: Nonce12,
    pub(crate) exporter_secret: SecByte32,
}

#[derive(Clone, Debug)]
pub struct HpkeSealed {
    pub enc: HpkeEnc,
    pub ciphertext: PublicBytes,
}

#[derive(Clone, Debug)]
pub struct HpkePublicKey {
    pub(crate) x_pub: PubByte32,
    pub(crate) k_pub: PublicBytes,
}

#[derive(Clone, Debug)]
pub struct HpkePrivateKey {
    pub(crate) x_priv: SecByte32,
    pub(crate) k_priv: SecretBytes,
}

impl HpkeEnc {
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.kem_ct.as_slice().len());
        out.extend_from_slice(self.x_pub.as_slice());
        out.extend_from_slice(self.kem_ct.as_slice());
        out
    }

    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        if bytes.len() <= X25519_PUB_LEN {
            return Err(LithiumError::invalid_len(X25519_PUB_LEN + 1, bytes.len()));
        }

        let x_pub = PubByte32::from_slice(&bytes[..X25519_PUB_LEN])?;
        let kem_ct = PublicBytes::from_slice(&bytes[X25519_PUB_LEN..]);

        Ok(Self { x_pub, kem_ct })
    }
}

impl HpkePublicKey {
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(X25519_PUB_LEN + MLKEM1024_PUB_LEN);
        out.extend_from_slice(self.x_pub.as_slice());
        out.extend_from_slice(self.k_pub.as_slice());
        out
    }

    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let expected = X25519_PUB_LEN + MLKEM1024_PUB_LEN;
        if bytes.len() != expected {
            return Err(LithiumError::invalid_len(expected, bytes.len()));
        }

        Ok(Self {
            x_pub: PubByte32::from_slice(&bytes[..X25519_PUB_LEN])?,
            k_pub: PublicBytes::from_slice(&bytes[X25519_PUB_LEN..]),
        })
    }
}

impl HpkePrivateKey {
    pub fn to_wire(&self) -> SecretBytes {
        let mut out = Vec::with_capacity(X25519_PRIV_LEN + MLKEM1024_SEED_LEN);
        out.extend_from_slice(self.x_priv.as_slice());
        out.extend_from_slice(self.k_priv.expose_as_slice());
        SecretBytes::new(out)
    }

    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let expected = X25519_PRIV_LEN + MLKEM1024_SEED_LEN;
        if bytes.len() != expected {
            return Err(LithiumError::invalid_len(expected, bytes.len()));
        }

        Ok(Self {
            x_priv: SecByte32::from_slice(&bytes[..X25519_PRIV_LEN])?,
            k_priv: SecretBytes::from_slice(&bytes[X25519_PRIV_LEN..]),
        })
    }
}


// ===== FILE: ./src/keys/keyfile.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use hkdf::Hkdf;
use sha2::Sha256;

use crate::crypto::{aead, keys};
use crate::error::{ErrorKind, LithiumError, Result};
use crate::public::PublicBytes;
use crate::secrets::{MasterKey32, SecByte12, SecByte32, SecretBytes, SecretFixedBytes};

const KEYFILE_MAGIC: &[u8; 4] = b"KEYF";
const KEYFILE_VERSION: u8 = 1;
const ALG_ID_AES256_GCM_SIV: u8 = 1;
const DEK_LEN: u16 = 32;
const KEYFILE_KEK_INFO: &[u8] = b"kek/v1";

#[inline]
pub fn read_keyfile_bytes(path: &Path) -> Result<SecretBytes> {
    Ok(SecretBytes::new(fs::read(path).map_err(LithiumError::io)?))
}

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

fn create_private_tmp(path: &Path) -> Result<(fs::File, PathBuf)> {
    for _ in 0..8 {
        let suffix = keys::random_fixed::<8>()?;
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = path.with_extension(format!(
            "tmp-{:x}-{:x}-{}",
            std::process::id(),
            seq,
            hex::encode(suffix.as_slice())
        ));

        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }

        match opts.open(&tmp) {
            Ok(f) => return Ok((f, tmp)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(LithiumError::io(e)),
        }
    }

    Err(LithiumError::io(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "keyfile tmp name not unique",
    )))
}

pub fn write_secure(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(LithiumError::io)?;
    }

    let (mut f, tmp) = create_private_tmp(path)?;

    let write_res = (|| -> Result<()> {
        f.write_all(data).map_err(LithiumError::io)?;
        f.sync_all().map_err(LithiumError::io)?;
        Ok(())
    })();

    if let Err(e) = write_res {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    fs::rename(&tmp, path).map_err(LithiumError::io)?;

    // fsync the dir too or the rename can vanish on a crash; best-effort, ignore errors
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        let _ = fs::File::open(parent).and_then(|dir| dir.sync_all());
    }

    Ok(())
}

#[inline]
fn aad_for(version: u8, key_type: &str) -> Vec<u8> {
    format!("keyfile:v{}|{}", version, key_type).into_bytes()
}

#[inline]
fn derive_kek(mk: &MasterKey32, salt: &[u8; 32]) -> Result<SecByte32> {
    let hk = Hkdf::<Sha256>::new(Some(salt), mk.as_slice());
    let mut out = SecByte32::new_zeroed();
    hk.expand(KEYFILE_KEK_INFO, out.as_mut_slice())?;
    Ok(out)
}

#[inline]
fn wrap_dek(kek: &SecByte32, dek: &SecByte32, aad: &[u8]) -> Result<(Vec<u8>, [u8; 12])> {
    let nonce = keys::random_fixed::<12>()?;
    let ct = aead::encrypt_raw(&SecretBytes::from_slice(dek.as_slice()), kek, &nonce, aad)?;

    Ok((ct.as_slice().to_vec(), *nonce.as_array()))
}

#[inline]
fn encrypt_payload(dek: &SecByte32, payload: &[u8], aad: &[u8]) -> Result<(Vec<u8>, [u8; 12])> {
    let nonce = keys::random_fixed::<12>()?;
    let ct = aead::encrypt_raw(&SecretBytes::from_slice(payload), dek, &nonce, aad)?;

    Ok((ct.as_slice().to_vec(), *nonce.as_array()))
}

#[allow(clippy::too_many_arguments)]
fn build_record(
    version: u8,
    alg_id: u8,
    dek_len: u16,
    salt: &[u8; 32],
    nonce_wrap: &[u8; 12],
    ct_wrap: &[u8],
    nonce_payload: &[u8; 12],
    ct_payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(KEYFILE_MAGIC);
    out.push(version);
    out.push(alg_id);
    out.extend_from_slice(&dek_len.to_be_bytes());

    out.extend_from_slice(&(salt.len() as u16).to_be_bytes());
    out.extend_from_slice(salt);

    out.extend_from_slice(&(nonce_wrap.len() as u16).to_be_bytes());
    out.extend_from_slice(nonce_wrap);

    out.extend_from_slice(&(ct_wrap.len() as u16).to_be_bytes());
    out.extend_from_slice(ct_wrap);

    out.extend_from_slice(&(nonce_payload.len() as u16).to_be_bytes());
    out.extend_from_slice(nonce_payload);

    out.extend_from_slice(&(ct_payload.len() as u32).to_be_bytes());
    out.extend_from_slice(ct_payload);

    out
}

fn read_u16(buf: &[u8], idx: &mut usize) -> Result<u16> {
    if *idx + 2 > buf.len() {
        return Err(LithiumError::new(ErrorKind::InvalidLength {
            expected: *idx + 2,
            got: buf.len(),
        }));
    }
    let v = u16::from_be_bytes([buf[*idx], buf[*idx + 1]]);
    *idx += 2;
    Ok(v)
}

fn read_u32(buf: &[u8], idx: &mut usize) -> Result<u32> {
    if *idx + 4 > buf.len() {
        return Err(LithiumError::new(ErrorKind::InvalidLength {
            expected: *idx + 4,
            got: buf.len(),
        }));
    }
    let v = u32::from_be_bytes([buf[*idx], buf[*idx + 1], buf[*idx + 2], buf[*idx + 3]]);
    *idx += 4;
    Ok(v)
}

#[allow(clippy::type_complexity)]
fn parse_keyfile(
    buf: &SecretBytes,
) -> Result<(u8, u8, u16, [u8; 32], [u8; 12], Vec<u8>, [u8; 12], Vec<u8>)> {
    let buf = buf.expose_as_slice();
    let mut idx = 0;

    if buf.len() < 8 {
        return Err(LithiumError::invalid_len(8, buf.len()));
    }
    if &buf[0..4] != KEYFILE_MAGIC {
        return Err(LithiumError::malformed_keyfile());
    }

    idx += 4;
    let version = buf[idx];
    idx += 1;
    let alg_id = buf[idx];
    idx += 1;
    let dek_len = u16::from_be_bytes([buf[idx], buf[idx + 1]]);
    idx += 2;

    let len_salt = read_u16(buf, &mut idx)? as usize;
    if len_salt != 32 || idx + 32 > buf.len() {
        return Err(LithiumError::malformed_keyfile());
    }
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&buf[idx..idx + 32]);
    idx += 32;

    let len_nonce_wrap = read_u16(buf, &mut idx)? as usize;
    if len_nonce_wrap != 12 || idx + 12 > buf.len() {
        return Err(LithiumError::malformed_keyfile());
    }
    let mut nonce_wrap = [0u8; 12];
    nonce_wrap.copy_from_slice(&buf[idx..idx + 12]);
    idx += 12;

    let len_ct_wrap = read_u16(buf, &mut idx)? as usize;
    if idx + len_ct_wrap > buf.len() {
        return Err(LithiumError::malformed_keyfile());
    }
    let ct_wrap = buf[idx..idx + len_ct_wrap].to_vec();
    idx += len_ct_wrap;

    let len_nonce_payload = read_u16(buf, &mut idx)? as usize;
    if len_nonce_payload != 12 || idx + 12 > buf.len() {
        return Err(LithiumError::malformed_keyfile());
    }
    let mut nonce_payload = [0u8; 12];
    nonce_payload.copy_from_slice(&buf[idx..idx + 12]);
    idx += 12;

    let len_ct_payload = read_u32(buf, &mut idx)? as usize;
    if idx + len_ct_payload > buf.len() {
        return Err(LithiumError::malformed_keyfile());
    }
    let ct_payload = buf[idx..idx + len_ct_payload].to_vec();

    Ok((
        version,
        alg_id,
        dek_len,
        salt,
        nonce_wrap,
        ct_wrap,
        nonce_payload,
        ct_payload,
    ))
}

#[cfg(feature = "fuzzing")]
#[allow(clippy::type_complexity)]
pub fn parse_keyfile_fuzz(
    bytes: &[u8],
) -> Result<(u8, u8, u16, [u8; 32], [u8; 12], Vec<u8>, [u8; 12], Vec<u8>)> {
    parse_keyfile(&SecretBytes::new(bytes.to_vec()))
}

fn unwrap_dek(
    mk: &MasterKey32,
    salt: &[u8; 32],
    nonce_wrap: &[u8; 12],
    ct_wrap: &[u8],
    aad: &[u8],
) -> Result<SecByte32> {
    let kek = derive_kek(mk, salt)?;
    let nonce = SecByte12::from_slice(nonce_wrap)?;
    let dek_bytes = aead::decrypt_raw(&PublicBytes::from_slice(ct_wrap), &kek, &nonce, aad)?;
    SecByte32::from_slice(dek_bytes.expose_as_slice())
}

fn decrypt_payload_bytes(
    dek: &SecByte32,
    nonce_payload: &[u8; 12],
    ct_payload: &[u8],
    aad: &[u8],
) -> Result<SecretBytes> {
    let nonce = SecByte12::from_slice(nonce_payload)?;
    aead::decrypt_raw(&PublicBytes::from_slice(ct_payload), dek, &nonce, aad)
}

fn decrypt_payload_32(
    dek: &SecByte32,
    nonce_payload: &[u8; 12],
    ct_payload: &[u8],
    aad: &[u8],
) -> Result<SecretFixedBytes<32>> {
    let pt = decrypt_payload_bytes(dek, nonce_payload, ct_payload, aad)?;
    SecretFixedBytes::<32>::from_slice(pt.expose_as_slice())
}

pub fn save_secret32_encrypted(
    path: &Path,
    mk: &MasterKey32,
    payload: &SecretFixedBytes<32>,
    key_type: &str,
) -> Result<()> {
    let dek = keys::random_fixed::<32>()?;
    let salt = keys::random_fixed::<32>()?;
    let kek = derive_kek(mk, salt.as_array())?;
    let aad = aad_for(KEYFILE_VERSION, key_type);

    let (ct_wrap, nonce_wrap) = wrap_dek(&kek, &dek, &aad)?;
    let (ct_payload, nonce_payload) = encrypt_payload(&dek, payload.as_slice(), &aad)?;

    let out = build_record(
        KEYFILE_VERSION,
        ALG_ID_AES256_GCM_SIV,
        DEK_LEN,
        salt.as_array(),
        &nonce_wrap,
        &ct_wrap,
        &nonce_payload,
        &ct_payload,
    );

    write_secure(path, &out)?;
    Ok(())
}

pub fn save_bytes_encrypted(
    path: &Path,
    mk: &MasterKey32,
    payload: &[u8],
    key_type: &str,
) -> Result<()> {
    let dek = keys::random_fixed::<32>()?;
    let salt = keys::random_fixed::<32>()?;
    let kek = derive_kek(mk, salt.as_array())?;
    let aad = aad_for(KEYFILE_VERSION, key_type);

    let (ct_wrap, nonce_wrap) = wrap_dek(&kek, &dek, &aad)?;
    let (ct_payload, nonce_payload) = encrypt_payload(&dek, payload, &aad)?;

    let out = build_record(
        KEYFILE_VERSION,
        ALG_ID_AES256_GCM_SIV,
        DEK_LEN,
        salt.as_array(),
        &nonce_wrap,
        &ct_wrap,
        &nonce_payload,
        &ct_payload,
    );

    write_secure(path, &out)?;
    Ok(())
}

pub fn load_secret32_decrypted(
    path: &Path,
    mk: &MasterKey32,
    key_type: &str,
) -> Result<SecretFixedBytes<32>> {
    let buf = read_keyfile_bytes(path)?;
    let (version, alg_id, dek_len, salt, nonce_wrap, ct_wrap, nonce_payload, ct_payload) =
        parse_keyfile(&buf)?;

    if version != KEYFILE_VERSION || alg_id != ALG_ID_AES256_GCM_SIV || dek_len != DEK_LEN {
        return Err(LithiumError::malformed_keyfile());
    }

    let aad = aad_for(version, key_type);
    let dek = unwrap_dek(mk, &salt, &nonce_wrap, &ct_wrap, &aad)?;
    decrypt_payload_32(&dek, &nonce_payload, &ct_payload, &aad)
}

pub fn load_bytes_decrypted(path: &Path, mk: &MasterKey32, key_type: &str) -> Result<SecretBytes> {
    let buf = read_keyfile_bytes(path)?;
    let (version, alg_id, dek_len, salt, nonce_wrap, ct_wrap, nonce_payload, ct_payload) =
        parse_keyfile(&buf)?;

    if version != KEYFILE_VERSION || alg_id != ALG_ID_AES256_GCM_SIV || dek_len != DEK_LEN {
        return Err(LithiumError::malformed_keyfile());
    }

    let aad = aad_for(version, key_type);
    let dek = unwrap_dek(mk, &salt, &nonce_wrap, &ct_wrap, &aad)?;
    decrypt_payload_bytes(&dek, &nonce_payload, &ct_payload, &aad)
}

pub fn rewrap_keyfile_dek_to_bytes(
    path: &Path,
    old_mk: &MasterKey32,
    new_mk: &MasterKey32,
    key_type: &str,
) -> Result<SecretBytes> {
    let buf = read_keyfile_bytes(path)?;
    let (
        version,
        alg_id,
        dek_len,
        salt_old,
        nonce_wrap_old,
        ct_wrap_old,
        nonce_payload,
        ct_payload,
    ) = parse_keyfile(&buf)?;

    if version != KEYFILE_VERSION || alg_id != ALG_ID_AES256_GCM_SIV || dek_len != DEK_LEN {
        return Err(LithiumError::malformed_keyfile());
    }

    let aad = aad_for(version, key_type);
    let dek = unwrap_dek(old_mk, &salt_old, &nonce_wrap_old, &ct_wrap_old, &aad)?;

    let salt_new = keys::random_fixed::<32>()?;
    let kek_new = derive_kek(new_mk, salt_new.as_array())?;
    let (ct_wrap_new, nonce_wrap_new) = wrap_dek(&kek_new, &dek, &aad)?;

    let out = build_record(
        version,
        alg_id,
        dek_len,
        salt_new.as_array(),
        &nonce_wrap_new,
        &ct_wrap_new,
        &nonce_payload,
        &ct_payload,
    );

    Ok(SecretBytes::new(out))
}

pub fn rewrap_keyfile_dek(
    path: &Path,
    old_mk: &MasterKey32,
    new_mk: &MasterKey32,
    key_type: &str,
) -> Result<()> {
    let out = rewrap_keyfile_dek_to_bytes(path, old_mk, new_mk, key_type)?;
    write_secure(path, out.expose_as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyfile_record_layout_is_pinned() {
        let salt = [0x33u8; 32];
        let nonce_wrap = [0x44u8; 12];
        let ct_wrap = [0x55u8; 48];
        let nonce_payload = [0x66u8; 12];
        let ct_payload = [0x77u8; 40];

        let rec = build_record(
            KEYFILE_VERSION,
            ALG_ID_AES256_GCM_SIV,
            DEK_LEN,
            &salt,
            &nonce_wrap,
            &ct_wrap,
            &nonce_payload,
            &ct_payload,
        );
        assert_eq!(
            hex::encode(&rec),
            "4b4559460101002000203333333333333333333333333333333333333333333333333333333333333333000c4444444444444444444444440030555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555000c6666666666666666666666660000002877777777777777777777777777777777777777777777777777777777777777777777777777777777"
        );

        let (v, alg, dl, s, nw, cw, np, cp) = parse_keyfile(&SecretBytes::new(rec)).unwrap();
        assert_eq!(v, KEYFILE_VERSION);
        assert_eq!(alg, ALG_ID_AES256_GCM_SIV);
        assert_eq!(dl, DEK_LEN);
        assert_eq!(s, salt);
        assert_eq!(nw, nonce_wrap);
        assert_eq!(cw, ct_wrap.to_vec());
        assert_eq!(np, nonce_payload);
        assert_eq!(cp, ct_payload.to_vec());
    }

    #[cfg(unix)]
    #[test]
    fn write_secure_creates_0600_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("lithium-keyfile-{}", std::process::id()));
        let path = dir.join("secret.keyf");

        write_secure(&path, b"top secret payload").unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "keyfile must be owner-only");
        assert_eq!(
            read_keyfile_bytes(&path).unwrap().expose_as_slice(),
            b"top secret payload"
        );
        assert!(
            fs::read_dir(&dir)
                .unwrap()
                .all(|e| { e.unwrap().file_name().to_string_lossy() == "secret.keyf" }),
            "no leftover tmp files"
        );

        let _ = fs::remove_dir_all(&dir);
    }
}


// ===== FILE: ./src/keys/manager.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::crypto::{aead, keys};
use crate::error::{LithiumError, Result};
use crate::public::{PubByte32, PublicBytes};
use crate::secrets::{ArenaByte32, ArenaByte64, MasterKey32, SecByte32, SecretArena, SecretBytes};

use super::keyfile;

const DEFAULT_ROTATE_EVERY: Duration = Duration::from_secs(3600);

const ARENA_CAPACITY: usize = 8 * 1024;

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
const X_PUB: &str = "x25519.pub";
const KYBER_PUB: &str = "kyber-mlkem1024.pub";
const DILI_PUB: &str = "dilithium-mldsa87.pub";

const ED_PRIV: &str = "ed25519.keyf";
const X_PRIV: &str = "x25519.keyf";
const KYBER_PRIV: &str = "kyber-mlkem1024.keyf";
const DILI_PRIV: &str = "dilithium-mldsa87.keyf";

const LEGACY_STATE_FILE: &str = "state.keyf";

const KT_ED_SEED: &str = "ed25519-seed-v1";
const KT_X_SEED: &str = "x25519-seed-v1";
const KT_KYBER_SK: &str = "kyber-mlkem1024-sk-v1";
const KT_DILI_SK: &str = "dilithium-mldsa87-sk-v1";
const KT_ROTATE_NEXT_OLD: &str = "rotate-next-mk-old-v1";
const KT_ROTATE_NEXT_NEW: &str = "rotate-next-mk-new-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStoreKind {
    Server,
    User,
}

impl KeyStoreKind {
    fn dir_name(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::User => "user",
        }
    }
}

pub trait MkProvider {
    fn load_mk(&self) -> Result<SecByte32>;
    fn store_mk(&self, mk: &SecByte32) -> Result<()>;

    fn derive_secret32(
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
        keyfile::write_secure(&self.path, mk.as_slice())
    }
}

#[derive(Clone)]
pub struct PublicKeys {
    pub ed25519: PubByte32,
    pub x25519: PubByte32,
    pub kyber: PublicBytes,
    pub dilithium: PublicBytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryLocking {
    Require,
    BestEffort,
}

pub struct KeyManager<P: MkProvider> {
    root_dir: PathBuf,
    pub_dir: PathBuf,
    priv_dir: PathBuf,
    secrets_dir: PathBuf,
    rotate_dir: PathBuf,
    mk_provider: P,
    public_keys: PublicKeys,
    arena: SecretArena,
    #[allow(dead_code)]
    lock_file: fs::File,
    rotate_every: Duration,
    next_rotation_at: Instant,
}

#[derive(Clone)]
struct RewrapTarget {
    live_path: PathBuf,
    relative_path: PathBuf,
    key_type: String,
}

fn acquire_exclusive_lock(root_dir: &Path) -> Result<fs::File> {
    let file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(root_dir.join(LOCK_FILE))
        .map_err(LithiumError::io)?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(fs::TryLockError::WouldBlock) => Err(LithiumError::keystore_locked()),
        Err(fs::TryLockError::Error(e)) => Err(LithiumError::io(e)),
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

#[inline]
fn read_pub32(path: &Path) -> Result<PubByte32> {
    let bytes = keyfile::read_keyfile_bytes(path)?;
    PubByte32::from_slice(bytes.expose_as_slice())
}

#[inline]
fn read_pub_bytes(path: &Path) -> Result<PublicBytes> {
    Ok(PublicBytes::from_slice(
        keyfile::read_keyfile_bytes(path)?.expose_as_slice(),
    ))
}

fn sync_public_cache(pub_dir: &Path, pks: &PublicKeys) -> Result<()> {
    fs::create_dir_all(pub_dir).map_err(LithiumError::io)?;
    keyfile::write_secure(&pub_dir.join(ED_PUB), pks.ed25519.as_slice())?;
    keyfile::write_secure(&pub_dir.join(X_PUB), pks.x25519.as_slice())?;
    keyfile::write_secure(&pub_dir.join(KYBER_PUB), pks.kyber.as_slice())?;
    keyfile::write_secure(&pub_dir.join(DILI_PUB), pks.dilithium.as_slice())?;
    sync_dir(pub_dir)?;
    Ok(())
}

fn load_public_cache(pub_dir: &Path) -> Result<PublicKeys> {
    Ok(PublicKeys {
        ed25519: read_pub32(&pub_dir.join(ED_PUB))?,
        x25519: read_pub32(&pub_dir.join(X_PUB))?,
        kyber: read_pub_bytes(&pub_dir.join(KYBER_PUB))?,
        dilithium: read_pub_bytes(&pub_dir.join(DILI_PUB))?,
    })
}

fn ensure_seed32_born_locked(
    arena: &SecretArena,
    path: &Path,
    mk: &MasterKey32,
    key_type: &str,
    pub_from_seed: impl FnOnce(&[u8; 32]) -> PubByte32,
) -> Result<PubByte32> {
    if path.exists() {
        let seed = keyfile::load_secret32_decrypted(path, mk, key_type)?;
        return Ok(pub_from_seed(seed.as_array()));
    }

    let seed = arena.random_fixed::<32>()?;
    let pk = pub_from_seed(seed.as_array());
    keyfile::save_bytes_encrypted(path, mk, seed.as_slice(), key_type)?;
    Ok(pk)
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
    let path = label_secret_path(secrets_dir, label);
    let key_type = label_key_type(label);

    if path.exists() {
        return keyfile::load_secret32_decrypted(&path, mk, &key_type);
    }

    let v = keys::random_32()?;
    keyfile::save_secret32_encrypted(&path, mk, &v, &key_type)?;
    Ok(v)
}

fn load_or_create_label_bytes(
    secrets_dir: &Path,
    mk: &MasterKey32,
    label: &[u8],
    generate: impl FnOnce() -> Result<SecretBytes>,
) -> Result<SecretBytes> {
    let path = label_secret_path(secrets_dir, label);
    let key_type = label_key_type(label);

    if path.exists() {
        return keyfile::load_bytes_decrypted(&path, mk, &key_type);
    }

    let v = generate()?;
    keyfile::save_bytes_encrypted(&path, mk, v.expose_as_slice(), &key_type)?;
    Ok(v)
}

fn ensure_asymmetric_material(
    pub_dir: &Path,
    priv_dir: &Path,
    mk: &MasterKey32,
    arena: &SecretArena,
) -> Result<PublicKeys> {
    fs::create_dir_all(pub_dir).map_err(LithiumError::io)?;
    fs::create_dir_all(priv_dir).map_err(LithiumError::io)?;

    let ed25519 = ensure_seed32_born_locked(
        arena,
        &priv_dir.join(ED_PRIV),
        mk,
        KT_ED_SEED,
        keys::ed25519_pub_from_seed,
    )?;

    let x25519 = ensure_seed32_born_locked(
        arena,
        &priv_dir.join(X_PRIV),
        mk,
        KT_X_SEED,
        keys::x25519_pub_from_seed,
    )?;

    let kyber = {
        let priv_path = priv_dir.join(KYBER_PRIV);
        let pub_path = pub_dir.join(KYBER_PUB);

        if priv_path.exists() && pub_path.exists() {
            let _ = keyfile::load_bytes_decrypted(&priv_path, mk, KT_KYBER_SK)?;
            read_pub_bytes(&pub_path)?
        } else if priv_path.exists() || pub_path.exists() {
            return Err(LithiumError::invalid_credentials(
                "keystore_layout_inconsistent",
            ));
        } else {
            let seed = arena.random_fixed::<64>()?;
            let pk_bytes = keys::mlkem1024_pub_from_seed(seed.as_slice())?;
            keyfile::save_bytes_encrypted(&priv_path, mk, seed.as_slice(), KT_KYBER_SK)?;
            keyfile::write_secure(&pub_path, pk_bytes.as_slice())?;
            pk_bytes
        }
    };

    let dilithium = {
        let priv_path = priv_dir.join(DILI_PRIV);
        let pub_path = pub_dir.join(DILI_PUB);

        if priv_path.exists() && pub_path.exists() {
            let _ = keyfile::load_bytes_decrypted(&priv_path, mk, KT_DILI_SK)?;
            read_pub_bytes(&pub_path)?
        } else if priv_path.exists() || pub_path.exists() {
            return Err(LithiumError::invalid_credentials(
                "keystore_layout_inconsistent",
            ));
        } else {
            let seed = arena.random_fixed::<32>()?;
            let pk_bytes = keys::mldsa87_pub_from_seed(seed.as_slice())?;
            keyfile::save_bytes_encrypted(&priv_path, mk, seed.as_slice(), KT_DILI_SK)?;
            keyfile::write_secure(&pub_path, pk_bytes.as_slice())?;
            pk_bytes
        }
    };

    let pks = PublicKeys {
        ed25519,
        x25519,
        kyber,
        dilithium,
    };

    sync_public_cache(pub_dir, &pks)?;
    Ok(pks)
}

fn has_legacy_or_inconsistent_layout(root_dir: &Path) -> bool {
    root_dir.join(LEGACY_STATE_FILE).exists()
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
        (priv_dir.join(X_PRIV), KT_X_SEED.to_owned()),
        (priv_dir.join(KYBER_PRIV), KT_KYBER_SK.to_owned()),
        (priv_dir.join(DILI_PRIV), KT_DILI_SK.to_owned()),
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
    fs::create_dir_all(&staged_root).map_err(LithiumError::io)?;

    for target in targets {
        let out = keyfile::rewrap_keyfile_dek_to_bytes(
            &target.live_path,
            old_mk,
            new_mk,
            &target.key_type,
        )?;
        let staged_path = stage_target_path(rotate_dir, &target.relative_path);
        if let Some(parent) = staged_path.parent() {
            fs::create_dir_all(parent).map_err(LithiumError::io)?;
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

impl<P: MkProvider> KeyManager<P> {
    pub fn start(base_dir: &Path, kind: KeyStoreKind, mk_provider: P) -> Result<Self> {
        Self::start_with_locking(base_dir, kind, mk_provider, MemoryLocking::Require)
    }

    pub fn start_best_effort(base_dir: &Path, kind: KeyStoreKind, mk_provider: P) -> Result<Self> {
        Self::start_with_locking(base_dir, kind, mk_provider, MemoryLocking::BestEffort)
    }

    fn start_with_locking(
        base_dir: &Path,
        kind: KeyStoreKind,
        mk_provider: P,
        locking: MemoryLocking,
    ) -> Result<Self> {
        let root_dir = base_dir.join(kind.dir_name());
        let pub_dir = root_dir.join(PUB_DIR);
        let priv_dir = root_dir.join(PRIV_DIR);
        let secrets_dir = root_dir.join(SECRETS_DIR);
        let rotate_dir = root_dir.join(ROTATE_DIR);

        fs::create_dir_all(&root_dir).map_err(LithiumError::io)?;
        fs::create_dir_all(&pub_dir).map_err(LithiumError::io)?;
        fs::create_dir_all(&priv_dir).map_err(LithiumError::io)?;
        fs::create_dir_all(&secrets_dir).map_err(LithiumError::io)?;

        let lock_file = acquire_exclusive_lock(&root_dir)?;

        match mk_provider.load_mk() {
            Ok(_) => {}
            Err(e) if e.is_not_found() => {
                let new_mk = keys::random_master_key32()?;
                mk_provider.store_mk(&new_mk)?;
            }
            Err(e) => return Err(e),
        }

        if has_legacy_or_inconsistent_layout(&root_dir) {
            return Err(LithiumError::invalid_credentials(
                "legacy_keystore_layout_unsupported",
            ));
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
            MemoryLocking::Require => SecretArena::with_capacity(ARENA_CAPACITY)?,
            MemoryLocking::BestEffort => SecretArena::with_capacity_best_effort(ARENA_CAPACITY)?,
        };
        let public_keys = ensure_asymmetric_material(&pub_dir, &priv_dir, &root_mk, &arena)?;

        Ok(Self {
            root_dir,
            pub_dir,
            priv_dir,
            secrets_dir,
            rotate_dir,
            mk_provider,
            public_keys,
            arena,
            lock_file,
            rotate_every: DEFAULT_ROTATE_EVERY,
            next_rotation_at: Instant::now() + DEFAULT_ROTATE_EVERY,
        })
    }

    #[cfg(feature = "insecure-plaintext-mk")]
    pub fn start_plain(
        base_dir: &Path,
        kind: KeyStoreKind,
    ) -> Result<KeyManager<InsecurePlaintextMkProvider>> {
        let mk_path = base_dir.join(kind.dir_name()).join("mk");
        let provider = InsecurePlaintextMkProvider::new(mk_path);
        KeyManager::start(base_dir, kind, provider)
    }

    pub fn public_keys(&self) -> &PublicKeys {
        &self.public_keys
    }

    pub fn memory_locked(&self) -> bool {
        self.arena.is_locked()
    }

    pub fn set_rotate_interval(&mut self, interval: Duration) {
        self.rotate_every = interval;
        self.next_rotation_at = Instant::now() + interval;
    }

    pub fn reload_public_keys(&mut self) -> Result<()> {
        self.public_keys = load_public_cache(&self.pub_dir)?;
        Ok(())
    }

    pub fn derive_secret32(&self, label: &[u8]) -> Result<SecByte32> {
        let root_mk = self.mk_provider.load_mk()?;
        self.mk_provider
            .derive_secret32(&root_mk, label, &self.secrets_dir)
    }

    pub fn encrypt_with_derived(
        &self,
        label: &[u8],
        plaintext: &SecretBytes,
        aad: &[u8],
    ) -> Result<PublicBytes> {
        let dek = self.derive_secret32(label)?;
        let nonce = keys::random_12()?;
        aead::encrypt(plaintext, &dek, &nonce, aad)
    }

    pub fn decrypt_with_derived(
        &self,
        label: &[u8],
        blob: &PublicBytes,
        aad: &[u8],
    ) -> Result<SecretBytes> {
        let dek = self.derive_secret32(label)?;
        aead::decrypt(blob, &dek, aad)
    }

    pub fn mk_provider_mut(&mut self) -> &mut P {
        &mut self.mk_provider
    }

    pub fn load_or_create_sealed_blob(
        &self,
        label: &[u8],
        generate: impl FnOnce() -> Result<SecretBytes>,
    ) -> Result<SecretBytes> {
        let root_mk = self.mk_provider.load_mk()?;
        load_or_create_label_bytes(&self.secrets_dir, &root_mk, label, generate)
    }

    pub fn with_signing_keys<R>(
        &self,
        f: impl FnOnce(ArenaByte32, ArenaByte32) -> Result<R>,
    ) -> Result<R> {
        let mk = self.mk_provider.load_mk()?;
        let ed_seed =
            keyfile::load_secret32_decrypted(&self.priv_dir.join(ED_PRIV), &mk, KT_ED_SEED)?;
        let dili_sk =
            keyfile::load_bytes_decrypted(&self.priv_dir.join(DILI_PRIV), &mk, KT_DILI_SK)?;
        let ed_locked = self.arena.store_fixed::<32>(ed_seed.as_array())?;
        let dili_locked = self
            .arena
            .store_slice_fixed::<32>(dili_sk.expose_as_slice())?;
        drop(ed_seed);
        drop(dili_sk);
        f(ed_locked, dili_locked)
    }

    pub fn with_x25519_and_kyber_sk<R>(
        &self,
        f: impl FnOnce(ArenaByte32, ArenaByte64) -> Result<R>,
    ) -> Result<R> {
        let mk = self.mk_provider.load_mk()?;
        let x_seed = keyfile::load_secret32_decrypted(&self.priv_dir.join(X_PRIV), &mk, KT_X_SEED)?;
        let kyber_sk =
            keyfile::load_bytes_decrypted(&self.priv_dir.join(KYBER_PRIV), &mk, KT_KYBER_SK)?;
        let x_locked = self.arena.store_fixed::<32>(x_seed.as_array())?;
        let kyber_locked = self
            .arena
            .store_slice_fixed::<64>(kyber_sk.expose_as_slice())?;
        drop(x_seed);
        drop(kyber_sk);
        f(x_locked, kyber_locked)
    }

    pub fn maybe_rotate_mk(&mut self) -> Result<()> {
        recover_pending_rotation_if_any(
            &self.root_dir,
            &self.priv_dir,
            &self.secrets_dir,
            &self.rotate_dir,
            &self.mk_provider,
        )?;

        if Instant::now() < self.next_rotation_at {
            return Ok(());
        }

        cleanup_rotation_dir(&self.rotate_dir)?;
        fs::create_dir_all(&self.rotate_dir).map_err(LithiumError::io)?;
        sync_dir(&self.rotate_dir)?;

        let old_mk = self.mk_provider.load_mk()?;
        let new_mk = keys::random_master_key32()?;
        let targets = collect_rewrap_targets(&self.root_dir, &self.priv_dir, &self.secrets_dir)?;

        let next_old_path = self.rotate_dir.join(ROTATE_NEXT_OLD_FILE);
        let next_new_path = self.rotate_dir.join(ROTATE_NEXT_NEW_FILE);
        keyfile::save_secret32_encrypted(&next_old_path, &old_mk, &new_mk, KT_ROTATE_NEXT_OLD)?;
        keyfile::save_secret32_encrypted(&next_new_path, &new_mk, &new_mk, KT_ROTATE_NEXT_NEW)?;
        sync_dir(&self.rotate_dir)?;

        prepare_staged_files(&self.rotate_dir, &old_mk, &new_mk, &targets)?;
        write_marker(&self.rotate_dir.join(ROTATE_READY_FILE), b"ready")?;

        apply_staged_files(&self.rotate_dir, &targets)?;
        self.mk_provider.store_mk(&new_mk)?;
        self.next_rotation_at = Instant::now() + self.rotate_every;

        cleanup_rotation_dir(&self.rotate_dir)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_values_are_pinned() {
        assert_eq!(KT_ED_SEED, "ed25519-seed-v1");
        assert_eq!(KT_X_SEED, "x25519-seed-v1");
        assert_eq!(KT_KYBER_SK, "kyber-mlkem1024-sk-v1");
        assert_eq!(KT_DILI_SK, "dilithium-mldsa87-sk-v1");
        assert_eq!(KT_ROTATE_NEXT_OLD, "rotate-next-mk-old-v1");
        assert_eq!(KT_ROTATE_NEXT_NEW, "rotate-next-mk-new-v1");
        assert_eq!(label_key_type(b"ab"), "secret32:6162");

        assert_eq!(ED_PRIV, "ed25519.keyf");
        assert_eq!(X_PRIV, "x25519.keyf");
        assert_eq!(KYBER_PRIV, "kyber-mlkem1024.keyf");
        assert_eq!(DILI_PRIV, "dilithium-mldsa87.keyf");
    }
}


// ===== FILE: ./src/keys/mod.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

pub mod keyfile;
pub mod manager;

pub use manager::{KeyManager, KeyStoreKind, MemoryLocking, MkProvider, PublicKeys};

#[cfg(feature = "insecure-plaintext-mk")]
pub use manager::InsecurePlaintextMkProvider;


// ===== FILE: ./src/lib.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

//! Post-quantum hybrid cryptography and at-rest key management, usable as a standalone library.
//!
//! Every construction is hybrid classical + post-quantum: X25519 + ML-KEM-1024 for encryption,
//! Ed25519 + ML-DSA-87 for signatures, AES-256-GCM-SIV / HKDF-SHA256 / Argon2 underneath. The
//! crate is `#![deny(unsafe_code)]`; the only `unsafe` backs SecretArena, which wraps the
//! `mlock`/`madvise`/`mmap` syscalls behind a safe API and is private. All domain-separation
//! labels are supplied by the caller, so the crypto stays application-agnostic.
//!
//! # Two pillars
//!
//! - **At-rest key management** ([`keys`], [`secrets`]): [`keys::KeyManager`] owns the on-disk
//!   keyfile, pluggable master-key providers, crash-safe hourly rotation and rewrap. Secret
//!   types ([`secrets::SecByte32`], [`secrets::SecretBytes`], [`secrets::MasterKey32`]) zeroize on
//!   drop.
//! - **Hybrid encryption** ([`crypto`]): [`crypto::kyberbox`] is the X25519 + ML-KEM-1024 AEAD
//!   construction; [`crypto::sign`] dual-signs Ed25519 + ML-DSA-87; [`crypto::aead`],
//!   [`crypto::kdf`], [`crypto::keys`] are the AEAD / KDF / keypair primitives beneath them.
//!
//! # Helpers
//!
//! Secondary, deployment-agnostic building blocks layered on the pillars: [`opaque`] (OPAQUE
//! PAKE + export-key DEK wrapping), [`passwords`] (password policy + DEK generation),
//! [`utils::store`] (TTL secret store), [`error`].
//!
//! # Security status
//!
//! Not yet independently audited. The constructions, their hybrid-combiner rationale and the
//! open questions for an auditor live under `docs/` (`combiner.md`, `threat-model.md`).
//!
//! The public surface is intended to be stable through the audit; treat it as frozen at `0.1`.
#![deny(unsafe_code)]

/// Hybrid encryption pillar: KyberBox AEAD, dual signatures, and the AEAD/KDF/keypair primitives.
pub mod crypto;
/// Shared error type returned across the crate.
pub mod error;
/// Helper: hex coder and decoder used by the library
mod hexcodec;
/// Hybrid HPKE-style seal/open, secret export and deterministic keypair derivation
pub mod hpke;
/// At-rest key management pillar: keyfile, master-key providers, rotation and rewrap.
pub mod keys;
/// Helper: OPAQUE PAKE and export-key DEK wrapping for password-authenticated key retrieval.
pub mod opaque;
/// Helper: password policy validation and data-encryption-key generation.
pub mod passwords;
/// Public key material: non-secret byte types parallel to secrets.
pub mod public;
/// At-rest key management pillar: zeroize-on-drop secret types.
pub mod secrets;
/// Helper: in-memory TTL store for ephemeral secrets.
pub mod utils;

pub use error::{ErrorKind, LithiumError, Result};


// ===== FILE: ./src/opaque/client.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, Identifiers, RegistrationResponse,
};
use rand_core::OsRng;

use crate::error::{LithiumError, Result};
use crate::opaque::suite::{
    ClientLoginState, ClientRegistrationState, LithiumCipherSuite, opaque_ksf,
};
use crate::secrets::{SecByte64, SecretString};

fn identifiers<'a>(handler: &'a [u8], server_id: &'a [u8]) -> Identifiers<'a> {
    Identifiers {
        client: Some(handler),
        server: Some(server_id),
    }
}

pub fn client_registration_start(
    password: &SecretString,
) -> Result<(Vec<u8>, ClientRegistrationState)> {
    let mut rng = OsRng;
    let res =
        ClientRegistration::<LithiumCipherSuite>::start(&mut rng, password.expose().as_bytes())
            .map_err(|_| LithiumError::internal("opaque_registration_start"))?;
    Ok((res.message.serialize().to_vec(), res.state))
}

pub fn client_registration_finish(
    state: ClientRegistrationState,
    response_bytes: &[u8],
    password: &SecretString,
    handler: &[u8],
    server_id: &[u8],
) -> Result<(Vec<u8>, SecByte64)> {
    let response = RegistrationResponse::<LithiumCipherSuite>::deserialize(response_bytes)
        .map_err(|_| LithiumError::invalid_credentials("bad_opaque_message"))?;
    let ksf = opaque_ksf()?;
    let mut rng = OsRng;
    let res = state
        .finish(
            &mut rng,
            password.expose().as_bytes(),
            response,
            ClientRegistrationFinishParameters::new(identifiers(handler, server_id), Some(&ksf)),
        )
        .map_err(|_| LithiumError::internal("opaque_registration_finish"))?;
    let export_key = SecByte64::from_slice(&res.export_key)?;
    Ok((res.message.serialize().to_vec(), export_key))
}

pub fn client_login_start(password: &SecretString) -> Result<(Vec<u8>, ClientLoginState)> {
    let mut rng = OsRng;
    let res = ClientLogin::<LithiumCipherSuite>::start(&mut rng, password.expose().as_bytes())
        .map_err(|_| LithiumError::internal("opaque_login_start"))?;
    Ok((res.message.serialize().to_vec(), res.state))
}

pub fn client_login_finish(
    state: ClientLoginState,
    response_bytes: &[u8],
    password: &SecretString,
    handler: &[u8],
    server_id: &[u8],
) -> Result<(Vec<u8>, SecByte64)> {
    let response = CredentialResponse::<LithiumCipherSuite>::deserialize(response_bytes)
        .map_err(|_| LithiumError::invalid_credentials("bad_opaque_message"))?;
    let ksf = opaque_ksf()?;
    let mut rng = OsRng;
    let res = state
        .finish(
            &mut rng,
            password.expose().as_bytes(),
            response,
            ClientLoginFinishParameters::new(None, identifiers(handler, server_id), Some(&ksf)),
        )
        .map_err(|_| LithiumError::invalid_credentials("opaque_login_failed"))?;
    let export_key = SecByte64::from_slice(&res.export_key)?;
    Ok((res.message.serialize().to_vec(), export_key))
}


// ===== FILE: ./src/opaque/dek.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::crypto::{aead, kdf, keys};
use crate::error::{LithiumError, Result};
use crate::public::PublicBytes;
use crate::secrets::bytes::SecretBytes;
use crate::secrets::{SecByte32, SecByte64, SecretString};

const DEK_WRAP_VER: u8 = 1;

fn wrap_key(export_key: &SecByte64, aad: &[u8]) -> Result<SecByte32> {
    kdf::derive32(&SecretBytes::from_slice(export_key.as_slice()), None, aad)
}

pub fn wrap_dek_under_export_key(
    dek: &SecByte32,
    export_key: &SecByte64,
    aad: &[u8],
) -> Result<SecretString> {
    let key = wrap_key(export_key, aad)?;
    let nonce = keys::random_12()?;
    let blob = aead::encrypt(&SecretBytes::from_slice(dek.as_slice()), &key, &nonce, aad)?;

    let mut out = Vec::with_capacity(1 + blob.len());
    out.push(DEK_WRAP_VER);
    out.extend_from_slice(blob.as_slice());

    Ok(SecretString::new(hex::encode(out)))
}

pub fn unwrap_dek_under_export_key(
    blob_hex: &SecretString,
    export_key: &SecByte64,
    aad: &[u8],
) -> Result<SecByte32> {
    let blob = SecretBytes::from_hex(blob_hex.expose().trim())?;

    if blob.len() < 1 + 1 + 12 + 16 {
        return Err(LithiumError::invalid_credentials("bad_dek_blob"));
    }
    if blob.expose_as_slice()[0] != DEK_WRAP_VER {
        return Err(LithiumError::invalid_credentials("bad_dek_blob"));
    }

    let key = wrap_key(export_key, aad)?;
    let wrapped = PublicBytes::from_slice(&blob.expose_as_slice()[1..]);
    let pt = aead::decrypt(&wrapped, &key, aad)?;

    SecByte32::from_slice(pt.expose_as_slice())
}


// ===== FILE: ./src/opaque/mod.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

pub mod client;
pub mod dek;
pub mod server;
pub(crate) mod suite;

pub use suite::{ClientLoginState, ClientRegistrationState, LithiumCipherSuite};


// ===== FILE: ./src/opaque/server.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use opaque_ke::{
    CredentialFinalization, CredentialRequest, Identifiers, RegistrationRequest,
    RegistrationUpload, ServerLogin, ServerLoginParameters, ServerRegistration,
};
use rand_core::OsRng;

use crate::error::{LithiumError, Result};
use crate::opaque::suite::LithiumCipherSuite;

type Setup = opaque_ke::ServerSetup<LithiumCipherSuite>;

pub struct ServerSetup(Setup);

impl ServerSetup {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        Self(Setup::new(&mut rng))
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.0.serialize().to_vec()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        Setup::deserialize(bytes)
            .map(Self)
            .map_err(|_| LithiumError::internal("opaque_server_setup_decode"))
    }
}

fn identifiers<'a>(handler: &'a [u8], server_id: &'a [u8]) -> Identifiers<'a> {
    Identifiers {
        client: Some(handler),
        server: Some(server_id),
    }
}

fn bad_message() -> LithiumError {
    LithiumError::invalid_credentials("bad_opaque_message")
}

pub fn server_registration_start(
    setup: &ServerSetup,
    request_bytes: &[u8],
    credential_identifier: &[u8],
) -> Result<Vec<u8>> {
    let request = RegistrationRequest::<LithiumCipherSuite>::deserialize(request_bytes)
        .map_err(|_| bad_message())?;
    let res = ServerRegistration::start(&setup.0, request, credential_identifier)
        .map_err(|_| LithiumError::internal("opaque_registration_start"))?;
    Ok(res.message.serialize().to_vec())
}

pub fn server_registration_finish(upload_bytes: &[u8]) -> Result<Vec<u8>> {
    let upload = RegistrationUpload::<LithiumCipherSuite>::deserialize(upload_bytes)
        .map_err(|_| bad_message())?;
    Ok(ServerRegistration::finish(upload).serialize().to_vec())
}

pub fn server_login_start(
    setup: &ServerSetup,
    record_bytes: &[u8],
    request_bytes: &[u8],
    credential_identifier: &[u8],
    handler: &[u8],
    server_id: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let record = ServerRegistration::<LithiumCipherSuite>::deserialize(record_bytes)
        .map_err(|_| LithiumError::internal("opaque_record_decode"))?;
    let request = CredentialRequest::<LithiumCipherSuite>::deserialize(request_bytes)
        .map_err(|_| bad_message())?;

    let params = ServerLoginParameters {
        context: None,
        identifiers: identifiers(handler, server_id),
    };

    let mut rng = OsRng;
    let res = ServerLogin::start(
        &mut rng,
        &setup.0,
        Some(record),
        request,
        credential_identifier,
        params,
    )
    .map_err(|_| LithiumError::internal("opaque_login_start"))?;

    Ok((
        res.message.serialize().to_vec(),
        res.state.serialize().to_vec(),
    ))
}

pub fn server_login_finish(
    state_bytes: &[u8],
    finalization_bytes: &[u8],
    handler: &[u8],
    server_id: &[u8],
) -> Result<()> {
    let state = ServerLogin::<LithiumCipherSuite>::deserialize(state_bytes)
        .map_err(|_| LithiumError::internal("opaque_login_state_decode"))?;
    let finalization =
        CredentialFinalization::<LithiumCipherSuite>::deserialize(finalization_bytes)
            .map_err(|_| bad_message())?;

    let params = ServerLoginParameters {
        context: None,
        identifiers: identifiers(handler, server_id),
    };

    state
        .finish(finalization, params)
        .map(|_| ())
        .map_err(|_| LithiumError::invalid_credentials("opaque_login_failed"))
}

#[cfg(feature = "fuzzing")]
pub fn opaque_parse_fuzz(data: &[u8]) {
    let _ = RegistrationRequest::<LithiumCipherSuite>::deserialize(data);
    let _ = RegistrationUpload::<LithiumCipherSuite>::deserialize(data);
    let _ = CredentialRequest::<LithiumCipherSuite>::deserialize(data);
    let _ = CredentialFinalization::<LithiumCipherSuite>::deserialize(data);
    let _ = ServerSetup::deserialize(data);
}


// ===== FILE: ./src/opaque/suite.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use argon2::{Algorithm, Argon2, Params, Version};
use opaque_ke::{CipherSuite, Ristretto255, TripleDh};
use sha2::Sha512;

use crate::crypto::kdf::{ARGON2_M_COST, ARGON2_P_COST, ARGON2_T_COST};
use crate::error::{LithiumError, Result};

pub struct LithiumCipherSuite;

impl CipherSuite for LithiumCipherSuite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, Sha512>;
    type Ksf = Argon2<'static>;
}

pub type ClientRegistrationState = opaque_ke::ClientRegistration<LithiumCipherSuite>;
pub type ClientLoginState = opaque_ke::ClientLogin<LithiumCipherSuite>;

// OPAQUE stretches the OPRF output to the envelope hash length (64), so output_len
// must stay unset; the cost profile matches kdf::argon2id().
pub(crate) fn opaque_ksf() -> Result<Argon2<'static>> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, None)
        .map_err(|_| LithiumError::internal("argon2_params"))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}


// ===== FILE: ./src/passwords/mod.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#[allow(clippy::module_inception)]
mod passwords;

pub use passwords::{PasswordPolicy, generate_dek, validate_password, validate_passwords_distinct};


// ===== FILE: ./src/passwords/passwords.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    crypto::keys,
    error::{LithiumError, Result},
    secrets::{SecByte32, SecretString},
};

#[derive(Debug, Clone, Copy)]
pub struct PasswordPolicy {
    pub min_len: usize,
    pub max_len: usize,
    pub require_lowercase: bool,
    pub require_uppercase: bool,
    pub require_digit: bool,
    pub require_special: bool,
    pub allow_whitespace: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_len: 12,
            max_len: 1024,
            require_lowercase: true,
            require_uppercase: true,
            require_digit: true,
            require_special: true,
            allow_whitespace: false,
        }
    }
}

pub fn validate_password(password: &SecretString, pol: PasswordPolicy) -> Result<()> {
    let s = password.expose();
    let len = s.chars().count();

    if len < pol.min_len || len > pol.max_len {
        return Err(LithiumError::string_policy());
    }

    if s.as_bytes().contains(&0) {
        return Err(LithiumError::string_policy());
    }

    if !pol.allow_whitespace && s.chars().any(|c| c.is_whitespace()) {
        return Err(LithiumError::string_policy());
    }

    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_special = false;

    for ch in s.chars() {
        if ch.is_ascii_lowercase() {
            has_lower = true;
        } else if ch.is_ascii_uppercase() {
            has_upper = true;
        } else if ch.is_ascii_digit() {
            has_digit = true;
        } else if !ch.is_whitespace() {
            has_special = true;
        }
    }

    if pol.require_lowercase && !has_lower {
        return Err(LithiumError::string_policy());
    }
    if pol.require_uppercase && !has_upper {
        return Err(LithiumError::string_policy());
    }
    if pol.require_digit && !has_digit {
        return Err(LithiumError::string_policy());
    }
    if pol.require_special && !has_special {
        return Err(LithiumError::string_policy());
    }

    Ok(())
}

pub fn validate_passwords_distinct(a: &SecretString, b: &SecretString) -> Result<()> {
    if a.expose() == b.expose() {
        return Err(LithiumError::invalid_credentials("passwords_not_distinct"));
    }
    Ok(())
}

pub fn generate_dek() -> Result<SecByte32> {
    keys::random_32()
}


// ===== FILE: ./src/public/bytes.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use core::fmt;

use crate::error::{LithiumError, Result};
use crate::hexcodec;

pub struct PublicFixedBytes<const N: usize>([u8; N]);

impl<const N: usize> PublicFixedBytes<N> {
    pub const LEN: usize = N;

    #[inline]
    pub fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != N {
            return Err(LithiumError::invalid_len(N, slice.len()));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(Self(out))
    }

    #[inline]
    pub fn as_array(&self) -> &[u8; N] {
        &self.0
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    #[inline]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    #[inline]
    pub fn from_hex(s: &str) -> Result<Self> {
        let mut out = [0u8; N];
        hexcodec::decode_into(s, &mut out)?;
        Ok(Self(out))
    }
}

impl<const N: usize> Copy for PublicFixedBytes<N> {}

impl<const N: usize> Clone for PublicFixedBytes<N> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<const N: usize> PartialEq for PublicFixedBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<const N: usize> Eq for PublicFixedBytes<N> {}

impl<const N: usize> fmt::Debug for PublicFixedBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicFixed<{N}>({})", hex::encode(self.0))
    }
}

impl<const N: usize> AsRef<[u8]> for PublicFixedBytes<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> From<[u8; N]> for PublicFixedBytes<N> {
    fn from(value: [u8; N]) -> Self {
        Self(value)
    }
}

impl<const N: usize> TryFrom<&[u8]> for PublicFixedBytes<N> {
    type Error = LithiumError;
    fn try_from(value: &[u8]) -> Result<Self> {
        Self::from_slice(value)
    }
}

pub type PubByte32 = PublicFixedBytes<32>;

#[derive(Clone, PartialEq, Eq)]
pub struct PublicBytes(Vec<u8>);

impl PublicBytes {
    #[inline]
    pub fn new(v: Vec<u8>) -> Self {
        Self(v)
    }
    #[inline]
    pub fn from_slice(v: &[u8]) -> Self {
        Self(v.to_vec())
    }
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
    #[inline]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    #[inline]
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
    #[inline]
    pub fn from_hex(s: &str) -> Result<Self> {
        Ok(Self(hexcodec::decode_vec(s)?))
    }
}

impl fmt::Debug for PublicBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicBytes({})", hex::encode(&self.0))
    }
}

impl AsRef<[u8]> for PublicBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for PublicBytes {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<&[u8]> for PublicBytes {
    fn from(value: &[u8]) -> Self {
        Self::from_slice(value)
    }
}


// ===== FILE: ./src/public/mod.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

pub(crate) mod bytes;

pub use bytes::{PubByte32, PublicBytes, PublicFixedBytes};


// ===== FILE: ./src/secrets/arena.rs =====
// ----------------------------------------

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


// ===== FILE: ./src/secrets/bytes.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use core::fmt;
use std::io;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};

use crate::error::{LithiumError, Result};
use crate::hexcodec;
use crate::secrets::SecretString;

pub struct SecretFixedBytes<const N: usize>(SecretBox<[u8; N]>);

impl<const N: usize> SecretFixedBytes<N> {
    pub const LEN: usize = N;

    #[inline]
    pub fn new(bytes: [u8; N]) -> Self {
        Self(SecretBox::new(Box::new(bytes)))
    }

    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != N {
            return Err(LithiumError::invalid_len(N, slice.len()));
        }
        let mut out = Self::new_zeroed();
        out.as_mut_slice().copy_from_slice(slice);
        Ok(out)
    }

    #[inline]
    pub fn as_array(&self) -> &[u8; N] {
        self.0.expose_secret()
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        self.0.expose_secret().as_slice()
    }

    #[inline]
    pub fn to_hex(&self) -> SecretString {
        SecretString::new(hex::encode(self.as_slice()))
    }

    #[inline]
    pub fn from_hex(s: &str) -> Result<Self> {
        let mut out = Self::new_zeroed();
        hexcodec::decode_into(s, out.as_mut_slice())?;
        Ok(out)
    }

    #[inline]
    pub fn new_zeroed() -> Self {
        Self(SecretBox::new(Box::new([0u8; N])))
    }

    #[inline]
    pub fn as_mut_array(&mut self) -> &mut [u8; N] {
        self.0.expose_secret_mut()
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.0.expose_secret_mut().as_mut_slice()
    }
}

impl<const N: usize> Clone for SecretFixedBytes<N> {
    fn clone(&self) -> Self {
        let mut out = Self::new_zeroed();
        out.as_mut_slice().copy_from_slice(self.as_slice());
        out
    }
}

impl<const N: usize> PartialEq for SecretFixedBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice().ct_eq(other.as_slice()).into()
    }
}

impl<const N: usize> Eq for SecretFixedBytes<N> {}

impl<const N: usize> fmt::Debug for SecretFixedBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretFixedBytes<{}>(..)", N)
    }
}

impl<const N: usize> AsRef<[u8]> for SecretFixedBytes<N> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<const N: usize> TryFrom<&[u8]> for SecretFixedBytes<N> {
    type Error = LithiumError;
    fn try_from(value: &[u8]) -> Result<Self> {
        Self::from_slice(value)
    }
}

impl<const N: usize> From<[u8; N]> for SecretFixedBytes<N> {
    fn from(value: [u8; N]) -> Self {
        Self::new(value)
    }
}

pub type SecByte12 = SecretFixedBytes<12>;
pub type SecByte32 = SecretFixedBytes<32>;
pub type SecByte64 = SecretFixedBytes<64>;

pub type MasterKey32 = SecByte32;
pub type Nonce12 = SecByte12;
pub type SessionId32 = SecByte32;

pub struct SecretBytes(SecretBox<Vec<u8>>);

impl SecretBytes {
    #[inline]
    pub fn new(v: Vec<u8>) -> Self {
        Self(SecretBox::new(Box::new(v)))
    }
    #[inline]
    pub fn from_slice(v: &[u8]) -> Self {
        Self::new(v.to_vec())
    }
    #[inline]
    pub fn from_wiped<T: AsMut<[u8]>>(mut src: T) -> Self {
        let out = Self::new(src.as_mut().to_vec());
        src.as_mut().zeroize();
        out
    }
    #[inline]
    pub fn expose_as_slice(&self) -> &[u8] {
        self.0.expose_secret().as_slice()
    }
    #[inline]
    pub fn expose_as_mut_vec(&mut self) -> &mut Vec<u8> {
        self.0.expose_secret_mut()
    }
    #[inline]
    pub fn expose_into_vec(self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.expose_secret().clone())
    }
    #[inline]
    pub fn to_hex(&self) -> SecretString {
        SecretString::new(hex::encode(self.expose_as_slice()))
    }
    #[inline]
    pub fn len(&self) -> usize {
        self.expose_as_slice().len()
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.expose_as_slice().is_empty()
    }

    #[inline]
    pub fn from_hex(s: &str) -> Result<Self> {
        Ok(Self::new(hexcodec::decode_vec(s)?))
    }
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self::from_slice(self.expose_as_slice())
    }
}
impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(..)")
    }
}
impl ExposeSecret<Vec<u8>> for SecretBytes {
    fn expose_secret(&self) -> &Vec<u8> {
        self.0.expose_secret()
    }
}
impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        self.expose_as_slice()
    }
}

pub struct ZeroizingWriter {
    buf: Vec<u8>,
}

impl ZeroizingWriter {
    #[inline]
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    #[inline]
    pub fn into_secret(self) -> SecretBytes {
        SecretBytes::new(self.buf)
    }
}

impl Default for ZeroizingWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl io::Write for ZeroizingWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        // Manual grow so the outgrown buffer is zeroized before it is freed; a
        // plain Vec realloc would leave secret fragments in freed heap.
        if self.buf.len() + data.len() > self.buf.capacity() {
            let new_cap = (self.buf.capacity() * 2)
                .max(self.buf.len() + data.len())
                .max(64);
            let mut next = Vec::with_capacity(new_cap);
            next.extend_from_slice(&self.buf);
            self.buf.zeroize();
            self.buf = next;
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn zeroizing_writer_concatenates_across_growth() {
        let mut w = ZeroizingWriter::new();
        let mut expected = Vec::new();
        for i in 0u16..2000 {
            let chunk = i.to_be_bytes();
            w.write_all(&chunk).unwrap();
            expected.extend_from_slice(&chunk);
        }
        assert_eq!(w.into_secret().expose_as_slice(), expected.as_slice());
    }

    #[test]
    fn zeroizing_writer_matches_serde_to_vec() {
        let value = serde_json::json!({"k_priv": "deadbeef", "n": 42, "list": [1, 2, 3]});
        let mut w = ZeroizingWriter::new();
        serde_json::to_writer(&mut w, &value).unwrap();
        assert_eq!(
            w.into_secret().expose_as_slice(),
            serde_json::to_vec(&value).unwrap().as_slice()
        );
    }
}


// ===== FILE: ./src/secrets/json.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use core::fmt;

use secrecy::{ExposeSecret, SecretBox};
use serde_json::{Value, map::Map};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{LithiumError, Result};
use crate::secrets::string::SecretString;

pub struct SecretJson {
    value: Value,
    raw: Option<SecretString>,
}

#[inline]
fn ty_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

impl SecretJson {
    #[inline]
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self> {
        let v: Value = serde_json::from_str(s)?;
        Ok(Self {
            value: v,
            raw: Some(SecretString::new(s.to_owned())),
        })
    }
    #[inline]
    pub fn from_string(s: String) -> Result<Self> {
        let v: Value = serde_json::from_str(&s)?;
        Ok(Self {
            value: v,
            raw: Some(SecretString::new(s)),
        })
    }
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let s = core::str::from_utf8(bytes)
            .map_err(|e| LithiumError::string_policy().with_source(e))?;
        Self::from_str(s)
    }
    #[inline]
    pub fn from_vec(bytes: Vec<u8>) -> Result<Self> {
        let s =
            String::from_utf8(bytes).map_err(|e| LithiumError::string_policy().with_source(e))?;
        Self::from_string(s)
    }
    #[inline]
    pub fn from_zeroizing_vec(bytes: Zeroizing<Vec<u8>>) -> Result<Self> {
        let s = core::str::from_utf8(bytes.as_slice())
            .map_err(|e| LithiumError::string_policy().with_source(e))?;
        Self::from_str(s)
    }
    #[inline]
    pub fn from_zeroizing_vec_no_raw(bytes: Zeroizing<Vec<u8>>) -> Result<Self> {
        let v: Value = serde_json::from_slice(bytes.as_slice())?;
        Ok(Self {
            value: v,
            raw: None,
        })
    }

    fn zeroize_value(v: &mut Value) {
        match v {
            Value::String(s) => {
                s.zeroize();
                s.clear();
                s.shrink_to_fit();
            }
            Value::Array(arr) => {
                for elem in arr.iter_mut() {
                    Self::zeroize_value(elem);
                }
                arr.clear();
                arr.shrink_to_fit();
            }
            Value::Object(map) => {
                let owned: Map<String, Value> = core::mem::take(map);
                for (mut k, mut mut_v) in owned.into_iter() {
                    Self::zeroize_value(&mut mut_v);
                    drop(mut_v);
                    k.zeroize();
                    k.clear();
                    k.shrink_to_fit();
                }
            }
            Value::Number(_) => *v = Value::Null,
            Value::Bool(_) | Value::Null => {}
        }
    }

    #[inline]
    pub fn with_exposed<R>(&self, f: impl FnOnce(&Value) -> R) -> R {
        f(&self.value)
    }
    #[inline]
    pub fn with_exposed_mut<R>(&mut self, f: impl FnOnce(&mut Value) -> R) -> R {
        f(&mut self.value)
    }
    #[inline]
    fn obj(&self) -> Result<&Map<String, Value>> {
        self.value
            .as_object()
            .ok_or_else(LithiumError::json_not_object)
    }
    #[inline]
    fn obj_mut(&mut self) -> Result<&mut Map<String, Value>> {
        self.value
            .as_object_mut()
            .ok_or_else(LithiumError::json_not_object)
    }

    #[inline]
    pub fn get_string(&self, key: &'static str) -> Result<SecretString> {
        let obj = self.obj()?;
        let v = obj
            .get(key)
            .ok_or_else(|| LithiumError::json_missing_field(key))?;
        match v {
            Value::String(s) => Ok(SecretString::new(s.clone())),
            other => Err(LithiumError::json_type_mismatch(key, ty_name(other))),
        }
    }
    #[inline]
    pub fn get_integer(&self, key: &'static str) -> Result<SecretBox<i64>> {
        let obj = self.obj()?;
        let v = obj
            .get(key)
            .ok_or_else(|| LithiumError::json_missing_field(key))?;
        match v.as_i64() {
            Some(i) => Ok(SecretBox::new(Box::new(i))),
            None => Err(LithiumError::json_type_mismatch(key, ty_name(v))),
        }
    }
    #[inline]
    pub fn get_bool(&self, key: &'static str) -> Result<bool> {
        let obj = self.obj()?;
        let v = obj
            .get(key)
            .ok_or_else(|| LithiumError::json_missing_field(key))?;
        v.as_bool()
            .ok_or_else(|| LithiumError::json_type_mismatch(key, ty_name(v)))
    }
    #[inline]
    pub fn get_array(&self, key: &'static str) -> Result<Vec<SecretJson>> {
        let obj = self.obj()?;
        let v = obj
            .get(key)
            .ok_or_else(|| LithiumError::json_missing_field(key))?;
        match v.as_array() {
            Some(a) => Ok(a.iter().cloned().map(SecretJson::from).collect()),
            None => Err(LithiumError::json_type_mismatch(key, ty_name(v))),
        }
    }
    #[inline]
    pub fn get_object(&self, key: &'static str) -> Result<SecretJson> {
        let obj = self.obj()?;
        let v = obj
            .get(key)
            .ok_or_else(|| LithiumError::json_missing_field(key))?;
        match v.as_object() {
            Some(o) => Ok(SecretJson::from(Value::Object(o.clone()))),
            None => Err(LithiumError::json_type_mismatch(key, ty_name(v))),
        }
    }
    #[inline]
    pub fn take_string(&mut self, key: &'static str) -> Result<SecretString> {
        let obj = self.obj_mut()?;
        match obj.remove(key) {
            Some(Value::String(s)) => Ok(SecretString::new(s)),
            Some(other) => Err(LithiumError::json_type_mismatch(key, ty_name(&other))),
            None => Err(LithiumError::json_missing_field(key)),
        }
    }
    #[inline]
    pub fn take_bool(&mut self, key: &'static str) -> Result<bool> {
        let obj = self.obj_mut()?;
        match obj.remove(key) {
            Some(Value::Bool(b)) => Ok(b),
            Some(other) => Err(LithiumError::json_type_mismatch(key, ty_name(&other))),
            None => Err(LithiumError::json_missing_field(key)),
        }
    }
    #[inline]
    pub fn take_i64(&mut self, key: &'static str) -> Result<SecretBox<i64>> {
        let obj = self.obj_mut()?;
        match obj.remove(key) {
            Some(Value::Number(n)) => n
                .as_i64()
                .map(|i| SecretBox::new(Box::new(i)))
                .ok_or_else(|| LithiumError::json_type_mismatch(key, "number")),
            Some(other) => Err(LithiumError::json_type_mismatch(key, ty_name(&other))),
            None => Err(LithiumError::json_missing_field(key)),
        }
    }
    #[inline]
    pub fn take_u64(&mut self, key: &'static str) -> Result<SecretBox<u64>> {
        let obj = self.obj_mut()?;
        match obj.remove(key) {
            Some(Value::Number(n)) => n
                .as_u64()
                .map(|u| SecretBox::new(Box::new(u)))
                .ok_or_else(|| LithiumError::json_type_mismatch(key, "number")),
            Some(other) => Err(LithiumError::json_type_mismatch(key, ty_name(&other))),
            None => Err(LithiumError::json_missing_field(key)),
        }
    }
    #[inline]
    pub fn take_f64(&mut self, key: &'static str) -> Result<SecretBox<f64>> {
        let obj = self.obj_mut()?;
        match obj.remove(key) {
            Some(Value::Number(n)) => n
                .as_f64()
                .map(|u| SecretBox::new(Box::new(u)))
                .ok_or_else(|| LithiumError::json_type_mismatch(key, "number")),
            Some(other) => Err(LithiumError::json_type_mismatch(key, ty_name(&other))),
            None => Err(LithiumError::json_missing_field(key)),
        }
    }
    #[inline]
    pub fn take_array(&mut self, key: &'static str) -> Result<Vec<SecretJson>> {
        let obj = self.obj_mut()?;
        match obj.remove(key) {
            Some(Value::Array(a)) => Ok(a.into_iter().map(SecretJson::from).collect()),
            Some(other) => Err(LithiumError::json_type_mismatch(key, ty_name(&other))),
            None => Err(LithiumError::json_missing_field(key)),
        }
    }
    #[inline]
    pub fn take_object(&mut self, key: &'static str) -> Result<SecretJson> {
        let obj = self.obj_mut()?;
        match obj.remove(key) {
            Some(Value::Object(o)) => Ok(SecretJson::from(Value::Object(o))),
            Some(other) => Err(LithiumError::json_type_mismatch(key, ty_name(&other))),
            None => Err(LithiumError::json_missing_field(key)),
        }
    }
    #[inline]
    pub fn take_raw_json(&mut self) -> Option<SecretString> {
        self.raw.take()
    }
    #[inline]
    pub fn get_raw_json(&self) -> Option<SecretString> {
        self.raw.as_ref().cloned()
    }
}

impl From<Value> for SecretJson {
    fn from(value: Value) -> Self {
        SecretJson { value, raw: None }
    }
}
impl Drop for SecretJson {
    fn drop(&mut self) {
        Self::zeroize_value(&mut self.value);
    }
}
impl fmt::Debug for SecretJson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretJson(<redacted>)")
    }
}
impl fmt::Display for SecretJson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}
impl ExposeSecret<Value> for SecretJson {
    fn expose_secret(&self) -> &Value {
        &self.value
    }
}


// ===== FILE: ./src/secrets/mod.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

pub(crate) mod arena;
pub(crate) mod bytes;
pub(crate) mod json;
pub(crate) mod string;

pub(crate) use arena::SecretArena;
pub use arena::{ArenaByte32, ArenaByte64, ArenaFixedBytes, harden_process};
pub use bytes::{
    MasterKey32, Nonce12, SecByte12, SecByte32, SecByte64, SecretBytes, SecretFixedBytes,
    SessionId32, ZeroizingWriter,
};
pub use json::SecretJson;
pub use string::SecretString;


// ===== FILE: ./src/secrets/string.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use core::fmt;

use secrecy::{ExposeSecret, SecretString as SecrecySecretString};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{LithiumError, Result};
use crate::secrets::bytes::SecretFixedBytes;

#[derive(Clone)]
pub struct SecretString(SecrecySecretString);

impl SecretString {
    #[inline]
    pub fn new(s: String) -> Self {
        Self(SecrecySecretString::new(Box::from(s)))
    }

    #[inline]
    pub fn new_checked(s: String) -> Result<Self> {
        if s.as_bytes().contains(&0) {
            return Err(LithiumError::string_policy());
        }
        Ok(Self::new(s))
    }

    #[inline]
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }

    #[inline]
    pub fn to_zeroizing(&self) -> Zeroizing<String> {
        Zeroizing::new(self.expose().to_owned())
    }

    #[inline]
    pub fn from_utf8_bytes(bytes: &[u8]) -> Result<Self> {
        let s = core::str::from_utf8(bytes)
            .map_err(|e| LithiumError::string_policy().with_source(e))?
            .to_owned();
        Self::new_checked(s)
    }

    #[inline]
    pub fn from_utf8_vec(bytes: Vec<u8>) -> Result<Self> {
        let s =
            String::from_utf8(bytes).map_err(|e| LithiumError::string_policy().with_source(e))?;
        Self::new_checked(s)
    }

    #[inline]
    pub fn decode_hex(&self) -> Result<Zeroizing<Vec<u8>>> {
        let v = hex::decode(self.expose()).map_err(LithiumError::from)?;
        Ok(Zeroizing::new(v))
    }

    #[inline]
    pub fn decode_hex_fixed<const N: usize>(&self) -> Result<SecretFixedBytes<N>> {
        SecretFixedBytes::<N>::from_hex(self.expose())
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut s = String::deserialize(deserializer)?;

        if s.as_bytes().contains(&0) {
            s.zeroize();
            return Err(D::Error::custom("invalid secret string"));
        }

        Ok(Self::new(s))
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl TryFrom<&[u8]> for SecretString {
    type Error = LithiumError;
    fn try_from(value: &[u8]) -> Result<Self> {
        Self::from_utf8_bytes(value)
    }
}

impl TryFrom<Vec<u8>> for SecretString {
    type Error = LithiumError;
    fn try_from(value: Vec<u8>) -> Result<Self> {
        Self::from_utf8_vec(value)
    }
}

impl TryFrom<&Vec<u8>> for SecretString {
    type Error = LithiumError;
    fn try_from(value: &Vec<u8>) -> Result<Self> {
        Self::from_utf8_bytes(value.as_slice())
    }
}

impl ExposeSecret<str> for SecretString {
    fn expose_secret(&self) -> &str {
        self.expose()
    }
}


// ===== FILE: ./src/utils/mod.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

pub mod store;


// ===== FILE: ./src/utils/store.rs =====
// ----------------------------------------

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


// ===== FILE: ./target/aarch64-apple-ios/debug/build/serde-791a490d9681dc0d/out/private.rs =====
// ----------------------------------------

#[doc(hidden)]
pub mod __private228 {
    #[doc(hidden)]
    pub use crate::private::*;
}
use serde_core::__private228 as serde_core_private;


// ===== FILE: ./target/aarch64-apple-ios/debug/build/serde_core-770ae208312a8549/out/private.rs =====
// ----------------------------------------

#[doc(hidden)]
pub mod __private228 {
    #[doc(hidden)]
    pub use crate::private::*;
}


// ===== FILE: ./target/aarch64-linux-android/debug/build/serde-3b862e733687116e/out/private.rs =====
// ----------------------------------------

#[doc(hidden)]
pub mod __private228 {
    #[doc(hidden)]
    pub use crate::private::*;
}
use serde_core::__private228 as serde_core_private;


// ===== FILE: ./target/aarch64-linux-android/debug/build/serde_core-29d18c30ac76507c/out/private.rs =====
// ----------------------------------------

#[doc(hidden)]
pub mod __private228 {
    #[doc(hidden)]
    pub use crate::private::*;
}


// ===== FILE: ./target/debug/build/serde-7e5af1b40ec37e24/out/private.rs =====
// ----------------------------------------

#[doc(hidden)]
pub mod __private228 {
    #[doc(hidden)]
    pub use crate::private::*;
}
use serde_core::__private228 as serde_core_private;


// ===== FILE: ./target/debug/build/serde-b7d6bd1946fd92ab/out/private.rs =====
// ----------------------------------------

#[doc(hidden)]
pub mod __private228 {
    #[doc(hidden)]
    pub use crate::private::*;
}
use serde_core::__private228 as serde_core_private;


// ===== FILE: ./target/debug/build/serde_core-4fd2d8317ddbd6a0/out/private.rs =====
// ----------------------------------------

#[doc(hidden)]
pub mod __private228 {
    #[doc(hidden)]
    pub use crate::private::*;
}


// ===== FILE: ./target/debug/build/serde_core-65eed7f7203d3051/out/private.rs =====
// ----------------------------------------

#[doc(hidden)]
pub mod __private228 {
    #[doc(hidden)]
    pub use crate::private::*;
}


// ===== FILE: ./target/x86_64-pc-windows-msvc/debug/build/serde-22c59705ca63fcf4/out/private.rs =====
// ----------------------------------------

#[doc(hidden)]
pub mod __private228 {
    #[doc(hidden)]
    pub use crate::private::*;
}
use serde_core::__private228 as serde_core_private;


// ===== FILE: ./target/x86_64-pc-windows-msvc/debug/build/serde_core-25a202bb69a3006d/out/private.rs =====
// ----------------------------------------

#[doc(hidden)]
pub mod __private228 {
    #[doc(hidden)]
    pub use crate::private::*;
}


// ===== FILE: ./target/x86_64-unknown-linux-gnu/debug/build/serde-fcc792fb7e62b3ce/out/private.rs =====
// ----------------------------------------

#[doc(hidden)]
pub mod __private228 {
    #[doc(hidden)]
    pub use crate::private::*;
}
use serde_core::__private228 as serde_core_private;


// ===== FILE: ./target/x86_64-unknown-linux-gnu/debug/build/serde_core-473a64d6280b0dba/out/private.rs =====
// ----------------------------------------

#[doc(hidden)]
pub mod __private228 {
    #[doc(hidden)]
    pub use crate::private::*;
}


// ===== FILE: ./tests/common/mod.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use lithium_core::keys::MkProvider;
use lithium_core::secrets::SecByte32;
use lithium_core::{LithiumError, Result};

/// Cleartext file provider for tests only; keeps the suite off the
/// `insecure-plaintext-mk` feature.
pub struct FileMk {
    pub path: PathBuf,
}

impl MkProvider for FileMk {
    fn load_mk(&self) -> Result<SecByte32> {
        let bytes = std::fs::read(&self.path).map_err(LithiumError::io)?;
        SecByte32::from_slice(&bytes)
    }

    fn store_mk(&self, mk: &SecByte32) -> Result<()> {
        std::fs::write(&self.path, mk.as_slice()).map_err(LithiumError::io)
    }
}


// ===== FILE: ./tests/crypto_tests.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::crypto::{Context, aead, kdf, keys, kyberbox, sign};
use lithium_core::error::ErrorKind;
use lithium_core::public::{PubByte32, PublicBytes};
use lithium_core::secrets::{SecByte12, SecByte32, SecretBytes};

fn sb(data: &[u8]) -> SecretBytes {
    SecretBytes::from_slice(data)
}

fn ctx_of(s: &str) -> Context<'_> {
    let mut parts = s.split('/');
    let mut c = Context::base(parts.next().unwrap()).unwrap();
    for p in parts {
        c = c.add(p).unwrap();
    }
    c
}

fn pb(data: &[u8]) -> PublicBytes {
    PublicBytes::from_slice(data)
}

fn key32(fill: u8) -> SecByte32 {
    SecByte32::new([fill; 32])
}

fn nonce12(fill: u8) -> SecByte12 {
    SecByte12::new([fill; 12])
}

#[test]
fn aead_raw_roundtrip() {
    let key = key32(0xAA);
    let nonce = nonce12(0x01);
    let plaintext = sb(b"hello aead");
    let aad = b"some-context";

    let ct = aead::encrypt_raw(&plaintext, &key, &nonce, aad).unwrap();
    let pt = aead::decrypt_raw(&ct, &key, &nonce, aad).unwrap();

    assert_eq!(pt.expose_as_slice(), plaintext.expose_as_slice());
}

#[test]
fn aead_blob_roundtrip() {
    let key = key32(0xBB);
    let nonce = nonce12(0x02);
    let plaintext = sb(b"blob roundtrip test");
    let aad = b"aad-blob";

    let blob = aead::encrypt(&plaintext, &key, &nonce, aad).unwrap();
    let recovered = aead::decrypt(&blob, &key, aad).unwrap();

    assert_eq!(recovered.expose_as_slice(), plaintext.expose_as_slice());
}

#[test]
fn aead_blob_starts_with_version_byte() {
    let key = key32(0x01);
    let nonce = nonce12(0x00);
    let blob = aead::encrypt(&sb(b"x"), &key, &nonce, b"aad").unwrap();
    assert_eq!(blob.as_slice()[0], 1, "first byte must be version 1");
}

#[test]
fn aead_blob_nonce_embedded() {
    let key = key32(0x01);
    let nonce = nonce12(0xCC);
    let blob = aead::encrypt(&sb(b"data"), &key, &nonce, b"aad").unwrap();
    assert_eq!(
        &blob.as_slice()[1..13],
        &[0xCC; 12],
        "nonce must be at bytes 1..13"
    );
}

#[test]
fn aead_wrong_key_fails() {
    let key = key32(0x10);
    let wrong_key = key32(0x11);
    let nonce = nonce12(0x03);
    let aad = b"ctx";

    let blob = aead::encrypt(&sb(b"secret"), &key, &nonce, aad).unwrap();
    let err = aead::decrypt(&blob, &wrong_key, aad).unwrap_err();
    assert_eq!(err.kind, ErrorKind::AeadFailed);
}

#[test]
fn aead_wrong_aad_fails() {
    let key = key32(0x20);
    let nonce = nonce12(0x04);

    let blob = aead::encrypt(&sb(b"secret"), &key, &nonce, b"correct-aad").unwrap();
    let err = aead::decrypt(&blob, &key, b"wrong-aad").unwrap_err();
    assert_eq!(err.kind, ErrorKind::AeadFailed);
}

#[test]
fn aead_tampered_ciphertext_fails() {
    let key = key32(0x30);
    let nonce = nonce12(0x05);
    let aad = b"tamper-test";

    let mut blob_vec = {
        let blob = aead::encrypt(&sb(b"original"), &key, &nonce, aad).unwrap();
        blob.as_slice().to_vec()
    };
    let last = blob_vec.len() - 1;
    blob_vec[last] ^= 0xFF;

    let tampered = pb(&blob_vec);
    let result = aead::decrypt(&tampered, &key, aad);
    assert!(result.is_err());
}

#[test]
fn aead_empty_plaintext() {
    let key = key32(0xAB);
    let nonce = nonce12(0x06);
    let aad = b"empty";

    let blob = aead::encrypt(&sb(b""), &key, &nonce, aad).unwrap();
    let pt = aead::decrypt(&blob, &key, aad).unwrap();
    assert!(pt.expose_as_slice().is_empty());
}

#[test]
fn aead_large_plaintext() {
    let key = key32(0xCD);
    let nonce = nonce12(0x07);
    let aad = b"large";
    let big = vec![0x42u8; 65536];

    let blob = aead::encrypt(&sb(&big), &key, &nonce, aad).unwrap();
    let pt = aead::decrypt(&blob, &key, aad).unwrap();
    assert_eq!(pt.expose_as_slice(), big.as_slice());
}

#[test]
fn aead_truncated_blob_fails() {
    let key = key32(0x01);
    let nonce = nonce12(0x00);
    let blob = aead::encrypt(&sb(b"data"), &key, &nonce, b"aad").unwrap();

    let short = pb(&blob.as_slice()[..10]);
    assert!(aead::decrypt(&short, &key, b"aad").is_err());
}

#[test]
fn kdf_deterministic() {
    let input = sb(b"master-key-material");
    let salt = sb(b"random-salt");
    let info = sb(b"test/v1");

    let k1 = kdf::derive32(&input, Some(&salt), info.expose_as_slice()).unwrap();
    let k2 = kdf::derive32(&input, Some(&salt), info.expose_as_slice()).unwrap();
    assert_eq!(k1, k2);
}

#[test]
fn kdf_different_info_gives_different_key() {
    let input = sb(b"material");
    let salt = sb(b"salt");

    let k1 = kdf::derive32(&input, Some(&salt), sb(b"info-a/v1").expose_as_slice()).unwrap();
    let k2 = kdf::derive32(&input, Some(&salt), sb(b"info-b/v1").expose_as_slice()).unwrap();
    assert_ne!(k1, k2);
}

#[test]
fn kdf_different_input_gives_different_key() {
    let info = sb(b"common-info/v1");

    let k1 = kdf::derive32(&sb(b"input-a"), None, info.expose_as_slice()).unwrap();
    let k2 = kdf::derive32(&sb(b"input-b"), None, info.expose_as_slice()).unwrap();
    assert_ne!(k1, k2);
}

#[test]
fn kdf_with_and_without_salt_differ() {
    let input = sb(b"ikm");
    let info = sb(b"label/v1");

    let k_with = kdf::derive32(&input, Some(&sb(b"salt")), info.expose_as_slice()).unwrap();
    let k_without = kdf::derive32(&input, None, info.expose_as_slice()).unwrap();
    assert_ne!(k_with, k_without);
}

#[test]
fn kdf_output_is_32_bytes() {
    let k = kdf::derive32(&sb(b"ikm"), None, sb(b"info/v1").expose_as_slice()).unwrap();
    assert_eq!(k.as_slice().len(), 32);
}

#[test]
fn kdf_output_is_not_all_zeros() {
    let k = kdf::derive32(&sb(b"ikm"), None, sb(b"info/v1").expose_as_slice()).unwrap();
    assert_ne!(k.as_slice(), &[0u8; 32]);
}

#[test]
fn keys_random_12_length() {
    let n = keys::random_12().unwrap();
    assert_eq!(n.as_slice().len(), 12);
}

#[test]
fn keys_random_32_length() {
    let k = keys::random_32().unwrap();
    assert_eq!(k.as_slice().len(), 32);
}

#[test]
fn keys_random_master_key_length() {
    let mk = keys::random_master_key32().unwrap();
    assert_eq!(mk.as_slice().len(), 32);
}

#[test]
fn keys_random_fixed_uniqueness() {
    let a = keys::random_fixed::<32>().unwrap();
    let b = keys::random_fixed::<32>().unwrap();
    assert_ne!(a, b);
}

#[test]
fn keys_x25519_keypair_sizes() {
    let (sk, pk) = keys::random_x25519_keypair().unwrap();
    assert_eq!(sk.as_slice().len(), 32);
    assert_eq!(pk.as_slice().len(), 32);
}

#[test]
fn keys_x25519_keypairs_unique() {
    let (sk1, pk1) = keys::random_x25519_keypair().unwrap();
    let (sk2, pk2) = keys::random_x25519_keypair().unwrap();
    assert_ne!(sk1, sk2);
    assert_ne!(pk1, pk2);
}

#[test]
fn keys_ed25519_keypair_sizes() {
    let (seed, vk) = keys::random_ed25519_keypair().unwrap();
    assert_eq!(seed.as_slice().len(), 32);
    assert_eq!(vk.as_slice().len(), 32);
}

#[test]
fn keys_kyber_keypair_sizes() {
    let (sk, pk) = keys::random_kyber_mlkem1024_keypair().unwrap();
    assert_eq!(sk.expose_as_slice().len(), 64);
    assert_eq!(pk.as_slice().len(), 1568);
}

#[test]
fn keys_dilithium_keypair_sizes() {
    let (sk, pk) = keys::random_dilithium_mldsa87_keypair().unwrap();
    assert_eq!(sk.expose_as_slice().len(), 32);
    assert_eq!(pk.as_slice().len(), 2592);
}

#[test]
fn sign_ed25519_roundtrip() {
    let (seed, pk) = keys::random_ed25519_keypair().unwrap();
    let msg = b"test message to sign";

    let sig = sign::sign_message(msg, seed.as_slice()).unwrap();
    assert!(sign::verify_signature(msg, sig.as_slice(), &pk));
}

#[test]
fn sign_ed25519_wrong_message_fails() {
    let (seed, pk) = keys::random_ed25519_keypair().unwrap();
    let sig = sign::sign_message(b"original", seed.as_slice()).unwrap();
    assert!(!sign::verify_signature(b"tampered", sig.as_slice(), &pk));
}

#[test]
fn sign_ed25519_wrong_key_fails() {
    let (seed, _pk) = keys::random_ed25519_keypair().unwrap();
    let (_, wrong_pk) = keys::random_ed25519_keypair().unwrap();
    let msg = b"test";

    let sig = sign::sign_message(msg, seed.as_slice()).unwrap();
    assert!(!sign::verify_signature(msg, sig.as_slice(), &wrong_pk));
}

#[test]
fn sign_ed25519_short_signature_fails() {
    let (_, pk) = keys::random_ed25519_keypair().unwrap();
    assert!(!sign::verify_signature(b"msg", &[0u8; 32], &pk));
}

#[test]
fn sign_ed25519_signature_is_64_bytes() {
    let (seed, _) = keys::random_ed25519_keypair().unwrap();
    let sig = sign::sign_message(b"data", seed.as_slice()).unwrap();
    assert_eq!(sig.as_slice().len(), 64);
}

#[test]
fn sign_ed25519_different_messages_different_sigs() {
    let (seed, _) = keys::random_ed25519_keypair().unwrap();
    let sig1 = sign::sign_message(b"message-one", seed.as_slice()).unwrap();
    let sig2 = sign::sign_message(b"message-two", seed.as_slice()).unwrap();
    assert_ne!(sig1.as_slice(), sig2.as_slice());
}

#[test]
fn sign_dili_roundtrip() {
    let (sk, pk) = keys::random_dilithium_mldsa87_keypair().unwrap();
    let msg = b"dilithium test message";

    let sig = sign::sign_message_dili(msg, sk.expose_as_slice()).unwrap();
    assert!(sign::verify_signature_dili(msg, sig.as_slice(), &pk));
}

#[test]
fn sign_dili_wrong_message_fails() {
    let (sk, pk) = keys::random_dilithium_mldsa87_keypair().unwrap();
    let sig = sign::sign_message_dili(b"original", sk.expose_as_slice()).unwrap();
    assert!(!sign::verify_signature_dili(
        b"tampered",
        sig.as_slice(),
        &pk
    ));
}

#[test]
fn sign_dili_wrong_key_fails() {
    let (sk, _pk) = keys::random_dilithium_mldsa87_keypair().unwrap();
    let (_, wrong_pk) = keys::random_dilithium_mldsa87_keypair().unwrap();
    let msg = b"test";

    let sig = sign::sign_message_dili(msg, sk.expose_as_slice()).unwrap();
    assert!(!sign::verify_signature_dili(msg, sig.as_slice(), &wrong_pk));
}

#[test]
fn sign_dili_garbage_signature_fails() {
    let (_, pk) = keys::random_dilithium_mldsa87_keypair().unwrap();
    assert!(!sign::verify_signature_dili(b"msg", &[0u8; 32], &pk));
}

/// Returns: (alice_x_sk, alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk)
fn kyberbox_alice_bob() -> (
    SecByte32,
    PubByte32,
    SecretBytes,
    PublicBytes,
    SecByte32,
    PubByte32,
) {
    let (alice_x_sk, alice_x_pk) = keys::random_x25519_keypair().unwrap();
    let (bob_x_sk, bob_x_pk) = keys::random_x25519_keypair().unwrap();
    let (bob_kyber_sk, bob_kyber_pk) = keys::random_kyber_mlkem1024_keypair().unwrap();
    (
        alice_x_sk,
        alice_x_pk,
        bob_kyber_sk,
        bob_kyber_pk,
        bob_x_sk,
        bob_x_pk,
    )
}

#[test]
fn kyberbox_roundtrip_body_and_headers() {
    let (alice_x_sk, alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();

    let body = sb(b"secret message");
    let ctx = "test-context";

    let wire = kyberbox::seal(
        &ctx_of(ctx),
        &alice_x_sk,
        &bob_x_pk,
        &bob_kyber_pk,
        b"",
        &body,
    )
    .unwrap();
    let dec_body = kyberbox::open(
        &ctx_of(ctx),
        &bob_x_sk,
        &alice_x_pk,
        &bob_kyber_sk,
        b"",
        &wire,
    )
    .unwrap();

    assert_eq!(dec_body.expose_as_slice(), body.expose_as_slice());
}

#[test]
fn kyberbox_empty_payload() {
    let (alice_x_sk, alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();

    let wire = kyberbox::seal(
        &ctx_of("ctx"),
        &alice_x_sk,
        &bob_x_pk,
        &bob_kyber_pk,
        b"",
        &sb(b""),
    )
    .unwrap();
    let body = kyberbox::open(
        &ctx_of("ctx"),
        &bob_x_sk,
        &alice_x_pk,
        &bob_kyber_sk,
        b"",
        &wire,
    )
    .unwrap();

    assert!(body.expose_as_slice().is_empty());
}

#[test]
fn kyberbox_wrong_x25519_key_fails() {
    let (alice_x_sk, alice_x_pk, bob_kyber_sk, bob_kyber_pk, _bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();

    let wire = kyberbox::seal(
        &ctx_of("ctx"),
        &alice_x_sk,
        &bob_x_pk,
        &bob_kyber_pk,
        b"",
        &sb(b"data"),
    )
    .unwrap();

    let (wrong_x_sk, _) = keys::random_x25519_keypair().unwrap();
    let result = kyberbox::open(
        &ctx_of("ctx"),
        &wrong_x_sk,
        &alice_x_pk,
        &bob_kyber_sk,
        b"",
        &wire,
    );
    assert!(result.is_err());
}

#[test]
fn kyberbox_aad_binds_ciphertext() {
    let (alice_x_sk, alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();

    let wire = kyberbox::seal(
        &ctx_of("ctx"),
        &alice_x_sk,
        &bob_x_pk,
        &bob_kyber_pk,
        b"header-v1",
        &sb(b"data"),
    )
    .unwrap();

    let open = |aad: &[u8]| {
        kyberbox::open(
            &ctx_of("ctx"),
            &bob_x_sk,
            &alice_x_pk,
            &bob_kyber_sk,
            aad,
            &wire,
        )
    };

    assert!(open(b"header-v2").is_err(), "wrong aad must fail");
    assert!(open(b"").is_err(), "aad is bound; empty must fail");
    assert_eq!(
        open(b"header-v1").unwrap().expose_as_slice(),
        b"data",
        "matching aad must open"
    );
}

#[test]
fn kyberbox_wrong_kyber_key_fails() {
    let (alice_x_sk, alice_x_pk, _bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();

    let wire = kyberbox::seal(
        &ctx_of("ctx"),
        &alice_x_sk,
        &bob_x_pk,
        &bob_kyber_pk,
        b"",
        &sb(b"data"),
    )
    .unwrap();

    let (wrong_kyber_sk, _) = keys::random_kyber_mlkem1024_keypair().unwrap();
    let result = kyberbox::open(
        &ctx_of("ctx"),
        &bob_x_sk,
        &alice_x_pk,
        &wrong_kyber_sk,
        b"",
        &wire,
    );
    assert!(result.is_err());
}

#[test]
fn kyberbox_different_contexts_incompatible() {
    let (alice_x_sk, alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();

    let wire = kyberbox::seal(
        &ctx_of("context-a"),
        &alice_x_sk,
        &bob_x_pk,
        &bob_kyber_pk,
        b"",
        &sb(b"data"),
    )
    .unwrap();
    let result = kyberbox::open(
        &ctx_of("context-b"),
        &bob_x_sk,
        &alice_x_pk,
        &bob_kyber_sk,
        b"",
        &wire,
    );
    assert!(result.is_err());
}

#[test]
fn kyberbox_large_payload() {
    let (alice_x_sk, alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();

    let big_data = vec![0xABu8; 16384];

    let wire = kyberbox::seal(
        &ctx_of("large"),
        &alice_x_sk,
        &bob_x_pk,
        &bob_kyber_pk,
        b"",
        &sb(&big_data),
    )
    .unwrap();
    let body = kyberbox::open(
        &ctx_of("large"),
        &bob_x_sk,
        &alice_x_pk,
        &bob_kyber_sk,
        b"",
        &wire,
    )
    .unwrap();

    assert_eq!(body.expose_as_slice(), big_data.as_slice());
}

#[test]
fn aead_wrong_version_byte_fails() {
    let key = key32(0x01);
    let nonce = nonce12(0x00);
    let mut blob = aead::encrypt(&sb(b"data"), &key, &nonce, b"aad")
        .unwrap()
        .as_slice()
        .to_vec();
    blob[0] = 2;
    assert!(aead::decrypt(&pb(&blob), &key, b"aad").is_err());
}

#[test]
fn aead_version_zero_fails() {
    let key = key32(0x01);
    let nonce = nonce12(0x00);
    let mut blob = aead::encrypt(&sb(b"data"), &key, &nonce, b"aad")
        .unwrap()
        .as_slice()
        .to_vec();
    blob[0] = 0;
    assert!(aead::decrypt(&pb(&blob), &key, b"aad").is_err());
}

#[test]
fn aead_bit_flip_in_nonce_fails() {
    let key = key32(0x50);
    let nonce = nonce12(0x10);
    let aad = b"ctx";
    let mut blob = aead::encrypt(&sb(b"payload"), &key, &nonce, aad)
        .unwrap()
        .as_slice()
        .to_vec();
    blob[1] ^= 0x01;
    assert!(aead::decrypt(&pb(&blob), &key, aad).is_err());
}

#[test]
fn aead_bit_flip_in_nonce_last_byte_fails() {
    let key = key32(0x51);
    let nonce = nonce12(0x11);
    let aad = b"ctx";
    let mut blob = aead::encrypt(&sb(b"payload"), &key, &nonce, aad)
        .unwrap()
        .as_slice()
        .to_vec();
    blob[12] ^= 0x80;
    assert!(aead::decrypt(&pb(&blob), &key, aad).is_err());
}

#[test]
fn aead_bit_flip_in_ciphertext_first_byte_fails() {
    let key = key32(0x52);
    let nonce = nonce12(0x12);
    let aad = b"ctx";
    let mut blob = aead::encrypt(&sb(b"hello world!!"), &key, &nonce, aad)
        .unwrap()
        .as_slice()
        .to_vec();
    blob[13] ^= 0x01;
    assert!(aead::decrypt(&pb(&blob), &key, aad).is_err());
}

#[test]
fn aead_bit_flip_in_auth_tag_fails() {
    let key = key32(0x53);
    let nonce = nonce12(0x13);
    let aad = b"ctx";
    let mut blob = aead::encrypt(&sb(b"message"), &key, &nonce, aad)
        .unwrap()
        .as_slice()
        .to_vec();
    let last = blob.len() - 1;
    blob[last] ^= 0x01;
    assert!(aead::decrypt(&pb(&blob), &key, aad).is_err());
}

#[test]
fn aead_aad_differs_by_one_byte_at_end_fails() {
    let key = key32(0x54);
    let nonce = nonce12(0x14);
    let blob = aead::encrypt(&sb(b"secret"), &key, &nonce, b"correct-aad").unwrap();
    assert!(aead::decrypt(&blob, &key, b"correct-aaf").is_err());
}

#[test]
fn aead_aad_differs_by_one_byte_at_start_fails() {
    let key = key32(0x55);
    let nonce = nonce12(0x15);
    let blob = aead::encrypt(&sb(b"secret"), &key, &nonce, b"correct-aad").unwrap();
    assert!(aead::decrypt(&blob, &key, b"Xorrect-aad").is_err());
}

#[test]
fn aead_empty_aad_roundtrip() {
    let key = key32(0x56);
    let nonce = nonce12(0x16);
    let blob = aead::encrypt(&sb(b"no-aad"), &key, &nonce, b"").unwrap();
    let pt = aead::decrypt(&blob, &key, b"").unwrap();
    assert_eq!(pt.expose_as_slice(), b"no-aad");
}

#[test]
fn aead_non_empty_aad_not_accepted_as_empty() {
    let key = key32(0x57);
    let nonce = nonce12(0x17);
    let blob = aead::encrypt(&sb(b"x"), &key, &nonce, b"real-aad").unwrap();
    assert!(aead::decrypt(&blob, &key, b"").is_err());
}

#[test]
fn aead_roundtrip_various_sizes() {
    let key = key32(0x58);
    let nonce = nonce12(0x18);
    let aad = b"size-sweep";
    for &size in &[0usize, 1, 7, 15, 16, 17, 31, 32, 33, 100, 1024, 8192] {
        let pt = vec![0x42u8; size];
        let blob = aead::encrypt(&sb(&pt), &key, &nonce, aad).unwrap();
        let recovered = aead::decrypt(&blob, &key, aad).unwrap();
        assert_eq!(recovered.expose_as_slice(), pt.as_slice(), "size={size}");
    }
}

#[test]
fn aead_raw_deterministic_same_inputs() {
    let key = key32(0x59);
    let nonce = nonce12(0x19);
    let pt = sb(b"deterministic-test");
    let aad = b"ctx";
    let ct1 = aead::encrypt_raw(&pt, &key, &nonce, aad).unwrap();
    let ct2 = aead::encrypt_raw(&pt, &key, &nonce, aad).unwrap();
    assert_eq!(
        ct1.as_slice(),
        ct2.as_slice(),
        "AEAD-GCM-SIV must be deterministic for identical inputs"
    );
}

#[test]
fn aead_min_size_blob_29_bytes() {
    let key = key32(0x5A);
    let nonce = nonce12(0x1A);
    let blob = aead::encrypt(&sb(b""), &key, &nonce, b"").unwrap();
    assert_eq!(blob.as_slice().len(), 29, "min blob size must be 29");
}

#[test]
fn aead_28_bytes_too_short_fails() {
    let key = key32(0x5B);
    let nonce = nonce12(0x1B);
    let blob = aead::encrypt(&sb(b""), &key, &nonce, b"").unwrap();
    let short = pb(&blob.as_slice()[..28]);
    assert!(aead::decrypt(&short, &key, b"").is_err());
}

#[test]
fn kdf_empty_ikm_still_works() {
    let k = kdf::derive32(&sb(b""), None, sb(b"info/v1").expose_as_slice()).unwrap();
    assert_eq!(k.as_slice().len(), 32);
    assert_ne!(k.as_slice(), &[0u8; 32]);
}

#[test]
fn kdf_empty_info_still_works() {
    let k = kdf::derive32(&sb(b"ikm"), None, sb(b"").expose_as_slice()).unwrap();
    assert_eq!(k.as_slice().len(), 32);
}

#[test]
fn kdf_domain_separation_all_distinct() {
    let ikm = sb(b"shared-ikm");
    let labels: &[&str] = &["a/v1", "b/v1", "c/v1", "d/v1", "e/v1"];
    let keys: Vec<_> = labels
        .iter()
        .map(|l| kdf::derive32(&ikm, None, l.as_bytes()).unwrap())
        .collect();
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            assert_ne!(keys[i], keys[j], "labels[{i}] and [{j}] collide");
        }
    }
}

#[test]
fn kdf_salt_domain_separation() {
    let ikm = sb(b"ikm");
    let info = sb(b"info/v1");
    let salts: &[&[u8]] = &[b"salt-a", b"salt-b", b"salt-c"];
    let keys: Vec<_> = salts
        .iter()
        .map(|s| kdf::derive32(&ikm, Some(&sb(s)), info.expose_as_slice()).unwrap())
        .collect();
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            assert_ne!(keys[i], keys[j], "salts[{i}] and [{j}] collide");
        }
    }
}

#[test]
fn sign_ed25519_empty_message_roundtrip() {
    let (seed, pk) = keys::random_ed25519_keypair().unwrap();
    let sig = sign::sign_message(b"", seed.as_slice()).unwrap();
    assert!(sign::verify_signature(b"", sig.as_slice(), &pk));
    assert!(!sign::verify_signature(b"x", sig.as_slice(), &pk));
}

#[test]
fn sign_ed25519_deterministic() {
    let (seed, _pk) = keys::random_ed25519_keypair().unwrap();
    let msg = b"deterministic";
    let sig1 = sign::sign_message(msg, seed.as_slice()).unwrap();
    let sig2 = sign::sign_message(msg, seed.as_slice()).unwrap();
    assert_eq!(sig1.as_slice(), sig2.as_slice());
}

#[test]
fn sign_ed25519_tampered_sig_first_byte_fails() {
    let (seed, pk) = keys::random_ed25519_keypair().unwrap();
    let msg = b"message";
    let mut sig = sign::sign_message(msg, seed.as_slice()).unwrap();
    sig[0] ^= 0x01;
    assert!(!sign::verify_signature(msg, &sig, &pk));
}

#[test]
fn sign_ed25519_tampered_sig_last_byte_fails() {
    let (seed, pk) = keys::random_ed25519_keypair().unwrap();
    let msg = b"message";
    let mut sig = sign::sign_message(msg, seed.as_slice()).unwrap();
    let last = sig.len() - 1;
    sig[last] ^= 0x01;
    assert!(!sign::verify_signature(msg, &sig, &pk));
}

#[test]
fn sign_ed25519_various_message_sizes() {
    let (seed, pk) = keys::random_ed25519_keypair().unwrap();
    for &size in &[0usize, 1, 31, 32, 33, 100, 1024] {
        let msg = vec![0x5Au8; size];
        let sig = sign::sign_message(&msg, seed.as_slice()).unwrap();
        assert!(
            sign::verify_signature(&msg, sig.as_slice(), &pk),
            "size={size}"
        );
    }
}

#[test]
fn sign_dili_empty_message_roundtrip() {
    let (sk, pk) = keys::random_dilithium_mldsa87_keypair().unwrap();
    let sig = sign::sign_message_dili(b"", sk.expose_as_slice()).unwrap();
    assert!(sign::verify_signature_dili(b"", sig.as_slice(), &pk));
    assert!(!sign::verify_signature_dili(b"x", sig.as_slice(), &pk));
}

#[test]
fn sign_dili_tampered_sig_last_byte_fails() {
    let (sk, pk) = keys::random_dilithium_mldsa87_keypair().unwrap();
    let msg = b"dili-test";
    let mut sig = sign::sign_message_dili(msg, sk.expose_as_slice()).unwrap();
    let last = sig.len() - 1;
    sig[last] ^= 0xFF;
    assert!(!sign::verify_signature_dili(msg, &sig, &pk));
}

#[test]
fn sign_dili_various_message_sizes() {
    let (sk, pk) = keys::random_dilithium_mldsa87_keypair().unwrap();
    for &size in &[0usize, 1, 31, 32, 64, 256] {
        let msg = vec![0xA5u8; size];
        let sig = sign::sign_message_dili(&msg, sk.expose_as_slice()).unwrap();
        assert!(
            sign::verify_signature_dili(&msg, sig.as_slice(), &pk),
            "size={size}"
        );
    }
}

fn kyberbox_corrupt_kem_byte_at(offset: usize) {
    let (alice_x_sk, alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();
    let wire = kyberbox::seal(
        &ctx_of("ctx"),
        &alice_x_sk,
        &bob_x_pk,
        &bob_kyber_pk,
        b"",
        &sb(b"body"),
    )
    .unwrap();

    let mut kem_bytes = wire.kem_ct.as_slice().to_vec();
    assert!(offset < kem_bytes.len());
    kem_bytes[offset] ^= 0xFF;

    let corrupted = kyberbox::KyberBoxSealed {
        kem_ct: PublicBytes::new(kem_bytes),
        ciphertext: wire.ciphertext.clone(),
    };
    assert!(
        kyberbox::open(
            &ctx_of("ctx"),
            &bob_x_sk,
            &alice_x_pk,
            &bob_kyber_sk,
            b"",
            &corrupted
        )
        .is_err(),
        "corrupt kem_ct byte at offset {offset} must cause failure"
    );
}

#[test]
fn kyberbox_corrupt_kem_version_byte_fails() {
    kyberbox_corrupt_kem_byte_at(0);
}

#[test]
fn kyberbox_corrupt_kem_id_fails() {
    kyberbox_corrupt_kem_byte_at(1);
}

#[test]
fn kyberbox_corrupt_kem_ciphertext_first_byte_fails() {
    kyberbox_corrupt_kem_byte_at(2);
}

#[test]
fn kyberbox_corrupt_kem_ciphertext_mid_byte_fails() {
    kyberbox_corrupt_kem_byte_at(800);
}

#[test]
fn kyberbox_truncated_kem_ciphertext_fails() {
    let (alice_x_sk, alice_x_pk, _bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();
    let (fresh_kyber_sk, _) = keys::random_kyber_mlkem1024_keypair().unwrap();
    let wire = kyberbox::seal(
        &ctx_of("ctx"),
        &alice_x_sk,
        &bob_x_pk,
        &bob_kyber_pk,
        b"",
        &sb(b"body"),
    )
    .unwrap();

    let truncated = PublicBytes::from_slice(&wire.kem_ct.as_slice()[..36]);
    let bad = kyberbox::KyberBoxSealed {
        kem_ct: truncated,
        ciphertext: wire.ciphertext.clone(),
    };
    assert!(
        kyberbox::open(
            &ctx_of("ctx"),
            &bob_x_sk,
            &alice_x_pk,
            &fresh_kyber_sk,
            b"",
            &bad
        )
        .is_err()
    );
}

#[test]
fn kyberbox_empty_kem_ct_fails() {
    let (alice_x_sk, alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();
    let wire = kyberbox::seal(
        &ctx_of("ctx"),
        &alice_x_sk,
        &bob_x_pk,
        &bob_kyber_pk,
        b"",
        &sb(b"body"),
    )
    .unwrap();
    let bad = kyberbox::KyberBoxSealed {
        kem_ct: pb(b""),
        ciphertext: wire.ciphertext.clone(),
    };
    assert!(
        kyberbox::open(
            &ctx_of("ctx"),
            &bob_x_sk,
            &alice_x_pk,
            &bob_kyber_sk,
            b"",
            &bad
        )
        .is_err()
    );
}

#[test]
fn kyberbox_corrupt_enc_data_tag_fails() {
    let (alice_x_sk, alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();
    let wire = kyberbox::seal(
        &ctx_of("ctx"),
        &alice_x_sk,
        &bob_x_pk,
        &bob_kyber_pk,
        b"",
        &sb(b"body"),
    )
    .unwrap();

    let mut body_bytes = wire.ciphertext.as_slice().to_vec();
    let last = body_bytes.len() - 1;
    body_bytes[last] ^= 0x01;

    let bad = kyberbox::KyberBoxSealed {
        kem_ct: wire.kem_ct.clone(),
        ciphertext: PublicBytes::new(body_bytes),
    };
    assert!(
        kyberbox::open(
            &ctx_of("ctx"),
            &bob_x_sk,
            &alice_x_pk,
            &bob_kyber_sk,
            b"",
            &bad
        )
        .is_err()
    );
}

#[test]
fn kyberbox_corrupt_enc_data_version_fails() {
    let (alice_x_sk, alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();
    let wire = kyberbox::seal(
        &ctx_of("ctx"),
        &alice_x_sk,
        &bob_x_pk,
        &bob_kyber_pk,
        b"",
        &sb(b"body"),
    )
    .unwrap();

    let mut body_bytes = wire.ciphertext.as_slice().to_vec();
    body_bytes[0] ^= 0xFF;

    let bad = kyberbox::KyberBoxSealed {
        kem_ct: wire.kem_ct.clone(),
        ciphertext: PublicBytes::new(body_bytes),
    };
    assert!(
        kyberbox::open(
            &ctx_of("ctx"),
            &bob_x_sk,
            &alice_x_pk,
            &bob_kyber_sk,
            b"",
            &bad
        )
        .is_err()
    );
}

#[test]
fn kyberbox_truncated_enc_body_fails() {
    let (alice_x_sk, alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();
    let wire = kyberbox::seal(
        &ctx_of("ctx"),
        &alice_x_sk,
        &bob_x_pk,
        &bob_kyber_pk,
        b"",
        &sb(b"body"),
    )
    .unwrap();

    let truncated = PublicBytes::from_slice(&wire.ciphertext.as_slice()[..10]);
    let bad = kyberbox::KyberBoxSealed {
        kem_ct: wire.kem_ct.clone(),
        ciphertext: truncated,
    };
    assert!(
        kyberbox::open(
            &ctx_of("ctx"),
            &bob_x_sk,
            &alice_x_pk,
            &bob_kyber_sk,
            b"",
            &bad
        )
        .is_err()
    );
}

#[test]
fn kyberbox_roundtrip_various_payload_sizes() {
    let (alice_x_sk, alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();
    for &size in &[0usize, 1, 15, 16, 32, 100, 1024] {
        let body = vec![0xBBu8; size];
        let wire = kyberbox::seal(
            &ctx_of("sweep"),
            &alice_x_sk,
            &bob_x_pk,
            &bob_kyber_pk,
            b"",
            &sb(&body),
        )
        .unwrap();
        let dec_data = kyberbox::open(
            &ctx_of("sweep"),
            &bob_x_sk,
            &alice_x_pk,
            &bob_kyber_sk,
            b"",
            &wire,
        )
        .unwrap();
        assert_eq!(
            dec_data.expose_as_slice(),
            body.as_slice(),
            "body size={size}"
        );
    }
}

#[test]
fn cross_kdf_then_aead_roundtrip() {
    let master = sb(b"master-key-material-for-cross-test");
    let aead_key = kdf::derive32(&master, None, sb(b"aead-key/v1").expose_as_slice()).unwrap();

    let nonce = nonce12(0x42);
    let aad = b"cross-module-aad";
    let plaintext = sb(b"cross module plaintext");

    let blob = aead::encrypt(&plaintext, &aead_key, &nonce, aad).unwrap();
    let recovered = aead::decrypt(&blob, &aead_key, aad).unwrap();
    assert_eq!(recovered.expose_as_slice(), plaintext.expose_as_slice());
}

#[test]
fn cross_kdf_derived_keys_not_usable_cross_purpose() {
    let master = sb(b"shared-master");
    let key_a = kdf::derive32(&master, None, sb(b"purpose-a/v1").expose_as_slice()).unwrap();
    let key_b = kdf::derive32(&master, None, sb(b"purpose-b/v1").expose_as_slice()).unwrap();

    let nonce = nonce12(0x43);
    let aad = b"aad";
    let blob = aead::encrypt(&sb(b"secret"), &key_a, &nonce, aad).unwrap();

    assert!(aead::decrypt(&blob, &key_b, aad).is_err());
}

#[test]
fn cross_ed25519_sign_verify_cross_keypair_fails() {
    let (seed_a, _pk_a) = keys::random_ed25519_keypair().unwrap();
    let (_, pk_b) = keys::random_ed25519_keypair().unwrap();
    let msg = b"same message, different key";
    let sig = sign::sign_message(msg, seed_a.as_slice()).unwrap();
    assert!(!sign::verify_signature(msg, sig.as_slice(), &pk_b));
}

#[test]
fn cross_dili_sign_verify_cross_keypair_fails() {
    let (sk_a, _) = keys::random_dilithium_mldsa87_keypair().unwrap();
    let (_, pk_b) = keys::random_dilithium_mldsa87_keypair().unwrap();
    let msg = b"cross-key dilithium";
    let sig = sign::sign_message_dili(msg, sk_a.expose_as_slice()).unwrap();
    assert!(!sign::verify_signature_dili(msg, sig.as_slice(), &pk_b));
}

#[test]
fn cross_ed25519_and_dili_sigs_are_not_interchangeable() {
    let (ed_seed, ed_pk) = keys::random_ed25519_keypair().unwrap();
    let (dili_sk, dili_pk) = keys::random_dilithium_mldsa87_keypair().unwrap();
    let msg = b"cross-scheme";

    let ed_sig = sign::sign_message(msg, ed_seed.as_slice()).unwrap();
    let dili_sig = sign::sign_message_dili(msg, dili_sk.expose_as_slice()).unwrap();

    assert!(!sign::verify_signature_dili(
        msg,
        ed_sig.as_slice(),
        &dili_pk
    ));
    assert!(!sign::verify_signature(
        msg,
        &dili_sig.as_slice()[..64],
        &ed_pk
    ));
}

#[test]
fn cross_kyberbox_nondeterministic_wire() {
    let (alice_x_sk, _alice_x_pk, _bob_kyber_sk, bob_kyber_pk, _bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();
    let body = sb(b"same body");

    let wire1 = kyberbox::seal(
        &ctx_of("ctx"),
        &alice_x_sk,
        &bob_x_pk,
        &bob_kyber_pk,
        b"",
        &body,
    )
    .unwrap();
    let wire2 = kyberbox::seal(
        &ctx_of("ctx"),
        &alice_x_sk,
        &bob_x_pk,
        &bob_kyber_pk,
        b"",
        &body,
    )
    .unwrap();

    assert_ne!(
        wire1.ciphertext.as_slice(),
        wire2.ciphertext.as_slice(),
        "KyberBox must produce non-deterministic ciphertexts"
    );
}

#[test]
fn kyberbox_cross_ctx_kem_ct_transplant_fails() {
    let (alice_x_sk, alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();

    let wire_alpha = kyberbox::seal(
        &ctx_of("ctx-alpha"),
        &alice_x_sk,
        &bob_x_pk,
        &bob_kyber_pk,
        b"",
        &sb(b"body"),
    )
    .unwrap();
    let wire_beta = kyberbox::seal(
        &ctx_of("ctx-beta"),
        &alice_x_sk,
        &bob_x_pk,
        &bob_kyber_pk,
        b"",
        &sb(b"body"),
    )
    .unwrap();

    let doctored = kyberbox::KyberBoxSealed {
        kem_ct: wire_alpha.kem_ct,
        ciphertext: wire_beta.ciphertext,
    };
    assert!(
        kyberbox::open(
            &ctx_of("ctx-beta"),
            &bob_x_sk,
            &alice_x_pk,
            &bob_kyber_sk,
            b"",
            &doctored
        )
        .is_err(),
        "kem_ct from a different ctx must not verify"
    );
}

#[test]
fn kyberbox_cross_ctx_enc_body_transplant_fails() {
    let (alice_x_sk, alice_x_pk, bob_kyber_sk, bob_kyber_pk, bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();

    let wire_alpha = kyberbox::seal(
        &ctx_of("ctx-alpha"),
        &alice_x_sk,
        &bob_x_pk,
        &bob_kyber_pk,
        b"",
        &sb(b"body"),
    )
    .unwrap();
    let wire_beta = kyberbox::seal(
        &ctx_of("ctx-beta"),
        &alice_x_sk,
        &bob_x_pk,
        &bob_kyber_pk,
        b"",
        &sb(b"body"),
    )
    .unwrap();

    let doctored = kyberbox::KyberBoxSealed {
        kem_ct: wire_beta.kem_ct,
        ciphertext: wire_alpha.ciphertext,
    };
    assert!(
        kyberbox::open(
            &ctx_of("ctx-beta"),
            &bob_x_sk,
            &alice_x_pk,
            &bob_kyber_sk,
            b"",
            &doctored
        )
        .is_err(),
        "enc_body from a different ctx must not decrypt"
    );
}

#[test]
fn kyberbox_wire_replay_to_different_recipient_fails() {
    let (alice_x_sk, alice_x_pk, _bob_kyber_sk, bob_kyber_pk, _bob_x_sk, bob_x_pk) =
        kyberbox_alice_bob();
    let (carol_x_sk, carol_x_pk, carol_kyber_sk, carol_kyber_pk, _, _) = kyberbox_alice_bob();
    let _ = (carol_x_pk, carol_kyber_pk);

    let wire = kyberbox::seal(
        &ctx_of("session-a"),
        &alice_x_sk,
        &bob_x_pk,
        &bob_kyber_pk,
        b"",
        &sb(b"secret"),
    )
    .unwrap();

    let result = kyberbox::open(
        &ctx_of("session-b"),
        &carol_x_sk,
        &alice_x_pk,
        &carol_kyber_sk,
        b"",
        &wire,
    );
    assert!(
        result.is_err(),
        "WirePayload addressed to bob must not decrypt for carol"
    );
}


// ===== FILE: ./tests/double_sig_tests.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::ErrorKind;
use lithium_core::crypto::sign::DoubleSig;
use lithium_core::crypto::{keys, sign};

struct Keys {
    ed_seed: lithium_core::secrets::SecretFixedBytes<32>,
    ed_pub: lithium_core::public::PubByte32,
    dili_sk: lithium_core::secrets::SecretBytes,
    dili_pub: lithium_core::public::PublicBytes,
}

fn fresh_keys() -> Keys {
    let (ed_seed, ed_pub) = keys::random_ed25519_keypair().unwrap();
    let (dili_sk, dili_pub) = keys::random_dilithium_mldsa87_keypair().unwrap();
    Keys {
        ed_seed,
        ed_pub,
        dili_sk,
        dili_pub,
    }
}

fn sign(k: &Keys, msg: &[u8]) -> DoubleSig {
    sign::sign_double(msg, k.ed_seed.as_slice(), k.dili_sk.expose_as_slice()).unwrap()
}

#[test]
fn roundtrips() {
    let k = fresh_keys();
    let msg = b"double-signed payload";
    let sig = sign(&k, msg);
    assert!(sign::verify_double(msg, &sig, &k.ed_pub, &k.dili_pub));
}

#[test]
fn wrong_message_fails() {
    let k = fresh_keys();
    let sig = sign(&k, b"original");
    assert!(!sign::verify_double(
        b"tampered",
        &sig,
        &k.ed_pub,
        &k.dili_pub
    ));
}

#[test]
fn both_branches_are_required() {
    // A valid ed branch from message A glued to a dili branch over message B
    // must fail: verify_double is AND, not OR.
    let k = fresh_keys();
    let sig_a = sign(&k, b"message-a");
    let sig_b = sign(&k, b"message-b");

    let mut bytes = sig_a.to_bytes();
    let b_bytes = sig_b.to_bytes();
    bytes[64..].copy_from_slice(&b_bytes[64..]); // keep ed(A), swap in dili(B)
    let mixed = DoubleSig::from_bytes(&bytes).unwrap();

    assert!(!sign::verify_double(
        b"message-a",
        &mixed,
        &k.ed_pub,
        &k.dili_pub
    ));
    assert!(!sign::verify_double(
        b"message-b",
        &mixed,
        &k.ed_pub,
        &k.dili_pub
    ));
}

#[test]
fn tamper_in_either_region_fails() {
    let k = fresh_keys();
    let msg = b"payload";
    let sig = sign(&k, msg);

    let mut ed_tampered = sig.to_bytes();
    ed_tampered[0] ^= 0x01;
    assert!(!sign::verify_double(
        msg,
        &DoubleSig::from_bytes(&ed_tampered).unwrap(),
        &k.ed_pub,
        &k.dili_pub
    ));

    let mut dili_tampered = sig.to_bytes();
    let last = dili_tampered.len() - 1;
    dili_tampered[last] ^= 0x01;
    assert!(!sign::verify_double(
        msg,
        &DoubleSig::from_bytes(&dili_tampered).unwrap(),
        &k.ed_pub,
        &k.dili_pub
    ));
}

#[test]
fn wrong_public_keys_fail() {
    let k = fresh_keys();
    let other = fresh_keys();
    let msg = b"payload";
    let sig = sign(&k, msg);

    assert!(!sign::verify_double(msg, &sig, &other.ed_pub, &k.dili_pub));
    assert!(!sign::verify_double(msg, &sig, &k.ed_pub, &other.dili_pub));
}

#[test]
fn bytes_roundtrip() {
    let k = fresh_keys();
    let sig = sign(&k, b"payload");
    let decoded = DoubleSig::from_bytes(&sig.to_bytes()).unwrap();
    assert_eq!(sig, decoded);
}

#[test]
fn hex_roundtrip() {
    let k = fresh_keys();
    let msg = b"payload";
    let sig = sign(&k, msg);
    let decoded = DoubleSig::from_hex(&sig.to_hex()).unwrap();
    assert_eq!(sig, decoded);
    assert!(sign::verify_double(msg, &decoded, &k.ed_pub, &k.dili_pub));
}

#[test]
fn from_bytes_rejects_too_short() {
    match DoubleSig::from_bytes(&[0u8; 64]) {
        Err(e) => assert!(matches!(e.kind, ErrorKind::InvalidLength { .. })),
        Ok(_) => panic!("64 bytes has no dilithium branch and must be rejected"),
    }
}

#[test]
fn from_hex_enforces_lowercase_no_prefix() {
    let k = fresh_keys();
    let hexed = sign(&k, b"payload").to_hex();
    assert!(DoubleSig::from_hex(&hexed.to_uppercase()).is_err());
    assert!(DoubleSig::from_hex(&format!("0x{hexed}")).is_err());
}


// ===== FILE: ./tests/golden_tests.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;

use lithium_core::crypto::hash::sha256;
use lithium_core::crypto::kyberbox::KyberBoxSealed;
use lithium_core::crypto::{Context, aead, kyberbox, sign};
use lithium_core::hpke::{self, HpkeEnc, HpkeSealed};
use lithium_core::public::{PubByte32, PublicBytes};
use lithium_core::secrets::{SecByte32, SecretBytes};

fn ctx_of(s: &str) -> Context<'_> {
    let mut parts = s.split('/');
    let mut c = Context::base(parts.next().unwrap()).unwrap();
    for p in parts {
        c = c.add(p).unwrap();
    }
    c
}

fn hpke_vectors() -> HashMap<&'static str, &'static str> {
    include_str!("testdata/hpke_golden_v1.txt")
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect()
}

#[test]
fn aead_blob_decrypts_to_pinned_plaintext() {
    let key =
        SecByte32::from_hex("9f2c1b8a4d6e0f3a57c9e1d2b40a8f6e7c5d3b1a09f8e7d6c5b4a39281706152")
            .unwrap();
    let aad = b"golden-aad-v1";
    let blob = PublicBytes::from_hex(
        "01a14b7e02c9d3f5081623ab9cf124d1138aab1944639ca1eae2f7c84bb0709ee5c22d2d4ccfba979e3e91a7eb2507a6604e1a5da8",
    )
    .unwrap();

    let pt = aead::decrypt(&blob, &key, aad).unwrap();
    assert_eq!(pt.expose_as_slice(), b"golden-aead-plaintext-v1");

    let mut tampered = blob.as_slice().to_vec();
    *tampered.last_mut().unwrap() ^= 0x01;
    assert!(aead::decrypt(&PublicBytes::new(tampered), &key, aad).is_err());
}

#[test]
fn kyberbox_wire_decrypts_to_pinned_plaintext() {
    let vectors: HashMap<&str, &str> = include_str!("testdata/kyberbox_golden_v1.txt")
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();

    let rx_x_priv = SecByte32::from_hex(vectors["RX_X_PRIV"]).unwrap();
    let msg_x_pub = PubByte32::from_hex(vectors["MSG_X_PUB"]).unwrap();
    let kyber_priv = SecretBytes::from_hex(vectors["KYBER_PRIV"]).unwrap();
    let wire = KyberBoxSealed {
        ciphertext: PublicBytes::from_hex(vectors["ENC_DATA"]).unwrap(),
        kem_ct: PublicBytes::from_hex(vectors["KEM_CT"]).unwrap(),
    };

    let body = kyberbox::open(
        &ctx_of("golden/kyberbox/v1"),
        &rx_x_priv,
        &msg_x_pub,
        &kyber_priv,
        b"",
        &wire,
    )
    .unwrap();

    assert_eq!(body.expose_as_slice(), b"golden-body-v1");
}

#[test]
fn mldsa87_signature_verifies_pinned_vector() {
    let vectors: HashMap<&str, &str> = include_str!("testdata/mldsa87_verify_golden_v1.txt")
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();

    let dili_pub = PublicBytes::from_hex(vectors["DILI_PUB"]).unwrap();
    let dili_sig = PublicBytes::from_hex(vectors["DILI_SIG"]).unwrap();
    let msg = b"golden-mldsa87-v1";

    assert_eq!(dili_pub.as_slice().len(), 2592);
    assert_eq!(dili_sig.as_slice().len(), 4627);

    assert!(sign::verify_signature_dili(
        msg,
        dili_sig.as_slice(),
        &dili_pub
    ));
    assert!(!sign::verify_signature_dili(
        b"tampered",
        dili_sig.as_slice(),
        &dili_pub
    ));
}

#[test]
fn hpke_derive_keypair_matches_pinned_vector() {
    let v = hpke_vectors();
    let ikm = hex::decode(v["KP_IKM"]).unwrap();

    let (sk, pk) = hpke::derive_keypair(&ctx_of(v["KP_CTX"]), &ikm).unwrap();
    let pk_wire = pk.to_wire();

    assert_eq!(hex::encode(&pk_wire[..32]), v["KP_X_PUB"]);
    assert_eq!(hex::encode(sha256(&pk_wire).as_slice()), v["KP_PK_SHA256"]);
    assert_eq!(
        hex::encode(sha256(sk.to_wire().expose_as_slice()).as_slice()),
        v["KP_SK_SHA256"]
    );
}

#[test]
fn hpke_sealed_opens_to_pinned_plaintext() {
    let v = hpke_vectors();
    let (sk, _) =
        hpke::derive_keypair(&ctx_of(v["KP_CTX"]), &hex::decode(v["KP_IKM"]).unwrap()).unwrap();
    let sk_wire = sk.to_wire();
    let sk_wire = sk_wire.expose_as_slice();
    let x_priv = SecByte32::from_slice(&sk_wire[..32]).unwrap();
    let k_priv = SecretBytes::from_slice(&sk_wire[32..]);

    let info = hex::decode(v["INFO"]).unwrap();
    let aad = hex::decode(v["AAD"]).unwrap();
    let sealed = HpkeSealed {
        enc: HpkeEnc::from_wire(&hex::decode(v["ENC"]).unwrap()).unwrap(),
        ciphertext: PublicBytes::from_hex(v["CIPHERTEXT"]).unwrap(),
    };

    let pt = hpke::open_base(
        &ctx_of(v["SEAL_CTX"]),
        &x_priv,
        &k_priv,
        &info,
        &aad,
        &sealed,
    )
    .unwrap();
    assert_eq!(
        pt.expose_as_slice(),
        hex::decode(v["PLAINTEXT"]).unwrap().as_slice()
    );

    let mut ct = sealed.ciphertext.as_slice().to_vec();
    *ct.last_mut().unwrap() ^= 0x01;
    let tampered = HpkeSealed {
        enc: sealed.enc.clone(),
        ciphertext: PublicBytes::new(ct),
    };
    assert!(
        hpke::open_base(
            &ctx_of(v["SEAL_CTX"]),
            &x_priv,
            &k_priv,
            &info,
            &aad,
            &tampered
        )
        .is_err()
    );
}

#[test]
fn hpke_export_reproduces_pinned_secret() {
    let v = hpke_vectors();
    let (sk, _) =
        hpke::derive_keypair(&ctx_of(v["KP_CTX"]), &hex::decode(v["KP_IKM"]).unwrap()).unwrap();
    let enc = HpkeEnc::from_wire(&hex::decode(v["ENC2"]).unwrap()).unwrap();

    let exported = hpke::setup_receiver_and_export(
        &ctx_of(v["EXP_CTX"]),
        &sk,
        &enc,
        &hex::decode(v["INFO"]).unwrap(),
        &hex::decode(v["EXPORTER_CONTEXT"]).unwrap(),
        v["EXPORTER_LEN"].parse().unwrap(),
    )
    .unwrap();

    assert_eq!(hex::encode(exported.expose_as_slice()), v["EXPORTED"]);
}


// ===== FILE: ./tests/hpke_stream_tests.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::crypto::Context;
use lithium_core::hpke::{derive_keypair, setup_receiver, setup_sender};
use lithium_core::public::PublicBytes;
use lithium_core::secrets::SecretBytes;

const CTX: &str = "lithium/hpke-stream/test/v1";

fn msg(b: &[u8]) -> SecretBytes {
    SecretBytes::from_slice(b)
}

fn ctx_of(s: &str) -> Context<'_> {
    let mut parts = s.split('/');
    let mut c = Context::base(parts.next().unwrap()).unwrap();
    for p in parts {
        c = c.add(p).unwrap();
    }
    c
}

#[test]
fn multi_message_roundtrips_in_order() {
    let (sk, pk) = derive_keypair(&ctx_of(CTX), b"stream-ikm-in-order").unwrap();
    let (enc, mut sender) = setup_sender(&ctx_of(CTX), &pk, b"info").unwrap();

    let c0 = sender.seal(b"aad-0", &msg(b"chunk zero")).unwrap();
    let c1 = sender.seal(b"aad-1", &msg(b"chunk one")).unwrap();
    let c2 = sender.seal(b"aad-2", &msg(b"chunk two")).unwrap();

    let mut receiver = setup_receiver(&ctx_of(CTX), &sk, &enc, b"info").unwrap();
    assert_eq!(
        receiver.open(b"aad-0", &c0).unwrap().expose_as_slice(),
        b"chunk zero"
    );
    assert_eq!(
        receiver.open(b"aad-1", &c1).unwrap().expose_as_slice(),
        b"chunk one"
    );
    assert_eq!(
        receiver.open(b"aad-2", &c2).unwrap().expose_as_slice(),
        b"chunk two"
    );
}

#[test]
fn same_plaintext_gives_distinct_ciphertexts_per_sequence() {
    let (_, pk) = derive_keypair(&ctx_of(CTX), b"stream-ikm-distinct").unwrap();
    let (_enc, mut sender) = setup_sender(&ctx_of(CTX), &pk, b"info").unwrap();

    let a = sender.seal(b"", &msg(b"same")).unwrap();
    let b = sender.seal(b"", &msg(b"same")).unwrap();
    assert_ne!(a.as_slice(), b.as_slice(), "sequence nonce must advance");
}

#[test]
fn out_of_order_open_fails() {
    let (sk, pk) = derive_keypair(&ctx_of(CTX), b"stream-ikm-order").unwrap();
    let (enc, mut sender) = setup_sender(&ctx_of(CTX), &pk, b"info").unwrap();

    let _c0 = sender.seal(b"aad-0", &msg(b"first")).unwrap();
    let c1 = sender.seal(b"aad-1", &msg(b"second")).unwrap();

    let mut receiver = setup_receiver(&ctx_of(CTX), &sk, &enc, b"info").unwrap();
    assert!(
        receiver.open(b"aad-1", &c1).is_err(),
        "receiver at seq 0 must reject the seq-1 ciphertext"
    );
}

#[test]
fn wrong_aad_fails() {
    let (sk, pk) = derive_keypair(&ctx_of(CTX), b"stream-ikm-aad").unwrap();
    let (enc, mut sender) = setup_sender(&ctx_of(CTX), &pk, b"info").unwrap();
    let c0 = sender.seal(b"bound-aad", &msg(b"payload")).unwrap();

    let mut receiver = setup_receiver(&ctx_of(CTX), &sk, &enc, b"info").unwrap();
    assert!(receiver.open(b"other-aad", &c0).is_err());
}

#[test]
fn tampered_ciphertext_fails() {
    let (sk, pk) = derive_keypair(&ctx_of(CTX), b"stream-ikm-tamper").unwrap();
    let (enc, mut sender) = setup_sender(&ctx_of(CTX), &pk, b"info").unwrap();
    let c0 = sender.seal(b"aad", &msg(b"payload")).unwrap();

    let mut bytes = c0.as_slice().to_vec();
    bytes[0] ^= 0x01;
    let tampered = PublicBytes::from_slice(&bytes);

    let mut receiver = setup_receiver(&ctx_of(CTX), &sk, &enc, b"info").unwrap();
    assert!(receiver.open(b"aad", &tampered).is_err());
}


// ===== FILE: ./tests/hpke_tests.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::crypto::Context;
use lithium_core::hpke::{self, HpkeEnc, HpkePrivateKey, HpkePublicKey, HpkeSealed};
use lithium_core::public::{PubByte32, PublicBytes};
use lithium_core::secrets::{SecByte32, SecretBytes};

const CTX: &str = "test/hpke/v1";
const INFO: &[u8] = b"unit-info";
const AAD: &[u8] = b"unit-aad";

fn sb(data: &[u8]) -> SecretBytes {
    SecretBytes::from_slice(data)
}

fn ctx_of(s: &str) -> Context<'_> {
    let mut parts = s.split('/');
    let mut c = Context::base(parts.next().unwrap()).unwrap();
    for p in parts {
        c = c.add(p).unwrap();
    }
    c
}

fn kp(ctx: &str, ikm: &[u8]) -> (HpkePrivateKey, HpkePublicKey) {
    hpke::derive_keypair(&ctx_of(ctx), ikm).unwrap()
}

fn pub_raw(pk: &HpkePublicKey) -> (PubByte32, PublicBytes) {
    let w = pk.to_wire();
    (
        PubByte32::from_slice(&w[..32]).unwrap(),
        PublicBytes::from_slice(&w[32..]),
    )
}

fn priv_raw(sk: &HpkePrivateKey) -> (SecByte32, SecretBytes) {
    let w = sk.to_wire();
    let w = w.expose_as_slice();
    (SecByte32::from_slice(&w[..32]).unwrap(), sb(&w[32..]))
}

fn seal(pk: &HpkePublicKey, ctx: &str, info: &[u8], aad: &[u8], pt: &[u8]) -> HpkeSealed {
    let (x_pub, k_pub) = pub_raw(pk);
    hpke::seal_base(&ctx_of(ctx), &x_pub, &k_pub, info, aad, &sb(pt)).unwrap()
}

fn open(
    sk: &HpkePrivateKey,
    ctx: &str,
    info: &[u8],
    aad: &[u8],
    sealed: &HpkeSealed,
) -> lithium_core::Result<SecretBytes> {
    let (x_priv, k_priv) = priv_raw(sk);
    hpke::open_base(&ctx_of(ctx), &x_priv, &k_priv, info, aad, sealed)
}

fn enc_flip(enc: &HpkeEnc, idx: usize) -> HpkeEnc {
    let mut w = enc.to_wire();
    w[idx] ^= 0x01;
    HpkeEnc::from_wire(&w).unwrap()
}

// ---- roundtrip / happy path ----

#[test]
fn seal_open_roundtrip() {
    let (sk, pk) = kp(CTX, b"seed-a");
    let sealed = seal(&pk, CTX, INFO, AAD, b"hello hpke");
    let pt = open(&sk, CTX, INFO, AAD, &sealed).unwrap();
    assert_eq!(pt.expose_as_slice(), b"hello hpke");
}

#[test]
fn setup_export_sender_receiver_agree() {
    let (sk, pk) = kp(CTX, b"seed-b");
    let (enc, sent) =
        hpke::setup_sender_and_export(&ctx_of(CTX), &pk, INFO, b"exp-ctx", 32).unwrap();
    let recv =
        hpke::setup_receiver_and_export(&ctx_of(CTX), &sk, &enc, INFO, b"exp-ctx", 32).unwrap();
    assert_eq!(sent.expose_as_slice(), recv.expose_as_slice());
    assert_eq!(sent.len(), 32);
}

#[test]
fn derive_keypair_is_deterministic() {
    let (sk1, pk1) = kp(CTX, b"same-seed");
    let (sk2, pk2) = kp(CTX, b"same-seed");
    assert_eq!(pk1.to_wire(), pk2.to_wire());
    assert_eq!(
        sk1.to_wire().expose_as_slice(),
        sk2.to_wire().expose_as_slice()
    );
}

#[test]
fn derive_keypair_empty_ikm_is_ok_and_deterministic() {
    let (_, pk1) = kp(CTX, b"");
    let (_, pk2) = kp(CTX, b"");
    assert_eq!(pk1.to_wire(), pk2.to_wire());
}

// ---- domain separation ----

#[test]
fn derive_keypair_diff_ikm_diff_keys() {
    let (_, a) = kp(CTX, b"ikm-1");
    let (_, b) = kp(CTX, b"ikm-2");
    assert_ne!(a.to_wire(), b.to_wire());
}

#[test]
fn derive_keypair_diff_ctx_diff_keys() {
    let (_, a) = kp("ctx-1", b"same");
    let (_, b) = kp("ctx-2", b"same");
    assert_ne!(a.to_wire(), b.to_wire());
}

// ---- authenticated negatives: open must fail ----

#[test]
fn open_wrong_ctx_fails() {
    let (sk, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, INFO, AAD, b"m");
    assert!(open(&sk, "other-ctx", INFO, AAD, &sealed).is_err());
}

#[test]
fn open_wrong_info_fails() {
    let (sk, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, INFO, AAD, b"m");
    assert!(open(&sk, CTX, b"other-info", AAD, &sealed).is_err());
}

#[test]
fn open_wrong_aad_fails() {
    let (sk, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, INFO, AAD, b"m");
    assert!(open(&sk, CTX, INFO, b"other-aad", &sealed).is_err());
}

#[test]
fn open_aad_prefix_fails() {
    let (sk, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, INFO, b"aad-full", b"m");
    assert!(open(&sk, CTX, INFO, b"aad", &sealed).is_err());
}

#[test]
fn open_wrong_recipient_fails() {
    let (_, pk) = kp(CTX, b"recipient-a");
    let (sk_b, _) = kp(CTX, b"recipient-b");
    let sealed = seal(&pk, CTX, INFO, AAD, b"m");
    assert!(open(&sk_b, CTX, INFO, AAD, &sealed).is_err());
}

#[test]
fn open_tampered_ciphertext_fails() {
    let (sk, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, INFO, AAD, b"tamper-me");
    let mut ct = sealed.ciphertext.as_slice().to_vec();
    ct[0] ^= 0x01;
    let bad = HpkeSealed {
        enc: sealed.enc.clone(),
        ciphertext: PublicBytes::new(ct),
    };
    assert!(open(&sk, CTX, INFO, AAD, &bad).is_err());
}

#[test]
fn open_tampered_enc_xpub_fails() {
    let (sk, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, INFO, AAD, b"m");
    let bad = HpkeSealed {
        enc: enc_flip(&sealed.enc, 0),
        ciphertext: sealed.ciphertext.clone(),
    };
    assert!(open(&sk, CTX, INFO, AAD, &bad).is_err());
}

#[test]
fn open_tampered_enc_kemct_fails() {
    let (sk, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, INFO, AAD, b"m");
    let bad = HpkeSealed {
        enc: enc_flip(&sealed.enc, 40),
        ciphertext: sealed.ciphertext.clone(),
    };
    assert!(open(&sk, CTX, INFO, AAD, &bad).is_err());
}

#[test]
fn open_empty_ciphertext_fails() {
    let (sk, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, INFO, AAD, b"m");
    let bad = HpkeSealed {
        enc: sealed.enc.clone(),
        ciphertext: PublicBytes::new(vec![]),
    };
    assert!(open(&sk, CTX, INFO, AAD, &bad).is_err());
}

#[test]
fn open_truncated_kem_ct_fails() {
    let (sk, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, INFO, AAD, b"m");
    let mut w = sealed.enc.to_wire();
    w.truncate(w.len() - 100);
    let bad = HpkeSealed {
        enc: HpkeEnc::from_wire(&w).unwrap(),
        ciphertext: sealed.ciphertext.clone(),
    };
    assert!(open(&sk, CTX, INFO, AAD, &bad).is_err());
}

#[test]
fn seal_is_randomized() {
    let (_, pk) = kp(CTX, b"s");
    let a = seal(&pk, CTX, INFO, AAD, b"same-plaintext");
    let b = seal(&pk, CTX, INFO, AAD, b"same-plaintext");
    assert_ne!(a.enc.to_wire(), b.enc.to_wire());
    assert_ne!(a.ciphertext.as_slice(), b.ciphertext.as_slice());
}

// ---- unauthenticated export: mismatch => different secret, not an error ----

#[test]
fn export_wrong_ctx_disagrees() {
    let (sk, pk) = kp(CTX, b"s");
    let (enc, sent) = hpke::setup_sender_and_export(&ctx_of(CTX), &pk, INFO, b"e", 32).unwrap();
    let recv =
        hpke::setup_receiver_and_export(&ctx_of("bad-ctx"), &sk, &enc, INFO, b"e", 32).unwrap();
    assert_ne!(sent.expose_as_slice(), recv.expose_as_slice());
}

#[test]
fn export_wrong_info_disagrees() {
    let (sk, pk) = kp(CTX, b"s");
    let (enc, sent) = hpke::setup_sender_and_export(&ctx_of(CTX), &pk, INFO, b"e", 32).unwrap();
    let recv =
        hpke::setup_receiver_and_export(&ctx_of(CTX), &sk, &enc, b"bad-info", b"e", 32).unwrap();
    assert_ne!(sent.expose_as_slice(), recv.expose_as_slice());
}

#[test]
fn export_wrong_exporter_context_disagrees() {
    let (sk, pk) = kp(CTX, b"s");
    let (enc, sent) = hpke::setup_sender_and_export(&ctx_of(CTX), &pk, INFO, b"ctx-a", 32).unwrap();
    let recv =
        hpke::setup_receiver_and_export(&ctx_of(CTX), &sk, &enc, INFO, b"ctx-b", 32).unwrap();
    assert_ne!(sent.expose_as_slice(), recv.expose_as_slice());
}

#[test]
fn export_mismatched_keys_disagree() {
    let (_, pk) = kp(CTX, b"key-a");
    let (sk_b, _) = kp(CTX, b"key-b");
    let (enc, sent) = hpke::setup_sender_and_export(&ctx_of(CTX), &pk, INFO, b"e", 32).unwrap();
    let recv = hpke::setup_receiver_and_export(&ctx_of(CTX), &sk_b, &enc, INFO, b"e", 32).unwrap();
    assert_ne!(sent.expose_as_slice(), recv.expose_as_slice());
}

#[test]
fn export_len_zero_is_empty() {
    let (_, pk) = kp(CTX, b"s");
    let (_, sent) = hpke::setup_sender_and_export(&ctx_of(CTX), &pk, INFO, b"e", 0).unwrap();
    assert!(sent.expose_as_slice().is_empty());
}

#[test]
fn export_len_is_honored() {
    let (_, pk) = kp(CTX, b"s");
    for len in [1usize, 16, 32, 64, 255, 1000] {
        let (_, sent) = hpke::setup_sender_and_export(&ctx_of(CTX), &pk, INFO, b"e", len).unwrap();
        assert_eq!(sent.len(), len);
    }
}

#[test]
fn export_hkdf_max_len_ok_over_max_errors() {
    let (_, pk) = kp(CTX, b"s");
    // HKDF-SHA256 caps output at 255 * 32 = 8160 bytes.
    assert!(hpke::setup_sender_and_export(&ctx_of(CTX), &pk, INFO, b"e", 8160).is_ok());
    assert!(hpke::setup_sender_and_export(&ctx_of(CTX), &pk, INFO, b"e", 8161).is_err());
}

#[test]
fn export_shorter_len_is_prefix_of_longer() {
    let (sk, pk) = kp(CTX, b"s");
    let (enc, short) = hpke::setup_sender_and_export(&ctx_of(CTX), &pk, INFO, b"e", 32).unwrap();
    let long = hpke::setup_receiver_and_export(&ctx_of(CTX), &sk, &enc, INFO, b"e", 64).unwrap();
    assert_eq!(&long.expose_as_slice()[..32], short.expose_as_slice());
}

// ---- annoying / edge inputs ----

#[test]
fn seal_open_empty_plaintext() {
    let (sk, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, INFO, AAD, b"");
    let pt = open(&sk, CTX, INFO, AAD, &sealed).unwrap();
    assert!(pt.expose_as_slice().is_empty());
}

#[test]
fn seal_open_empty_info_and_aad() {
    let (sk, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, b"", b"", b"payload");
    let pt = open(&sk, CTX, b"", b"", &sealed).unwrap();
    assert_eq!(pt.expose_as_slice(), b"payload");
}

#[test]
fn seal_open_large_plaintext() {
    let (sk, pk) = kp(CTX, b"s");
    let big = vec![0xABu8; 200_000];
    let sealed = seal(&pk, CTX, INFO, AAD, &big);
    let pt = open(&sk, CTX, INFO, AAD, &sealed).unwrap();
    assert_eq!(pt.expose_as_slice(), big.as_slice());
}

#[test]
fn seal_open_binary_info_and_aad() {
    let (sk, pk) = kp(CTX, b"s");
    let info: Vec<u8> = (0u16..=255).map(|b| b as u8).collect();
    let aad = vec![0x00, 0xFF, 0x00, 0xFF];
    let sealed = seal(&pk, CTX, &info, &aad, b"bin");
    assert_eq!(
        open(&sk, CTX, &info, &aad, &sealed)
            .unwrap()
            .expose_as_slice(),
        b"bin"
    );
}

#[test]
fn info_with_null_bytes_still_separates() {
    // schedule labels join with a NUL; a NUL inside `info` must not let two
    // different infos collide.
    let (sk, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, b"a\0b", AAD, b"m");
    assert!(open(&sk, CTX, b"a\0c", AAD, &sealed).is_err());
    assert_eq!(
        open(&sk, CTX, b"a\0b", AAD, &sealed)
            .unwrap()
            .expose_as_slice(),
        b"m"
    );
}

// ---- wire format: to_wire / from_wire ----

#[test]
fn enc_wire_roundtrip() {
    let (_, pk) = kp(CTX, b"s");
    let sealed = seal(&pk, CTX, INFO, AAD, b"m");
    let w = sealed.enc.to_wire();
    let back = HpkeEnc::from_wire(&w).unwrap();
    assert_eq!(back.to_wire(), w);
}

#[test]
fn enc_from_wire_rejects_len_at_or_below_xpub() {
    assert!(HpkeEnc::from_wire(&[]).is_err());
    assert!(HpkeEnc::from_wire(&[0u8; 32]).is_err());
    // 33 bytes is the minimum accepted (1-byte kem_ct); parsing succeeds even
    // though decap will later reject it.
    assert!(HpkeEnc::from_wire(&[0u8; 33]).is_ok());
}

#[test]
fn pubkey_wire_roundtrip() {
    let (_, pk) = kp(CTX, b"s");
    let w = pk.to_wire();
    assert_eq!(w.len(), 32 + 1568);
    let back = HpkePublicKey::from_wire(&w).unwrap();
    assert_eq!(back.to_wire(), w);
}

#[test]
fn pubkey_from_wire_wrong_len_err() {
    assert!(HpkePublicKey::from_wire(&[]).is_err());
    assert!(HpkePublicKey::from_wire(&[0u8; 32 + 1568 - 1]).is_err());
    assert!(HpkePublicKey::from_wire(&[0u8; 32 + 1568 + 1]).is_err());
}

#[test]
fn privkey_wire_roundtrip() {
    let (sk, _) = kp(CTX, b"s");
    let w = sk.to_wire();
    assert_eq!(w.len(), 32 + 64);
    let back = HpkePrivateKey::from_wire(w.expose_as_slice()).unwrap();
    assert_eq!(back.to_wire().expose_as_slice(), w.expose_as_slice());
}

#[test]
fn privkey_from_wire_wrong_len_err() {
    assert!(HpkePrivateKey::from_wire(&[]).is_err());
    assert!(HpkePrivateKey::from_wire(&[0u8; 32 + 64 - 1]).is_err());
    assert!(HpkePrivateKey::from_wire(&[0u8; 32 + 64 + 1]).is_err());
}

#[test]
fn full_wire_interop_seal_open() {
    // Everything crosses a serialization boundary, as a real peer would.
    let (sk, pk) = kp(CTX, b"s");

    let pk = HpkePublicKey::from_wire(&pk.to_wire()).unwrap();
    let (x_pub, k_pub) = pub_raw(&pk);
    let sealed = hpke::seal_base(&ctx_of(CTX), &x_pub, &k_pub, INFO, AAD, &sb(b"wire")).unwrap();

    let enc = HpkeEnc::from_wire(&sealed.enc.to_wire()).unwrap();
    let ct = PublicBytes::new(sealed.ciphertext.as_slice().to_vec());
    let sealed = HpkeSealed {
        enc,
        ciphertext: ct,
    };

    let sk = HpkePrivateKey::from_wire(sk.to_wire().expose_as_slice()).unwrap();
    let pt = open(&sk, CTX, INFO, AAD, &sealed).unwrap();
    assert_eq!(pt.expose_as_slice(), b"wire");
}


// ===== FILE: ./tests/keymanager_arena_tests.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::crypto::{keys, sign};
use lithium_core::keys::{KeyManager, KeyStoreKind};

mod common;
use common::FileMk;

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("lithium-km-arena-{tag}-{}", std::process::id()))
}

#[test]
fn arena_backed_signing_keys_sign_and_verify() {
    let dir = tmp_dir("sign");
    std::fs::remove_dir_all(&dir).ok();
    let km = KeyManager::start(
        &dir,
        KeyStoreKind::Server,
        FileMk {
            path: dir.join("mk"),
        },
    )
    .unwrap();

    let ed_pub = km.public_keys().ed25519;
    let dili_pub = km.public_keys().dilithium.clone();
    let msg = b"born-locked signing path";

    let (ed_sig, dili_sig) = km
        .with_signing_keys(|ed_seed, dili_sk| {
            let e = sign::sign_message(msg, ed_seed.as_slice())?;
            let d = sign::sign_message_dili(msg, dili_sk.as_slice())?;
            Ok((e, d))
        })
        .unwrap();

    assert!(sign::verify_signature(msg, &ed_sig, &ed_pub));
    assert!(sign::verify_signature_dili(msg, &dili_sig, &dili_pub));

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn arena_backed_x25519_kyber_load_is_correct() {
    let dir = tmp_dir("xkyber");
    std::fs::remove_dir_all(&dir).ok();
    let km = KeyManager::start(
        &dir,
        KeyStoreKind::Server,
        FileMk {
            path: dir.join("mk"),
        },
    )
    .unwrap();

    let x_pub = km.public_keys().x25519;
    let kyber_pub = km.public_keys().kyber.clone();

    km.with_x25519_and_kyber_sk(|x_seed, kyber_sk| {
        assert_eq!(x_seed.len(), 32);
        assert_eq!(kyber_sk.len(), 64);
        assert_eq!(keys::x25519_pub_from_seed(x_seed.as_array()), x_pub);
        assert_eq!(
            keys::mlkem1024_pub_from_seed(kyber_sk.as_slice())
                .unwrap()
                .as_slice(),
            kyber_pub.as_slice()
        );
        Ok(())
    })
    .unwrap();

    std::fs::remove_dir_all(&dir).ok();
}


// ===== FILE: ./tests/keymanager_lock_tests.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::ErrorKind;
use lithium_core::keys::{KeyManager, KeyStoreKind};

mod common;
use common::FileMk;

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("lithium-km-lock-{tag}-{}", std::process::id()))
}

fn start(dir: &std::path::Path) -> lithium_core::Result<KeyManager<FileMk>> {
    KeyManager::start(
        dir,
        KeyStoreKind::Server,
        FileMk {
            path: dir.join("mk"),
        },
    )
}

#[test]
fn second_instance_on_same_store_is_rejected() {
    let dir = tmp_dir("reject");
    std::fs::remove_dir_all(&dir).ok();

    let km1 = start(&dir).unwrap();

    match start(&dir) {
        Err(e) => assert!(
            matches!(e.kind, ErrorKind::KeystoreLocked),
            "second instance must be rejected as locked, got {e:?}"
        ),
        Ok(_) => panic!("second instance must not acquire the store"),
    }

    drop(km1);
    start(&dir).expect("lock is released once the first instance drops");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn different_kinds_do_not_contend() {
    let dir = tmp_dir("kinds");
    std::fs::remove_dir_all(&dir).ok();

    let _server = KeyManager::start(
        &dir,
        KeyStoreKind::Server,
        FileMk {
            path: dir.join("server-mk"),
        },
    )
    .unwrap();
    let _user = KeyManager::start(
        &dir,
        KeyStoreKind::User,
        FileMk {
            path: dir.join("user-mk"),
        },
    )
    .expect("distinct store directories must not share a lock");

    std::fs::remove_dir_all(&dir).ok();
}


// ===== FILE: ./tests/password_tests.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::error::ErrorKind;
use lithium_core::opaque::dek::{unwrap_dek_under_export_key, wrap_dek_under_export_key};
use lithium_core::passwords::{
    PasswordPolicy, generate_dek, validate_password, validate_passwords_distinct,
};
use lithium_core::secrets::{SecByte64, SecretString};

const TEST_DEK_AAD: &[u8] = b"lithium-core/test/dek-wrap";

fn pass(s: &str) -> SecretString {
    SecretString::new(s.to_owned())
}

fn default_policy() -> PasswordPolicy {
    PasswordPolicy::default()
}

fn export_key(seed: u8) -> SecByte64 {
    SecByte64::from_slice(&[seed; 64]).unwrap()
}

#[test]
fn password_valid_default_policy() {
    assert!(validate_password(&pass("Passw0rd!Abc"), default_policy()).is_ok());
}

#[test]
fn password_too_short() {
    let err = validate_password(&pass("Ab1!"), default_policy()).unwrap_err();
    assert_eq!(err.kind, ErrorKind::StringPolicy);
}

#[test]
fn password_too_long() {
    let long = "Aa1!".repeat(300);
    let err = validate_password(&pass(&long), default_policy()).unwrap_err();
    assert_eq!(err.kind, ErrorKind::StringPolicy);
}

#[test]
fn password_missing_lowercase() {
    let err = validate_password(&pass("PASSW0RD!ABC"), default_policy()).unwrap_err();
    assert_eq!(err.kind, ErrorKind::StringPolicy);
}

#[test]
fn password_missing_uppercase() {
    let err = validate_password(&pass("passw0rd!abc"), default_policy()).unwrap_err();
    assert_eq!(err.kind, ErrorKind::StringPolicy);
}

#[test]
fn password_missing_digit() {
    let err = validate_password(&pass("Password!Abc"), default_policy()).unwrap_err();
    assert_eq!(err.kind, ErrorKind::StringPolicy);
}

#[test]
fn password_missing_special() {
    let err = validate_password(&pass("Password1Abc"), default_policy()).unwrap_err();
    assert_eq!(err.kind, ErrorKind::StringPolicy);
}

#[test]
fn password_with_whitespace_rejected_by_default() {
    let err = validate_password(&pass("Pass w0rd!Ab"), default_policy()).unwrap_err();
    assert_eq!(err.kind, ErrorKind::StringPolicy);
}

#[test]
fn password_with_whitespace_allowed_when_permitted() {
    let mut pol = default_policy();
    pol.allow_whitespace = true;
    assert!(validate_password(&pass("Pass w0rd!Ab"), pol).is_ok());
}

#[test]
fn password_custom_policy_no_special_required() {
    let pol = PasswordPolicy {
        require_special: false,
        ..default_policy()
    };
    assert!(validate_password(&pass("Password1Abc"), pol).is_ok());
}

#[test]
fn password_custom_policy_short_min() {
    let pol = PasswordPolicy {
        min_len: 4,
        require_uppercase: false,
        require_digit: false,
        require_special: false,
        ..default_policy()
    };
    assert!(validate_password(&pass("abcd"), pol).is_ok());
}

#[test]
fn password_exactly_min_length() {
    assert!(validate_password(&pass("Passw0rd!Ab2"), default_policy()).is_ok());
}

#[test]
fn passwords_distinct_ok() {
    assert!(validate_passwords_distinct(&pass("first"), &pass("second")).is_ok());
}

#[test]
fn passwords_distinct_same_fails() {
    let err = validate_passwords_distinct(&pass("same"), &pass("same")).unwrap_err();
    assert!(matches!(err.kind, ErrorKind::InvalidCredentials { .. }));
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


// ===== FILE: ./tests/secret_tests.rs =====
// ----------------------------------------

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::error::ErrorKind;
use lithium_core::secrets::{
    SecByte12, SecByte32, SecByte64, SecretBytes, SecretJson, SecretString,
};

#[test]
fn fixed_bytes_new_and_as_slice() {
    let b = SecByte32::new([0xAA; 32]);
    assert_eq!(b.as_slice(), &[0xAAu8; 32]);
}

#[test]
fn fixed_bytes_from_slice_ok() {
    let data = [0x11u8; 32];
    let b = SecByte32::from_slice(&data).unwrap();
    assert_eq!(b.as_slice(), &data);
}

#[test]
fn fixed_bytes_from_slice_wrong_length() {
    let err = SecByte32::from_slice(&[0u8; 16]).unwrap_err();
    assert!(matches!(
        err.kind,
        ErrorKind::InvalidLength {
            expected: 32,
            got: 16
        }
    ));
}

#[test]
fn fixed_bytes_from_slice_too_long() {
    let err = SecByte32::from_slice(&[0u8; 64]).unwrap_err();
    assert!(matches!(
        err.kind,
        ErrorKind::InvalidLength {
            expected: 32,
            got: 64
        }
    ));
}

#[test]
fn fixed_bytes_new_zeroed() {
    let b = SecByte32::new_zeroed();
    assert_eq!(b.as_slice(), &[0u8; 32]);
}

#[test]
fn fixed_bytes_clone() {
    let original = SecByte32::new([0x55; 32]);
    let cloned = original.clone();
    assert_eq!(original.as_slice(), cloned.as_slice());
}

#[test]
fn fixed_bytes_eq_same() {
    let a = SecByte32::new([0x77; 32]);
    let b = SecByte32::new([0x77; 32]);
    assert_eq!(a, b);
}

#[test]
fn fixed_bytes_eq_different() {
    let a = SecByte32::new([0x77; 32]);
    let b = SecByte32::new([0x88; 32]);
    assert_ne!(a, b);
}

#[test]
fn fixed_bytes_from_array() {
    let arr = [0x33u8; 32];
    let b: SecByte32 = arr.into();
    assert_eq!(b.as_slice(), &arr);
}

#[test]
fn fixed_bytes_try_from_slice() {
    use std::convert::TryFrom;
    let data = [0x44u8; 32];
    let b = SecByte32::try_from(data.as_slice()).unwrap();
    assert_eq!(b.as_slice(), &data);
}

#[test]
fn fixed_bytes_as_ref() {
    let b = SecByte32::new([0x22; 32]);
    let slice: &[u8] = b.as_ref();
    assert_eq!(slice, &[0x22u8; 32]);
}

#[test]
fn fixed_bytes_len_const() {
    assert_eq!(SecByte32::LEN, 32);
    assert_eq!(SecByte12::LEN, 12);
    assert_eq!(SecByte64::LEN, 64);
}

#[test]
fn fixed_bytes_debug_redacted() {
    let b = SecByte32::new([0xFF; 32]);
    let s = format!("{:?}", b);
    assert!(!s.contains("ff"), "Debug must not reveal bytes: {s}");
    assert!(s.contains("FixedBytes"));
}

#[test]
fn fixed_bytes_to_hex_roundtrip() {
    let original = SecByte32::new([0xDE; 32]);
    let hex_str = original.to_hex();
    let recovered = SecByte32::from_hex(hex_str.expose()).unwrap();
    assert_eq!(original, recovered);
}

#[test]
fn fixed_bytes_from_hex_correct_length() {
    let valid = "deadbeef".repeat(8);
    let b = SecByte32::from_hex(&valid).unwrap();
    assert_eq!(b.as_slice().len(), 32);
}

#[test]
fn fixed_bytes_from_hex_0x_prefix_rejected() {
    let err = SecByte32::from_hex("0xdeadbeef").unwrap_err();
    assert_eq!(err.kind, ErrorKind::HexDisallowedPrefix);
}

#[test]
fn fixed_bytes_from_hex_uppercase_rejected() {
    let upper = "DEADBEEF".repeat(8);
    let err = SecByte32::from_hex(&upper).unwrap_err();
    assert_eq!(err.kind, ErrorKind::HexMustBeLowercase);
}

#[test]
fn fixed_bytes_from_hex_wrong_length_rejected() {
    let short = "deadbeef";
    let err = SecByte32::from_hex(short).unwrap_err();
    assert!(matches!(
        err.kind,
        ErrorKind::InvalidHexLength { expected: 64, .. }
    ));
}

#[test]
fn fixed_bytes_from_hex_invalid_char_rejected() {
    // 62 valid chars + 2 invalid
    let mut hex = "aa".repeat(31);
    hex.push_str("zz");
    let err = SecByte32::from_hex(&hex).unwrap_err();
    assert_eq!(err.kind, ErrorKind::InvalidHex);
}

#[test]
fn from_hex_multibyte_input_errors_without_panic() {
    let multibyte = "砜砜";
    assert!(SecByte32::from_hex(multibyte).is_err());
    assert!(SecretBytes::from_hex(multibyte).is_err());
}

#[test]
fn secret_bytes_from_slice() {
    let data = b"hello world";
    let sb = SecretBytes::from_slice(data);
    assert_eq!(sb.expose_as_slice(), data);
}

#[test]
fn secret_bytes_len() {
    let sb = SecretBytes::from_slice(b"abcde");
    assert_eq!(sb.len(), 5);
}

#[test]
fn secret_bytes_is_empty_false() {
    let sb = SecretBytes::from_slice(b"x");
    assert!(!sb.is_empty());
}

#[test]
fn secret_bytes_is_empty_true() {
    let sb = SecretBytes::from_slice(b"");
    assert!(sb.is_empty());
}

#[test]
fn secret_bytes_clone() {
    let original = SecretBytes::from_slice(b"clone me");
    let cloned = original.clone();
    assert_eq!(original.expose_as_slice(), cloned.expose_as_slice());
}

#[test]
fn secret_bytes_debug_redacted() {
    let sb = SecretBytes::from_slice(b"top secret");
    let s = format!("{:?}", sb);
    assert!(!s.contains("top secret"), "Debug must not reveal data: {s}");
    assert!(s.contains("SecretBytes"));
}

#[test]
fn secret_bytes_as_ref() {
    let sb = SecretBytes::from_slice(b"data");
    let r: &[u8] = sb.as_ref();
    assert_eq!(r, b"data");
}

#[test]
fn secret_bytes_to_hex_from_hex_roundtrip() {
    let original = SecretBytes::from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
    let hex = original.to_hex();
    let recovered = SecretBytes::from_hex(hex.expose()).unwrap();
    assert_eq!(original.expose_as_slice(), recovered.expose_as_slice());
}

#[test]
fn secret_bytes_from_hex_0x_prefix_rejected() {
    let err = SecretBytes::from_hex("0xdeadbeef").unwrap_err();
    assert_eq!(err.kind, ErrorKind::HexDisallowedPrefix);
}

#[test]
fn secret_bytes_from_hex_uppercase_rejected() {
    let err = SecretBytes::from_hex("DEADBEEF").unwrap_err();
    assert_eq!(err.kind, ErrorKind::HexMustBeLowercase);
}

#[test]
fn secret_bytes_from_hex_odd_length_rejected() {
    let err = SecretBytes::from_hex("abc").unwrap_err();
    assert!(matches!(err.kind, ErrorKind::InvalidHexLength { .. }));
}

#[test]
fn secret_bytes_from_hex_empty() {
    let sb = SecretBytes::from_hex("").unwrap();
    assert!(sb.is_empty());
}

#[test]
fn secret_string_new_expose() {
    let ss = SecretString::new("hello".to_owned());
    assert_eq!(ss.expose(), "hello");
}

#[test]
fn secret_string_new_checked_ok() {
    let ss = SecretString::new_checked("valid string".to_owned()).unwrap();
    assert_eq!(ss.expose(), "valid string");
}

#[test]
fn secret_string_new_checked_null_byte_rejected() {
    let err = SecretString::new_checked("null\0byte".to_owned()).unwrap_err();
    assert_eq!(err.kind, ErrorKind::StringPolicy);
}

#[test]
fn secret_string_debug_redacted() {
    let ss = SecretString::new("sensitive data".to_owned());
    let dbg = format!("{:?}", ss);
    assert!(
        !dbg.contains("sensitive"),
        "Debug must not show value: {dbg}"
    );
    assert!(dbg.contains("redacted") || dbg.contains("SecretString"));
}

#[test]
fn secret_string_display_redacted() {
    let ss = SecretString::new("sensitive data".to_owned());
    let disp = format!("{}", ss);
    assert!(
        !disp.contains("sensitive"),
        "Display must not show value: {disp}"
    );
    assert_eq!(disp, "<redacted>");
}

#[test]
fn secret_string_from_utf8_bytes_valid() {
    let ss = SecretString::from_utf8_bytes(b"valid utf8").unwrap();
    assert_eq!(ss.expose(), "valid utf8");
}

#[test]
fn secret_string_from_utf8_bytes_invalid_utf8() {
    let invalid = b"\xff\xfe";
    let err = SecretString::from_utf8_bytes(invalid).unwrap_err();
    assert_eq!(err.kind, ErrorKind::StringPolicy);
}

#[test]
fn secret_string_from_utf8_vec_valid() {
    let ss = SecretString::from_utf8_vec(b"from vec".to_vec()).unwrap();
    assert_eq!(ss.expose(), "from vec");
}

#[test]
fn secret_string_decode_hex() {
    let ss = SecretString::new("deadbeef".to_owned());
    let bytes = ss.decode_hex().unwrap();
    assert_eq!(bytes.as_slice(), &[0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn secret_string_decode_hex_fixed() {
    let hex_str = "aa".repeat(32);
    let ss = SecretString::new(hex_str);
    let b32: SecByte32 = ss.decode_hex_fixed().unwrap();
    assert_eq!(b32.as_slice(), &[0xAAu8; 32]);
}

#[test]
fn secret_string_to_zeroizing() {
    let ss = SecretString::new("hello".to_owned());
    let z = ss.to_zeroizing();
    assert_eq!(z.as_str(), "hello");
}

#[test]
fn secret_string_clone() {
    let ss = SecretString::new("clone test".to_owned());
    let cloned = ss.clone();
    assert_eq!(cloned.expose(), ss.expose());
}

#[test]
fn secret_json_from_str_valid() {
    let j = SecretJson::from_str(r#"{"key":"value"}"#).unwrap();
    let s = j.get_string("key").unwrap();
    assert_eq!(s.expose(), "value");
}

#[test]
fn secret_json_from_str_invalid() {
    let err = SecretJson::from_str("not json {{{").unwrap_err();
    assert_eq!(err.kind, ErrorKind::JsonParse);
}

#[test]
fn secret_json_not_an_object() {
    let j = SecretJson::from_str(r#"[1, 2, 3]"#).unwrap();
    let err = j.get_string("x").unwrap_err();
    assert_eq!(err.kind, ErrorKind::JsonNotObject);
}

#[test]
fn secret_json_missing_field() {
    let j = SecretJson::from_str(r#"{"a":"b"}"#).unwrap();
    let err = j.get_string("missing").unwrap_err();
    assert_eq!(err.kind, ErrorKind::JsonMissingField { key: "missing" });
}

#[test]
fn secret_json_type_mismatch_string_not_number() {
    let j = SecretJson::from_str(r#"{"n": 42}"#).unwrap();
    let err = j.get_string("n").unwrap_err();
    assert!(matches!(
        err.kind,
        ErrorKind::JsonTypeMismatch { key: "n", .. }
    ));
}

#[test]
fn secret_json_get_integer() {
    use secrecy::ExposeSecret;
    let j = SecretJson::from_str(r#"{"count": 99}"#).unwrap();
    let v = j.get_integer("count").unwrap();
    assert_eq!(*v.expose_secret(), 99i64);
}

#[test]
fn secret_json_get_bool_true() {
    let j = SecretJson::from_str(r#"{"flag": true}"#).unwrap();
    assert!(j.get_bool("flag").unwrap());
}

#[test]
fn secret_json_get_bool_false() {
    let j = SecretJson::from_str(r#"{"flag": false}"#).unwrap();
    assert!(!j.get_bool("flag").unwrap());
}

#[test]
fn secret_json_take_string_removes_field() {
    let mut j = SecretJson::from_str(r#"{"token": "abc123", "other": "keep"}"#).unwrap();
    let taken = j.take_string("token").unwrap();
    assert_eq!(taken.expose(), "abc123");
    let err = j.get_string("token").unwrap_err();
    assert_eq!(err.kind, ErrorKind::JsonMissingField { key: "token" });
    assert_eq!(j.get_string("other").unwrap().expose(), "keep");
}

#[test]
fn secret_json_take_bool() {
    let mut j = SecretJson::from_str(r#"{"enabled": true}"#).unwrap();
    assert!(j.take_bool("enabled").unwrap());
    assert!(j.get_bool("enabled").is_err());
}

#[test]
fn secret_json_take_i64() {
    use secrecy::ExposeSecret;
    let mut j = SecretJson::from_str(r#"{"x": -7}"#).unwrap();
    let v = j.take_i64("x").unwrap();
    assert_eq!(*v.expose_secret(), -7i64);
}

#[test]
fn secret_json_take_u64() {
    use secrecy::ExposeSecret;
    let mut j = SecretJson::from_str(r#"{"big": 9999999}"#).unwrap();
    let v = j.take_u64("big").unwrap();
    assert_eq!(*v.expose_secret(), 9999999u64);
}

#[test]
fn secret_json_take_f64() {
    use secrecy::ExposeSecret;
    let mut j = SecretJson::from_str(r#"{"pi": 3.141592653589793}"#).unwrap();
    let v = j.take_f64("pi").unwrap();
    let pi = *v.expose_secret();
    assert!((pi - std::f64::consts::PI).abs() < 1e-9);
}

#[test]
fn secret_json_get_array() {
    let j = SecretJson::from_str(r#"{"items": ["a", "b", "c"]}"#).unwrap();
    let arr = j.get_array("items").unwrap();
    assert_eq!(arr.len(), 3);
}

#[test]
fn secret_json_get_object() {
    let j = SecretJson::from_str(r#"{"nested": {"x": "y"}}"#).unwrap();
    let nested = j.get_object("nested").unwrap();
    assert_eq!(nested.get_string("x").unwrap().expose(), "y");
}

#[test]
fn secret_json_take_object() {
    let mut j = SecretJson::from_str(r#"{"inner": {"k": "v"}}"#).unwrap();
    let inner = j.take_object("inner").unwrap();
    assert_eq!(inner.get_string("k").unwrap().expose(), "v");
    assert!(j.get_object("inner").is_err());
}

#[test]
fn secret_json_debug_redacted() {
    let j = SecretJson::from_str(r#"{"secret": "mysecret"}"#).unwrap();
    let dbg = format!("{:?}", j);
    assert!(
        !dbg.contains("mysecret"),
        "Debug must not reveal data: {dbg}"
    );
}

#[test]
fn secret_json_display_redacted() {
    let j = SecretJson::from_str(r#"{"secret": "mysecret"}"#).unwrap();
    let disp = format!("{}", j);
    assert!(
        !disp.contains("mysecret"),
        "Display must not reveal data: {disp}"
    );
    assert_eq!(disp, "<redacted>");
}

#[test]
fn secret_json_raw_json_preserved() {
    let raw = r#"{"key":"val"}"#;
    let j = SecretJson::from_str(raw).unwrap();
    let gotten = j.get_raw_json().unwrap();
    assert_eq!(gotten.expose(), raw);
}

#[test]
fn secret_json_take_raw_json_removes_it() {
    let mut j = SecretJson::from_str(r#"{"k":"v"}"#).unwrap();
    let raw = j.take_raw_json().unwrap();
    assert!(j.take_raw_json().is_none());
    assert_eq!(raw.expose(), r#"{"k":"v"}"#);
}

#[test]
fn secret_json_from_bytes_valid() {
    let j = SecretJson::from_bytes(b"{\"a\":1}").unwrap();
    use secrecy::ExposeSecret;
    let v = j.get_integer("a").unwrap();
    assert_eq!(*v.expose_secret(), 1i64);
}

#[test]
fn secret_json_from_vec_valid() {
    let j = SecretJson::from_vec(b"{\"z\":true}".to_vec()).unwrap();
    assert!(j.get_bool("z").unwrap());
}


// ===== FILE: ./tests/store_tests.rs =====
// ----------------------------------------

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

    assert_eq!(
        store.peek("a").unwrap().unwrap().expose_as_slice(),
        b"alpha"
    );
    assert_eq!(store.peek("b").unwrap().unwrap().expose_as_slice(), b"beta");
    assert_eq!(
        store.peek("c").unwrap().unwrap().expose_as_slice(),
        b"gamma"
    );
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
    assert_eq!(store.peek("key").unwrap().unwrap().expose_as_slice(), b"v2");
}

