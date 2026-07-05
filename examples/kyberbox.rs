// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

//! Hybrid X25519 + ML-KEM-1024 anonymous encryption round-trip (Pillar 2).
//!
//! Run with: `cargo run -p lithium_core --example kyberbox`

use lithium_core::crypto::{Context, keys, kyberbox};
use lithium_core::secrets::SecretBytes;

fn main() -> lithium_core::Result<()> {
    let ctx = Context::base("myapp")?.add("message")?;

    let (recipient_priv_x, recipient_pub_x) = keys::ephemeral_x25519_keypair()?;
    let (recipient_kyber_priv, recipient_kyber_pub) = keys::ephemeral_kyber_mlkem1024_keypair()?;

    let body = SecretBytes::from_slice(b"attack at dawn");

    let (wire, _sender_priv_x) =
        kyberbox::seal(&ctx, &recipient_pub_x, &recipient_kyber_pub, b"", &body)?;

    let plain_data = kyberbox::open(&ctx, &recipient_priv_x, &recipient_kyber_priv, b"", &wire)?;

    assert_eq!(plain_data.expose_as_slice(), body.expose_as_slice());

    println!(
        "kyberbox round-trip ok ({} sealed body bytes)",
        wire.ciphertext().as_slice().len()
    );
    Ok(())
}
