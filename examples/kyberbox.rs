// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

//! Hybrid X25519 + ML-KEM-1024 dual encryption with a bundled reply key (Pillar 2).
//!
//! Run with: `cargo run -p lithium_core --example kyberbox`

use lithium_core::crypto::Context;
use lithium_core::crypto::kyberbox::DualEncryptionPrivateKey;
use lithium_core::secrets::SecretBytes;

fn main() -> lithium_core::Result<()> {
    let ctx = Context::base("myapp")?.add("message")?;

    let (bob_priv, bob_pub) = DualEncryptionPrivateKey::ephemeral()?;

    let request = SecretBytes::from_slice(b"attack at dawn");
    let (sealed, alice_reply_priv) = bob_pub.seal(&ctx, b"", &request)?;

    let (got_request, alice_reply_pub) = bob_priv.open(&ctx, b"", &sealed)?;
    assert_eq!(got_request.expose_as_slice(), request.expose_as_slice());

    let reply = SecretBytes::from_slice(b"hold the line");
    let (sealed_reply, _) = alice_reply_pub.seal(&ctx, b"", &reply)?;

    let (got_reply, _) = alice_reply_priv.open(&ctx, b"", &sealed_reply)?;
    assert_eq!(got_reply.expose_as_slice(), reply.expose_as_slice());

    println!(
        "kyberbox dual request/reply round-trip ok ({} sealed wire bytes)",
        sealed.to_wire().len()
    );
    Ok(())
}
