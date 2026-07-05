# lithium_core

Post-quantum **hybrid** cryptography and at-rest key management as a standalone Rust library.

> **Security status:** pre-audit. This crate has not gone through an independent
> cryptographic audit and should not be used to protect sensitive production data yet.

Every construction combines a classical and a post-quantum primitive, so it stays secure as long
as *either* one holds:

* **Encryption** - X25519 + ML-KEM-1024, sealed with AES-256-GCM-SIV (`crypto::kyberbox`)
* **Signatures** - Ed25519 + ML-DSA-87, both provided by `crypto::sign`
* **KDF / passwords** - HKDF-SHA256, Argon2

The crate is `#![deny(unsafe_code)]` (the only `unsafe` is confined to `secrets::arena`, which
wraps OS-locked memory behind a safe API - `mmap`/`mlock` on unix, `VirtualAlloc`/`VirtualLock`
on Windows), secret types zeroize on drop, and all domain-separation labels are supplied by the
caller as a validated `crypto::Context` - the crypto itself is application-agnostic.

## Two pillars

### 1. At-rest key management (`keys`, `secrets`)

`KeyManager` owns an on-disk key store: it generates the hybrid identity, seals private keys under
a master key from a pluggable `MkProvider`, and performs crash-safe MK rotation and rewrap
automatically on a background thread. The only built-in provider stores the MK in cleartext and is gated
behind the non-default `insecure-plaintext-mk` feature (dev/tests only); production callers supply
password-backed, hardware-backed, TPM-backed, or application-specific sealing (see
`examples/password_mkprovider.rs` and [`docs/mkprovider-examples.md`](docs/mkprovider-examples.md)).

Secret types (`SecByte32`, `SecretBytes`, `MasterKey32`, ...) zeroize on drop.

### 2. Hybrid encryption (`crypto`)

`crypto::kyberbox` is the X25519 + ML-KEM-1024 AEAD construction: the KEM produces a fresh
shared secret per message that is combined with the X25519 output through HKDF, so recovering the
message key requires breaking *both* branches. See [`docs/combiner.md`](docs/combiner.md) for the exact
construction and its rationale, and [`docs/kyberbox.md`](docs/kyberbox.md) for the wire format.

## Helpers

Secondary, deployment-agnostic building blocks layered on the pillars: `opaque` (OPAQUE PAKE +
export-key DEK wrapping), `passwords` (DEK generation), `utils::store` (TTL secret store).

## Examples

```bash
cargo run --example kyberbox            # hybrid encrypt/decrypt round-trip
cargo run --example password_mkprovider # KeyManager identity, master key sealed under a passphrase

# dev-only: same lifecycle on the built-in cleartext master-key provider
cargo run --features insecure-plaintext-mk --example keyfile
```

```rust
use lithium_core::crypto::{Context, keys, kyberbox};
use lithium_core::secrets::SecretBytes;

// Domain separation, built from validated segments; the library adds the /v1.
let ctx = Context::base("myapp")?.add("message")?;

let (recipient_priv_x, recipient_pub_x) = keys::ephemeral_x25519_keypair()?;
let (recipient_kyber_priv, recipient_kyber_pub) = keys::ephemeral_kyber_mlkem1024_keypair()?;

let body = SecretBytes::from_slice(b"Hello world!");

// `seal` draws a fresh ephemeral sender key per call; its public half is
// carried inside `wire`. It also returns the matching secret: drop it for
// one-shot anonymous sealing, or keep it to open a reply.
// `aad` is an optional caller header bound into the ciphertext (b"" = none).
let (wire, _sender_priv_x) = kyberbox::seal(
    &ctx,
    &recipient_pub_x,
    &recipient_kyber_pub,
    b"",
    &body,
)?;

let plain = kyberbox::open(
    &ctx,
    &recipient_priv_x,
    &recipient_kyber_priv,
    b"",
    &wire,
)?;

assert_eq!(plain.expose_as_slice(), body.expose_as_slice());
```

## Security status

**Not yet independently audited.** The constructions, the hybrid-combiner rationale and the open
questions for an auditor are documented under [`docs/`](docs/index.md): `combiner.md`, `kyberbox.md`,
`threat-model.md`. The public API is intended to be frozen at `0.1` through the audit.

The library deliberately does not provide a whole application security model. In particular, the
caller is responsible for authentic recipient public keys, unique domain-separation labels, replay
protection, transport security, and deciding when to call key rotation.

To report a vulnerability, see [`SECURITY.md`](SECURITY.md).

## Contributing

Contributions are accepted under AGPL-3.0-only with a grant for commercial relicensing, and
require a DCO sign-off - see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

GNU AGPL-3.0-only, with a commercial license available (dual licensing) - see [`LICENSE`](LICENSE).
