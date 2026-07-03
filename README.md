# lithium_core

Post-quantum **hybrid** cryptography and at-rest key management as a standalone Rust library.

> **Security status:** pre-audit. This crate has not gone through an independent
> cryptographic audit and should not be used to protect sensitive production data yet.

Every construction combines a classical and a post-quantum primitive, so it stays secure as long
as *either* one holds:

* **Encryption** - X25519 + ML-KEM-1024, sealed with AES-256-GCM-SIV (`crypto::kyberbox`)
* **Signatures** - Ed25519 + ML-DSA-87, both provided by `crypto::sign`
* **KDF / passwords** - HKDF-SHA256, Argon2

The crate is `#![forbid(unsafe_code)]`, secret types zeroize on drop, and all domain-separation
labels are supplied by the caller - the crypto itself is application-agnostic.

## Two pillars

### 1. At-rest key management (`keys`, `secrets`)

`KeyManager` owns an on-disk key store: it generates the hybrid identity, seals private keys under
a master key from a pluggable `MkProvider`, and can perform crash-safe rotation and rewrap when
the caller invokes rotation. The built-in provider is a plain file provider, while password-backed,
hardware-backed, TPM-backed, or application-specific sealing can be supplied by the caller.

Secret types (`SecByte32`, `SecretBytes`, `MasterKey32`, ...) zeroize on drop.

### 2. Hybrid encryption (`crypto`)

`crypto::kyberbox` is the X25519 + ML-KEM-1024 AEAD construction: the KEM produces a fresh
shared secret per message that is combined with the X25519 output through HKDF, so recovering the
message key requires breaking *both* branches. See [`docs/combiner.md`](docs/combiner.md) for the exact
construction and its rationale, and [`docs/kyberbox.md`](docs/kyberbox.md) for the wire format.

## Helpers

Secondary, deployment-agnostic building blocks layered on the pillars: `opaque` (OPAQUE PAKE +
export-key DEK wrapping), `pow` (proof-of-work), `passwords` (policy + DEK generation),
`utils::store` (TTL secret store).

## Examples

```bash
cargo run --example kyberbox   # hybrid encrypt/decrypt round-trip
cargo run --example keyfile    # KeyManager identity persistence
```

```rust
use lithium_core::crypto::{keys, kyberbox};
use lithium_core::secrets::SecretBytes;

let ctx = "myapp/message/v1";

let (recipient_priv_x, recipient_pub_x) = keys::random_x25519_keypair()?;
let (recipient_kyber_priv, recipient_kyber_pub) = keys::random_kyber_mlkem1024_keypair()?;
let (sender_priv_x, sender_pub_x) = keys::random_x25519_keypair()?;

let body = SecretBytes::from_slice(b"Hello world!");

let wire = kyberbox::encrypt(
    ctx,
    &sender_priv_x,
    &recipient_pub_x,
    &recipient_kyber_pub,
    &body,
)?;

let plain = kyberbox::decrypt(
    ctx,
    &recipient_priv_x,
    &sender_pub_x,
    &recipient_kyber_priv,
    &wire,
)?;

assert_eq!(plain.expose_as_slice(), body.expose_as_slice());
```

## Security status

**Not yet independently audited.** The constructions, the hybrid-combiner rationale and the open
questions for an auditor are documented under [`docs/`](docs/index.md): `combiner.md`, `kyberbox.md`,
`threat-model.md`. The public API is intended to be frozen at `0.1` through the audit.

The library deliberately does not provide the whole messenger security model. In particular, the
caller is responsible for authentic recipient public keys, unique domain-separation labels, replay
protection, transport security, and deciding when to call key rotation.

To report a vulnerability, see [`SECURITY.md`](SECURITY.md).

## Contributing

Contributions are accepted under AGPL-3.0-only with a grant for commercial relicensing, and
require a DCO sign-off - see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

GNU AGPL-3.0-only, with a commercial license available (dual licensing) - see [`LICENSE`](LICENSE).
