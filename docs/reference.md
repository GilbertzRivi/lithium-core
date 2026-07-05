# lithium_core

The shared library of cryptography, secret types, and key 
management for the Lithium project.

`lithium_core` targets environments where the server, the 
operator, and the infrastructure may be completely untrusted. The 
goal isn't convenience, it's to mathematically limit what even the 
operator can reveal; the crate implements the cryptographic 
foundations of that model.

## Place in the architecture

`lithium_core` is a standalone dependency: a consuming application 
links it and builds its transport, session, and UI layers on top. 
The crate holds everything that isn't specific to one layer, the 
cryptography, the secret types, and key management, and knows 
nothing about the application above it.

## Modules

### `crypto`: cryptographic operations

#### `crypto::Context`: domain-separation labels

A validated, caller-supplied domain-separation tag. It is threaded into
every primitive - `aead`, `kdf`, `sign`, `kyberbox`, `hpke` - so each
derived key, signature and AEAD label is bound to one usage. The library
owns the version suffix; callers never write it.

```
Context::base(root: &str) -> Result<Context>            // first segment
Context::add(&self, segment: &str) -> Result<Context>   // append a segment (non-mutating)
```

Construction is the only public surface: there is no `from_str`, and no
way to turn a `Context` back into a raw string. A context is built one
validated segment at a time, and the crate-internal label always ends
in the version tag (`/v1`), added by the library.

Segment rules (each `base` / `add` argument): non-empty, printable
ASCII (`0x21..=0x7e`) only, and no `/` (the segment separator). The
whole context is capped at 255 bytes. A violation returns
`LithiumError::invalid_context`.

`add` does not mutate; it returns a fresh `Context`, so one base can fan
out into several without repeating the prefix:
```
let base = Context::base("myapp")?.add("mail")?;
let enc  = base.add("encrypt")?;   // myapp/mail/encrypt
let mac  = base.add("mac")?;       // myapp/mail/mac
```

Why segments instead of one string: a hand-written `"app/" + input`
lets a `/` in `input` forge another context. `add` validates every
segment and forbids `/`, so caller-supplied parts cannot inject
separators. The safe path is the only path.

#### `crypto::aead`: symmetric encryption

AES-256-GCM-SIV with an authenticated ciphertext (AEAD).

```
encrypt(plaintext: &SecretBytes, key, nonce, ctx: &Context, aad) -> PublicBytes   // versioned blob with nonce
decrypt(blob: &PublicBytes, key, ctx: &Context, aad) -> SecretBytes               // parses the blob automatically
```

Plaintext is a `SecretBytes`; the resulting ciphertext/blob is public
wire data, so it is returned as `PublicBytes` (and consumed as
`&PublicBytes` on the way back in). The effective AEAD associated data
is `ctx` bound with the caller's `aad`, so a ciphertext only
authenticates under the same `Context`; `aad` is a plain `&[u8]`.

`encrypt` blob format:
```
[version: u8 = 1][nonce: 12 bytes][ciphertext + tag: N bytes]
```

The `ctx` and `aad` at `decrypt` must match the ones used at
`encrypt`; a mismatch fails authentication. An empty `aad` is
valid, as long as both sides use the same value.

#### `crypto::kdf`: key derivation

HKDF-SHA256. One call derives 32 bytes of key.

```
derive32(input, salt, ctx: &Context, aad: &[u8]) -> SecByte32              // 32 bytes
derive_bytes(input, salt, ctx: &Context, aad: &[u8], len) -> SecretBytes   // arbitrary length
hkdf_extract(salt, ikm) -> SecByte32                                       // HKDF-Extract (PRK)
hkdf_expand(prk, info, len) -> SecretBytes                                 // HKDF-Expand
```

`input` (IKM) and the optional `salt` are secret (`&SecretBytes`). The
HKDF `info` is `ctx` bound with the caller's `aad`: both are the
domain-separation label, public by definition, not a secret. `ctx` is
always required. `hkdf_extract` / `hkdf_expand` expose the two HKDF
stages separately for callers that need them.

#### `crypto::hash`: hashing

SHA-256, used for transcript binding inside `kyberbox`/`hpke` and for
pinning golden vectors.

```
sha256(data: &[u8]) -> SecByte32
```

#### `crypto::sign`: digital signatures

Dual signature: every message is signed classically and 
post-quantum at the same time.

```
// Hybrid: sign/verify both schemes as one unit (preferred)
sign_double(message, ed_seed, dili_sk, ctx: &Context) -> DoubleSig
verify_double(message, &DoubleSig, ed_pub: &PubByte32, dili_pub: &PublicBytes, ctx: &Context) -> bool
DoubleSig::{to_bytes, from_bytes, to_hex, from_hex}   // ed(64) || dili wire form

// Single-scheme primitives
sign_message(message, priv_ed_seed, ctx: &Context) -> Vec<u8>           // Ed25519, 64 bytes
verify_signature(message, signature: &[u8], pub_key: &PubByte32, ctx: &Context) -> bool
sign_message_dili(message, dili_sk_bytes, ctx: &Context) -> Vec<u8>     // ML-DSA-87 / Dilithium
verify_signature_dili(message, signature: &[u8], dili_pk_bytes: &PublicBytes, ctx: &Context) -> bool
```

Every signature is computed over `ctx` bound with the message, so a
signature only verifies under the same `Context`; sign and verify must
use the same one. A signature is a public authenticator, not a secret,
so it is returned as a plain `Vec<u8>`; verification takes the public
key as a public type (`PubByte32` for Ed25519, `PublicBytes` for
ML-DSA-87).

`verify_double` is AND: it returns true only when both branches verify,
so a forgery requires breaking both schemes and the result stays secure
while either one holds. Prefer it over calling the two primitives
separately, which lets a caller check only one branch and silently
downgrade to a single scheme. `DoubleSig` owns the wire form
(`ed(64) || dili`) so callers never hand-split the two signatures;
`from_hex` enforces the crate's lowercase, no-prefix hex.

#### `crypto::keys`: generating cryptographic material

Key-pair and random-material generators. All use the system CSRNG 
(`SysRng`).

```
random_fixed::<N>() -> SecretFixedBytes<N>
random_12() -> Nonce12
random_32() -> SecByte32
random_64() -> SecByte64

ephemeral_x25519_keypair() -> (SecByte32, PubByte32)              // (seed_sk, pk)
ephemeral_ed25519_keypair() -> (SecByte32, PubByte32)             // (seed, pk)
ephemeral_kyber_mlkem1024_keypair() -> (SecByte64, PublicBytes)   // (sk, pk)
ephemeral_dilithium_mldsa87_keypair() -> (SecByte32, PublicBytes) // (sk, pk)

// derive the public half from a stored seed
ed25519_pub_from_seed(seed: &impl SeedBytes<32>) -> PubByte32
x25519_pub_from_seed(seed: &impl SeedBytes<32>) -> PubByte32
mldsa87_pub_from_seed(seed: &impl SeedBytes<32>) -> PublicBytes
mlkem1024_pub_from_seed(seed: &impl SeedBytes<64>) -> PublicBytes
```

Each `ephemeral_*` generator returns the secret half in a fixed-size,
heap-backed secret type (`SecByte32`/`SecByte64`, zeroize-on-drop) and
the public half in a public type (`PubByte32`/`PublicBytes`). Long-term
keys are created and held by the `KeyManager` in a locked-memory arena.

`SeedBytes<N>` is a sealed trait implemented only for the fixed-size
secret types (`SecByte32`/`SecByte64` and `ArenaByte32`/`ArenaByte64`).
The `*_pub_from_seed` derivations take `&impl SeedBytes<N>`, so a seed
must arrive as a secret type: a raw `&[u8; N]` is rejected at compile
time and can never be passed as unprotected bytes. It exposes one
method, `seed() -> &[u8; N]`, borrowing the bytes without copying.

#### `crypto::kyberbox`: hybrid asymmetric encryption

`kyberbox` is a hybrid scheme that joins X25519 (ECDH) with 
ML-KEM-1024 (Kyber). Security depends on both algorithms at once, 
breaking one does not compromise the encryption. The combiner is 
an instance of the UniversalCombiner 
(`draft-irtf-cfrg-hybrid-kems`); see [`combiner.md`](combiner.md).

The scheme for one message:

```
1. ECDH: shared = X25519(priv_x, peer_pub_x)
2. ecdh_key = HKDF(shared, info="{ctx}/ecdh-key/v1")
3. (ss_kem, ct_kem) = ML-KEM-1024.Encapsulate(peer_kyber_pub)
4. base_key = HKDF(ecdh_key, salt=ss_kem,
                   info="{ctx}/base-key/v1" || ct_T || ek_T || SHA256(ct_kem))
5. enc_data = AES-256-GCM-SIV(data, base_key, aad="{ctx}/data/v1" [|| 0x00 || caller_aad])
```

The `{ctx}/.../v1` labels come from the caller's
[`Context`](#cryptocontext-domain-separation-labels): the parts
`ecdh-key`, `base-key`, `data` are appended as segments and the `/v1`
suffix is added by the library.

A single payload is sealed: `base_key` is used directly as the AEAD
key, with `"{ctx}/data/v1"` as the AAD. See `caller_aad` below.

`KyberBoxSealed` output format:

```rust
pub struct KyberBoxSealed {
    pub ciphertext: PublicBytes,
    pub kem_ct: PublicBytes,   // ML-KEM ciphertext
}
```

Internal format of `kem_ct`:
```
[ver: u8][kem_id: u8][kyber_ciphertext: N bytes]
```

`ct_T` is the sender's ephemeral X25519 public key, `ek_T` the 
recipient's X25519 public key. Both are bound into the `base_key` 
info, along with `SHA256(ct_kem)`.

Interface:

```
seal(ctx: &Context, priv_x, peer_pub_x: &PubByte32, peer_k_pub: &PublicBytes,
     aad: &[u8], data) -> KyberBoxSealed
open(ctx: &Context, priv_x, peer_pub_x: &PubByte32, kyber_priv,
     aad: &[u8], sealed: &KyberBoxSealed) -> SecretBytes
```

The sender's X25519 secret (`priv_x`) and the recipient's ML-KEM
secret (`kyber_priv`) are secret types; the peer public keys are
public types. `ctx` is a [`Context`](#cryptocontext-domain-separation-labels)
that separates domains.

`aad` is an optional caller-supplied AAD, for binding the ciphertext to
an external header or transcript. When non-empty it is appended to the
`data` label as `label || 0x00 || aad`; when empty the AAD is just the
label (no wire change). The label is NUL-free, so the `0x00` separator
is unambiguous and a crafted `aad` cannot impersonate another context.
`aad` is bound: `open` must pass the exact same bytes or decryption
fails. Domain separation itself lives in the derived key, so `aad` is
an additional binding, not a substitute for `ctx`.

The full construction, properties, and open questions: 
[`kyberbox.md`](kyberbox.md).

---

### `hpke`: hybrid HPKE-style seal / open and export

An HPKE-style layer built on the same hybrid KEM as
`kyberbox` (X25519 + ML-KEM-1024). It adds a deterministic keypair
derivation, a base-mode `seal`/`open`, a multi-message context, and a
secret-export mode. Only the base (unauthenticated-sender) mode is
provided.

```
derive_keypair(ctx: &Context, ikm) -> (HpkePrivateKey, HpkePublicKey)   // deterministic from ikm

seal_base(ctx: &Context, recipient_x_pub: &PubByte32, recipient_k_pub: &PublicBytes,
          info, aad, plaintext: &SecretBytes) -> HpkeSealed
open_base(ctx: &Context, recipient_x_priv: &SecByte32, recipient_k_priv: &SecretBytes,
          info, aad, sealed: &HpkeSealed) -> SecretBytes

// Multi-message: one KEM setup, then many messages under a sequence nonce.
setup_sender(ctx: &Context, recipient_pk: &HpkePublicKey, info) -> (HpkeEnc, HpkeSenderContext)
setup_receiver(ctx: &Context, recipient_sk: &HpkePrivateKey, enc: &HpkeEnc, info) -> HpkeReceiverContext
HpkeSenderContext::seal(&mut self, aad, plaintext: &SecretBytes) -> PublicBytes
HpkeReceiverContext::open(&mut self, aad, ciphertext: &PublicBytes) -> SecretBytes

setup_sender_and_export(ctx: &Context, recipient_pk: &HpkePublicKey,
                        info, exporter_context, exporter_length) -> (HpkeEnc, SecretBytes)
setup_receiver_and_export(ctx: &Context, recipient_sk: &HpkePrivateKey, enc: &HpkeEnc,
                          info, exporter_context, exporter_length) -> SecretBytes
```

`ctx` is a [`Context`](#cryptocontext-domain-separation-labels), not a
string; it is the domain-separation tag threaded through the keypair
derivation, the KEM, and the key schedule. Do not confuse it with the
per-session `HpkeSenderContext` / `HpkeReceiverContext` below (an RFC
9180 term for the established encryption state).

`derive_keypair` derives both halves deterministically from `ikm`, so
the same seed always yields the same keypair. `info` binds the key
schedule; `aad` binds the AEAD. The export mode derives an
independent shared secret of `exporter_length` bytes and never fails
authentication (a mismatch simply yields a different secret).

The multi-message context (RFC 9180 section 5.2) runs the hybrid KEM once and
then seals each message under nonce `base_nonce XOR seq`, incrementing
`seq` per call on both sides. Sender and receiver must stay in lockstep:
message N opens only when the receiver is at sequence N. A dropped or
reordered message desynchronizes the stream, so the caller supplies
ordering and any truncation protection (a chunked "streaming AEAD" over
large data is built on top: export a secret with `setup_sender_and_export`
and drive `crypto::aead` directly).

Wire types (public material is public-typed; ciphertext is
`PublicBytes`):

```rust
pub struct HpkePublicKey  { /* x25519 pub + ML-KEM pub */ }   // to_wire/from_wire: 32 + 1568 bytes
pub struct HpkePrivateKey { /* x25519 priv + ML-KEM seed */ } // to_wire -> SecretBytes: 32 + 64 bytes
pub struct HpkeEnc        { /* ephemeral x25519 pub + kem_ct */ }
pub struct HpkeSealed     { pub enc: HpkeEnc, pub ciphertext: PublicBytes }
```

`HpkeEnc`, `HpkePublicKey` and `HpkeSealed` expose `to_wire()` /
`from_wire()` for transport; `HpkePrivateKey::to_wire()` returns a
`SecretBytes`.

---

### `keys`: key management

#### `keys::manager`: `KeyManager<P>`

The central component that manages all cryptographic material of 
one identity (a server or a user). A key security element, it 
stores private keys encrypted under the Master Key, handles MK 
rotation, and recovers an interrupted rotation.

**On-disk directory layout:**

```
{base_dir}/KeyManager/
  pub/
    ed25519.pub
    x25519.pub
    kyber-mlkem1024.pub
    dilithium-mldsa87.pub
  priv/
    ed25519.keyf            (encrypted keyfile)
    x25519.keyf
    kyber-mlkem1024.keyf
    dilithium-mldsa87.keyf
  secrets/
    {hex_label}.keyf        (arbitrary derived secrets)
  .rotate/                  (temporary MK rotation dir)
    next-mk-old.keyf
    next-mk-new.keyf
    staged/                 (files before commit)
    ready                   (readiness marker)
  mk                        (Master Key, InsecurePlaintextMkProvider)
```

**Master Key rotation:**

MK rotation is atomic and crash-safe. The protocol:

1. Write the old and new MK to `.rotate/` (both encrypted).
2. Prepare every `.keyf` file with the old wrapping and the new 
   wrapping in `.rotate/staged/`.
3. Write the `.rotate/ready` marker.
4. Apply the staged files to their target locations.
5. Update the MK at the provider.
6. Remove the `.rotate/` directory.

On startup `KeyManager` checks for an unfinished rotation and 
tries to finish or roll it back before loading keys.

Rotation is **automatic**: `start` spawns a background thread that
rotates the MK once the interval elapses; the caller drives nothing.
The default interval is **3600 seconds** (1 hour), adjustable with
`set_rotate_interval`. Rotation runs under an internal write lock, so
it is serialized against every operation that reads key material -
concurrent `with_signing_keys`/`get_or_create_secret32` calls never observe a
half-rewrapped store. A rotation failure is routed through the
`RotationErrorPolicy` given at `start` (see below), never silently
dropped.

**The `MkProvider` trait:**

```rust
pub trait MkProvider {
    fn load_mk(&self) -> Result<SecByte32>;
    fn store_mk(&self, mk: &SecByte32) -> Result<()>;
    fn get_or_create_secret32(&self, mk: &SecByte32, label: &[u8], secrets_dir: &Path) -> Result<SecByte32>;
}
```

Production callers implement this trait to seal the MK (password, TPM,
KMS, ...); see `examples/password_mkprovider.rs` and
[`docs/mkprovider-examples.md`](mkprovider-examples.md). The only built-in
provider is `InsecurePlaintextMkProvider`, which stores the MK in cleartext
and is gated behind the non-default `insecure-plaintext-mk` feature so it
cannot ship to production by accident; `start_plain` and the type only exist
with that feature.

**API:**

```rust
// Initialization (fail-closed locking; start_best_effort is the opt-in unlocked fallback)
KeyManager::start(base_dir, mk_provider, public_cache_policy, rotation_error_policy) -> Result<KeyManager<P>>
KeyManager::start_best_effort(base_dir, mk_provider, public_cache_policy, rotation_error_policy) -> Result<KeyManager<P>>

// Full control over the tunable knobs (rotation cadence, locked-arena capacity)
KeyManagerConfig::new(locking, public_cache_policy)
    .rotate_every(interval: Duration)   // default KeyManagerConfig::DEFAULT_ROTATE_EVERY (1h)
    .arena_capacity(bytes: usize)       // default KeyManagerConfig::DEFAULT_ARENA_CAPACITY (8 KiB)
KeyManager::start_with_config(base_dir, mk_provider, config, rotation_error_policy) -> Result<KeyManager<P>>

#[cfg(feature = "insecure-plaintext-mk")]  // dev/tests only
KeyManager::start_plain(base_dir, public_cache_policy, rotation_error_policy) -> Result<KeyManager<InsecurePlaintextMkProvider>>

// Access to private keys (callback pattern, loaded only for the call)
manager.with_signing_keys(|ed_seed: ArenaByte32, dili_sk: ArenaByte32| { ... }) -> Result<R>
manager.with_x25519_and_kyber_sk(|x_seed: ArenaByte32, kyber_sk: ArenaByte64| { ... }) -> Result<R>

// Public keys / memory-locking state
manager.public_keys() -> PublicKeys     // owned snapshot (cloned from behind the lock)
manager.reload_public_keys() -> Result<()>  // re-derive from the private keys and re-check the cache
manager.memory_locked() -> bool   // is the secret arena wired into RAM?

// Label-based secrets: get-or-create a 32-byte secret keyed by label, sealed per label under the MK
manager.get_or_create_secret32(label: &[u8]) -> Result<SecByte32>
manager.encrypt_with_label(label: &[u8], plaintext: &SecretBytes, aad: &[u8]) -> Result<PublicBytes>
manager.decrypt_with_label(label: &[u8], blob: &PublicBytes, aad: &[u8]) -> Result<SecretBytes>
manager.load_or_create_sealed_blob(label: &[u8], generate: impl FnOnce() -> Result<SecretBytes>) -> Result<SecretBytes>

// Rotation (runs automatically on a background thread; this only adjusts the cadence)
manager.set_rotate_interval(interval: Duration)
```

`get_or_create_secret32` returns the per-label secret, generating and
sealing it under the MK on first use and loading it thereafter.
`encrypt_with_label` / `decrypt_with_label` use that secret as the AEAD
key, so a round-trip needs the same label and `aad`.
`load_or_create_sealed_blob` is the variable-length variant: it seals the
output of `generate` under the label on first use.

The label of a label-based secret is 1 to 64 bytes; outside that range
the call fails with `MalformedInput { reason: "secret_label_len" }`. The
label becomes the on-disk `{hex_label}.keyf` filename, so the bound keeps
it within filesystem name limits. Hash a longer identifier down yourself
before passing it.

`KeyManager<P>` is `Clone` (a cheap `Arc` handle) and every method takes
`&self`; the background rotation thread is stopped and joined when the
last handle is dropped. `P: MkProvider` must be `Send + Sync + 'static`.

**`PublicCachePolicy`** (`keys::PublicCachePolicy`) governs how the cached
`pub/*.pub` files are reconciled against the keys derived from the private
seeds, so a swapped public key cannot pass unnoticed:

- `Strict` - a missing **or** mismatched public key is an error.
- `RepairMissingOnly` - a *missing* public key is re-derived from the
  private seed and rewritten; a *mismatched* one is still an error (a wrong
  value is tampering, not a gap).

A mismatch/missing surfaces as `invalid_public_key`, whose error carries the
offending key (e.g. `invalid public key [ed25519-seed-v1]: public_key_mismatch`).

**`RotationErrorPolicy`** (`keys::RotationErrorPolicy`) decides what a
background rotation failure does; both variants take a required callback:

- `Strict(cb)` - **fail-closed**: the manager is disabled (every later
  operation returns an error) *and* `cb` is invoked with the error.
- `Callback(cb)` - `cb` is invoked and the manager keeps running (it will
  retry on the next interval).

`start` takes an exclusive advisory lock on `<store>/.lock`, held for the
manager's lifetime, so exactly one instance drives a store directory; a
second `start` on the same directory returns `keystore_locked`. This is a
single-writer contract on a local filesystem (`flock` is unreliable over
NFS); scaling out means one store directory per instance, not sharing one.

`KeyManager` owns a small `SecretArena` (see `secrets::arena`). `start`
is fail-closed: if that arena cannot be locked into RAM it returns an
error. `start_best_effort` is the deliberate opt-in that instead
proceeds on swappable memory; `memory_locked()` then reports the actual
state (log or attest it, do not surface it as a user prompt). The two
constructors are the `MemoryLocking::{Require, BestEffort}` policy,
re-exported as `keys::MemoryLocking`.
Private keys are load-on-demand: the callback receives them as 
arena-backed handles (`ArenaByte32`, `ArenaByte64`) decrypted 
into locked memory for the call and dropped after. Confinement past 
the callback is not enforced by the type system, so the caller must 
not persist or leak them. The seeds themselves (ed25519/x25519/
ML-KEM/ML-DSA - all 32/64-byte seeds) are generated born-locked from 
the system CSRNG at first run.

**`PublicKeys`:**

```rust
pub struct PublicKeys {
    pub ed25519: PubByte32,
    pub x25519: PubByte32,
    pub kyber: PublicBytes,
    pub dilithium: PublicBytes,
}
```

#### `keys::keyfile`: the key file format

A binary `.keyf` format implementing envelope encryption:

```
[KEYF magic: 4 bytes][version: u8][alg_id: u8][dek_len: u16]
[salt_len: u16][salt: 32 bytes]
[nonce_wrap_len: u16][nonce_wrap: 12 bytes]
[ct_wrap_len: u16][ct_wrap: N bytes]        // AES-256-GCM-SIV(DEK, KEK)
[nonce_payload_len: u16][nonce_payload: 12 bytes]
[ct_payload_len: u32][ct_payload: M bytes]  // AES-256-GCM-SIV(secret, DEK)
```

Encryption scheme:
- **KEK** = HKDF(MasterKey, salt, info=`"kek/v1"`)
- **DEK** = a random 32-byte key per file
- The payload is encrypted with the DEK, the DEK is encrypted with 
  the KEK
- The AAD carries the version and key type (`"keyfile:v1|{key_type}"`), 
  a wrong type causes a decryption failure

Writing through `write_secure` uses a `tmp + rename` pattern with 
`fsync`. On Unix the file is created `0o600` (owner-only); on 
Windows no DACL is set and the file inherits the parent directory's 
ACL, so keep the store under a per-user profile directory or protect 
the MK with a sealing `MkProvider`.

Rewrapping (changing the MK without decrypting the payload):

```
rewrap_keyfile_dek(path, old_mk, new_mk, key_type) -> Result<()>
rewrap_keyfile_dek_to_bytes(path, old_mk, new_mk, key_type) -> Result<SecretBytes>
```

---

### `secrets`: secret types

All secret types provide:
- No `Display`/`Debug` that reveals the content (they print 
  `<redacted>` or `SecretFixedBytes<N>(..)`).
- Memory zeroization on `Drop` (through `secrecy::SecretBox` + 
  `zeroize`).
- No automatic conversion to `String` and no serialization to 
  logs.

#### `SecretFixedBytes<N>` and aliases

A fixed-length secret buffer. Held in `SecretBox<[u8; N]>`.

```rust
pub type SecByte12 = SecretFixedBytes<12>;   // nonce
pub type SecByte32 = SecretFixedBytes<32>;   // key, seed, hash
pub type SecByte64 = SecretFixedBytes<64>;   // Ed25519 signature
```

Selected methods:
```rust
SecretFixedBytes::new(bytes: [u8; N]) -> Self          // moves the array in, then zeroizes it
SecretFixedBytes::from_slice(slice: &[u8]) -> Result<Self>
SecretFixedBytes::from_wiped<T: AsMut<[u8]>>(src: T) -> Result<Self>  // copies, then zeroizes the source
SecretFixedBytes::from_wiped_array(src: &mut [u8; N]) -> Self         // copies, then zeroizes the source in place
SecretFixedBytes::from_hex(s: &str) -> Result<Self>    // requires lowercase, rejects a 0x prefix
SecretFixedBytes::new_zeroed() -> Self
SecretFixedBytes::to_hex() -> SecretString
SecretFixedBytes::expose_as_array() -> &[u8; N]
SecretFixedBytes::expose_as_slice() -> &[u8]
SecretFixedBytes::expose_into_array() -> Zeroizing<[u8; N]>   // owned, auto-wiped copy
```

#### `SecretBytes`

A variable-length secret buffer. Held in `SecretBox<Vec<u8>>`.

```rust
SecretBytes::new(v: Vec<u8>) -> Self
SecretBytes::from_slice(v: &[u8]) -> Self
SecretBytes::from_wiped<T: AsMut<[u8]>>(src: T) -> Self   // copies, then zeroizes the source
SecretBytes::from_hex(s: &str) -> Result<Self>
SecretBytes::expose_as_slice() -> &[u8]
SecretBytes::expose_into_array::<N>() -> Result<Zeroizing<[u8; N]>>   // length-checked, auto-wiped
SecretBytes::to_hex() -> SecretString
```

#### `SecretString`

A secret UTF-8 string. Implements `Display` as `<redacted>`.

```rust
SecretString::new(s: String) -> Self
SecretString::new_checked(s: String) -> Result<Self>   // rejects null bytes
SecretString::expose() -> &str                          // the only access method
SecretString::from_utf8_bytes(bytes: &[u8]) -> Result<Self>
SecretString::decode_hex() -> Result<Zeroizing<Vec<u8>>>
SecretString::decode_hex_fixed::<N>() -> Result<SecretFixedBytes<N>>
```

#### `SecretJson`

A secret JSON document that zeroizes on `Drop`. Recursively 
zeroizes all strings and object keys.

```rust
SecretJson::from_str(s: &str) -> Result<Self>
SecretJson::from_bytes(bytes: &[u8]) -> Result<Self>
SecretJson::get_string(key) -> Result<SecretString>
SecretJson::get_integer(key) -> Result<SecretBox<i64>>
SecretJson::get_bool(key) -> Result<bool>
SecretJson::take_string(key) -> Result<SecretString>   // removes the field from the map
SecretJson::with_exposed(|value| { ... }) -> R         // access to serde_json::Value
```

#### `secrets::arena`: OS-locked memory for long-lived keys

Per-value zeroize does not stop a secret from being swapped to disk 
or captured in a core dump before it is cleared. `SecretArena` holds 
long-lived key material in a private memory region that is locked into 
RAM (never swapped) and, where the OS supports it, excluded from core 
dumps. A secret is *born* in the locked region, not locked after the 
fact.

The region is cross-platform, behind one internal OS layer:

- Unix (Linux, Android, iOS, macOS): `mmap` + `mlock`, plus
  `madvise(MADV_DONTDUMP)` on Linux and Android (Darwin has no
  equivalent; `RLIMIT_CORE 0` from `harden_process` covers dumps there).
- Windows: `VirtualAlloc` + `VirtualLock`.

Locking is fail-closed by default: if the pages cannot be locked
(typically a low `RLIMIT_MEMLOCK` or working-set quota),
`with_capacity` returns an error rather than handing back swappable
memory. An embedder that genuinely cannot lock memory opts into
`with_capacity_best_effort`, a deliberate, in-code choice; the silent
downgrade is never made for it, and `is_locked()` reports the actual
state (for logs / attestation, never a runtime prompt to a user).

The `SecretArena` allocator itself is `pub(crate)`; it is wired in by
`KeyManager`, not driven directly by embedders. The public surface is
the fixed-size handle type and its aliases, re-exported at `secrets`
(`ArenaFixedBytes`, `ArenaByte32` = `ArenaFixedBytes<32>`, `ArenaByte64`
= `ArenaFixedBytes<64>`, `harden_process`).

```rust
// SecretArena is pub(crate); shown here for context.
SecretArena::with_capacity(bytes) -> Result<Self>              // fail-closed: Err if unlockable
SecretArena::with_capacity_best_effort(bytes) -> Result<Self>  // opt-in: fall back to unlocked memory
arena.is_locked() -> bool                                      // whether the pages are wired into RAM

arena.random_fixed::<N>() -> Result<ArenaFixedBytes<N>>          // filled from the CSRNG in place
arena.store_fixed::<N>(&[u8; N]) -> Result<ArenaFixedBytes<N>>   // copy a fixed-size secret in
arena.store_slice_fixed::<N>(&[u8]) -> Result<ArenaFixedBytes<N>>  // copy a slice, length-checked to N
arena.store_fixed_wiped::<N, T: AsMut<[u8]>>(src) -> Result<ArenaFixedBytes<N>>  // copy in, then zeroize the source

// ArenaFixedBytes<N> (and aliases ArenaByte32/ArenaByte64): Deref/DerefMut
//   to [u8], zeroized-and-reused on drop, redacted Debug; expose_as_slice()/
//   expose_as_mut_slice()/expose_as_array() -> &[u8; N]/len(); ct_eq PartialEq.

harden_process() -> Result<()>   // opt-in, process-global; per OS:
//   Linux/Android: PR_SET_DUMPABLE 0 + RLIMIT_CORE 0
//   other unix (iOS/macOS): RLIMIT_CORE 0
//   Windows: SetErrorMode + WerSetFlags(NOHEAP) (no full PR_SET_DUMPABLE analog)
```

Scope is genuinely long-lived keys only (master key, seeds, 
ML-KEM/ML-DSA secret keys); ephemeral values 
(nonces, HPKE shared secrets) are not worth the arena. `KeyManager` 
wires it in: it born-locks every seed it generates and hands 
`with_signing_keys` / 
`with_x25519_and_kyber_sk` arena-backed handles. `harden_process()` 
is opt-in and never called implicitly, since it sets process-global 
state. The protection ceiling (a root attacker, register/stack 
spills, cold-boot, a low `RLIMIT_MEMLOCK`, and the unavoidable heap 
transit when AES-GCM-SIV decrypts a key or a PQ seed is expanded for 
an operation) is detailed in [`threat-model.md`](threat-model.md).

#### Type aliases (re-exported at `secrets`)

```rust
pub type MasterKey32 = SecByte32;
pub type Nonce12 = SecByte12;
pub type SessionId32 = SecByte32;
```

---

### `public`: public key material

Non-secret byte types, parallel to `secrets` but without zeroization,
with plain `Debug`/`==` and hex helpers. Public keys, signatures'
verification inputs, ciphertext and wire blobs use these so public
data never masquerades as a secret.

#### `PublicFixedBytes<N>` and alias

A fixed-length public buffer (`Copy`). Held inline as `[u8; N]`.

```rust
pub type PubByte32 = PublicFixedBytes<32>;   // x25519 / ed25519 public key

PublicFixedBytes::new(bytes: [u8; N]) -> Self
PublicFixedBytes::from_slice(slice: &[u8]) -> Result<Self>
PublicFixedBytes::from_hex(s: &str) -> Result<Self>
PublicFixedBytes::to_hex() -> String
PublicFixedBytes::as_array() -> &[u8; N]
PublicFixedBytes::as_slice() -> &[u8]
```

#### `PublicBytes`

A variable-length public buffer. Held as `Vec<u8>`.

```rust
PublicBytes::new(v: Vec<u8>) -> Self
PublicBytes::from_slice(v: &[u8]) -> Self
PublicBytes::from_hex(s: &str) -> Result<Self>
PublicBytes::as_slice() -> &[u8]
PublicBytes::into_vec() -> Vec<u8>
PublicBytes::to_hex() -> String
```

---

### `passwords`: password handling

#### Argon2id parameters

The Argon2id cost profile (64 MB memory, 3 iterations, 1 lane, 
32-byte output) is defined in `crypto::kdf` and reused by the OPAQUE 
key-stretching function (`opaque::suite`). There is no standalone 
password-hash API: password authentication goes through the OPAQUE 
flow below, which never exposes or stores the password.

#### DEK (Data Encryption Key)

`generate_dek()` (in `passwords`) mints a random 32-byte DEK.
Wrapping and unwrapping it under an OPAQUE export key live in
`opaque::dek`:

```rust
generate_dek() -> Result<SecByte32>
wrap_dek_under_export_key(dek: &SecByte32, export_key: &SecByte64, aad: &[u8]) -> Result<SecretString>   // hex blob
unwrap_dek_under_export_key(blob_hex: &SecretString, export_key: &SecByte64, aad: &[u8]) -> Result<SecByte32>
```

DEK blob format (hex-encoded):
```
[ver: u8 = 1][aead_blob: N bytes]
```

The wrapping key = `HKDF(export_key, info=ctx+aad)` and `aead_blob` is
the standard versioned `aead::encrypt` output, both under a fixed
internal `Context` (`lithium/opaque/dek-wrap`); `aad` is supplied by
the caller for extra domain separation. The `export_key` comes from the
OPAQUE flow below.

---

### `opaque`: password-authenticated key exchange

An OPAQUE aPAKE (thin wrapper over `opaque-ke`) that lets a server
authenticate a user by password without ever seeing the password,
and yields a per-user 64-byte **export key** the client can use to
wrap secrets (e.g. the DEK above).

The cipher suite (`opaque::suite::LithiumCipherSuite`) pins:
OPRF over Ristretto255, key exchange `TripleDh<Ristretto255, SHA-512>`,
and Argon2 as the key-stretching function.

All `*_bytes` arguments and non-key return values are opaque
serialized protocol messages passed between client and server;
`handler` / `server_id` are the OPAQUE identifiers, and
`credential_identifier` keys the server-side record.

**Server setup** (`opaque::server`):

```rust
ServerSetup::generate() -> Self
ServerSetup::serialize() -> SecretBytes            // long-term server key; zeroizes on drop
ServerSetup::deserialize(bytes: &SecretBytes) -> Result<Self>
```

The server setup and the login state (`server_login_start`'s second
return, fed into `server_login_finish`) are secrets in
`secrets::SecretBytes`; persist the setup through a sealing store.
The public wire messages are `&[u8]`.

**Registration** (`opaque::client` / `opaque::server`):

```
client_registration_start(password) -> (request, ClientRegistrationState)
server_registration_start(setup, request_bytes, credential_identifier) -> response
client_registration_finish(state, response_bytes, password, handler, server_id, ksf_params)
    -> (upload, SecByte64)          // SecByte64 = export key
server_registration_finish(upload_bytes) -> record   // persist per user
```

`ksf_params: crypto::kdf::Argon2Params` is the Argon2id cost profile
(`Argon2Params::default()` is the OWASP baseline). The same params must
be used at registration and at every later login, or the export key
changes and login fails; persist your choice.

**Login** (`opaque::client` / `opaque::server`):

```
client_login_start(password) -> (request, ClientLoginState)
server_login_start(setup, record_bytes, request_bytes, credential_identifier,
                   handler, server_id, context) -> (response, login_state)
client_login_finish(state, response_bytes, password, handler, server_id, context, ksf_params)
    -> (finalization, SecByte64)    // same export key as registration
server_login_finish(login_state, finalization_bytes, handler, server_id, context) -> ()
    // Ok(()) means the password matched; Err is InvalidCredentials
```

`context: Option<&[u8]>` is optional application context bound into the
login transcript; it must match on the client and both server calls.

`ClientRegistrationState` / `ClientLoginState` (re-exported at
`opaque::`) are `opaque-ke` state types carried between the two
client steps. The 64-byte export key is identical across a
registration and every later successful login, so it is a stable
key for `opaque::dek` wrapping.

---

### `utils`: helpers

#### `utils::store`: `EphemeralStoreManager`

An in-memory store with TTL and zeroization on expiry. Used among 
other things to hold temporary session tokens. Values are held
AEAD-encrypted under a per-instance key kept in the locked-memory
arena, and the lookup keys are stored SHA-256-hashed, so a memory dump
never exposes stored plaintext or the caller's key strings.

```rust
store.set(key, value, ttl) -> Result<()>
store.set_if_absent(key, value, ttl) -> Result<bool>
store.peek(key) -> Result<Option<SecretBytes>>   // read without removing
store.take(key) -> Result<Option<SecretBytes>>   // read and remove
store.del(key) -> Result<()>
```

A background `std::thread` proactively sweeps expired entries, 
waking exactly at the next entry's expiry deadline (re-planned on 
each insert), so an expired `SecretBytes` is zeroized as soon as it 
lapses. The thread stops when the last `EphemeralStoreManager` 
handle is dropped. The crate carries no async runtime dependency.

---

### `error`: error handling

```rust
pub type Result<T> = core::result::Result<T, LithiumError>;

pub struct LithiumError {
    pub kind: ErrorKind,
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}
```

The `Display` message is always honest about the error kind; only the
`source` chain is gated behind `LithiumError::is_verbose()`
(`debug_assertions`). This library is not the oracle boundary - a caller
crossing a trust boundary (e.g. a network response an attacker can probe)
must flatten distinguishable errors into coarse categories itself.

Selected `ErrorKind` variants:
- `AeadFailed`: AEAD authenticity/decryption failure
- `KdfFailed`: key derivation failure
- `KemInvalidCiphertext`: malformed KEM ciphertext
- `InvalidPublicKey { key, reason }`: unusable public key; `key` names the
  offending key (e.g. low-order point, or a tampered/missing public-cache entry)
- `KeyImportFailed { reason }`: raw bytes could not be parsed into a key
- `MalformedInput { reason }`: a caller-supplied serialized blob could not be
  parsed (e.g. a corrupt or untrusted OPAQUE record/state/setup); distinct from
  `Internal`, which is a library invariant break, never input-driven
- `InvalidContext { reason }`: a `crypto::Context` segment failed
  validation (empty, contains `/`, non-graphic ASCII, or over 255 bytes)
- `RandomFailed`: OS CSPRNG failure
- `InvalidLength { expected, got }`: wrong buffer length
- `InvalidHex` / `HexMustBeLowercase` / `HexDisallowedPrefix`: hex 
  parsing errors
- `StringPolicy`: a password/string policy violation
- `InvalidCredentials { msg }`: authentication failure
- `InvalidPermissions { msg }`: a permissions violation
- `TtlTooLarge`: a `utils::store` TTL that overflows the monotonic clock
- `Io`: an I/O error
- `Internal { reason }`: a broken invariant; `reason` is a fixed
  code-authored label, never attacker-derived data

`From` is implemented for: `std::io::Error`, `hex::FromHexError`, 
`serde_json::Error`, `hkdf::InvalidLength`, 
`aes_gcm_siv::aead::Error`, `rand::rngs::SysError`.

---

## Cryptographic dependencies

| Crate           | Version     | Role                                       |
|-----------------|-------------|--------------------------------------------|
| `aes-gcm-siv`   | 0.11.1      | AEAD: AES-256-GCM-SIV                      |
| `hkdf`          | 0.12        | KDF: HKDF-SHA256                           |
| `sha2`          | 0.10.9      | SHA-256 (HKDF, transcript binding)         |
| `ml-kem`        | 0.3.2       | ML-KEM-1024 (Kyber) KEM                    |
| `ml-dsa`        | 0.1.1       | ML-DSA-87 (Dilithium) signatures          |
| `ed25519-dalek` | 2.2.0       | Ed25519 (signatures)                       |
| `x25519-dalek`  | 2.0.1       | X25519 (ECDH)                              |
| `argon2`        | 0.5.3       | Argon2id (password hash, DEK wrap)         |
| `opaque-ke`     | 4.0.1       | OPAQUE PAKE (export-key DEK wrapping)      |
| `zeroize`       | 1.8.2       | Memory zeroization                         |
| `secrecy`       | 0.10.3      | Secret types (`SecretBox`)                 |
| `rand`          | 0.10.0      | CSRNG (`SysRng`)                           |

The crate is `#![deny(unsafe_code)]`; the only `unsafe` is confined 
to `secrets::arena` (the locked-memory and process-hardening FFI),
behind a safe API. The OS bindings are platform-scoped: `libc` on unix
(`mmap`/`mlock`/`madvise`/`prctl`/`setrlimit`), `windows-sys` on Windows
(`VirtualAlloc`/`VirtualLock`/`SetErrorMode`/`WerSetFlags`).

---

## Platforms and Cargo features

The only platform-specific code is `secrets::arena` (locked memory +
process hardening); the rest is portable pure Rust. `cargo check` is
verified on `x86_64-unknown-linux-gnu`, `x86_64-pc-windows-msvc`,
`aarch64-apple-ios`, and `aarch64-linux-android`. Platform dependencies
are pulled only where they apply: `libc` under `cfg(unix)`,
`windows-sys` under `cfg(windows)`.

Cargo features (both off by default):

- `insecure-plaintext-mk`: enables `InsecurePlaintextMkProvider` and
  `KeyManager::start_plain`, which store the master key in cleartext.
  For dev/tests only; never enable in production.
- `fuzzing`: test-only hooks for the fuzz targets under `fuzz/`.

---

## Security model

The library's guarantee boundary (what `lithium_core` provides and 
what is the caller's responsibility) is in 
[`threat-model.md`](threat-model.md); the hybrid encryption 
argument is in [`kyberbox.md`](kyberbox.md). The concrete 
mechanisms behind those guarantees:

- **Private-key confidentiality**: access only through a callback 
  (`with_signing_keys`, `with_x25519_and_kyber_sk`); `KeyManager` 
  loads the key for the call and does not retain it afterwards. 
  Confinement past the callback is the caller's responsibility.
- **Domain separation**: every KDF/AEAD operation runs under a 
  unique `info`/`aad` label.
- **Zeroization**: `SecretFixedBytes`/`SecretBytes`/`SecretString`/`SecretJson` 
  clear memory on `Drop`.
- **Rotation crash-safety**: an unfinished MK rotation is finished 
  or rolled back on startup.
- **I/O safety**: atomic `tmp + rename` writes with `fsync`; 
  `0o600` on Unix (Windows inherits the parent directory's ACL).
- **Opaque errors in release**: `LithiumError` reveals only the 
  category, not internal details.

## Non-goals

By the project model, `lithium_core` deliberately does not 
provide:

- Recovery after losing the Master Key, no key means lost data.
- Key synchronization between devices.
- Offline operation without access to the MK.
- Message delivery guarantees, this is not the transport layer.

The absence of these is on purpose. Recovery is worse than losing 
data if the alternative is weaker security.
