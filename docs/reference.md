# lithium_core

The shared library of cryptography, secret types, and key 
management for the Lithium project.

Lithium is a messenger designed for environments where the server, 
the operator, and the infrastructure may be completely untrusted. 
The goal isn't convenience, it's to mathematically limit what even 
the operator can reveal. `lithium_core` implements all the 
cryptographic foundations of that model.

## Place in the architecture

```
lithiumg (GUI)
  | IPC
lithiumd (daemon)      uses lithium_core
  | HTTPS
lithiums (server)      uses lithium_core
```

`lithium_core` is a shared dependency of `lithiumd` and 
`lithiums`. It holds everything that isn't specific to one layer: 
the cryptography, the secret types, and key management.

## Modules

### `crypto`: cryptographic operations

#### `crypto::aead`: symmetric encryption

AES-256-GCM-SIV with an authenticated ciphertext (AEAD).

```
encrypt_raw(plaintext: &SecretBytes, key, nonce, aad) -> PublicBytes   // raw AES-256-GCM-SIV
decrypt_raw(ciphertext: &PublicBytes, key, nonce, aad) -> SecretBytes

encrypt(plaintext: &SecretBytes, key, nonce, aad) -> PublicBytes       // versioned blob with nonce
decrypt(blob: &PublicBytes, key, aad) -> SecretBytes                   // parses the blob automatically
```

Plaintext is a `SecretBytes`; the resulting ciphertext/blob is public
wire data, so it is returned as `PublicBytes` (and consumed as
`&PublicBytes` on the way back in). `aad` is a plain `&[u8]`.

`encrypt` blob format:
```
[version: u8 = 1][nonce: 12 bytes][ciphertext + tag: N bytes]
```

AAD is always required, a wrong or empty AAD causes a decryption 
failure.

#### `crypto::kdf`: key derivation

HKDF-SHA256. One call derives 32 bytes of key.

```
derive32(input, salt, info) -> SecByte32              // 32 bytes
derive_bytes(input, salt, info, len) -> SecretBytes   // arbitrary length
hkdf_extract(salt, ikm) -> SecByte32                  // HKDF-Extract (PRK)
hkdf_expand(prk, info, len) -> SecretBytes            // HKDF-Expand
```

`salt` is optional. `info` is always required and is used for 
domain separation. `derive_bytes` backs `derive32` and the HPKE key
schedule; `hkdf_extract` / `hkdf_expand` expose the two HKDF stages
separately for callers that need them.

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
// Ed25519 (classical)
sign_message(message, priv_ed_seed) -> Vec<u8>           // 64 bytes
verify_signature(message, signature: &[u8], pub_key: &PubByte32) -> bool

// ML-DSA-87 / Dilithium (post-quantum)
sign_message_dili(message, dili_sk_bytes) -> Vec<u8>
verify_signature_dili(message, signature: &[u8], dili_pk_bytes: &PublicBytes) -> bool
```

A signature is a public authenticator, not a secret, so it is
returned as a plain `Vec<u8>`; verification takes the public key as a
public type (`PubByte32` for Ed25519, `PublicBytes` for ML-DSA-87).

#### `crypto::keys`: generating cryptographic material

Key-pair and random-material generators. All use the system CSRNG 
(`SysRng`).

```
random_fixed::<N>() -> SecretFixedBytes<N>
random_12() -> Nonce12
random_32() -> SessionId32
random_master_key32() -> MasterKey32

random_x25519_keypair() -> (SecretFixedBytes<32>, PubByte32)      // (seed_sk, pk)
random_ed25519_keypair() -> (SecretFixedBytes<32>, PubByte32)     // (seed, pk)
random_kyber_mlkem1024_keypair() -> (SecretBytes, PublicBytes)    // (sk, pk)
random_dilithium_mldsa87_keypair() -> (SecretBytes, PublicBytes)  // (sk, pk)
```

Each generator returns the secret half in a secret type
(`SecretFixedBytes`/`SecretBytes`) and the public half in a public
type (`PubByte32`/`PublicBytes`).

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
5. enc_data = AES-256-GCM-SIV(data, base_key, aad="{ctx}/data/v1")
```

A single payload is sealed: `base_key` is used directly as the AEAD
key, with `"{ctx}/data/v1"` as the AAD.

`WirePayload` output format:

```rust
pub struct WirePayload {
    pub enc_data: PublicBytes,
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
encrypt(ctx, priv_x, peer_pub_x: &PubByte32, peer_k_pub: &PublicBytes, data) -> WirePayload
decrypt(ctx, priv_x, peer_pub_x: &PubByte32, kyber_priv, wire) -> SecretBytes   // data
```

The sender's X25519 secret (`priv_x`) and the recipient's ML-KEM
secret (`kyber_priv`) are secret types; the peer public keys are
public types. `ctx` is a context string that separates domains (for
example `"shake"`, `"session"`).

The full construction, properties, and open questions: 
[`kyberbox.md`](kyberbox.md).

---

### `hpke`: hybrid HPKE-style seal / open and export

An HPKE-style single-shot layer built on the same hybrid KEM as
`kyberbox` (X25519 + ML-KEM-1024). It adds a deterministic keypair
derivation, a base-mode `seal`/`open`, and a secret-export mode. Only
the base (unauthenticated-sender) mode is provided.

```
derive_keypair(ctx, ikm) -> (HpkePrivateKey, HpkePublicKey)   // deterministic from ikm

seal_base(ctx, recipient_x_pub: &PubByte32, recipient_k_pub: &PublicBytes,
          info, aad, plaintext: &SecretBytes) -> HpkeSealed
open_base(ctx, recipient_x_priv: &SecByte32, recipient_k_priv: &SecretBytes,
          info, aad, sealed: &HpkeSealed) -> SecretBytes

setup_sender_and_export(ctx, recipient_pk: &HpkePublicKey,
                        info, exporter_context, exporter_length) -> (HpkeEnc, SecretBytes)
setup_receiver_and_export(ctx, recipient_sk: &HpkePrivateKey, enc: &HpkeEnc,
                          info, exporter_context, exporter_length) -> SecretBytes
```

`derive_keypair` derives both halves deterministically from `ikm`, so
the same seed always yields the same keypair. `info` binds the key
schedule; `aad` binds the AEAD. The export mode derives an
independent shared secret of `exporter_length` bytes and never fails
authentication (a mismatch simply yields a different secret).

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
{base_dir}/{kind}/
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
  mk                        (Master Key, PlainFileMkProvider)
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
tries to finish or roll it back before loading keys. The default 
rotation interval is **3600 seconds** (1 hour).

**The `MkProvider` trait:**

```rust
pub trait MkProvider {
    fn load_mk(&self) -> Result<SecByte32>;
    fn store_mk(&self, mk: &SecByte32) -> Result<()>;
    fn derive_secret32(&self, mk: &SecByte32, label: &[u8], secrets_dir: &Path) -> Result<SecByte32>;
}
```

The default `PlainFileMkProvider` stores the MK as a binary file. 
The trait is pluggable, `lithiumd` can plug in its own provider 
based on the user's password and a server component.

**API:**

```rust
// Initialization
KeyManager::start(base_dir, kind, mk_provider) -> Result<KeyManager<P>>
KeyManager::start_plain(base_dir, kind) -> Result<KeyManager<PlainFileMkProvider>>

// Access to private keys (callback pattern, loaded only for the call)
manager.with_signing_keys(|ed_seed, dili_sk| { ... }) -> Result<R>
manager.with_x25519_and_kyber_sk(|x_seed, kyber_sk| { ... }) -> Result<R>

// Public keys
manager.public_keys() -> &PublicKeys

// Derived secrets (label-based)
manager.derive_secret32(label: &[u8]) -> Result<SecByte32>

// JWT secret (rotated together with the MK)
manager.jwt_secret() -> &SecByte32

// Rotation
manager.maybe_rotate_mk() -> Result<()>
```

Key material is loaded only for the duration of the callback and 
is not stored by `KeyManager` after use. The callback receives 
owned secret values (`SecByte32`, `SecretBytes`); confinement is not 
enforced by the type system, so the caller must not persist or 
leak them past that scope.

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
`fsync` and `0o600` permissions (Unix).

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
SecretFixedBytes::new(bytes: [u8; N]) -> Self
SecretFixedBytes::from_slice(slice: &[u8]) -> Result<Self>
SecretFixedBytes::from_hex(s: &str) -> Result<Self>    // requires lowercase, rejects a 0x prefix
SecretFixedBytes::new_zeroed() -> Self
SecretFixedBytes::to_hex() -> SecretString
SecretFixedBytes::as_array() -> &[u8; N]
SecretFixedBytes::as_slice() -> &[u8]
```

#### `SecretBytes`

A variable-length secret buffer. Held in `SecretBox<Vec<u8>>`.

```rust
SecretBytes::new(v: Vec<u8>) -> Self
SecretBytes::from_slice(v: &[u8]) -> Self
SecretBytes::from_wiped<T: AsMut<[u8]>>(src: T) -> Self   // copies, then zeroizes the source
SecretBytes::from_hex(s: &str) -> Result<Self>
SecretBytes::expose_as_slice() -> &[u8]
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

#### Type aliases (`secrets::types`)

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

#### Hashing (Argon2id)

Standard parameters: 64 MB memory, 3 iterations, 1 thread, 32-byte 
output.

```rust
hash_password_phc(password: &SecretString) -> Result<String>       // PHC string
verify_password_phc(phc: &str, password: &SecretString) -> Result<bool>
```

#### Password validation

```rust
pub struct PasswordPolicy {
    pub min_len: usize,          // default: 8
    pub max_len: usize,          // default: 1024
    pub require_lowercase: bool, // default: true
    pub require_uppercase: bool, // default: true
    pub require_digit: bool,     // default: true
    pub require_special: bool,   // default: true
    pub allow_whitespace: bool,  // default: false
}

validate_password(password: &SecretString, pol: PasswordPolicy) -> Result<()>
validate_passwords_distinct(a: &SecretString, b: &SecretString) -> Result<()>
```

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

The wrapping key = `HKDF(export_key, info=aad)`; `aead_blob` is the
standard versioned `aead::encrypt` output. `aad` is supplied by the
caller for domain separation. The `export_key` comes from the OPAQUE
flow below.

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
ServerSetup::serialize() -> Vec<u8>
ServerSetup::deserialize(bytes: &[u8]) -> Result<Self>
```

**Registration** (`opaque::client` / `opaque::server`):

```
client_registration_start(password) -> (request, ClientRegistrationState)
server_registration_start(setup, request_bytes, credential_identifier) -> response
client_registration_finish(state, response_bytes, password, handler, server_id)
    -> (upload, SecByte64)          // SecByte64 = export key
server_registration_finish(upload_bytes) -> record   // persist per user
```

**Login** (`opaque::client` / `opaque::server`):

```
client_login_start(password) -> (request, ClientLoginState)
server_login_start(setup, record_bytes, request_bytes, credential_identifier,
                   handler, server_id) -> (response, login_state)
client_login_finish(state, response_bytes, password, handler, server_id)
    -> (finalization, SecByte64)    // same export key as registration
server_login_finish(login_state, finalization_bytes, handler, server_id) -> ()
    // Ok(()) means the password matched; Err is InvalidCredentials
```

`ClientRegistrationState` / `ClientLoginState` (re-exported at
`opaque::`) are `opaque-ke` state types carried between the two
client steps. The 64-byte export key is identical across a
registration and every later successful login, so it is a stable
key for `opaque::dek` wrapping.

---

### `pow`: proof of work

A SHA-256 hashcash-style proof of work, used to rate-limit sending.

```
challenge(ctx, mailbox, content) -> [u8; 32]     // SHA-256(ctx || len(mailbox) || mailbox || content)
verify(challenge, nonce, bits) -> bool           // SHA-256(challenge || nonce_le) has >= bits leading zero bits
try_solve(challenge, bits, max_iters) -> Option<u64>   // brute-force a nonce from 0, up to max_iters

DEFAULT_SEND_POW_BITS: u32 = 18
```

`bits == 0` accepts any nonce (`verify` returns true, `try_solve`
returns `Some(0)`). `try_solve` returns `None` once `max_iters` is
exhausted.

---

### `utils`: helpers

#### `utils::store`: `EphemeralStoreManager`

An in-memory store with TTL and zeroization on expiry. Used among 
other things to hold temporary session tokens.

```rust
store.set(key, value, ttl) -> Result<()>
store.set_if_absent(key, value, ttl) -> Result<bool>
store.peek(key) -> Result<Option<SecretBytes>>   // read without removing
store.take(key) -> Result<Option<SecretBytes>>   // read and remove
store.del(key) -> Result<()>
```

An internal task (`tokio::spawn`) sweeps expired entries every 500 
ms. When an expired entry is removed, the `SecretBytes` content is 
zeroized before `drop`. The task is aborted when the last 
`EphemeralStoreManager` handle is dropped.

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
(`debug_assertions`). This library is not the oracle boundary — a caller
crossing a trust boundary (e.g. a network response an attacker can probe)
must flatten distinguishable errors into coarse categories itself.

Selected `ErrorKind` variants:
- `AeadFailed`: AEAD authenticity/decryption failure
- `KdfFailed`: key derivation failure
- `KemInvalidCiphertext`: malformed KEM ciphertext
- `InvalidPublicKey { reason }`: unusable public key (e.g. low-order point)
- `KeyImportFailed { reason }`: raw bytes could not be parsed into a key
- `RandomFailed`: OS CSPRNG failure
- `InvalidLength { expected, got }`: wrong buffer length
- `InvalidHex` / `HexMustBeLowercase` / `HexDisallowedPrefix`: hex 
  parsing errors
- `StringPolicy`: a password/string policy violation
- `InvalidCredentials { msg }`: authentication failure
- `InvalidPermissions { msg }`: a permissions violation
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

The whole crate is `#![forbid(unsafe_code)]`.

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
- **I/O safety**: atomic `tmp + rename` writes with `fsync`, 
  `0o600` permissions.
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
