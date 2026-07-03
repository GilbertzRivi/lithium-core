# Threat model: the `lithium_core` library

The scope here is the `lithium_core` crate alone, as a
cryptography and at-rest key-management library, not the
application around it. The boundary matters for the audit: we
audit the tight surface of the library, not the messenger that
uses it.

## Scope

In scope: the two pillars (`keys`/`secrets`, `crypto`) and the
helpers (`opaque`, `pow`, `passwords`, `utils::store`). Out of
scope (the application layers in `lithiumd`/`lithiums`/`lithiumg`):
the network, the relay server, REST transport, handshake/invite,
IPC, the cover-traffic policy, the unlock UX.

## What the library guarantees (when the assumptions below hold)

- **Message confidentiality**: `crypto::kyberbox` (X25519 +
  ML-KEM-1024, AES-256-GCM-SIV). Hybrid: recovering the message
  key requires breaking **both** branches (see
  [`combiner.md`](combiner.md)).
- **Authenticity/integrity**: `crypto::sign` (Ed25519 + ML-DSA-87,
  dual signature), when the caller signs and verifies.
- **At-rest key protection**: private keys sealed under a master
  key supplied by `MkProvider` (a file, or any sealing provider the
  caller plugs in); secret types zeroize on drop; crash-safe
  rotation with rewrap.
- **Context and AAD binding**: KyberBox binds ciphertexts to a
  typed `crypto::Context` and to caller AAD. The public KyberBox
  API takes `&Context`; there is no KyberBox path that silently
  drops it.
- **Post-quantum resistance (harvest-now-decrypt-later)**: the
  ML-KEM-1024 branch protects traffic recorded today against a
  future quantum adversary.

## Assumptions (the caller's responsibility, the library boundary)

KyberBox and the signatures are primitives; security depends on
the caller upholding:

- **Authenticity of the recipient's public keys.** KyberBox does
  not verify that `peer_pub_x` or `peer_k_pub` belong to the
  intended recipient. Substituting the keys encrypts for the wrong
  party. Binding identity is the messenger's invite/handshake
  layer, not the library.
- **Domain-separation labels.** Context roots and all other labels
  (OPAQUE/POW/DEK labels) are supplied by the caller. They must be
  unique per use and consistent between sides. The library checks
  `crypto::Context` syntax and length, but it cannot know whether a
  chosen label is semantically right for the protocol.
- **Valid `Context` values.** Context segments are non-empty
  printable ASCII, cannot contain `/`, and the whole context is at
  most 255 bytes before the version suffix. Invalid contexts fail as
  `InvalidContext`; they are not normalized or repaired.
- **No replay protection at the crypto level.** KyberBox does not
  bind the ciphertext to a counter or state; replay detection is
  in the messenger's session/storage layer (a window on `step` +
  `msg_id` dedup), see [`kyberbox.md`](kyberbox.md).
- **No transport security.** TLS / anti-MITM at the network level
  is the server/proxy layer.
- **Randomness quality.** The constructions rely on the system
  CSRNG (fresh nonces, ephemeral X25519 keys, and ML-KEM
  encapsulation randomness).

## AAD and context binding

`Context::base(root)` starts a context. `Context::add(segment)` adds
one path segment. The label used by crypto code is:

```text
<context-path>/v1
```

KyberBox derives separate labels from that context, for example:

```text
<context-path>/ecdh-key/v1
<context-path>/base-key/v1
<context-path>/data/v1
```

The payload AEAD AAD is framed as:

```text
<context-path>/data/v1 || 0x00 || caller_aad
```

If `caller_aad` is empty, only the context data label is used. The
`0x00` byte matters because valid context labels are printable ASCII
and NUL-free. It separates the library label from caller bytes and
avoids bare concatenation ambiguity.

The lower-level `crypto::aead` helpers still accept arbitrary AAD;
that is their job. The KyberBox public API does not expose a way to
seal or open a KyberBox message without passing `&Context`.

## Adversary view (at the library level)

- **Ciphertext only (`KyberBoxSealed`).** The wire value is the
  KyberBox sealed object: an AEAD blob in `ciphertext` plus a KEM
  ciphertext in `kem_ct`. The AEAD blob is versioned and carries
  its nonce; `kem_ct` is also versioned and tagged with the KEM id.
  A ciphertext-only attacker must break X25519 *and* ML-KEM-1024.
  Nonce reuse is tolerated by AES-256-GCM-SIV as defense-in-depth.
- **At-rest files without the master key.** Private keys are
  sealed; without the MK they are unreadable. Security reduces to
  protecting the MK through `MkProvider`.
- **Adaptive attacker on decapsulation.** ML-KEM-1024 is IND-CCA2
  (FO transform with implicit rejection). A tampered KEM ciphertext
  gives a different `ss_kem` and the raw KEM ciphertext is also
  rebound through `SHA256(ct_kem)` in `base_key`, so the payload
  AEAD check fails.
- **Context or AAD mismatch.** If either side uses a different
  `Context` or caller AAD, payload AEAD authentication fails. This
  is an authentication failure, not a fallback to unbound data.

## Forward secrecy / post-compromise

The library provides the primitives (fresh `ss_kem` per message,
rotating RX keys). The actual FS/PCS guarantees of the
E2E layer.

## In-memory secret protection

OS-level page hygiene beats per-value zeroize alone: the guiding
rule is that a secret must be **born** in a locked region, not
`mlock`-ed after the fact - otherwise a copy already lived in an
unlocked, swappable page.

- **`secrets::SecretArena`** (a `pub(crate)` allocator wired in by
  `KeyManager`) is a private OS mapping. On Unix it uses `mmap`; on
  Windows it uses `VirtualAlloc`. It then tries to lock the pages
  with `mlock` or `VirtualLock`. On Linux/Android it also asks the
  kernel to exclude the mapping from core dumps with
  `MADV_DONTDUMP`.
- `random_fixed::<N>()` allocates then fills from the CSRNG *in
  place*, so the secret never transits an unlocked page created by
  the library. `store_fixed::<N>` / `store_slice_fixed::<N>` copy an
  externally-generated secret in; that transient must be zeroized by
  the owner.
- The public surface is the fixed-size handle `ArenaFixedBytes<N>`
  and its aliases `ArenaByte32`/`ArenaByte64`, plus
  `harden_process`. Freed slots are zeroized and reused; the whole
  region is zeroized, unlocked and unmapped/freed on drop.
- **`KeyManager` wires it in.** Every long-lived private key here is
  a 32/64-byte seed (ed25519, x25519, ML-KEM, ML-DSA), and new
  material is generated born-locked: the seed bytes are filled from
  the system CSRNG straight into the arena, then the keypair is
  derived via `from_seed`. Private keys are load-on-demand:
  `with_signing_keys` / `with_x25519_and_kyber_sk` decrypt into
  arena-backed handles for the call and drop them after.
- **`secrets::harden_process()`** is opt-in - the embedder calls it;
  the library never sets process-global state implicitly. On
  Linux/Android it applies `PR_SET_DUMPABLE 0` and on Unix it sets
  `RLIMIT_CORE 0`. On Windows it sets process error mode flags and
  asks WER for `WER_FAULT_REPORTING_FLAG_NOHEAP`.
- The crate is `#![deny(unsafe_code)]`; all `unsafe` used for arena
  OS calls is confined to the (`pub(crate)`) arena module behind a
  safe API.

### Platform matrix

- **Linux / Android**
  - allocation: `mmap`
  - page lock: `mlock`
  - dump exclusion: `MADV_DONTDUMP` for the arena mapping
  - `harden_process`: `PR_SET_DUMPABLE 0` and `RLIMIT_CORE 0`
  - limits: `RLIMIT_MEMLOCK` can make locking fail
- **macOS / iOS and other Unix targets**
  - allocation: `mmap`
  - page lock: `mlock`
  - dump exclusion: no `MADV_DONTDUMP` path in this code
  - `harden_process`: `RLIMIT_CORE 0`
  - limits: crash reporting, sandbox rules and `mlock` quota are OS
    policy; this document does not claim more than the code does
- **Windows**
  - allocation: `VirtualAlloc`
  - page lock: `VirtualLock`
  - dump exclusion: no arena-specific dump flag in this code
  - `harden_process`: `SetErrorMode(...)` and WER no-heap flag
  - limits: the working-set quota can make `VirtualLock` fail; WER
    no-heap is not the same thing as proving that no dump can exist
- **Other targets**
  - allocation: unsupported by the arena backend
  - page lock: unsupported
  - dump exclusion: unsupported
  - `harden_process`: no platform-specific hardening here
  - limits: both strict and best-effort arena creation return
    `locked_memory_unsupported_platform`; there is no hidden heap
    fallback

### Locking policy

Locking is fail-closed by default. `SecretArena::with_capacity` and
`KeyManager::start` require locked pages. If locking fails, they
return an error rather than silently handing back swappable memory.

An embedder that really accepts this downgrade must opt in in code:
`SecretArena::with_capacity_best_effort` or
`KeyManager::start_best_effort`. On Unix/Windows this can create an
unlocked arena if the mapping succeeds but the lock call fails. The
real state is observable through `is_locked()` and
`memory_locked()`.

This downgrade is never a silent default and never a runtime prompt
to a user. On targets that are neither Unix nor Windows,
best-effort does not mean heap fallback; arena creation still fails.

### The ceiling (what it does *not* protect)

The goal is to *minimize* exposure, not drive it to zero - that is
impossible without an in-house crypto stack, which the project
deliberately avoids. Two heap transits remain unavoidable with the
current library APIs, both bounded and `ZeroizeOnDrop`:

- **Decrypt output**: loading a key on demand runs it through
  AES-256-GCM-SIV, which returns the plaintext as a heap `Vec`; it
  is copied into the arena and the transient zeroized, but a
  short-lived heap copy existed.
- **PQ key expansion**: signing / decapsulating expands the
  32/64-byte seed into the full working key (ML-DSA `s1`/`s2`/`t0`,
  the ML-KEM decapsulation key) on the normal heap for the duration
  of the operation. The seed is born-locked; its expansion is not.

Also out of reach: a root attacker or `ptrace`/`/proc/pid/mem` from
root reading live memory; register/stack spills of secret bytes;
cold-boot / DMA / hardware attacks; OS crash reporters outside the
specific hardening calls listed above. A same-UID local attacker is
partly mitigated on Linux/Android by `PR_SET_DUMPABLE 0`, but root
is still out of scope.

On-disk material is unaffected by all of this: private keys stay
sealed under the master key. Where the MK itself lives depends on
the `MkProvider`. The only built-in one,
`InsecurePlaintextMkProvider`, keeps the MK in cleartext (file perms
only); it is gated behind the non-default `insecure-plaintext-mk`
feature so a production build cannot reach it by accident.
Production callers supply a sealing provider.

## Out of scope (the library's non-goals)

- Key distribution / PKI / identity verification.
- Side-channel resistance beyond what the primitives give. Note:
  ML-KEM/ML-DSA come from the RustCrypto `ml-kem` / `ml-dsa` crates
  (pure Rust), the constant-time assumptions are inherited from
  those implementations.
- Process memory against a local attacker with the same UID:
  partially mitigated by `secrets::arena` + `harden_process()` on
  the platforms listed above. A root attacker remains out of scope.
  See "In-memory secret protection".
