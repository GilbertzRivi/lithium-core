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
- **Domain-separation labels.** All contexts (`ctx`, OPAQUE/POW/DEK 
  labels) are supplied by the caller; they must be unique per use 
  and consistent between sides. The library is deliberately 
  label-agnostic.
- **No replay protection at the crypto level.** KyberBox does not 
  bind the ciphertext to a counter or state; replay detection is 
  in the messenger's session/storage layer (a window on `step` + 
  `msg_id` dedup), see [`kyberbox.md`](kyberbox.md).
- **No transport security.** TLS / anti-MITM at the network level 
  is the server/proxy layer.
- **Randomness quality.** The constructions rely on the system 
  CSRNG (fresh nonces, ephemeral X25519 keys, and ML-KEM 
  encapsulation randomness).

## Adversary view (at the library level)

- **Ciphertext only (`WirePayload`).** Must break X25519 *and* 
  ML-KEM-1024 (hybrid). Nonce reuse is tolerated by 
  AES-256-GCM-SIV as defense-in-depth.
- **At-rest files without the master key.** Private keys are 
  sealed; without the MK they are unreadable. Security reduces to 
  protecting the MK through `MkProvider`.
- **Adaptive attacker on decapsulation.** ML-KEM-1024 is IND-CCA2 
  (FO transform with implicit rejection); a tampered `ct_kem` 
  yields a different `ss_kem` and is also rebound through 
  `SHA256(ct_kem)` in `base_key`, so it fails the payload AEAD.

## Forward secrecy / post-compromise

The library provides the primitives (fresh `ss_kem` per message, 
rotating RX keys). The actual FS/PCS guarantees of the 
E2E layer (epoch boundaries, passive vs active attacker, identity 
keys don't rotate) are a property of how `session.rs` uses 
KyberBox.

## In-memory secret protection

OS-level page hygiene beats per-value zeroize alone: the guiding 
rule is that a secret must be **born** in a locked region, not 
`mlock`-ed after the fact - otherwise a copy already lived in an 
unlocked, swappable page.

- **`secrets::SecretArena`** (a `pub(crate)` allocator wired in by
  `KeyManager`) is an `mmap` region that is 
  `mlock`-ed (never swapped to disk) and 
  `madvise(MADV_DONTDUMP)`-marked (excluded from core dumps). 
  `random_fixed::<N>()` allocates then fills 
  from the CSRNG *in place*, so the secret never transits an 
  unlocked page. `store_fixed::<N>` / `store_slice_fixed::<N>` copy an 
  externally-generated secret in (its transient must be zeroized by the 
  owner). The public surface is the fixed-size handle 
  `ArenaFixedBytes<N>` and its aliases `ArenaByte32`/`ArenaByte64`, plus 
  `harden_process`. Freed slots are zeroized and reused; the whole region 
  is zeroized, unlocked and unmapped on drop.
- **`KeyManager` wires it in.** Every long-lived key here is a 
  32/64-byte seed (ed25519, x25519, ML-KEM, ML-DSA), and each is 
  generated **born-locked**: the seed bytes are filled from the 
  system CSRNG straight into the arena, then the keypair is derived 
  via `from_seed` - the library's own key-generation RNG is not 
  used. Private keys are load-on-demand: `with_signing_keys` / 
  `with_x25519_and_kyber_sk` decrypt into arena-backed handles for 
  the call and drop them after.
- **`secrets::harden_process()`** is opt-in - the embedder calls 
  it; the library never sets process-global state implicitly. It 
  applies `PR_SET_DUMPABLE 0` (which also blocks same-UID `ptrace` 
  and `/proc/pid/mem`) and `RLIMIT_CORE 0`.
- The crate is `#![deny(unsafe_code)]`; all `unsafe` is confined 
  to the (`pub(crate)`) arena module - the 
  `mmap`/`mlock`/`madvise`/`prctl` FFI - behind a safe API.

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
  the ML-KEM decapsulation key) on the normal heap for the 
  duration of the operation. The seed is born-locked; its expansion 
  is not.

Also out of reach: a root attacker or `ptrace`/`/proc/pid/mem` from 
root reading live memory; register/stack spills of secret bytes; 
cold-boot / DMA / hardware attacks. `RLIMIT_MEMLOCK` can be low 
without privilege; arena creation surfaces the failure (and 
`KeyManager::start` propagates it) so the caller degrades 
deliberately rather than silently.

On-disk material is unaffected by all of this: private keys stay 
sealed under the master key. Where the MK itself lives depends on 
the `MkProvider` - `PlainFileMkProvider` keeps it in cleartext 
(file perms only) and is not intended for production.

## Out of scope (the library's non-goals)

- Key distribution / PKI / identity verification.
- Side-channel resistance beyond what the primitives give. Note: 
  ML-KEM/ML-DSA come from the RustCrypto `ml-kem` / `ml-dsa` crates 
  (pure Rust), the constant-time assumptions are inherited from 
  those implementations.
- Process memory against a local attacker with the same UID: 
  partially mitigated by `secrets::arena` + `harden_process()` 
  (anti-swap, anti-coredump, same-UID `ptrace`/`/proc/mem` 
  blocked); a **root** attacker remains out of scope. See 
  "In-memory secret protection".
