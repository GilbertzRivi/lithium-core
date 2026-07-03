# KyberBox: security analysis

This document covers the KyberBox construction in 
`lithium_core/src/crypto/kyberbox.rs` and its use in 
`lithiumd/src/e2e/session.rs`: the goal, the key flow, the 
properties, the responsibility boundary, and the risks for an 
audit.

## Goal

KyberBox encrypts one plaintext (`data`) in one operation. Output: 
two opaque blobs, `enc_data` and `kem_ct`.

Hybrid by design:

- Break only X25519: still can't decrypt.
- Break only ML-KEM-1024: still can't decrypt.
- You need both.

Scope: confidentiality only. KyberBox does not authenticate the 
sender, does not bind the ciphertext to an identity, does not stop 
replay. Those sit in the layers above.

## Primitives

All versions are pinned in `Cargo.lock`.

| Primitive | Implementation | Version |
|---|---|---|
| X25519 ECDH | `x25519-dalek` / `curve25519-dalek` | 2.0.1 / 4.1.3 |
| ML-KEM-1024 | `ml-kem` (RustCrypto, pure Rust, FIPS 203) | 0.3.2 |
| AES-256-GCM-SIV | `aes-gcm-siv` | 0.11.1 |
| HKDF-SHA256 | `hkdf` + `sha2` | 0.12.4 / 0.10.9 |
| CSRNG | `rand::rngs::SysRng` | - |

ML-KEM-1024 is the RustCrypto `ml-kem` crate: a pure-Rust FIPS 203
implementation, no C or FFI. The recipient key is a 1568-byte
encapsulation key; the stored secret is a 64-byte seed from which the
decapsulation key is rebuilt on use.

## Key flow

The caller provides:

- `priv_x`: sender's ephemeral X25519 private key (fresh per 
  message in `session.rs`)
- `peer_pub_x`: recipient's X25519 public key (their reply/ratchet 
  key)
- `peer_k_pub`: recipient's ML-KEM-1024 public key
- `data`: the plaintext
- `ctx`: a context string for domain separation 
  (`"lithiumd/e2e-msg/v1"` in practice)

```
msg_x_priv (32B) <-- CSRNG  -->  msg_x_pub (ct_T, sent as from_x_pub in WireV1)

Step 1: ECDH
  ecdh_ss  = X25519(msg_x_priv, peer_pub_x)
  ecdh_key = HKDF-SHA256(IKM=ecdh_ss, salt=none, info="{ctx}/ecdh-key/v1")

Step 2: ML-KEM encapsulation
  (ss_kem, ct_kem) = ML-KEM-1024.Encapsulate(peer_k_pub)
  kem_ct           = [ver=1, kem_id=1] || ct_kem

Step 3: Base key (combination of both paths)
  base_key = HKDF-SHA256(IKM=ecdh_key, salt=ss_kem,
                         info="{ctx}/base-key/v1" || ct_T || ek_T
                              || SHA256(ct_kem))

Step 4: Encrypt the payload
  enc_data = [0x01] || nonce || AES-256-GCM-SIV(data, base_key, nonce,
                                                 "{ctx}/data/v1")

Result: WirePayload { enc_data, kem_ct }
```

Notes:

- `ct_T` is `msg_x_pub` (sender's ephemeral X25519 public key).
- `ek_T` is `peer_pub_x` (recipient's X25519 public key).
- `nonce` is 12 random bytes from the CSRNG, drawn per call.
- `base_key` is used directly as the AEAD key; the AAD is
  `"{ctx}/data/v1"`.

Decryption runs the same steps in reverse: parse `kem_ct`, 
decapsulate `ss_kem` from `ct_kem`, rebuild the key chain from 
`ecdh_key` and `ss_kem` with the same bound transcript, decrypt 
`data`.

## Properties from the construction

These follow from the design, not from a formal proof. KyberBox 
has had no formal analysis or external audit. The properties hold 
as long as the primitives meet their standard assumptions.

**Hybrid security.** `base_key` comes from both branches: `ss_kem` 
as the HKDF salt, `ecdh_key` as the IKM. To get `base_key` without 
both, an attacker breaks X25519 (for `ecdh_key`) or ML-KEM-1024 
(for `ss_kem`). `HKDF-Extract(salt, IKM)` with one secret per slot 
is the known dualPRF / split-key-PRF combiner (Bindel et al. 2019; 
Giacon et al. 2018). Mapping: [`combiner.md`](combiner.md).

**Fresh key per message.** Every message draws a fresh `ss_kem` 
from ML-KEM encapsulation, even when the recipient's public keys 
are reused (which lasts until they reply). `ss_kem` is the salt in 
`base_key`, so every message gets a unique `base_key`.

**Nonce-reuse resistance.** The payload uses AES-256-GCM-SIV, not 
plain GCM. Under SIV, a nonce collision only reveals that two 
messages under one key are identical; it does not leak the key or 
the plaintext. With 96-bit random nonces a collision needs about 
2^48 blobs under one AEAD key (out of reach), and would also need 
`base_key` reuse (which does not happen). Defense in depth.

**Transcript binding.** The `base_key` HKDF `info` binds the full 
transcript: `ct_T` (sender's ephemeral X25519 public key), `ek_T` 
(recipient's X25519 public key), and `SHA256(ct_kem)`. Tampering 
with `ct_kem` changes the decapsulated `ss_kem` (ML-KEM implicit 
rejection) and the bound `SHA256(ct_kem)`, so `base_key` changes 
and the AEAD fails. This is the UniversalCombiner shape 
(`draft-irtf-cfrg-hybrid-kems`); mapping: 
[`combiner.md`](combiner.md).

## Assumptions

The caller has to uphold these.

**Recipient public keys are authentic.** KyberBox does not check 
that `peer_pub_x` or `peer_k_pub` belong to the intended 
recipient. Substituted keys encrypt the message for the wrong 
party. In `session.rs` the keys come from stored contact state; 
the invite/handshake layer owns their authenticity.

**The context string is unique to this use.** Domain separation 
through `ctx` only works when different uses pick different values. 
The only caller today is `session.rs` with `"lithiumd/e2e-msg/v1"`. 
Reusing the same `ctx` in another context would open cross-protocol 
attacks.

**The caller passes `from_x_pub` into decrypt correctly.** 
`decrypt_with_privs` in `session.rs` reads `from_x_pub` from the 
wire frame and passes it as `peer_pub_x`. That value is `ct_T`, 
bound into the `base_key` `info`. Changing it in transit changes 
both the ECDH secret and the bound transcript, and the AEAD fails. 
Attribution to a specific sender stays the caller's job (the 
external signature in `session.rs`). KyberBox binds the key it was 
given; it does not check whose key it is.

**The CSRNG is not compromised.** The ephemeral X25519 key, the 
ML-KEM encapsulation randomness, and all AEAD nonces come from 
`SysRng`. A biased or predictable generator breaks the 
fresh-key-per-message property.

## What KyberBox does not guarantee

**Sender authentication.** Nothing in KyberBox ties the ciphertext 
to a sender. Anyone who knows `peer_k_pub` and `peer_pub_x` (or 
intercepts `from_x_pub` in transit) can produce a valid 
`WirePayload`. In Lithium the Ed25519 + ML-DSA-87 dual signature 
over the plaintext provides authentication, 
verified in `session.rs` before content is returned.

**Replay protection (at the KyberBox level).** A recorded 
`WirePayload` resent to the same recipient still passes AEAD. 
KyberBox binds no counter or state, and decryption does not consume 
the RX key (`self_get_rx_privs` is a read, not a delete). Two 
independent layers above handle replay.

**Layer 1: the replay window in `session.rs`.** Each header 
carries a rising sender counter `step`, in the signed header. After 
the signature check and before any peer-state mutation, 
`decrypt_with_privs` calls `peer_st.replay.check_and_record(hdr.step)` 
(`ReplayWindow`, `state.rs:117-145`). It is a sliding window of 
width 64. A duplicate `step`, or one below the window, is rejected 
with `replayed_message_err()`. The window tolerates reordering of 
new `step` values in range, because the RX key layer accepts 
out-of-order messages anyway. Order matters (signature -> replay 
-> mutation): a forged `step` can't poison the window, and a 
rejected replay leaves no partial state.

**Layer 2: `msg_id` dedup in storage (defense in depth).** Each 
message carries a random `msg_id` (16 B) in the signed header. 
Auto-fetch (`traffic.rs`) stores it through `add_message` into a 
table with a `UNIQUE(msg_id)` constraint. A repeat returns 
`Ok(false)`, marks the item `duplicate`, and skips history. The 
server also deletes a message on first fetch (one-time fetch), so 
a real replay needs a malicious server re-injecting the frame. If 
one slips past both, re-decryption is idempotent: sequence numbers 
and generations only move forward.

**Forward secrecy within one ratchet epoch.** The recipient's 
X25519 key (`rx_x_priv`) lives until the recipient replies and the 
sender switches keys. Every message in that epoch shares the X25519 
component. Compromising `rx_x_priv` retroactively decrypts the ECDH 
part of all messages under that key. The ML-KEM path still gives 
per-message separation (unique `ss_kem`), but a broken ML-KEM plus 
a recovered `rx_x_priv` opens the whole epoch.

**Binding through `base_key`.** `enc_data` and `kem_ct` are 
independent blobs with no shared MAC. The binding runs through 
`base_key`: `enc_data` decrypts only when `ss_kem` is recovered from 
`kem_ct` and the bound transcript matches. Swapping in a field from 
another message fails AEAD, which reads as transmission corruption, 
not as a protocol-level signal.

## Open risks and questions for the auditor

The combiner rationale (X-Wing and UniversalCombiner mapping, and 
what the auditor confirms) is in [`combiner.md`](combiner.md). The 
construction-level risks:

**HKDF with no salt in `derive_ecdh_key`.** The call is 
`HKDF-SHA256(IKM=ecdh_ss, salt=None, info=...)`. Per RFC 5869 sec. 
2.2, no salt means HKDF-Extract uses an all-zero HMAC key of length 
`HashLen`. The X25519 output then goes in as the IKM. That output 
is a 32-byte Curve25519 value, not uniform over 256 bits (top bit 
is 0, low bits cleared by clamping). Standard practice in many 
protocols. The auditor should confirm the security proof covers 
this IKM distribution.

**Storing the X25519 private key as a raw seed before clamping.** 
`random_x25519_keypair` returns and stores `sk_seed`, the 32 bytes 
before clamping, not the clamped scalar. Clamping runs on every use 
through `XStaticSecret::from(seed_array)`. Correct and consistent 
in the codebase. Any future code that read the stored bytes 
directly as a Curve25519 scalar would be wrong. The auditor should 
check that every use site goes through `XStaticSecret::from()`.

**ML-KEM is an unaudited dependency.** ML-KEM-1024 is the RustCrypto 
`ml-kem` crate (pure Rust, FIPS 203). The Lithium team has not 
audited it. A timing side channel, correctness bug, or FIPS 203 
mismatch there would carry over. A standard dependency risk, called 
out given the threat model.

## Summary

- ML-KEM-1024 and X25519 each give an independent shared secret.
- HKDF joins them into `base_key` (the UniversalCombiner shape, 
  full transcript in `info`).
- AES-256-GCM-SIV encrypts the payload under `base_key`.
- Goals: fresh key per message (per-message `ss_kem`), hybrid 
  classical/post-quantum security (combined derivation), 
  nonce-reuse resistance (SIV).

KyberBox does not provide authentication, replay protection, or 
forward secrecy on its own. The layers above do:

- authentication and forward secrecy: `lithiumd/src/e2e/session.rs`
- replay: a sliding window on the signed `step` (`ReplayWindow`) 
  plus `msg_id` dedup with a `UNIQUE` constraint (`traffic.rs` + 
  `add_message`), backed by one-time fetch on the server

Main items for external validation:

- the RustCrypto `ml-kem` ML-KEM-1024 implementation
- the X25519 clamping convention at every store and use site
- HKDF-SHA256 with the X25519 output as IKM and no explicit salt
